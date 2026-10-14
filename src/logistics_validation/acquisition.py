"""Transparent acquisition for a fixed, finite milestone-contract catalog.

This is a certificate-producing application of partial-information evaluation,
not a new conformance formalism or active-feature-acquisition theory. Labels
mean compatibility with the declared observed-trace contract, not business
completion, natural-error truth, or full procurement correctness.

Soundness is conditional on a trusted domain: the actual profile belongs to the
catalog, the base sequence is the complete observed milestone projection, and
first timestamps belong to the supported RFC3339 domain. Hidden invalid values
cannot be discovered without reading them. Visible unsupported input produces
``unsupported``. In particular, early rejection is NOT input validation.

Feature mapping expected by acquire():
    activities: ordered canonical milestone names, including repetitions
    profile: one catalog key
    first_times: mapping from observed milestone name to its first timestamp

Only ``activities`` is read initially. Metadata is read through the accessor,
which records every accessed block. ``always_both`` is the literal full-access
reference; ``profile_first`` and ``time_first`` stop at a singleton certificate.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from decimal import Decimal, localcontext
import re
from types import MappingProxyType

UNOBSERVED = object()
DEFAULT_CATALOG = MappingProxyType({
    "3-way match, invoice after GR": (
        ("create", "receive", "invoice", "clear"),
        (("create", "receive"), ("receive", "invoice"), ("invoice", "clear")),
    ),
    "3-way match, invoice before GR": (
        ("create", "receive", "invoice", "clear"),
        (("create", "receive"), ("create", "invoice"), ("receive", "clear"), ("invoice", "clear")),
    ),
    "2-way match": (
        ("create", "invoice", "clear"), (("create", "invoice"), ("invoice", "clear")),
    ),
    "Consignment": (("create", "receive"), (("create", "receive"),)),
})
DOMAIN_ASSUMPTIONS = (
    "actual profile is in the declared finite catalog",
    "activities is the complete observed milestone projection in source order",
    "first_times provides a supported RFC3339 timestamp for every observed milestone",
    "hidden clocks may have any order; observed event position does not certify clock order",
    "only the stated presence, first-position and first-time predicates define the label",
    "optional forbidden activities apply only to explicitly named catalog profiles",
)
_STAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z"
)


def exact_first_time(value):
    """Independent exact normalization; unknown offsets/leap seconds unsupported."""
    if not isinstance(value, str):
        return None
    match = _STAMP.fullmatch(value)
    if match is None:
        return None
    y, mo, d, h, minute, second = map(int, match.groups()[:6])
    fraction, zone = match.groups()[6:]
    if h > 23 or minute > 59 or second > 59 or zone == "-00:00":
        return None
    try:
        days = date(y, mo, d).toordinal() - date(1970, 1, 1).toordinal()
    except ValueError:
        return None
    offset = 0
    if zone.upper() != "Z":
        zh, zm = int(zone[1:3]), int(zone[4:6])
        if zh > 23 or zm > 59:
            return None
        offset = (zh * 3600 + zm * 60) * (1 if zone[0] == "+" else -1)
    with localcontext() as context:
        context.prec = max(40, len(fraction or "") + 25)
        return Decimal(days * 86400 + h * 3600 + minute * 60 + second - offset) + Decimal("0." + (fraction or "0"))


def _unsupported(reason, observed):
    return {
        "status": "unsupported", "decision": "unsupported", "possible_labels": [],
        "observed_blocks": list(observed), "need_fields": [], "profile_results": {},
        "reason": reason, "assumptions": list(DOMAIN_ASSUMPTIONS),
    }


def possible_outcomes(activities, *, profile=UNOBSERVED, first_times=UNOBSERVED,
                      catalog=DEFAULT_CATALOG, forbidden=None):
    """Enumerate exactly possible binary labels over admissible completions.

    For an unknown clock block, every structurally satisfied profile containing
    an active edge admits both a monotone timestamp completion and one inverted
    edge completion. A profile with a structural violation admits only reject.
    With visible clocks every known profile has a single determined label.
    Unknown profiles are enumerated over the declared catalog, not inferred
    from labels or observed frequencies. ``need_fields`` lists unobserved blocks
    available for resolving ambiguity; it is not a minimal acquisition set.
    """
    observed = ["activities"]
    if profile is not UNOBSERVED:
        observed.append("profile")
    if first_times is not UNOBSERVED:
        observed.append("first_times")
    if not isinstance(catalog, Mapping) or not catalog:
        return _unsupported("empty or invalid catalog", observed)
    if not isinstance(activities, Sequence) or isinstance(activities, (str, bytes)):
        return _unsupported("activities must be an ordered sequence", observed)
    if any(not isinstance(activity, str) for activity in activities):
        return _unsupported("activity names must be strings", observed)
    alphabet = set()
    try:
        for name, (required, edges) in catalog.items():
            if not isinstance(name, str):
                raise ValueError("catalog profile names must be strings")
            alphabet.update(required)
            for a, b in edges:
                alphabet.update((a, b))
    except (TypeError, ValueError):
        return _unsupported("malformed catalog", observed)
    prohibitions = {}
    if forbidden is not None:
        if not isinstance(forbidden, Mapping):
            return _unsupported("forbidden policy must be a mapping", observed)
        for name, values in forbidden.items():
            if name not in catalog:
                return _unsupported("forbidden policy names an unknown profile", observed)
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                return _unsupported("forbidden activities must be an explicit sequence", observed)
            if any(not isinstance(value, str) or value not in alphabet for value in values):
                return _unsupported("forbidden activity outside the declared milestone alphabet", observed)
            prohibitions[name] = tuple(values)
    if any(activity not in alphabet for activity in activities):
        return _unsupported("activity outside the declared milestone alphabet", observed)
    if profile is not UNOBSERVED and (not isinstance(profile, str) or profile not in catalog):
        return _unsupported("visible profile outside the declared catalog", observed)
    first = {}
    for position, activity in enumerate(activities):
        first.setdefault(activity, position)
    parsed_times = {}
    if first_times is not UNOBSERVED:
        if not isinstance(first_times, Mapping):
            return _unsupported("visible first_times is not a mapping", observed)
        for activity in first:
            value = exact_first_time(first_times.get(activity))
            if value is None:
                return _unsupported(f"missing or unsupported visible timestamp: {activity}", observed)
            parsed_times[activity] = value
    considered = tuple(catalog) if profile is UNOBSERVED else (profile,)
    per_profile = {}
    union = set()
    for name in considered:
        required, edges = catalog[name]
        missing = [activity for activity in required if activity not in first]
        forbidden_present = [activity for activity in prohibitions.get(name, ()) if activity in first]
        positional = [f"{a}->{b}" for a, b in edges
                      if b in first and (a not in first or first[a] >= first[b])]
        active = [(a, b) for a, b in edges if a in first and b in first]
        clock_alerts = [] if first_times is UNOBSERVED else [
            f"{a}->{b}" for a, b in active if parsed_times[a] > parsed_times[b]
        ]
        if missing or forbidden_present or positional or clock_alerts:
            labels = {"reject"}
        elif first_times is UNOBSERVED and active:
            labels = {"accept", "reject"}
        else:
            labels = {"accept"}
        union.update(labels)
        per_profile[name] = {
            "possible_labels": sorted(labels), "missing_required": missing,
            "forbidden_present": forbidden_present,
            "position_alerts": positional, "time_alerts": clock_alerts,
            "clock_block_observed": first_times is not UNOBSERVED,
        }
    determined = len(union) == 1
    need = []
    if not determined:
        if profile is UNOBSERVED:
            need.append("profile")
        if first_times is UNOBSERVED:
            need.append("first_times")
    return {
        "status": "determined" if determined else "ambiguous",
        "decision": next(iter(union)) if determined else None,
        "possible_labels": sorted(union), "observed_blocks": observed,
        "need_fields": need, "profile_results": per_profile,
        "forbidden_policy": {name: list(values) for name, values in prohibitions.items()},
        "reason": "all admissible completions agree" if determined else "admissible completions disagree",
        "assumptions": list(DOMAIN_ASSUMPTIONS),
    }


class MetadataAccessor:
    """Read-audited accessor; policies never receive hidden metadata values."""

    def __init__(self, features):
        self._features = features
        self.activities = features["activities"]
        self.read_blocks = []

    def fetch(self, name):
        if name not in ("profile", "first_times"):
            raise ValueError(name)
        if name in self.read_blocks:
            raise RuntimeError(f"Metadata block requested twice: {name}")
        self.read_blocks.append(name)
        return self._features[name]


def structural_order(activities, *, catalog=DEFAULT_CATALOG, forbidden=None):
    """Choose a fixed policy from visible structure only, with no fitting.

    When every catalog profile is structurally eligible, inspect clocks first.
    Otherwise inspect profile first. Determinate base cases use profile_first,
    whose evaluator immediately stops without a query. This transparent
    baseline is not asserted to minimize cost; it has no frequency estimates,
    hidden-field access, clock knowledge, or deployment-specific cost model.
    """
    certificate = possible_outcomes(activities, catalog=catalog, forbidden=forbidden)
    if certificate["status"] == "unsupported":
        raise ValueError(certificate["reason"])
    all_eligible = all(
        not result["missing_required"] and not result["position_alerts"] and not result["forbidden_present"]
        for result in certificate["profile_results"].values()
    )
    return "time_first" if certificate["status"] == "ambiguous" and all_eligible else "profile_first"


def acquire(features, policy="profile_first", *, catalog=DEFAULT_CATALOG, forbidden=None):
    """Execute a fixed acquisition order and return its read trace/certificates.

    `features` may be a read-instrumented Mapping. Metadata is accessed only
    through MetadataAccessor.fetch(); a skipped block is never inspected to
    check its validity. Consequently the domain assumptions are essential.
    """
    if policy not in ("always_both", "profile_first", "time_first"):
        raise ValueError(f"Unknown acquisition policy: {policy}")
    access = MetadataAccessor(features)
    values = {}
    initial = possible_outcomes(access.activities, catalog=catalog, forbidden=forbidden)
    certificates = [initial]
    certificate = initial
    order = ("first_times", "profile") if policy == "time_first" else ("profile", "first_times")
    if initial["status"] != "unsupported":
        for name in order:
            if policy != "always_both" and certificate["status"] != "ambiguous":
                break
            try:
                values[name] = access.fetch(name)
            except KeyError:
                certificate = _unsupported(f"requested metadata block is missing: {name}",
                                           ["activities"] + access.read_blocks)
                certificates.append(certificate)
                if policy != "always_both":
                    break
                continue
            certificate = possible_outcomes(access.activities, catalog=catalog, forbidden=forbidden, **values)
            certificates.append(certificate)
            if policy != "always_both" and certificate["status"] == "unsupported":
                break
    # A missing first block in always_both must not disappear when the second
    # block is fetched and a new partial certificate happens to be determined.
    unsupported = next((c for c in certificates if c["status"] == "unsupported"), None)
    if unsupported is not None:
        certificate = unsupported
    return {
        "policy": policy, "decision": certificate["decision"],
        "status": certificate["status"], "certificate": certificate,
        "certificate_trace": certificates,
        "fetched_blocks": access.read_blocks,
        "profile_queries": int("profile" in access.read_blocks),
        "time_queries": int("first_times" in access.read_blocks),
        "assumptions": list(DOMAIN_ASSUMPTIONS),
    }
