"""Actual MP-Declare conformance checking with explicitly matched semantics.

Declare4Py 2.2.0 supplies the unmodified engine and templates. The adapter
retains input order, labels the first occurrence of each activity, and copies
IDs/references into event attributes; it does not precompute violations.

``process`` checks required milestones and first-occurrence precedence in both
position and signed time. ``full`` additionally checks ID uniqueness, local
reference existence and object identity. Neither mode checks JSON Schema.

The library's native duration interval is based on abs(timestamp difference).
Signed time order is therefore expressed as a numeric correlation predicate.
This is an encoding of existing MP-Declare expressiveness, not a new formalism.
Sources: https://github.com/ivanDonadello/Declare4Py and
https://ceur-ws.org/Vol-3216/paper_249.pdf .
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from decimal import Decimal, localcontext
from functools import lru_cache
import re
from typing import Literal

from Declare4Py.D4PyEventLog import D4PyEventLog
from Declare4Py.ProcessMiningTasks.ConformanceChecking.MPDeclareAnalyzer import MPDeclareAnalyzer
from Declare4Py.ProcessModels.DeclareModel import DeclareModel
from Declare4Py.Utils.Declare.TraceStates import TraceState
from pm4py.objects.log.obj import EventLog, Trace, Event as PMEvent

from .model import Case

Scope = Literal["process", "full"]
SUPPORTED_RULES = {
    "process": ("required_activity", "first_positional_precedence", "first_signed_time_precedence"),
    "full": ("required_activity", "first_positional_precedence", "first_signed_time_precedence",
             "duplicate_id", "dangling_reference", "object_identity"),
}
RFC3339 = re.compile(
    r"(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})[Tt]"
    r"(?P<h>\d{2}):(?P<minute>\d{2}):(?P<s>\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>[Zz]|[+-]\d{2}:\d{2})\Z"
)
EPOCH_ORDINAL = date(1970, 1, 1).toordinal()


def exact_timestamp(value: str | None) -> Decimal | None:
    """Independent RFC3339 normalization with exact fractional seconds.

    Invalid or absent timestamps are delegated to the shared schema stage, as
    in the application contract. No floating-point epoch conversion is used.
    Leap seconds are not supported by this adapter; the current official
    schema checker configuration also rejects them.
    """
    if not isinstance(value, str):
        return None
    match = RFC3339.fullmatch(value)
    if match is None:
        return None
    p = match.groupdict()
    try:
        day = date(int(p["y"]), int(p["m"]), int(p["d"]))
        h, minute, second = int(p["h"]), int(p["minute"]), int(p["s"])
        if h > 23 or minute > 59 or second > 59:
            return None
        zone = p["zone"]
        offset = 0
        if zone.upper() != "Z":
            oh, om = int(zone[1:3]), int(zone[4:6])
            if oh > 23 or om > 59:
                return None
            offset = (oh * 3600 + om * 60) * (1 if zone[0] == "+" else -1)
        integer = (day.toordinal() - EPOCH_ORDINAL) * 86400 + h * 3600 + minute * 60 + second - offset
        fraction = p["fraction"] or ".0"
        with localcontext() as ctx:
            ctx.prec = max(40, len(fraction) + 20)
            return Decimal(integer) + Decimal("0" + fraction)
    except (TypeError, ValueError):
        return None


@lru_cache(maxsize=64)
def _compiled(required: tuple[str, ...], edges: tuple[tuple[str, str], ...], scope: Scope):
    if scope not in SUPPORTED_RULES:
        raise ValueError(f"Unsupported MP-Declare scope: {scope}")
    activities = sorted(set(required) | {x for edge in edges for x in edge})
    codes = {name: f"s{i}" for i, name in enumerate(activities)}
    lines = ["activity event"] + [f"# {code} = {name!r}" for name, code in codes.items()]
    names = []
    for activity in required:
        lines.append(f"Existence[event] | A.step is {codes[activity]} |")
        names.append(f"required:{activity}")
    for before, after in edges:
        # Explicit pos comparison excludes the activation event itself even
        # when before == after. Parentheses are needed around attribute-to-
        # attribute operands in the Declare4Py 2.2.0 condition parser.
        activation = f"A.step is {codes[after]} and A.first = 1"
        correlation = (
            f"T.step is {codes[before]} and T.first = 1 and ( T.pos ) < ( A.pos ) "
            "and ( A.time_valid = 0 or T.time_valid = 0 or ( T.ts ) <= ( A.ts ) )"
        )
        lines.append(f"Precedence[event, event] | {activation} | {correlation} |")
        names.append(f"first_precedence:{before}:{after}")
    if scope == "full":
        lines.extend([
            "Not Response[event, event] | | ( A.eid ) = ( T.eid ) and ( A.pos ) < ( T.pos ) |",
            "Responded Existence[event, event] | A.has_ref = 1 | ( A.ref ) = ( T.eid ) |",
            "Absence[event] | ( A.obj ) != ( A.expected_obj ) |",
        ])
        names.extend(["duplicate_id", "dangling_reference", "object_identity"])
    source = "\n".join(lines)
    model = DeclareModel().parse_from_string(source)
    if len(model.constraints) != len(names):
        raise RuntimeError("Declare4Py silently omitted a generated constraint")
    return model, tuple(names), codes, source


def model_text(case: Case, scope: Scope = "full") -> str:
    """Export the exact DECLARE rules for review and reproduction."""
    return _compiled(tuple(case.required), tuple(case.edges), scope)[3]


def _trace(case: Case, codes: dict[str, str]) -> Trace:
    trace = Trace(attributes={"concept:name": case.case_id})
    seen = set()
    stamps = [exact_timestamp(event.time) for event in case.events]
    # MP-Declare receives ordinal time ranks, not finite-precision epochs. This
    # strictly preserves equalities and signed order; it expresses no duration.
    ranks = {stamp: rank for rank, stamp in enumerate(sorted({x for x in stamps if x is not None}))}
    for pos, (event, stamp) in enumerate(zip(case.events, stamps)):
        trace.append(PMEvent({
            "concept:name": "event", "step": codes.get(event.activity, "other"),
            "first": int(event.activity not in seen), "pos": pos,
            "ts": ranks[stamp] if stamp is not None else 0, "time_valid": int(stamp is not None),
            "eid": event.event_id, "obj": event.object_id,
            "expected_obj": case.attributes.get("object_id", event.object_id),
            "ref": event.ref or "", "has_ref": int(bool(event.ref)),
        }))
        seen.add(event.activity)
    return trace


def mp_declare_issues(cases: list[Case], scope: Scope = "full") -> dict[str, set[str]]:
    """Evaluate through MPDeclareAnalyzer, never through indexed/SQL rules.

    Constraint names diagnose the DECLARE encoding; a first_precedence failure
    can mean missing predecessor, wrong first position, or reversed first time.
    Thus case decisions, not one-to-one diagnostic strings, match the contract.
    Conversion and grouping are included in this call. Profile compilation is
    cached; callers measuring cold execution should call clear_model_cache().
    """
    if scope not in SUPPORTED_RULES:
        raise ValueError(f"Unsupported MP-Declare scope: {scope}")
    if len({c.case_id for c in cases}) != len(cases):
        raise ValueError("Each case_id must be unique within an evaluation batch")
    groups = defaultdict(list)
    for case in cases:
        groups[(tuple(case.required), tuple(case.edges))].append(case)
    answer = {}
    for (required, edges), group in groups.items():
        model, names, codes, _ = _compiled(required, edges, scope)
        log = EventLog([_trace(case, codes) for case in group], properties={
            "pm4py:param:timestamp_key": "ts", "pm4py:param:activity_key": "concept:name",
        })
        results = MPDeclareAnalyzer(D4PyEventLog(log=log), model, consider_vacuity=True).run()
        if len(results.model_check_res) != len(group):
            raise RuntimeError("Declare4Py omitted a case result")
        for case, row in zip(group, results.model_check_res):
            if len(row) != len(names):
                raise RuntimeError("Declare4Py omitted a constraint result")
            if any(r.state not in (TraceState.SATISFIED, TraceState.VIOLATED) for r in row):
                raise RuntimeError("Complete-case analysis returned an undecided state")
            answer[case.case_id] = {name for name, result in zip(names, row)
                                    if result.state == TraceState.VIOLATED}
    return answer


def clear_model_cache() -> None:
    _compiled.cache_clear()
