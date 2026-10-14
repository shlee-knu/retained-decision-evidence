"""Domain-relative certificates on fixed universal state identifiers.

The restrictions are hypothetical guarantees, not inferred archive properties.
Existing scientific modules are imported unchanged. No structural-policy helper
is reused on a restricted table: all gate decisions have broad-domain proofs.
"""
from collections import defaultdict

from logistics_validation.catalog_audit import (
    ALPHABET, PROFILES, intersect_masks, minimal_masks, observation,
)

DOMAINS = ("cartesian", "chronological", "consignment_exclusion", "both")
GUARANTEES = {
    "cartesian": frozenset(),
    "chronological": frozenset(("chronological",)),
    "consignment_exclusion": frozenset(("consignment_exclusion",)),
    "both": frozenset(("chronological", "consignment_exclusion")),
}


def domain_contains(state, domain):
    if domain not in GUARANTEES:
        raise ValueError(f"unknown domain: {domain}")
    guarantees = GUARANTEES[domain]
    if "chronological" in guarantees and any(a > b for a, b in zip(state.ranks, state.ranks[1:])):
        return False
    if "consignment_exclusion" in guarantees and state.profile == 3 and set(state.order) & {2, 3}:
        return False
    return True


def reference_domain_contains(features, domain):
    """Independent raw filter uses the original Decimal clock implementation.

    Does not invoke abstract(), State, or domain_contains(). Validate all clocks
    even when the domain itself imposes no clock-order condition.
    """
    from logistics_validation.acquisition import exact_first_time
    if domain not in DOMAINS:
        raise ValueError(f"unknown domain: {domain}")
    if features["profile"] not in PROFILES:
        raise ValueError("unsupported profile")
    order = list(dict.fromkeys(features["activities"]))
    if any(a not in ALPHABET for a in order):
        raise ValueError("unsupported activity")
    clocks = [exact_first_time(features["first_times"].get(a)) for a in order]
    if any(t is None for t in clocks):
        raise ValueError("unsupported timestamp")
    chronological = all(a <= b for a, b in zip(clocks, clocks[1:]))
    exclusion = features["profile"] != "Consignment" or not any(a in order for a in ("invoice", "clear"))
    return {"cartesian": True, "chronological": chronological,
            "consignment_exclusion": exclusion, "both": chronological and exclusion}[domain]


class DomainCertificateTable:
    """Entries outside the selected domain are None, never vacuous certificates."""
    def __init__(self, states, labels, domain):
        if len(states) != len(labels) or any(label not in (False, True) for label in labels):
            raise ValueError("exactly one binary label is required per universal state")
        self.states = tuple(states)
        self.labels = bytes(labels)
        self.domain = domain
        self.active = tuple(domain_contains(s, domain) for s in states)
        self.fibers = tuple(defaultdict(list) for _ in range(4))
        self.sufficient = [None] * len(states)
        for i, state in enumerate(states):
            if self.active[i]:
                self.sufficient[i] = 0
                for mask in range(4):
                    self.fibers[mask][observation(state, mask)].append(i)
        for mask, groups in enumerate(self.fibers):
            for ids in groups.values():
                if len({self.labels[i] for i in ids}) == 1:
                    for i in ids:
                        self.sufficient[i] |= 1 << mask
        self.sufficient = tuple(self.sufficient)
        self.minimal = tuple(None if bits is None else minimal_masks(bits) for bits in self.sufficient)
        self.necessary = tuple(None if m is None else intersect_masks(m) for m in self.minimal)


def domain_changes(old, new, index):
    if old.states != new.states:
        raise ValueError("comparisons require identical universal state identifiers")
    if old.sufficient[index] is None or new.sufficient[index] is None:
        return {"supported_both": False, "verdict_preserved": None, "lost": (), "gained": ()}
    preserved = old.labels[index] == new.labels[index]
    before, after = old.sufficient[index], new.sufficient[index]
    return {"supported_both": True, "verdict_preserved": preserved,
            "lost": tuple(m for m in range(4) if preserved and before & (1 << m) and not after & (1 << m)),
            "gained": tuple(m for m in range(4) if preserved and after & (1 << m) and not before & (1 << m))}


def guarantee_mask(state, domain):
    """Which blocks establish membership, chosen from the visible base only."""
    guarantees = GUARANTEES[domain]
    clock = "chronological" in guarantees and len(state.order) >= 2
    profile = "consignment_exclusion" in guarantees and bool(set(state.order) & {2, 3})
    return int(profile) + 2 * int(clock)


def verified_gate_mask(state_index, domain, broad_table, order="profile_first"):
    """Pay membership checks, then stop only with a broad-domain certificate.

    The function returns a replay trace for an already represented complete
    input. Query choices read only base and actually fetched blocks through the
    corresponding completion-fiber certificate; no narrower-domain assumption
    drives a stop. Failed checks use precisely the same broad-domain fallback.
    """
    if broad_table.domain != "cartesian":
        raise ValueError("fallback table must use the full Cartesian domain")
    if order not in ("profile_first", "time_first"):
        raise ValueError("unknown order")
    state = broad_table.states[state_index]
    mask = guarantee_mask(state, domain)
    verification_mask = mask
    passed = domain_contains(state, domain)
    trace = [m for m in (1, 2) if mask & m]
    if not broad_table.sufficient[state_index] & (1 << mask):
        for block in ((1, 2) if order == "profile_first" else (2, 1)):
            if not mask & block:
                trace.append(block)
                mask |= block
            if broad_table.sufficient[state_index] & (1 << mask):
                break
    assert broad_table.sufficient[state_index] & (1 << mask)
    return {"mask": mask, "verification_mask": verification_mask,
            "guarantee_holds": passed, "used_fallback": not passed,
            "decision": bool(broad_table.labels[state_index]), "read_order": trace}


def withdrawal_pairs():
    """Strict nesting only; no false comparison of incomparable assumptions."""
    return tuple((small, large) for small in DOMAINS for large in DOMAINS
                 if GUARANTEES[small] > GUARANTEES[large])
