"""Complete access certificates for a deliberately fixed four-milestone fragment.

No duration, multiplicity, later-event or reference predicates are supported.
All known profiles and all clock weak orders are admissible completions. The
minimum certificate size is pointwise/clairvoyant, not an optimal online policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations, product
from collections import defaultdict
from datetime import datetime
from fractions import Fraction
import re

ALPHABET = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR",
            "2-way match", "Consignment")
MASK_NAMES = ("empty", "P", "T", "PT")


@dataclass(frozen=True)
class Rule:
    required: frozenset[int]
    forbidden: frozenset[int]
    edges: frozenset[tuple[int, int]]


BASELINE = (
    Rule(frozenset(range(4)), frozenset(), frozenset(((0, 1), (1, 2), (2, 3)))),
    Rule(frozenset(range(4)), frozenset(), frozenset(((0, 1), (0, 2), (1, 3), (2, 3)))),
    Rule(frozenset((0, 2, 3)), frozenset(), frozenset(((0, 2), (2, 3)))),
    Rule(frozenset((0, 1)), frozenset(), frozenset(((0, 1),))),
)


@dataclass(frozen=True)
class State:
    order: tuple[int, ...]
    ranks: tuple[int, ...]
    profile: int

    def key(self):
        return (len(self.order), len(set(self.ranks)), self.order, self.ranks, self.profile)


def weak_orders(n):
    if not n:
        return ((),)
    return tuple(q for q in product(range(n), repeat=n)
                 if set(q) == set(range(max(q) + 1)))


def universe():
    return tuple(sorted((State(order, ranks, p)
                         for k in range(5) for order in permutations(range(4), k)
                         for ranks in weak_orders(k) for p in range(4)), key=State.key))


def verdict(state, catalog=BASELINE):
    rule = catalog[state.profile]
    present = set(state.order)
    if not rule.required <= present or rule.forbidden & present:
        return False
    pos = {a: i for i, a in enumerate(state.order)}
    clock = dict(zip(state.order, state.ranks))
    return all(b not in pos or (a in pos and pos[a] < pos[b] and clock[a] <= clock[b])
               for a, b in rule.edges)


def generated_catalogs():
    """Frozen 80 single edits; strict anchor is separately marked two edits."""
    out = [("baseline", BASELINE, {"kind": "anchor", "edits": 0})]
    strict = list(BASELINE)
    r = strict[3]
    strict[3] = Rule(r.required, frozenset((2, 3)), r.edges)
    out.append(("strict_consignment", tuple(strict), {"kind": "anchor", "edits": 2}))
    for p in range(4):
        original = BASELINE[p]
        for a in range(4):
            rules = list(BASELINE)
            rules[p] = Rule(original.required ^ {a}, original.forbidden, original.edges)
            out.append((f"required_p{p}_a{a}", tuple(rules),
                        {"kind": "toggle_required", "profile": p, "activity": a, "edits": 1}))
        for a in range(4):
            rules = list(BASELINE)
            rules[p] = Rule(original.required, original.forbidden | {a}, original.edges)
            out.append((f"forbidden_p{p}_a{a}", tuple(rules),
                        {"kind": "add_forbidden", "profile": p, "activity": a, "edits": 1}))
        for a, b in permutations(range(4), 2):
            rules = list(BASELINE)
            rules[p] = Rule(original.required, original.forbidden, original.edges ^ {(a, b)})
            out.append((f"edge_p{p}_a{a}_b{b}", tuple(rules),
                        {"kind": "toggle_edge", "profile": p, "edge": [a, b], "edits": 1}))
    return tuple(out)


def observation(state, mask):
    return (state.order, state.profile if mask & 1 else None,
            state.ranks if mask & 2 else None)


class CertificateTable:
    """Truth vectors and complete mask sufficiency; fibers include actual state."""
    def __init__(self, states, labels):
        if len(states) != len(labels):
            raise ValueError("one label is required per state")
        self.states = states
        self.labels = bytes(labels)
        self.fibers = [defaultdict(list) for _ in range(4)]
        for i, s in enumerate(states):
            for mask in range(4):
                self.fibers[mask][observation(s, mask)].append(i)
        self.sufficient = [0] * len(states)
        for mask, groups in enumerate(self.fibers):
            for ids in groups.values():
                if len({self.labels[i] for i in ids}) == 1:
                    for i in ids:
                        self.sufficient[i] |= 1 << mask
        self.minimal = [minimal_masks(bits) for bits in self.sufficient]
        self.necessary = [intersect_masks(masks) for masks in self.minimal]
        tied_labels = defaultdict(list)
        for i, state in enumerate(states):
            if not any(state.ranks):
                tied_labels[state.order].append(self.labels[i])
        self.structural_first = {order: 2 if all(labels) else 1 for order, labels in tied_labels.items()}

    def policy_mask(self, index, policy):
        if policy == "always_both":
            return 3
        if self.sufficient[index] & 1:
            return 0
        first = (self.structural_first[self.states[index].order] if policy == "structural_order"
                 else {"profile_first": 1, "time_first": 2}[policy])
        return first if self.sufficient[index] & (1 << first) else 3


def minimal_masks(bits):
    return tuple(m for m in range(4) if bits & (1 << m)
                 and not any(bits & (1 << n) and n != m and n & m == n for n in range(4)))


def intersect_masks(masks):
    result = 3
    for mask in masks:
        result &= mask
    return result


def changes(old, new, index):
    if old.labels[index] != new.labels[index]:
        return {"verdict_preserved": False, "lost": (), "gained": ()}
    before, after = old.sufficient[index], new.sufficient[index]
    return {"verdict_preserved": True,
            "lost": tuple(m for m in range(4) if before & (1 << m) and not after & (1 << m)),
            "gained": tuple(m for m in range(4) if after & (1 << m) and not before & (1 << m))}


def loss_witness(old, new, allowed_anchors=None):
    """Canonical minimum quotient pair; no real-world edit-distance claim."""
    allowed = None if allowed_anchors is None else set(allowed_anchors)
    for i, state in enumerate(old.states):
        if allowed is not None and i not in allowed:
            continue
        for mask in changes(old, new, i)["lost"]:
            for j in new.fibers[mask][observation(state, mask)]:
                if new.labels[j] != new.labels[i]:
                    assert old.labels[i] == old.labels[j]
                    return {"anchor_index": i, "completion_index": j, "lost_mask": mask}
    return None


def concrete(state):
    return {"activities": [ALPHABET[a] for a in state.order],
            "profile": PROFILES[state.profile],
            "first_times": {ALPHABET[a]: f"2020-01-01T00:00:0{r}Z"
                            for a, r in zip(state.order, state.ranks)}}


_RFC = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z")


def reference_time(value):
    """Independent datetime calendar validation plus exact Fraction arithmetic."""
    match = _RFC.fullmatch(value) if isinstance(value, str) else None
    if not match or match[4] == "-00:00":
        raise ValueError("unsupported RFC3339 timestamp")
    d, hms, fraction, zone = match.groups()
    if zone.upper() == "Z":
        zone = "+00:00"
    if int(zone[1:3]) > 23 or int(zone[4:]) > 59:
        raise ValueError("unsupported offset")
    t = datetime.fromisoformat(d + "T" + hms + zone)
    whole = (t.toordinal() - datetime(1970, 1, 1).toordinal()) * 86400
    whole += t.hour * 3600 + t.minute * 60 + t.second - int(t.utcoffset().total_seconds())
    return Fraction(whole) + (Fraction(int(fraction), 10 ** len(fraction)) if fraction else 0)


def abstract(features):
    order = tuple(dict.fromkeys(ALPHABET.index(a) for a in features["activities"]))
    clocks = [reference_time(features["first_times"][ALPHABET[a]]) for a in order]
    ranks = {v: r for r, v in enumerate(sorted(set(clocks)))}
    return State(order, tuple(ranks[v] for v in clocks), PROFILES.index(features["profile"]))


def reference_verdict(features, catalog=BASELINE):
    """Raw reference: scan source sequence separately for each declared atom.

    Intentionally does not invoke abstract(), verdict(), or certificate tables.
    Validates every observed first clock before Boolean early exits.
    """
    activities = features["activities"]
    if any(a not in ALPHABET for a in activities):
        raise ValueError("unsupported activity")
    p = PROFILES.index(features["profile"])
    required, forbidden, edges = catalog[p].required, catalog[p].forbidden, catalog[p].edges
    clocks = {a: reference_time(features["first_times"][a]) for a in set(activities)}
    if any(ALPHABET[a] not in activities for a in required):
        return False
    if any(ALPHABET[a] in activities for a in forbidden):
        return False
    for a, b in edges:
        aa, bb = ALPHABET[a], ALPHABET[b]
        if bb in activities:
            if aa not in activities or activities.index(aa) >= activities.index(bb):
                return False
            if clocks[aa] > clocks[bb]:
                return False
    return True


def catalog_json(catalog):
    return {PROFILES[p]: {"required": [ALPHABET[a] for a in sorted(r.required)],
                          "forbidden": [ALPHABET[a] for a in sorted(r.forbidden)],
                          "edges": [[ALPHABET[a], ALPHABET[b]] for a, b in sorted(r.edges)]}
            for p, r in enumerate(catalog)}
