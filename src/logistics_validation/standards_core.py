"""Exact evidence audit for named finite blocks, independent of any standard.

This is explicit finite enumeration, not a general FHIR/GS1 validator. Domains
are fixed supported abstractions. An absent-field category is an observed value;
an unread field has no observation. Receipt labels do not add domain assumptions.
Compilation stores O(N * 2**B) state references; projection construction also
costs up to a factor B. Planner compilation is measured separately. Pointwise
minimum additions are offline diagnostics, not an optimal acquisition policy.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from itertools import product
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


def selected(mask, count):
    return tuple(i for i in range(count) if mask & (1 << i))


def project(state, mask):
    return tuple(value for i, value in enumerate(state) if mask & (1 << i))


def antichain(masks):
    ordered = sorted(set(masks), key=lambda m: (m.bit_count(), m))
    kept = []
    for mask in ordered:
        if not any(mask & smaller == smaller for smaller in kept):
            kept.append(mask)
    return tuple(kept)


class CompiledModel:
    """Compile all observation fibers for a Cartesian, named-block abstraction.

    spec: name, block_names, domains, old_predicate, new_predicate;
    optional encode_state and metadata are consumed by the experiment harness.
    Boolean labels are checked strictly to avoid coercing errors/unknowns to True.
    """

    def __init__(self, spec):
        self.name = spec["name"]
        self.block_names = tuple(spec["block_names"])
        self.domains = tuple(tuple(d) for d in spec["domains"])
        self.count = len(self.block_names)
        if not self.count or len(self.domains) != self.count:
            raise ValueError("one nonempty domain is needed per named block")
        if len(set(self.block_names)) != self.count:
            raise ValueError("block names must be unique")
        for domain in self.domains:
            if not domain or len(set(domain)) != len(domain):
                raise ValueError("domain categories must be nonempty, unique and hashable")
        self.full_mask = (1 << self.count) - 1
        self.states = tuple(product(*self.domains))
        self.indices = {s: i for i, s in enumerate(self.states)}
        self.old_labels = tuple(spec["old_predicate"](s) for s in self.states)
        self.new_labels = tuple(spec["new_predicate"](s) for s in self.states)
        if any(type(v) is not bool for v in self.old_labels + self.new_labels):
            raise ValueError("predicates must return bool; errors and unknowns are separate")
        self.domain_digest = digest({"blocks": self.block_names, "domains": self.domains})
        self.old_digest = digest({"domain": self.domain_digest, "labels": self.old_labels})
        self.new_digest = digest({"domain": self.domain_digest, "labels": self.new_labels})
        self._fibers = []
        self._outcomes = {"old": [], "new": []}
        for mask in range(self.full_mask + 1):
            groups = defaultdict(list)
            for i, state in enumerate(self.states):
                groups[project(state, mask)].append(i)
            fibers = {key: tuple(ids) for key, ids in groups.items()}
            self._fibers.append(fibers)
            for version, labels in (("old", self.old_labels), ("new", self.new_labels)):
                self._outcomes[version].append({key: frozenset(labels[i] for i in ids)
                                               for key, ids in fibers.items()})
        self._influence_cache = {}

    def mask(self, names):
        names = tuple(names)
        unknown = set(names) - set(self.block_names)
        if unknown:
            raise ValueError("unknown blocks: " + repr(sorted(unknown)))
        return sum(1 << i for i, name in enumerate(self.block_names) if name in names)

    def _check_mask(self, mask):
        if type(mask) is not int or mask < 0 or mask > self.full_mask:
            raise ValueError("invalid observation mask")

    def fiber(self, index, mask):
        self._check_mask(mask)
        return self._fibers[mask][project(self.states[index], mask)]

    def outcomes(self, index, mask, version="new"):
        self._check_mask(mask)
        return self._outcomes[version][mask][project(self.states[index], mask)]

    def observation_classes(self, version="old", sufficient_only=True):
        for mask, fibers in enumerate(self._fibers):
            for ids in fibers.values():
                if not sufficient_only or len(self.outcomes(ids[0], mask, version)) == 1:
                    yield ids[0], mask

    def minimal_masks(self, index, version="new"):
        return antichain(mask for mask in range(self.full_mask + 1)
                         if len(self.outcomes(index, mask, version)) == 1)

    def minimal_additions(self, index, retained_mask):
        self._check_mask(retained_mask)
        return antichain(mask & ~retained_mask for mask in range(self.full_mask + 1)
                         if len(self.outcomes(index, mask | retained_mask)) == 1)

    def classify(self, index, mask, old_verdict):
        if type(old_verdict) is not bool or self.outcomes(index, mask, "old") != {old_verdict}:
            return "invalid_receipt"
        labels = self.outcomes(index, mask)
        if len(labels) != 1:
            return "insufficient"
        return "safe" if labels == {old_verdict} else "stale_verdict"

    def witness(self, index, mask):
        """Two new-label-opposed completions with identical retained values."""
        by_label = {}
        for i in self.fiber(index, mask):
            by_label.setdefault(self.new_labels[i], i)
        if len(by_label) < 2:
            return None
        return (by_label[False], by_label[True])

    def influential(self, index, mask, version="new"):
        """Blocks whose free variation changes a label inside the current fiber.

        Depends on observed values alone. Cartesian support makes a one-coordinate
        edge test complete for finding a useful next block in a nonconstant fiber.
        """
        key = (version, mask, project(self.states[index], mask))
        if key in self._influence_cache:
            return self._influence_cache[key]
        labels = self.old_labels if version == "old" else self.new_labels
        ids = self.fiber(index, mask)
        influence = 0
        if len(self.outcomes(index, mask, version)) > 1:
            for block in selected(self.full_mask & ~mask, self.count):
                others = self.full_mask ^ (1 << block)
                values = {}
                for i in ids:
                    fixed = project(self.states[i], others)
                    if fixed in values and values[fixed] != labels[i]:
                        influence |= 1 << block
                        break
                    values[fixed] = labels[i]
        self._influence_cache[key] = influence
        return influence

    def recover(self, index, retained_mask=0, version="new"):
        """Fixed block-order policy with value-dependent irrelevant blocks skipped.

        The current fiber, rather than unread values, selects each next block.
        Returns final mask and ordered new block indices; no optimality claim.
        """
        mask = retained_mask
        reads = []
        while len(self.outcomes(index, mask, version)) > 1:
            available = self.influential(index, mask, version)
            if not available:
                raise AssertionError("nonconstant Cartesian fiber has no influential coordinate")
            block = next(i for i in range(self.count) if available & (1 << i))
            mask |= 1 << block
            reads.append(block)
        return mask, tuple(reads)

    def static_delta_plan(self, changed_names):
        """Sound prior-label/changed-dependency comparator, with explicit fallback.

        A prior label is usable here because a self-contained old certificate was
        verified. For each prior label, prove new-label determination by changed
        blocks over the entire domain; if it fails use all new dependencies.
        Pure implication/identity can establish a constant without new reads.
        """
        changed_mask = self.mask(changed_names)
        all_dependencies = self.influential(0, 0)
        result = {}
        for old_label in (False, True):
            ids = [i for i, v in enumerate(self.old_labels) if v == old_label]
            if not ids:
                result[old_label] = {"mask": 0, "reason": "unreachable_old_label"}
                continue
            if len({self.new_labels[i] for i in ids}) == 1:
                result[old_label] = {"mask": 0, "reason": "verified_label_implication"}
                continue
            groups = defaultdict(set)
            for i in ids:
                groups[project(self.states[i], changed_mask)].add(self.new_labels[i])
            if all(len(values) == 1 for values in groups.values()):
                result[old_label] = {"mask": changed_mask, "reason": "verified_changed_dependencies"}
            else:
                result[old_label] = {"mask": all_dependencies, "reason": "all_new_dependencies_fallback"}
        return result

    def representative(self, observations):
        """Find a compatible representative using only retained categories."""
        if not isinstance(observations, dict):
            raise ValueError("observations must be a mapping of block names to categories")
        if set(observations) - set(self.block_names):
            raise ValueError("unknown observation block")
        state = [d[0] for d in self.domains]
        for name, category in observations.items():
            block = self.block_names.index(name)
            if category not in self.domains[block]:
                raise ValueError("unsupported observation category")
            state[block] = category
        return self.indices[tuple(state)], self.mask(observations)

    def check_receipt(self, receipt, expected_snapshot):
        """Check finite evidence and caller-supplied immutable snapshot binding.

        SHA identifiers detect mixups; they do not authenticate an external issuer.
        Raw payload/category consistency is checked by the standard adapter layer.
        """
        if not isinstance(receipt, dict):
            return {"status": "invalid_receipt", "reason": "malformed_receipt"}
        if (receipt.get("domain_sha256") != self.domain_digest
                or receipt.get("old_predicate_sha256") != self.old_digest
                or receipt.get("snapshot_sha256") != expected_snapshot):
            return {"status": "invalid_receipt", "reason": "binding_mismatch"}
        try:
            index, mask = self.representative(receipt["observations"])
            status = self.classify(index, mask, receipt["verdict"])
        except (KeyError, TypeError, ValueError):
            return {"status": "invalid_receipt", "reason": "unsupported_observation"}
        result = {"status": status, "representative": index, "mask": mask}
        if status == "insufficient":
            result["witness"] = self.witness(index, mask)
        elif status in {"safe", "stale_verdict"}:
            result["verdict"] = next(iter(self.outcomes(index, mask)))
        return result
