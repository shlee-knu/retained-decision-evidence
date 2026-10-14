"""Strict query boundary and direct residual comparator for revision evidence.

The frozen focused engines remain unchanged. All three methods are available
through :class:`ValidatedDiagnostics`, which checks the same normalized query
schema before dispatch. Malformed queries produce the ordinary
``invalid_receipt`` result; :func:`validate_query` exposes a detailed ValueError
for callers that need to distinguish malformed syntax from an insufficient old
receipt. ``old_valid`` and literal witness lifting remain in ``Problem.report``.

The direct comparator enumerates only the requested Cartesian fiber, evaluating
the authored old and new predicates. It neither compiles all observation masks
nor reads FiniteDiagnostics labels. The independent raw checker is deliberately
external to this module and to its measured generation cost.
"""
from __future__ import annotations

from collections.abc import Mapping
from itertools import product

from logistics_validation.catalog_audit import ALPHABET, PROFILES, weak_orders
from logistics_validation.focused_diagnostics import FiniteDiagnostics, SMTDiagnostics


METHODS = ("finite_fibers", "incremental_smt", "direct_residual")
_QUERY_FIELDS = frozenset(("base", "mask", "observed", "old_verdict"))


class QueryValidationError(ValueError):
    """A query is outside the supported normalized query schema."""


def _sequence(value, field):
    if type(value) not in (list, tuple):
        raise QueryValidationError(f"{field} must be a list or tuple")
    return tuple(value)


def validate_query(problem, query):
    """Return a canonical query, or raise :class:`QueryValidationError`.

    Exactly four fields are accepted. Lists and tuples are equivalent input
    containers and become tuples; integers must be actual integers, not bools.
    Procurement ``base`` is a duplicate-free first-occurrence activity order,
    so every permutation is legitimate and its order is preserved. A retained
    time vector contains one canonical weak rank per activity in that order:
    the occupied levels are exactly 0 through max(rank). EPCIS bases are empty
    and retained categories belong to the corresponding declared block domain.

    This validates schema/domain membership only. Old-verdict sufficiency over
    the entire compatible fiber is still checked by every diagnostic engine.
    No query or nested input container is mutated.
    """
    if not isinstance(query, Mapping) or set(query) != _QUERY_FIELDS:
        raise QueryValidationError("query must contain exactly base, mask, observed, old_verdict")
    base = _sequence(query["base"], "base")
    mask = query["mask"]
    if type(mask) is not int or not 0 <= mask < (1 << problem.count):
        raise QueryValidationError("mask must be an integer within the declared block range")
    old = query["old_verdict"]
    if type(old) is not bool:
        raise QueryValidationError("old_verdict must be a Boolean")
    observed = _sequence(query["observed"], "observed")
    if len(observed) != mask.bit_count():
        raise QueryValidationError("observed length must equal the number of retained blocks")

    if problem.procurement:
        if any(type(a) is not int or not 0 <= a < len(ALPHABET) for a in base):
            raise QueryValidationError("base must contain supported integer activity identifiers")
        if len(base) != len(set(base)):
            raise QueryValidationError("base must not repeat activities")
    elif base:
        raise QueryValidationError("EPCIS base must be empty")

    values = []
    retained = (i for i in range(problem.count) if mask & (1 << i))
    for block, value in zip(retained, observed):
        if problem.procurement and block == 0:
            if type(value) is not int or not 0 <= value < len(PROFILES):
                raise QueryValidationError("profile must be a supported integer category")
        elif problem.procurement:
            value = _sequence(value, "first_times")
            if len(value) != len(base):
                raise QueryValidationError("first_times must contain one rank per base activity")
            if any(type(rank) is not int or not 0 <= rank < len(base) for rank in value):
                raise QueryValidationError("first_times ranks must be supported nonnegative integers")
            if value and set(value) != set(range(max(value) + 1)):
                raise QueryValidationError("first_times ranks must be canonical without missing levels")
        elif type(value) is not str or value not in problem.spec["domains"][block]:
            raise QueryValidationError(f"unsupported category for {problem.blocks[block]}")
        values.append(value)
    return {"base": base, "mask": mask, "observed": tuple(values), "old_verdict": old}


# Both names describe the same strict operation; no permissive coercion occurs.
normalize_query = validate_query


def _invalid_receipt():
    return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}


class DirectResidualDiagnostics:
    """Exact essential-block diagnosis on a query-restricted Cartesian fiber.

    A block is essential iff an opposed pair differs only in that block.
    Grouping labels by all other coordinates detects exactly such pairs. Every
    robust additional set must include each essential block; changing any
    nonessential coordinates one at a time proves the converse on a Cartesian
    fiber. Thus the essential blocks form its unique minimal robust set.

    The time vector is ONE coordinate, including its internal weak-rank
    constraint. The argument does not apply to domains with cross-block
    correlations. Old verdicts are verified, never used to restrict the new
    completion domain. Only rank domains encountered with unread times are
    cached; there are no cross-query truth labels or semantic result caches.
    """

    def __init__(self, problem):
        self.problem = problem
        self._rank_domains = {}

    def diagnose(self, query):
        try:
            query = validate_query(self.problem, query)
        except QueryValidationError:
            return _invalid_receipt()
        return self._diagnose_validated(query)

    def _domains(self, query):
        retained = iter(query["observed"])
        domains = []
        for block in range(self.problem.count):
            if query["mask"] & (1 << block):
                domains.append((next(retained),))
            elif self.problem.procurement and block == 0:
                domains.append(range(len(PROFILES)))
            elif self.problem.procurement:
                size = len(query["base"])
                if size not in self._rank_domains:
                    self._rank_domains[size] = weak_orders(size)
                domains.append(self._rank_domains[size])
            else:
                domains.append(self.problem.spec["domains"][block])
        return domains

    def _diagnose_validated(self, query):
        base, mask, old = query["base"], query["mask"], query["old_verdict"]
        # For each unread coordinate, retain one label per assignment of the
        # OTHER coordinates. An opposite label certifies a one-coordinate flip.
        contexts = {i: {} for i in range(self.problem.count) if not mask & (1 << i)}
        essential = 0
        examples = {}
        for state in product(*self._domains(query)):
            if self.problem.label(base, state, False) != old:
                return _invalid_receipt()
            label = self.problem.label(base, state, True)
            examples.setdefault(label, state)
            found = []
            for block, labels in contexts.items():
                context = state[:block] + state[block + 1:]
                if context in labels and labels[context] != label:
                    essential |= 1 << block
                    found.append(block)
                else:
                    labels[context] = label
            # Once a block is proved essential, no further pairs are needed.
            for block in found:
                del contexts[block]
        if not examples:
            return _invalid_receipt()
        if len(examples) == 1:
            return {"status": "safe" if old in examples else "stale_verdict",
                    "witnesses": None, "robust_masks": [0]}
        return {"status": "insufficient", "witnesses": [examples[False], examples[True]],
                "robust_masks": [essential]}


class ValidatedDiagnostics:
    """Common strict boundary for all three equal-output diagnostic methods.

    Engine construction is eager so setup remains separately measurable. Every
    request is validated before the underlying engine's diagnosis is invoked.
    Unsupported method names are configuration errors and raise ValueError.
    """

    def __init__(self, problem, method_name):
        engines = {"finite_fibers": FiniteDiagnostics,
                   "incremental_smt": SMTDiagnostics,
                   "direct_residual": DirectResidualDiagnostics}
        if method_name not in engines:
            raise ValueError(f"unknown diagnostic method: {method_name}")
        self.problem, self.method_name = problem, method_name
        self.engine = engines[method_name](problem)

    def diagnose(self, query):
        try:
            query = validate_query(self.problem, query)
        except QueryValidationError:
            return _invalid_receipt()
        if self.method_name == "direct_residual":
            return self.engine._diagnose_validated(query)
        return self.engine.diagnose(query)
