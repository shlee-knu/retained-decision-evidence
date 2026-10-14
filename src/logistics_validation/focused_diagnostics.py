"""Equal-output diagnostics: finite fibers and independently authored SMT logic.

Robust query sets depend only on retained observations: they distinguish *all*
opposed completions, not just a supplied hidden actual record. No recovery is
performed. Finite outcomes and witness pairs are never supplied to the SMT code.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import product

from logistics_validation.catalog_audit import (
    BASELINE, State, concrete, reference_verdict, universe, verdict,
)
from logistics_validation.standards_epcis import (
    build_models, document_from_state, independent_document_oracle,
)


def freeze(value):
    return tuple(freeze(x) for x in value) if isinstance(value, (tuple, list)) else value


def masks(count, retained):
    return sorted((m for m in range(1 << count) if not m & retained),
                  key=lambda m: (m.bit_count(), m))


def projection(state, mask):
    return tuple(x for i, x in enumerate(state) if mask & (1 << i))


class Problem:
    """Rules and raw validation boundary; no compiled labels created here."""
    def __init__(self, name, catalog=None):
        self.name, self.catalog = name, catalog
        self.procurement = name.startswith("procurement_")
        if self.procurement:
            self.blocks, self.count = ("profile", "first_times"), 2
        else:
            self.spec = next(s for s in build_models() if s["name"] == name)
            self.blocks = self.spec["block_names"]
            self.count = len(self.blocks)

    def all_states(self):
        if self.procurement:
            for s in universe():
                yield s.order, (s.profile, s.ranks)
        else:
            for state in product(*self.spec["domains"]):
                yield (), state

    def label(self, base, state, new):
        if self.procurement:
            return verdict(State(base, state[1], state[0]), self.catalog if new else BASELINE)
        return self.spec["new_predicate" if new else "old_predicate"](state)

    def raw(self, base, state):
        if self.procurement:
            return concrete(State(base, state[1], state[0]))
        return document_from_state(self.spec, state)

    def raw_label(self, base, state, new):
        raw = self.raw(base, state)
        if self.procurement:
            return reference_verdict(raw, self.catalog if new else BASELINE)
        got = independent_document_oracle(raw)
        if not got["supported"]:
            raise AssertionError("Unsupported independent raw witness")
        return got["compliant_selected" if new else "compatible_selected"]

    def report(self, query, result, receipt=None):
        witnesses = ([self.raw(tuple(query["base"]), freeze(s)) for s in result["witnesses"]]
                     if result["witnesses"] is not None else None)
        if receipt is not None and witnesses is not None:
            # Lift canonical completions to the actual retained receipt. The
            # source sequence may repeat activities, and retained clocks must
            # keep their literal original values, not merely the same ranks.
            for witness in witnesses:
                witness["activities"] = receipt["activities"]
                witness.update(receipt["observed"])
        report = {"status": result["status"],
                "old_valid": result["status"] != "invalid_receipt",
                "witnesses": witnesses,
                "robust_additional_sets": [[name for i, name in enumerate(self.blocks) if m & (1 << i)]
                                             for m in result["robust_masks"]]}
        if receipt is not None:
            report["binding"] = {"snapshot_sha256": receipt["snapshot_sha256"],
                                 "old_catalog_sha256": receipt["catalog_sha256"],
                                 "domain_version": receipt["domain_version"],
                                 "target": self.name}
        return report


def request_key(query):
    return (freeze(query["base"]), query["mask"], freeze(query["observed"]), query["old_verdict"])


class FiniteDiagnostics:
    """Existing explicit fiber mechanism, with quantified robust-set reporting."""
    def __init__(self, problem):
        self.problem = problem
        self.groups = defaultdict(list)
        for base, state in problem.all_states():
            self.groups[base].append(state)
        self.labels, self.fibers = {}, {}
        for base, states in self.groups.items():
            self.labels[base] = [(problem.label(base, s, False), problem.label(base, s, True)) for s in states]
            for mask in range(1 << problem.count):
                groups = defaultdict(list)
                for i, s in enumerate(states):
                    groups[projection(s, mask)].append(i)
                self.fibers[base, mask] = dict(groups)

    def diagnose(self, query):
        base, retained, observed, old = request_key(query)
        ids = self.fibers.get((base, retained), {}).get(observed, ())
        if not ids or {self.labels[base][i][0] for i in ids} != {old} or type(old) is not bool:
            return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}
        outcomes = {self.labels[base][i][1] for i in ids}
        if len(outcomes) == 1:
            status = "safe" if outcomes == {old} else "stale_verdict"
            return {"status": status, "witnesses": None, "robust_masks": [0]}
        first = {}
        for i in ids:
            first.setdefault(self.labels[base][i][1], self.groups[base][i])
        robust = []
        for add in masks(self.problem.count, retained):
            if any(m & add == m for m in robust):
                continue
            by_extra = defaultdict(set)
            for i in ids:
                by_extra[projection(self.groups[base][i], add)].add(self.labels[base][i][1])
            if all(len(labels) == 1 for labels in by_extra.values()):
                robust.append(add)
        return {"status": "insufficient", "witnesses": [first[False], first[True]], "robust_masks": robust}


class SMTDiagnostics:
    """Two-copy incremental SMT with direct rule formulas; no state enumeration.

Each visible procurement order has its own lazily constructed solver. Old
Boolean labels are checked by satisfiability and never constrain new queries.
Each solver supports push/pop and is reused throughout a batch.
"""
    def __init__(self, problem):
        import z3
        self.z3, self.problem = z3, problem
        self.solvers = {}
        if not problem.procurement:
            self.solvers[()] = self._build(())

    def _build(self, base):
        z = self.z3
        pair = []
        domain = []
        for copy in range(2):
            if self.problem.procurement:
                p = z.Int(f"p{copy}")
                times = tuple(z.Int(f"t{copy}_{i}") for i in range(len(base)))
                domain.append(z.And(p >= 0, p < 4))
                # Canonical weak ranks: bounded and every level below an occupied
                # level is occupied. This encodes the domain, never truth labels.
                domain += [z.And(t >= 0, t < len(base)) for t in times]
                for level in range(1, len(base)):
                    domain.append(z.Implies(z.Or(*[t >= level for t in times]),
                                            z.Or(*[t == level - 1 for t in times])))
                variables = (p, times)

                def formula(catalog):
                    terms = []
                    positions = {a: i for i, a in enumerate(base)}
                    for profile, rule in enumerate(catalog):
                        structural = rule.required <= set(base) and not rule.forbidden.intersection(base)
                        clauses = [z.BoolVal(bool(structural))]
                        for a, b in rule.edges:
                            if b in positions:
                                if a not in positions or positions[a] >= positions[b]:
                                    clauses.append(z.BoolVal(False))
                                else:
                                    clauses.append(times[positions[a]] <= times[positions[b]])
                        terms.append(z.And(p == profile, *clauses))
                    return z.Or(*terms)
                old, new = formula(BASELINE), formula(self.problem.catalog)
            else:
                fields = self.problem.blocks
                variables = tuple(z.Int(f"b{copy}_{i}") for i in range(len(fields)))
                domain += [z.And(v >= 0, v < len(d)) for v, d in zip(variables, self.problem.spec["domains"])]

                def eq(field, category):
                    i = fields.index(field)
                    return variables[i] == self.problem.spec["domains"][i].index(category)
                if self.problem.name == "epcis_object_profile":
                    old = z.And(z.Or(eq("epcList", "nonempty"), eq("quantityList", "nonempty")),
                                z.Or(eq("ilmd", "absent"), eq("action", "ADD")))
                elif self.problem.name == "epcis_aggregation_profile":
                    old = z.And(z.Or(eq("action", "OBSERVE"), eq("parentID", "present")),
                                z.Or(eq("action", "DELETE"), eq("childEPCs", "nonempty"),
                                     eq("childQuantityList", "nonempty")))
                else:
                    inp = z.Or(eq("inputEPCList", "nonempty"), eq("inputQuantityList", "nonempty"))
                    out = z.Or(eq("outputEPCList", "nonempty"), eq("outputQuantityList", "nonempty"))
                    old = z.If(eq("transformationID", "present"), z.Or(inp, out), z.And(inp, out))
                new = z.And(old, z.Not(eq("bizStep", "vendor")))
            pair.append((variables, old, new))
        solver = z.Solver()
        solver.set(random_seed=0)
        solver.add(*domain)
        return solver, pair

    def _observation(self, variables, mask, observed):
        out, obs_index = [], 0
        for i in range(self.problem.count):
            if mask & (1 << i):
                value = observed[obs_index]
                obs_index += 1
                if self.problem.procurement:
                    if i == 0:
                        out.append(variables[i] == value)
                    else:
                        out.extend(v == n for v, n in zip(variables[i], value))
                else:
                    out.append(variables[i] == self.problem.spec["domains"][i].index(value))
        return out

    def _state(self, model, variables):
        def integer(v):
            return model.eval(v, model_completion=True).as_long()
        if self.problem.procurement:
            return integer(variables[0]), tuple(integer(v) for v in variables[1])
        return tuple(domain[integer(v)] for domain, v in zip(self.problem.spec["domains"], variables))

    def _check(self, solver, constraints, variables=None):
        solver.push()
        solver.add(*constraints)
        got = solver.check()
        if got not in (self.z3.sat, self.z3.unsat):
            raise RuntimeError("SMT returned unknown: " + solver.reason_unknown())
        state = self._state(solver.model(), variables) if got == self.z3.sat and variables is not None else None
        solver.pop()
        return got == self.z3.sat, state

    def diagnose(self, query):
        base, retained, observed, old = request_key(query)
        if type(old) is not bool:
            return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}
        if base not in self.solvers:
            self.solvers[base] = self._build(base)
        solver, pair = self.solvers[base]
        x, old_x, new_x = pair[0]
        y, _, new_y = pair[1]
        solver.push()
        solver.add(*self._observation(x, retained, observed))
        exists, _ = self._check(solver, [])
        invalid, _ = self._check(solver, [old_x != old])
        if not exists or invalid:
            solver.pop()
            return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}
        examples = {}
        for label in (False, True):
            exists, state = self._check(solver, [new_x == label], x)
            if exists:
                examples[label] = state
        if len(examples) == 1:
            solver.pop()
            return {"status": "safe" if old in examples else "stale_verdict", "witnesses": None, "robust_masks": [0]}
        solver.add(*self._observation(y, retained, observed), new_x != new_y)
        robust = []
        for add in masks(self.problem.count, retained):
            if any(m & add == m for m in robust):
                continue
            equalities = []
            for i in range(self.problem.count):
                if add & (1 << i):
                    if self.problem.procurement and i == 1:
                        equalities.extend(a == b for a, b in zip(x[i], y[i]))
                    else:
                        equalities.append(x[i] == y[i])
            opposed, _ = self._check(solver, equalities)
            if not opposed:
                robust.append(add)
        solver.pop()
        return {"status": "insufficient", "witnesses": [examples[False], examples[True]], "robust_masks": robust}


class RawVerifier:
    """Independent raw predicates, direct completion grouping after timing."""
    def __init__(self, problem):
        self.problem = problem
        self.groups = defaultdict(list)
        for base, state in problem.all_states():
            self.groups[base].append((state, problem.raw_label(base, state, False),
                                      problem.raw_label(base, state, True)))
        self.checks = 0

    def verify(self, query, result):
        base, mask, observed, old = request_key(query)
        rows = [r for r in self.groups[base] if projection(r[0], mask) == observed]
        valid = bool(rows) and {r[1] for r in rows} == {old} and type(old) is bool
        outcomes = {r[2] for r in rows}
        status = ("invalid_receipt" if not valid else "insufficient" if len(outcomes) > 1 else
                  "safe" if outcomes == {old} else "stale_verdict")
        assert result["status"] == status
        self.checks += 1
        if status == "insufficient":
            assert len(result["witnesses"]) == 2
            for label, state in zip((False, True), result["witnesses"]):
                state = freeze(state)
                assert any(state == r[0] for r in rows)
                assert projection(state, mask) == observed
                assert self.problem.raw_label(base, state, True) == label
                self.checks += 3
        else:
            assert result["witnesses"] is None
            self.checks += 1
        expected = []
        if valid:
            # Independent brute-force direct test of every unread block subset.
            succeeds = []
            for additional in range(1 << self.problem.count):
                if additional & mask:
                    continue
                assignments = defaultdict(set)
                for state, _, label in rows:
                    assignments[projection(state, additional)].add(label)
                if all(len(values) == 1 for values in assignments.values()):
                    succeeds.append(additional)
                self.checks += 1
            expected = [a for a in succeeds if not any(b != a and b & a == b for b in succeeds)]
        assert set(result["robust_masks"]) == set(expected)
        self.checks += 1
