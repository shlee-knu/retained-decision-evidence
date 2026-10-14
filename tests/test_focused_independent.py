"""Independent regressions for the scope of matched diagnostic comparisons.

These fixtures are semantic checks, not extra measured migration scenarios.
They deliberately exercise a relaxation absent from the measured strengthening
workload and distinguish robust query guarantees from pointwise certificates.
"""
from dataclasses import replace

import pytest

from logistics_validation.catalog_audit import BASELINE, Rule
from logistics_validation.focused_diagnostics import (
    FiniteDiagnostics,
    Problem,
    SMTDiagnostics,
)


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_robust_additions_cannot_use_a_favorable_hidden_actual_profile(engine):
    # With no creation event the old predicate fails for every profile and
    # clock assignment. The new profile-0 rule instead tests receipt→invoice;
    # all other profiles retain their creation requirement.
    target = list(BASELINE)
    target[0] = Rule(frozenset((1, 2)), frozenset(), frozenset(((1, 2),)))
    service = engine(Problem("procurement_independent_mixed", tuple(target)))
    query = dict(base=[1, 2], mask=0, observed=[], old_verdict=False)
    result = service.diagnose(query)

    assert result["status"] == "insufficient"
    # For an actual profile of 1, observing P alone would certify failure.
    # Before that value is known, however, neither P alone nor T alone
    # distinguishes *every* pair of compatible completions. Both are needed.
    assert result["robust_masks"] == [3]
    false_state, true_state = result["witnesses"]
    assert true_state[0] == 0
    assert true_state[1][0] <= true_state[1][1]
    assert false_state[0] != 0 or false_state[1][0] > false_state[1][1]


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_old_failure_is_not_a_new_domain_restriction_under_relaxation(engine):
    # The completely empty base fails every original contract. After removing
    # all requirements and edges, that same observation suffices for PASS.
    unrestricted = Rule(frozenset(), frozenset(), frozenset())
    service = engine(Problem("procurement_independent_relaxation", (unrestricted,) * 4))
    result = service.diagnose(dict(base=[], mask=0, observed=[], old_verdict=False))
    assert result == {
        "status": "stale_verdict", "witnesses": None, "robust_masks": [0]
    }


def _forbid_finite_evidence(*args, **kwargs):
    raise AssertionError("Direct SMT must not consume enumerated states or truth labels")


def test_procurement_smt_uses_direct_rules_without_finite_evidence(monkeypatch):
    target = list(BASELINE)
    target[3] = replace(target[3], forbidden=frozenset((2, 3)))
    problem = Problem("procurement_independent_direct", tuple(target))
    monkeypatch.setattr(problem, "all_states", _forbid_finite_evidence)
    monkeypatch.setattr(problem, "label", _forbid_finite_evidence)
    result = SMTDiagnostics(problem).diagnose(dict(
        base=[0, 1, 2, 3], mask=2, observed=[[0, 1, 2, 3]], old_verdict=True
    ))
    assert result["status"] == "insufficient"
    assert result["robust_masks"] == [1]


@pytest.mark.parametrize("name,observed,biz_bit", [
    ("epcis_object_profile", ["ADD", "nonempty"], 16),
    ("epcis_aggregation_profile", ["DELETE", "present"], 16),
    ("epcis_transformation_profile", ["present", "nonempty"], 32),
])
def test_gs1_smt_does_not_call_compiled_labels(monkeypatch, name, observed, biz_bit):
    problem = Problem(name)
    monkeypatch.setattr(problem, "all_states", _forbid_finite_evidence)
    monkeypatch.setattr(problem, "label", _forbid_finite_evidence)
    monkeypatch.setitem(problem.spec, "old_predicate", _forbid_finite_evidence)
    monkeypatch.setitem(problem.spec, "new_predicate", _forbid_finite_evidence)
    result = SMTDiagnostics(problem).diagnose(dict(
        base=[], mask=3, observed=observed, old_verdict=True
    ))
    assert result["status"] == "insufficient"
    assert result["robust_masks"] == [biz_bit]
