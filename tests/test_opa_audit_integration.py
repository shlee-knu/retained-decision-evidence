"""Meaningful cross-language regressions requiring a genuine OPA executable."""
import importlib.util
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("benchmark_opa_audit", ROOT / "scripts/benchmark_opa_audit.py")
opa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(opa)


@pytest.fixture(scope="module")
def binary():
    path = opa.DEFAULT_OPA if opa.DEFAULT_OPA.exists() else shutil.which("opa")
    if not path:
        pytest.skip("Real OPA binary required; install pinned dependency or place opa on PATH")
    return Path(path)


def problem(target):
    rules = next(c for n, c, _ in opa.generated_catalogs() if n == target)
    return opa.Problem("procurement_" + target, rules)


def test_real_opa_all_supported_states_and_independent_rule_grammar(binary):
    engine = opa.OpaAuditAdapter(problem("strict_consignment"), binary)
    assert opa.verify_labels(engine) == 17224
    assert len(engine.labels) == 8612


def test_masked_correct_old_decision_must_still_prove_old_sufficiency(binary):
    engine = opa.OpaAuditAdapter(problem("strict_consignment"), binary, bases={(0, 1, 2, 3)})
    # This concrete record truly passed. Removing P and T nonetheless leaves
    # both old outcomes possible; recorded Boolean is not a domain filter.
    payload = {"record": {"base": [0, 1, 2, 3], "profile": 0, "ranks": [0, 1, 2, 3]},
               "old_catalog": opa.catalog_wire(opa.BASELINE)}
    value, _, _ = opa.opa_eval(binary, payload, "data.audit.predicates.old_decision")
    assert value is True
    query = dict(base=[0, 1, 2, 3], mask=0, observed=[], old_verdict=True)
    assert engine.diagnose(query)["status"] == "invalid_receipt"
    query.update(mask=2, observed=[[0, 1, 2, 3]])
    result = engine.diagnose(query)
    assert (result["status"], result["robust_masks"]) == ("insufficient", [1])
    opa.RawVerifier(engine.problem).verify(query, result)
    restricted = engine.diagnose(query, new_domain="consignment_exclusion:v1")
    assert (restricted["status"], restricted["robust_masks"]) == ("safe", [0])


def test_weakening_new_fiber_not_restricted_by_old_boolean(binary):
    engine = opa.OpaAuditAdapter(problem("required_p2_a3"), binary, bases={(0, 2)})
    cases = [(0, [], "insufficient", [3]), (1, [2], "insufficient", [2]),
             (1, [0], "safe", [0]), (3, [2, [0, 1]], "stale_verdict", [0])]
    for mask, observed, status, robust in cases:
        query = dict(base=[0, 2], mask=mask, observed=observed, old_verdict=False)
        result = engine.diagnose(query)
        assert (result["status"], result["robust_masks"]) == (status, robust)
        opa.RawVerifier(engine.problem).verify(query, result)


def test_generation_never_calls_saved_or_python_predicate_labels(binary, monkeypatch):
    p = problem("strict_consignment")
    def forbidden(*args, **kwargs):
        raise AssertionError("Python predicate called during OPA generation")
    monkeypatch.setattr(p, "label", forbidden)
    monkeypatch.setattr(p, "raw_label", forbidden)
    engine = opa.OpaAuditAdapter(p, binary, bases={(0, 1, 2, 3)})
    result = engine.diagnose(dict(base=[0, 1, 2, 3], mask=2, observed=[[0, 1, 2, 3]], old_verdict=True))
    assert result["status"] == "insufficient"
    # Strict input typing: bool cannot stand in for integer mask.
    assert engine.diagnose(dict(base=[], mask=True, observed=[], old_verdict=True))["status"] == "invalid_receipt"
