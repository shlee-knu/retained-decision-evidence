"""Strict shared boundary and independent essential-block semantic regressions."""
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache

import pytest

from logistics_validation.catalog_audit import BASELINE, Rule, generated_catalogs, reference_verdict
from logistics_validation.focused_diagnostics import Problem, RawVerifier
from logistics_validation.revision_diagnostics import (
    METHODS, DirectResidualDiagnostics, QueryValidationError, ValidatedDiagnostics,
    normalize_query, validate_query,
)


INVALID = {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}


@lru_cache
def _problem(target):
    catalog = next(rules for name, rules, _ in generated_catalogs() if name == target)
    return Problem("procurement_" + target, catalog)


@lru_cache
def _oracle(target):
    return RawVerifier(_problem(target))


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("target,base", [
    ("edge_p0_a0_b1", [1, 2, 0, 3]),
    ("required_p2_a3", [0, 2]),
    ("edge_p2_a0_b2", [2, 0, 3]),
    ("edge_p2_a2_b3", [0, 3, 2]),
])
def test_old_false_weakening_requires_both_blocks(method, target, base):
    query = dict(base=base, mask=0, observed=[], old_verdict=False)
    result = ValidatedDiagnostics(_problem(target), method).diagnose(query)
    assert result["status"] == "insufficient"
    assert result["robust_masks"] == [3]
    _oracle(target).verify(query, result)


@pytest.mark.parametrize("method", METHODS)
def test_residual_changes_after_an_actual_block_is_observed(method):
    problem = _problem("required_p2_a3")
    service = ValidatedDiagnostics(problem, method)
    cases = [
        (0, [], "insufficient", [3]),
        (1, [2], "insufficient", [2]),
        (1, [0], "safe", [0]),
        (2, [[0, 1]], "insufficient", [1]),
        (2, [[1, 0]], "safe", [0]),
        (3, [2, [0, 1]], "stale_verdict", [0]),
    ]
    for mask, observed, status, robust in cases:
        query = dict(base=[0, 2], mask=mask, observed=observed, old_verdict=False)
        result = service.diagnose(query)
        assert (result["status"], result["robust_masks"]) == (status, robust)
        _oracle("required_p2_a3").verify(query, result)


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("name,observed,biz_bit", [
    ("epcis_object_profile", ["ADD", "nonempty"], 16),
    ("epcis_aggregation_profile", ["DELETE", "present"], 16),
    ("epcis_transformation_profile", ["present", "nonempty"], 32),
])
def test_gs1_residual_has_one_essential_block(method, name, observed, biz_bit):
    problem = Problem(name)
    query = dict(base=[], mask=3, observed=observed, old_verdict=True)
    result = ValidatedDiagnostics(problem, method).diagnose(query)
    assert (result["status"], result["robust_masks"]) == ("insufficient", [biz_bit])
    RawVerifier(problem).verify(query, result)


@pytest.mark.parametrize("method", METHODS)
def test_old_verdict_checked_over_entire_fiber_without_restricting_target(method):
    unrestricted = Rule(frozenset(), frozenset(), frozenset())
    problem = Problem("procurement_relaxation", (unrestricted,) * 4)
    service = ValidatedDiagnostics(problem, method)
    assert service.diagnose(dict(base=[], mask=0, observed=[], old_verdict=False)) == {
        "status": "stale_verdict", "witnesses": None, "robust_masks": [0]}
    # Some full-base completions pass old, others fail. Both claimed labels
    # must be rejected even though the target is constant over the fiber.
    for old in (False, True):
        assert service.diagnose(dict(base=[0, 1, 2, 3], mask=0,
                                     observed=[], old_verdict=old)) == INVALID


@pytest.mark.parametrize("method", METHODS)
def test_gs1_known_absence_safe_and_known_vendor_stale(method):
    service = ValidatedDiagnostics(Problem("epcis_object_profile"), method)
    assert service.diagnose(dict(base=[], mask=6, observed=["absent", "absent"],
                                 old_verdict=False)) == {
        "status": "safe", "witnesses": None, "robust_masks": [0]}
    assert service.diagnose(dict(base=[], mask=19, observed=["ADD", "nonempty", "vendor"],
                                 old_verdict=True)) == {
        "status": "stale_verdict", "witnesses": None, "robust_masks": [0]}


def _must_not_run(*args, **kwargs):
    raise AssertionError("malformed query reached diagnostic engine")


@pytest.fixture(params=METHODS)
def guarded_service(request, monkeypatch):
    service = ValidatedDiagnostics(_problem("baseline"), request.param)
    monkeypatch.setattr(service.engine, "diagnose", _must_not_run)
    if request.param == "direct_residual":
        monkeypatch.setattr(service.engine, "_diagnose_validated", _must_not_run)
    return service


@pytest.mark.parametrize("patch", [
    {"mask": True}, {"mask": False}, {"mask": -1}, {"mask": 4}, {"mask": 1.0}, {"mask": "0"},
    {"observed": ["unexpected"]}, {"observed": None}, {"observed": ""},
    {"mask": 1, "observed": []}, {"mask": 2, "observed": [[], "extra"]},
    {"old_verdict": 0}, {"old_verdict": "false"}, {"old_verdict": None},
    {"base": [0, 0]}, {"base": [True]}, {"base": [0.0]}, {"base": [-1]}, {"base": [4]},
    {"base": ""}, {"base": {}}, {"base": {0, 1}}, {"base": [[0]]},
    {"mask": 1, "observed": [True]}, {"mask": 1, "observed": [-1]},
    {"mask": 1, "observed": [4]}, {"mask": 1, "observed": ["2"]},
    {"mask": 2, "observed": [[0]]},
    {"base": [0, 2], "mask": 2, "observed": [[0]]},
    {"base": [0, 2], "mask": 2, "observed": [[0, 1, 2]]},
    {"base": [0, 2], "mask": 2, "observed": [[1, 1]]},
    {"base": [0, 1, 2], "mask": 2, "observed": [[0, 2, 2]]},
    {"base": [0, 2], "mask": 2, "observed": [[0, True]]},
    {"base": [0, 2], "mask": 2, "observed": [[0, 1.0]]},
    {"base": [0, 2], "mask": 2, "observed": [[0, -1]]},
    {"base": [0, 2], "mask": 2, "observed": [[0, 2]]},
    {"base": [0, 2], "mask": 2, "observed": ["01"]},
])
def test_malformed_procurement_rejected_before_engine(guarded_service, patch):
    query = dict(base=[], mask=0, observed=[], old_verdict=False)
    query.update(patch)
    with pytest.raises(QueryValidationError):
        validate_query(guarded_service.problem, query)
    assert guarded_service.diagnose(query) == INVALID


@pytest.mark.parametrize("query", [None, [], "query", {},
    dict(base=[], mask=0, observed=[]),
    dict(base=[], mask=0, observed=[], old_verdict=False, hidden_actual=0),
])
def test_query_shape_rejected_before_engine(guarded_service, query):
    with pytest.raises(QueryValidationError):
        validate_query(guarded_service.problem, query)
    assert guarded_service.diagnose(query) == INVALID


@pytest.mark.parametrize("method", METHODS)
def test_gs1_boundary_rejects_categories_and_nonempty_base(method, monkeypatch):
    service = ValidatedDiagnostics(Problem("epcis_object_profile"), method)
    monkeypatch.setattr(service.engine, "diagnose", _must_not_run)
    if method == "direct_residual":
        monkeypatch.setattr(service.engine, "_diagnose_validated", _must_not_run)
    for patch in ({"base": [0]}, {"mask": 32}, {"mask": True},
                  {"observed": [True]}, {"observed": [0]},
                  {"observed": ["add"]}, {"observed": ["nonempty"]},
                  {"observed": [["ADD"]]}, {"observed": ["ADD", "extra"]}):
        query = dict(base=[], mask=1, observed=["ADD"], old_verdict=True)
        query.update(patch)
        assert service.diagnose(query) == INVALID


def test_normalization_preserves_order_and_canonicalizes_without_mutation():
    query = dict(base=[2, 0], mask=3, observed=[2, [1, 0]], old_verdict=False)
    before = deepcopy(query)
    normalized = validate_query(_problem("baseline"), query)
    assert normalized == dict(base=(2, 0), mask=3, observed=(2, (1, 0)), old_verdict=False)
    assert query == before
    assert normalize_query(_problem("baseline"), normalized) == normalized
    empty = dict(base=[], mask=3, observed=[0, []], old_verdict=False)
    assert validate_query(_problem("baseline"), empty)["observed"] == (0, ())


def test_direct_only_evaluates_requested_fiber_and_never_compiles_finite(monkeypatch):
    problem = _problem("required_p2_a3")
    original_label = problem.label
    calls = []

    def tracked(base, state, new):
        calls.append((base, state, new))
        return original_label(base, state, new)

    monkeypatch.setattr(problem, "all_states", _must_not_run)
    monkeypatch.setattr(problem, "raw_label", _must_not_run)
    monkeypatch.setattr(problem, "label", tracked)
    monkeypatch.setattr("logistics_validation.revision_diagnostics.FiniteDiagnostics", _must_not_run)
    service = DirectResidualDiagnostics(problem)
    assert calls == []
    result = service.diagnose(dict(base=[0, 2], mask=2, observed=[[0, 1]], old_verdict=False))
    assert result["robust_masks"] == [1]
    assert len(calls) == 8  # Four compatible profiles, each checked against old and new.
    assert all(base == (0, 2) and state[1] == (0, 1) for base, state, _ in calls)
    assert service._rank_domains == {}  # Retained clocks require no rank enumeration.
    assert service.diagnose(dict(base=[], mask=4, observed=[], old_verdict=False)) == INVALID
    assert len(calls) == 8


@pytest.mark.parametrize("method", METHODS)
def test_literal_report_lifting_preserves_source_sequence_and_clocks(method):
    target = list(BASELINE)
    target[3] = replace(target[3], forbidden=frozenset((2, 3)))
    problem = Problem("procurement_literal_strict", tuple(target))
    query = dict(base=[0, 1, 2, 3], mask=2, observed=[[0, 1, 2, 3]], old_verdict=True)
    receipt = dict(
        activities=["create", "receive", "invoice", "create", "clear"],
        observed={"first_times": {
            "create": "2025-01-01T09:00:00.0000000001+09:00",
            "receive": "2025-01-01T00:00:00.0000000002Z",
            "invoice": "2025-01-01T00:00:00.0000000003Z",
            "clear": "2025-01-01T00:00:00.0000000004Z"}},
        snapshot_sha256="snapshot", catalog_sha256="old-catalog", domain_version="cartesian:v1")
    result = ValidatedDiagnostics(problem, method).diagnose(query)
    report = problem.report(query, result, receipt)
    assert report["old_valid"] is True
    assert report["robust_additional_sets"] == [["profile"]]
    for label, witness in zip((False, True), report["witnesses"]):
        assert witness["activities"] == receipt["activities"]
        assert witness["first_times"] == receipt["observed"]["first_times"]
        assert reference_verdict(witness, tuple(target)) == label


def test_unknown_method_is_a_configuration_error():
    with pytest.raises(ValueError, match="unknown diagnostic method"):
        ValidatedDiagnostics(_problem("baseline"), "approximate")
