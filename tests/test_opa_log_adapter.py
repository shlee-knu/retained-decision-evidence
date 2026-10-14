"""Meaningful import boundaries for a fixed, explicitly conditional log schema."""
from copy import deepcopy

import pytest

from logistics_validation.audit_report import digest
from logistics_validation.catalog_audit import BASELINE, PROFILES, catalog_json, generated_catalogs
from logistics_validation.opa_log_adapter import (
    BINDING_SCHEMA, LogImportError, import_decision_log, plan_followup,
)


def fixture(*, hide_profile=True, hide_times=False, aliases=True):
    activities = ["create", "receive", "receive", "invoice", "clear"]
    times = {"create": "2019-01-01T00:00:00.0010Z", "receive": "2019-01-02T00:00:00Z",
             "invoice": "2019-01-03T09:00:00+09:00", "clear": "2019-01-04T00:00:00Z"}
    payload = {"case_id": "public-fixture-case", "activities": activities,
               "profile": PROFILES[0], "first_times": times, "model": "procurement",
               "mask_profile": hide_profile, "mask_times": hide_times}
    if aliases:
        payload["record"] = {"base": [0, 1, 2, 3], "profile": 0, "ranks": [0, 1, 2, 3]}
    event = {"decision_id": "different-policy-evaluation-id", "path": "audit/predicates/logged_old_decision",
             "bundles": {"local/bundle": {"revision": "fixture-baseline"}}, "input": payload, "result": True,
             "erased": []}
    for hidden, raw, alias in ((hide_profile, "profile", "profile"), (hide_times, "first_times", "ranks")):
        if hidden:
            payload.pop(raw)
            event["erased"].append("/input/" + raw)
            if aliases:
                payload["record"].pop(alias)
                event["erased"].append("/input/record/" + alias)
    binding = {"schema_version": BINDING_SCHEMA, "event_sha256": digest(event),
               "decision_id": event["decision_id"], "source_case_id": payload["case_id"],
               "decision_path": "/audit/predicates/logged_old_decision", "domain_version": "cartesian:v1",
               "snapshot_sha256": "a" * 64,
               "bundle": {"name": "local/bundle", "revision": "fixture-baseline", "archive_sha256": "b" * 64,
                          "catalog_sha256": digest(catalog_json(BASELINE))},
               "source_assertions": {"source_case_id": payload["case_id"], "snapshot_sha256": "a" * 64,
                                     "complete_fields": {"activities": True, "profile": True, "first_times": True},
                                     "normalized_aliases": aliases}}
    return event, binding


def seal(event, binding):
    # This tests semantic/schema guards beyond a digest check, not authenticity.
    binding["event_sha256"] = digest(event)


def test_profile_erasure_import_preserves_literals_and_opposed_witnesses():
    event, binding = fixture()
    before = deepcopy((event, binding))
    result = import_decision_log(event, binding)
    assert result["summary"]["status"] == "insufficient"
    assert result["summary"]["robust_additional_sets"] == [["profile"]]
    assert result["decision_id"] != result["receipt"]["receipt_id"]
    for witness in result["summary"]["labeled_witnesses"]:
        assert witness["raw"]["activities"] == event["input"]["activities"]
        assert witness["raw"]["first_times"] == event["input"]["first_times"]
    assert {w["new_verdict"] for w in result["summary"]["labeled_witnesses"]} == {False, True}
    assert (event, binding) == before


def test_genuine_old_boolean_after_both_erased_is_invalid_old_evidence():
    result = import_decision_log(*fixture(hide_times=True))
    assert result["summary"]["status"] == "invalid_receipt"
    assert result["summary"]["old_verdict_candidates"] == [False, True]
    assert result["summary"]["labeled_witnesses"] == []
    assert plan_followup(result, authorized_and_available=["profile", "first_times"])["action"] == "invalid_receipt"


@pytest.mark.parametrize("replacement", [None, "", "Consignment", False, {}])
def test_upsert_replacement_is_unknown_even_if_it_looks_like_a_profile(replacement):
    event, binding = fixture()
    event["input"]["profile"] = replacement
    event["erased"].remove("/input/profile")
    event["masked"] = ["/input/profile"]
    seal(event, binding)
    result = import_decision_log(event, binding)
    assert "profile" not in result["receipt"]["observed"]
    assert result["summary"]["status"] == "insufficient"


def test_false_boolean_is_an_accepted_recorded_verdict():
    event, binding = fixture(hide_profile=False)
    event["result"] = False
    event["input"].update(activities=["create"], first_times={"create": "2019-01-01T00:00:00Z"},
                          record={"base": [0], "profile": 0, "ranks": [0]})
    seal(event, binding)
    result = import_decision_log(event, binding)
    assert result["summary"]["status"] == "safe"
    assert plan_followup(result)["verdict"] is False


@pytest.mark.parametrize("replacement", ["true", "false", 1, 0, None])
def test_result_is_never_boolean_coerced(replacement):
    event, binding = fixture()
    event["result"] = replacement
    seal(event, binding)
    with pytest.raises(LogImportError, match="recorded_result_not_boolean"):
        import_decision_log(event, binding)


@pytest.mark.parametrize("pointer", ["/result", "/input", "/input/activities", "/input/case_id", "/input/record/base"])
def test_result_or_base_or_identity_redaction_rejected(pointer):
    event, binding = fixture()
    event["masked"] = [pointer]
    seal(event, binding)
    with pytest.raises(LogImportError, match="unsupported_mask_path"):
        import_decision_log(event, binding)


@pytest.mark.parametrize("mutation,code", [
    (lambda e: e["input"].update(case_id="other"), "source_case_id_mismatch"),
    (lambda e: e.update(decision_id="other"), "decision_id_mismatch"),
    (lambda e: e["bundles"]["local/bundle"].update(revision="other"), "bundle_revision_mismatch"),
    (lambda e: e.update(bundles={"other": {"revision": "fixture-baseline"}}), "bundle_name_mismatch"),
    (lambda e: e.update(path="another/rule"), "decision_path_mismatch"),
])
def test_resealed_event_must_still_match_independent_bindings(mutation, code):
    event, binding = fixture()
    mutation(event)
    seal(event, binding)
    with pytest.raises(LogImportError, match=code):
        import_decision_log(event, binding)


def test_mutated_event_fails_original_canonical_digest():
    event, binding = fixture()
    event["input"]["first_times"]["clear"] = "2020-01-01T00:00:00Z"
    with pytest.raises(LogImportError, match="event_digest_mismatch"):
        import_decision_log(event, binding)


@pytest.mark.parametrize("mutation,code", [
    (lambda b: b.update(snapshot_sha256="c" * 64), "snapshot_binding_mismatch"),
    (lambda b: b["bundle"].update(catalog_sha256="c" * 64), "catalog_binding_mismatch"),
    (lambda b: b["bundle"].update(archive_sha256="not-a-hash"), "bundle_binding_shape"),
    (lambda b: b["source_assertions"]["complete_fields"].update(first_times=False), "incomplete_original_blocks"),
    (lambda b: b.update(domain_version="chronological:v1"), "unsupported_domain"),
])
def test_snapshot_catalog_and_completeness_bindings(mutation, code):
    event, binding = fixture()
    mutation(binding)
    with pytest.raises(LogImportError, match=code):
        import_decision_log(event, binding)


@pytest.mark.parametrize("operation,code", [("no_provenance", "missing_field_without_provenance"),
                                           ("erased_present", "erased_field_present"),
                                           ("masked_absent", "masked_field_absent")])
def test_missing_erased_and_upserted_properties_are_distinct(operation, code):
    event, binding = fixture()
    if operation == "no_provenance":
        event["erased"].remove("/input/profile")
    elif operation == "erased_present":
        event["input"]["profile"] = None
    else:
        event["erased"].remove("/input/profile")
        event["masked"] = ["/input/profile"]
    seal(event, binding)
    with pytest.raises(LogImportError, match=code):
        import_decision_log(event, binding)


def test_partial_timestamp_redaction_is_not_a_complete_block():
    event, binding = fixture()
    event["input"]["first_times"].pop("clear")
    event["erased"].append("/input/first_times/clear")
    seal(event, binding)
    with pytest.raises(LogImportError, match="unsupported_mask_path"):
        import_decision_log(event, binding)


@pytest.mark.parametrize("alias", ["profile", "ranks"])
def test_normalized_alias_cannot_leak_a_masked_raw_block(alias):
    event, binding = fixture(hide_profile=alias == "profile", hide_times=alias == "ranks")
    event["input"]["record"][alias] = 0 if alias == "profile" else [0, 1, 2, 3]
    event["erased"].remove("/input/record/" + alias)
    seal(event, binding)
    with pytest.raises(LogImportError, match="leaked_normalized_alias"):
        import_decision_log(event, binding)


@pytest.mark.parametrize("alias,replacement", [("base", [0, 1, 2]), ("profile", 1), ("ranks", [0, 0, 1, 2]), ("profile", False)])
def test_retained_aliases_must_match_raw_derived_values_exactly(alias, replacement):
    event, binding = fixture(hide_profile=False)
    event["input"]["record"][alias] = replacement
    seal(event, binding)
    with pytest.raises(LogImportError, match="alias_mismatch"):
        import_decision_log(event, binding)


def test_normalized_aliases_are_optional_by_explicit_contract():
    result = import_decision_log(*fixture(aliases=False))
    assert result["summary"]["status"] == "insufficient"


@pytest.mark.parametrize("kwargs,reason", [
    ({}, "access_not_established"),
    ({"unavailable": ["profile"]}, "source_unavailable"),
    ({"unauthorized": ["profile"]}, "authorization_not_granted"),
    ({"authorized_and_available": ["profile"], "read_failures": ["profile"]}, "read_failed"),
    ({"authorized_and_available": ["profile"], "unauthorized": ["profile"]}, "authorization_not_granted"),
])
def test_no_permission_or_failed_read_never_certifies_repair(kwargs, reason):
    result = plan_followup(import_decision_log(*fixture()), **kwargs)
    assert result["action"] == "unresolved"
    assert result["reasons"] == {"profile": reason}
    assert result["verdict"] is None
    assert result["reads_performed"] == [] and not result["acquisition_completed"]


def test_accessible_robust_set_is_a_plan_not_a_completed_read():
    result = plan_followup(import_decision_log(*fixture()), authorized_and_available=["profile"])
    assert result["action"] == "acquire" and result["planned_blocks"] == ["profile"]
    assert result["verdict"] is None and not result["acquisition_completed"]


def test_full_retention_needs_no_acquisition_even_if_source_is_unavailable():
    result = plan_followup(import_decision_log(*fixture(hide_profile=False)), unavailable=["profile", "first_times"])
    assert result["action"] == "retain" and result["verdict"] is True
    assert result["planned_blocks"] == []


def test_new_singleton_can_update_without_reading_anything():
    event, binding = fixture(hide_profile=False)
    catalog = next(c for name, c, _ in generated_catalogs() if name == "forbidden_p0_a0")
    result = plan_followup(import_decision_log(event, binding, target_catalog=catalog))
    assert result["action"] == "update" and result["verdict"] is False
    assert result["planned_blocks"] == [] and not result["acquisition_completed"]


def test_empty_timestamp_map_can_be_complete_for_an_empty_activity_base():
    event, binding = fixture(hide_profile=False)
    event["input"].update(activities=[], first_times={}, record={"base": [], "profile": 0, "ranks": []})
    event["result"] = False
    seal(event, binding)
    result = import_decision_log(event, binding)
    assert result["receipt"]["observed"]["first_times"] == {}
    assert result["summary"]["status"] == "safe"


def test_wrong_but_boolean_old_verdict_fails_the_sufficiency_check():
    event, binding = fixture()
    event["result"] = False
    seal(event, binding)
    result = import_decision_log(event, binding)
    assert result["summary"]["status"] == "invalid_receipt"
    assert result["summary"]["old_verdict_candidates"] == [True]


@pytest.mark.parametrize("mutation", [
    lambda e: e["input"].update(profile="not-a-supported-profile"),
    lambda e: e["input"]["first_times"].update(create="not-a-timestamp"),
    lambda e: e["input"]["first_times"].pop("clear"),
])
def test_unsupported_retained_profile_clock_and_incomplete_clock_map(mutation):
    event, binding = fixture(hide_profile=False)
    mutation(event)
    seal(event, binding)
    with pytest.raises(LogImportError, match="unsupported_retained_values"):
        import_decision_log(event, binding)
