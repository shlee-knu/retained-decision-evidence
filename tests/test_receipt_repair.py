"""Execution boundaries, not just a replay of the strategy implementation."""
from copy import deepcopy
import gzip
import json

import pytest

from logistics_validation.audit_report import digest, file_digest
from logistics_validation.catalog_audit import BASELINE, PROFILES, catalog_json, generated_catalogs
from logistics_validation.receipt_repair import PublicSnapshot, ReceiptRepair, RecoveryError


CATALOGS = {name: catalog for name, catalog, _ in generated_catalogs()}


def receipt(activities=None, observed=None, verdict=False):
    return {"schema_version": 1, "receipt_id": "case-1", "snapshot_sha256": "a" * 64,
            "catalog_sha256": digest(catalog_json(BASELINE)), "domain_version": "cartesian:v1",
            "activities": activities if activities is not None else ["create", "invoice"],
            "observed": deepcopy(observed or {}), "verdict": verdict}


class MemorySource:
    def __init__(self, profile=PROFILES[0], *, capabilities=None, fault=None):
        self.values = {"profile": profile,
                       "first_times": {"create": "2019-01-01T00:00:00.0010Z", "invoice": "2019-01-02T00:00:00Z"}}
        self.capabilities = {"profile": "authorized", "first_times": "authorized"} if capabilities is None else capabilities
        self.checked, self.reads, self.fault = [], [], fault

    def capability(self, old, block):
        self.checked.append(block)
        return self.capabilities.get(block, "access_not_established")

    def read(self, old, block):
        self.reads.append(block)
        out = {"case_id": old["receipt_id"], "snapshot_sha256": old["snapshot_sha256"],
               "request_receipt_sha256": digest(old), "activities": deepcopy(old["activities"]),
               "block": block, "complete": True, "value": deepcopy(self.values[block])}
        if self.fault:
            self.fault(out)
        return out


def engine(target="required_p2_a3"):
    return ReceiptRepair("procurement_" + target, CATALOGS[target])


def test_p_value_can_finish_without_even_querying_t_permission():
    old = receipt()
    frozen = deepcopy(old)
    source = MemorySource(capabilities={"profile": "authorized", "first_times": "source_unavailable"})
    result = engine().execute(old, source)
    assert result["initial_robust_additional_sets"] == [["profile", "first_times"]]
    assert source.checked == source.reads == ["profile"]
    assert result["replacement_verified"] and result["acquisition_completed"]
    assert result["replacement_receipt"]["verdict"] is False
    assert result["replacement_receipt"]["observed"] == {"profile": PROFILES[0]}
    assert old == frozen


@pytest.mark.parametrize("reason", ["source_unavailable", "authorization_not_granted", "access_not_established"])
def test_partial_read_without_singleton_never_creates_replacement(reason):
    source = MemorySource(PROFILES[2], capabilities={"profile": "authorized", "first_times": reason})
    result = engine().execute(receipt(), source)
    assert source.checked == ["profile", "first_times"] and source.reads == ["profile"]
    assert result["reason"] == reason and result["successful_reads"] == ["profile"]
    assert result["replacement_receipt"] is None and not result["acquisition_completed"]


def test_both_blocks_produce_new_true_verdict_and_preserve_literal_clocks():
    source = MemorySource(PROFILES[2])
    result = engine().execute(receipt(), source)
    assert result["successful_reads"] == ["profile", "first_times"]
    assert result["replacement_receipt"]["verdict"] is True
    assert result["replacement_receipt"]["observed"]["first_times"] == source.values["first_times"]


def test_fixed_robust_control_really_reads_both_even_when_p_would_suffice():
    source = MemorySource()
    result = engine().execute(receipt(), source, strategy="robust_all_first")
    assert source.checked == source.reads == ["profile", "first_times"]
    assert result["replacement_verified"] and set(result["replacement_receipt"]["observed"]) == {"profile", "first_times"}


def test_fixed_robust_preflight_blocks_all_reads_when_t_unavailable():
    source = MemorySource(capabilities={"profile": "authorized", "first_times": "source_unavailable"})
    result = engine().execute(receipt(), source, strategy="robust_all_first")
    assert source.reads == [] and result["replacement_receipt"] is None


@pytest.mark.parametrize("field,value,reason", [
    ("case_id", "different", "source_case_mismatch"),
    ("snapshot_sha256", "b" * 64, "snapshot_mismatch"),
    ("request_receipt_sha256", "b" * 64, "read_request_mismatch"),
    ("activities", ["create"], "base_mismatch"),
    ("block", "first_times", "read_block_mismatch"),
    ("complete", False, "incomplete_block"),
    ("value", "not-a-profile", "unsupported_acquired_value"),
])
def test_failed_read_contract_never_certifies_recovery(field, value, reason):
    source = MemorySource(fault=lambda response: response.update({field: value}))
    result = engine().execute(receipt(), source)
    assert result["reason"] == reason and result["successful_reads"] == []
    assert result["attempted_reads"] == ["profile"]
    assert result["replacement_receipt"] is None and not result["replacement_verified"]


@pytest.mark.parametrize("exception,reason", [(OSError("offline"), "read_failed"),
                                             (RuntimeError("remote error"), "read_failed"),
                                             (RecoveryError("retained_value_conflict"), "retained_value_conflict")])
def test_read_exceptions_do_not_turn_a_plan_into_success(exception, reason):
    def fault(_):
        raise exception
    result = engine().execute(receipt(), MemorySource(fault=fault))
    assert result["reason"] == reason and result["replacement_receipt"] is None


def test_second_read_failure_preserves_partial_read_ledger_but_no_replacement():
    def fault(response):
        if response["block"] == "first_times":
            raise OSError("historical version gone")
    source = MemorySource(PROFILES[2], fault=fault)
    result = engine().execute(receipt(), source)
    assert result["successful_reads"] == ["profile"]
    assert result["attempted_reads"] == ["profile", "first_times"]
    assert not result["acquisition_completed"] and result["replacement_receipt"] is None


@pytest.mark.parametrize("strategy", ["adaptive_p_first", "robust_all_first"])
def test_capability_callback_exception_is_an_unresolved_outcome(strategy):
    class BrokenSource(MemorySource):
        def capability(self, old, block):
            raise RuntimeError("authorization service unavailable")
    result = engine().execute(receipt(), BrokenSource(), strategy=strategy)
    assert result["reason"] == "capability_failed" and result["attempted_reads"] == []
    assert result["replacement_receipt"] is None


@pytest.mark.parametrize("strategy", ["adaptive_p_first", "robust_all_first"])
@pytest.mark.parametrize("value", [[], {}, None, True])
def test_malformed_capability_response_is_rejected_before_read(strategy, value):
    class MalformedSource(MemorySource):
        def capability(self, old, block):
            return value
    source = MalformedSource()
    result = engine().execute(receipt(), source, strategy=strategy)
    assert result["reason"] == "invalid_capability" and result["replacement_receipt"] is None
    assert source.reads == result["attempted_reads"] == []
    # Even an unsupported value leaves a serializable bounded error record.
    assert json.loads(json.dumps(result))["capability_checks"][0]["state"] == "invalid_capability"


def test_callback_argument_mutation_cannot_change_controller_retained_state():
    class MutatingSource(MemorySource):
        def capability(self, old, block):
            old["activities"].clear()
            old["observed"]["first_times"] = {}
            return "authorized"
    old = receipt()
    result = engine().execute(old, MutatingSource())
    assert result["replacement_verified"]
    assert result["replacement_receipt"]["activities"] == old["activities"] == ["create", "invoice"]
    assert set(result["replacement_receipt"]["observed"]) == {"profile"}


def test_read_callback_cannot_rebind_the_case_by_mutating_its_argument():
    class MutatingSource(MemorySource):
        def read(self, old, block):
            old["receipt_id"] = "different"
            return super().read(old, block)
    old = receipt()
    result = engine().execute(old, MutatingSource())
    assert old["receipt_id"] == "case-1"
    assert result["reason"] == "source_case_mismatch" and result["replacement_receipt"] is None


@pytest.mark.parametrize("times", [{"create": "2019-01-01T00:00:00Z"},
                                   {"create": "invalid-clock", "invoice": "2019-01-02T00:00:00Z"}])
def test_incomplete_or_malformed_second_block_leaves_only_profile_accepted(times):
    source = MemorySource(PROFILES[2])
    source.values["first_times"] = times
    result = engine().execute(receipt(), source)
    assert result["reason"] == "unsupported_acquired_value"
    assert result["successful_reads"] == ["profile"] and len(result["accepted_responses"]) == 1
    assert result["replacement_receipt"] is None


def test_invalid_old_boolean_receives_no_source_access():
    source = MemorySource()
    result = engine().execute(receipt(verdict=True), source)
    assert result["action"] == "invalid_receipt" and source.checked == source.reads == []


@pytest.mark.parametrize("value", [None, [], {}, {"receipt_id": "incomplete"}, {"receipt_id": object()}])
def test_malformed_receipt_is_rejected_before_digest_or_callback(value):
    source = MemorySource()
    result = engine().execute(value, source)
    assert result["action"] == "invalid_receipt" and result["replacement_receipt"] is None
    assert result["original_receipt_sha256"] is None and result["source_case_id"] is None
    assert source.checked == source.reads == []
    assert json.loads(json.dumps(result))["action"] == "invalid_receipt"


def test_safe_old_receipt_yields_target_binding_without_acquisition():
    source = MemorySource(capabilities={})
    old = receipt(activities=["create"])
    result = engine().execute(old, source)
    assert result["initial_status"] == "safe" and result["replacement_verified"]
    assert result["reason"] == "retained_sufficient_evidence" and not result["acquisition_completed"]
    assert source.checked == source.reads == []


def test_stale_sufficient_receipt_changes_boolean_without_acquisition():
    old = receipt(observed={"profile": PROFILES[2], "first_times": MemorySource().values["first_times"]})
    source = MemorySource(capabilities={})
    result = engine().execute(old, source)
    assert result["initial_status"] == "stale_verdict"
    assert result["replacement_receipt"]["verdict"] is True
    assert source.checked == source.reads == [] and not result["acquisition_completed"]


@pytest.mark.parametrize("field,value", [("catalog_sha256", "b" * 64), ("domain_version", "both:v1")])
def test_wrong_original_binding_is_rejected_before_access(field, value):
    old = receipt()
    old[field] = value
    source = MemorySource()
    result = engine().execute(old, source)
    assert result["action"] == "invalid_receipt" and source.checked == []


@pytest.mark.parametrize("mutate", [
    lambda replacement: replacement.update(catalog_sha256="b" * 64),
    lambda replacement: replacement.update(snapshot_sha256="b" * 64),
    lambda replacement: replacement.update(receipt_id="another"),
    lambda replacement: replacement.update(verdict=True),
    lambda replacement: replacement["observed"].clear(),
])
def test_replacement_checker_rejects_tampering(mutate):
    runner, old = engine(), receipt()
    replacement = runner.execute(old, MemorySource())["replacement_receipt"]
    mutate(replacement)
    with pytest.raises(ValueError):
        runner.verify_replacement(replacement, old, ["profile"])


def test_public_source_checks_retained_values_against_pinned_content(tmp_path):
    path = tmp_path / "snapshot.jsonl.gz"
    row = {"case_id": "case-1", "activities": ["create", "invoice"], **MemorySource().values}
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write(json.dumps(row) + "\n")
    source = PublicSnapshot(path, file_digest(path), capabilities={"first_times": "authorized"})
    old = receipt(observed={"profile": PROFILES[2]})
    old["snapshot_sha256"] = source.snapshot_sha256
    result = engine().execute(old, source)
    assert result["reason"] == "retained_value_conflict" and result["replacement_receipt"] is None


def test_public_source_never_accepts_a_different_snapshot_file(tmp_path):
    path = tmp_path / "snapshot.jsonl.gz"
    path.write_bytes(b"wrong bytes")
    with pytest.raises(RecoveryError, match="snapshot_file_mismatch"):
        PublicSnapshot(path, "a" * 64)
