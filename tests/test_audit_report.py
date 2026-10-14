"""Portable-report integrity, raw semantics and mock adapter boundary tests."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from logistics_validation.audit_report import (
    AdapterContractError, catalog_from_content, digest, make_bundle, mock_envelope,
    receipt_query, validate_envelope, verify_bundle,
)
from logistics_validation.focused_diagnostics import Problem

ROOT = Path(__file__).resolve().parents[1]


def fixture_spec():
    data = json.loads((ROOT / "results/focused_revision/diagnostic_inputs/procurement_strict.json").read_text())
    catalog = catalog_from_content(json.loads((ROOT / data["target"]).read_text()))
    return {"problem": Problem(data["name"], catalog), "query": data["queries"][0],
            "receipt": data["exemplars"][0], "request_id": "strict:" + data["exemplars"][0]["receipt_id"]}


@pytest.fixture
def bundle():
    return make_bundle([fixture_spec()])


def reseal(bundle):
    # An untrusted caller can recompute hashes. Semantic/binding validation must
    # still reject contradictory payloads; authenticity needs an external trust root.
    for report in bundle["reports"]:
        report["report_sha256"] = digest({k: v for k, v in report.items() if k != "report_sha256"})
    bundle["bundle_sha256"] = digest({k: v for k, v in bundle.items() if k != "bundle_sha256"})


def test_portable_native_receipt_and_literal_witnesses(bundle):
    assert verify_bundle(bundle)["status"] == "passed"
    report = bundle["reports"][0]
    assert report["status"] == "insufficient"
    assert report["robust_additional_sets"] == [["profile"]]
    assert {w["new_verdict"] for w in report["labeled_witnesses"]} == {False, True}
    for witness in report["labeled_witnesses"]:
        assert witness["raw"]["activities"] == report["receipt"]["activities"]
        assert witness["raw"]["first_times"] == report["receipt"]["observed"]["first_times"]


def test_epcis_bundle_needs_no_native_archive():
    spec = {"problem": Problem("epcis_object_profile"),
            "query": {"base": [], "mask": 3, "observed": ["ADD", "nonempty"], "old_verdict": True},
            "request_id": "synthetic:one", "receipt_id": "synthetic:one", "snapshot_sha256": "0" * 64}
    bundle = make_bundle([spec])
    assert verify_bundle(bundle)["status"] == "passed"
    report = bundle["reports"][0]
    assert report["robust_additional_sets"] == [["bizStep"]]
    assert report["receipt"]["synthetic"] is True
    assert all(w["raw"]["type"] == "EPCISDocument" for w in report["labeled_witnesses"])


def test_invalid_old_claim_round_trips_with_no_witnesses():
    spec = fixture_spec()
    spec["receipt"]["verdict"] = spec["query"]["old_verdict"] = False
    bundle = make_bundle([spec])
    report = bundle["reports"][0]
    assert report["status"] == "invalid_receipt"
    assert report["labeled_witnesses"] == []
    assert report["new_verdict_candidates"] == [False, True]
    assert verify_bundle(bundle)["status"] == "passed"


def test_target_content_only_tampering_fails_even_if_bundle_resealed(bundle):
    reference = bundle["reports"][0]["bindings"]["new_rule"]
    bundle["artifacts"][reference]["content"]["Consignment"]["forbidden"] = []
    reseal(bundle)
    with pytest.raises(ValueError, match="artifact content mismatch"):
        verify_bundle(bundle)


@pytest.mark.parametrize("field,value,message", [
    ("receipt_id", "another-receipt", "receipt ID mix"),
    ("snapshot_sha256", "f" * 64, "snapshot mismatch"),
    ("status", "safe", "raw verification failed: status"),
    ("robust_additional_sets", [[]], "raw verification failed: robust_additional_sets"),
    ("old_valid", False, "raw verification failed: old_valid"),
])
def test_resealed_report_still_checks_bindings_and_semantics(bundle, field, value, message):
    bundle["reports"][0][field] = value
    reseal(bundle)
    with pytest.raises(ValueError, match=message):
        verify_bundle(bundle)


def test_independent_raw_verifier_does_not_call_compiled_labels(bundle, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("compiled diagnostics called")
    monkeypatch.setattr(Problem, "label", forbidden)
    monkeypatch.setattr(Problem, "all_states", forbidden)
    assert verify_bundle(bundle)["status"] == "passed"


def test_witness_raw_payload_tampering_fails_after_reseal(bundle):
    bundle["reports"][0]["labeled_witnesses"][0]["raw"]["first_times"]["create"] = "2020-01-01T00:00:00Z"
    reseal(bundle)
    with pytest.raises(ValueError, match="witness does not preserve observations/domain"):
        verify_bundle(bundle)


def test_witness_false_label_fails_after_reseal(bundle):
    bundle["reports"][0]["labeled_witnesses"][0]["old_verdict"] = False
    reseal(bundle)
    with pytest.raises(ValueError, match="raw witness label mismatch"):
        verify_bundle(bundle)


def test_external_digest_rejects_consistently_rewritten_receipt_id(bundle):
    retained_digest = bundle["bundle_sha256"]
    report = bundle["reports"][0]
    report["receipt"]["receipt_id"] = report["receipt_id"] = "different"
    report["receipt_sha256"] = digest(report["receipt"])
    report["observed_sha256"] = digest({"query": report["query"], "receipt": report["receipt"]})
    reseal(bundle)
    with pytest.raises(ValueError, match="external bundle digest mismatch"):
        verify_bundle(bundle, expected_sha256=retained_digest)


@pytest.mark.parametrize("field,value", [("old_valid", 1), ("new_verdict_candidates", [0, 1]),
                                         ("old_completion_classes", True)])
def test_boolean_integer_substitutions_rejected(bundle, field, value):
    bundle["reports"][0][field] = value
    reseal(bundle)
    with pytest.raises(ValueError):
        verify_bundle(bundle)


def test_trusted_bundle_digest_also_binds_review_and_exact_id_sidecars():
    sys.path.insert(0, str(ROOT / "scripts"))
    from export_audit_report import verify_sidecar_bindings
    review = {"affected_classes": [0, 6, 14], "bundle_sha256": "initial"}
    ids = [{"receipt_id": "one", "class_index": 0}]
    bundle = {"provenance": {"affected_id_index_content_sha256": digest(ids),
              "change_review_content_sha256": digest({k: v for k, v in review.items() if k != "bundle_sha256"})}}
    bundle["bundle_sha256"] = digest(bundle)
    review["bundle_sha256"] = bundle["bundle_sha256"]
    verify_sidecar_bindings(bundle, review, ids)
    with pytest.raises(ValueError, match="affected ID content binding mismatch"):
        verify_sidecar_bindings(bundle, review, [{"receipt_id": "another", "class_index": 0}])
    review["affected_classes"] = [0, 6, 15]
    with pytest.raises(ValueError, match="review content binding mismatch"):
        verify_sidecar_bindings(bundle, review, ids)


def test_native_query_matches_existing_receipt_binding_parser():
    sys.path.insert(0, str(ROOT / "scripts"))
    from revalidate_receipt import receipt_key
    receipt = fixture_spec()["receipt"]
    mask, (base, profile, ranks) = receipt_key(receipt)
    query = receipt_query(receipt)
    assert query == {"base": base, "mask": mask, "observed": (ranks,), "old_verdict": receipt["verdict"]}


@pytest.mark.parametrize("mutation,code", [
    (lambda e: e["reads"]["profile"].update(epoch="mock-snapshot-2"), "snapshot_mismatch"),
    (lambda e: e["reads"]["profile"].update(snapshot_sha256="f" * 64), "snapshot_mismatch"),
    (lambda e: e["reads"]["activity_projection"].pop("complete"), "incomplete_field"),
    (lambda e: e["reads"]["profile"].update(ok=False), "acquisition_failed"),
])
def test_mock_adapter_contract_rejects_bad_reads(mutation, code):
    envelope = mock_envelope("0" * 64, ["activity_projection", "profile"])
    mutation(envelope)
    with pytest.raises(AdapterContractError) as caught:
        validate_envelope(envelope, "0" * 64, ["activity_projection", "profile"])
    assert caught.value.code == code


def test_incomplete_collection_is_not_known_absent():
    envelope = mock_envelope("0" * 64, ["visible_base", "epcList"])
    envelope["reads"]["epcList"].update(value=[], complete=False)
    with pytest.raises(AdapterContractError, match="incomplete_field"):
        validate_envelope(envelope, "0" * 64, ["visible_base", "epcList"])


def test_future_withdrawal_preserves_snapshot_attestation_but_historical_revocation_rejects():
    envelope = mock_envelope("0" * 64, ["activity_projection"], ["consignment_exclusion"])
    envelope["revocations"] = [{"id": "consignment_exclusion", "scope": "future_inputs"}]
    assert validate_envelope(envelope, "0" * 64, ["activity_projection"], ["consignment_exclusion"])
    envelope["revocations"].append({"id": "consignment_exclusion", "scope": "snapshot", "snapshot_sha256": "0" * 64})
    with pytest.raises(AdapterContractError, match="snapshot_attestation_revoked"):
        validate_envelope(envelope, "0" * 64, ["activity_projection"], ["consignment_exclusion"])


def test_guarantee_control_and_withdrawal_change_acquisition_obligation():
    strict = fixture_spec()
    control = make_bundle([{**strict, "new_domain": "consignment_exclusion:v1"}])
    assert verify_bundle(control)["status"] == "passed"
    assert control["reports"][0]["status"] == "safe"
    assert control["reports"][0]["robust_additional_sets"] == [[]]
    broad = make_bundle([strict])
    assert broad["reports"][0]["status"] == "insufficient"
    assert broad["reports"][0]["robust_additional_sets"] == [["profile"]]


def test_cli_verifies_detached_bundle(tmp_path, bundle):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/export_audit_report.py"),
                             "verify-report", "--bundle", str(path)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "passed"
