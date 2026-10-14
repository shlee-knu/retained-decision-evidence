"""Equal-workflow obligations, adversarial envelopes and ordinary implementation checks."""
from copy import deepcopy
import gzip
import importlib.util
import json
from pathlib import Path
import sys

import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_equal_workflow as paired
import benchmark_audit_workflow as shared
from ordinary_audit_workflow import OrdinaryWorkflow
from logistics_validation.receipt_repair import PublicSnapshot, ReceiptRepair
from logistics_validation.audit_report import catalog_from_content, raw_summary, receipt_query, verify_bundle
from logistics_validation.focused_diagnostics import Problem


@pytest.fixture(scope="module")
def data():
    protocol = paired.protocol()
    all_receipts = shared.load_receipts(protocol)
    prepared = paired.select(all_receipts, "representatives")
    source = PublicSnapshot(ROOT / protocol["snapshot_source"], protocol["pinned_files"][protocol["snapshot_source"]], capabilities={"profile":"authorized", "first_times":"authorized"})
    ordinary = OrdinaryWorkflow(shared.read_json(ROOT/protocol["old_catalog"]), shared.read_json(ROOT/protocol["target_catalog"]))
    generic = ReceiptRepair("procurement_workflow_strict", catalog_from_content(shared.read_json(ROOT/protocol["target_catalog"])))
    return protocol, prepared, source, ordinary, generic, all_receipts


def test_all_twenty_native_observations_have_equal_semantic_summaries_and_literal_reports(data):
    config, prepared, _, ordinary, generic, _ = data
    generated = ordinary.construct_reports(prepared, config)
    assert verify_bundle(generated["bundle"])["reports"] == 20
    for receipt in prepared["receipts"]:
        got = ordinary.summary(receipt)
        wanted = generic._summary(receipt)
        assert {k:v for k,v in got.items() if k != "labeled_witnesses"} == {k:v for k,v in wanted.items() if k != "labeled_witnesses"}


def test_all_native_classes_have_identical_complete_repair_ledgers(data):
    _, prepared, source, ordinary, generic, _ = data
    for receipt in prepared["receipts"]:
        assert ordinary.execute(receipt, source) == generic.execute(receipt, source)


def test_ordinary_persisted_workflow_passes_independent_readback(data, tmp_path):
    config, prepared, source, ordinary, _, _ = data
    generated = ordinary.construct_reports(prepared, config)
    ledger, counts, fingerprint = paired.recovery(prepared, source, generated, ordinary, "ordinary_worklist")
    output = tmp_path/"ordinary"
    manifest, _ = shared.persist_artifacts(output, generated, ledger, counts, fingerprint)
    result = shared.verify_persisted(output, manifest, prepared, source, config)
    assert result["receipts"] == 20 and result["affected_ids"] == 3


@pytest.mark.parametrize("mutation", ["snapshot", "request", "case", "activities", "incomplete", "value", "denied"])
def test_baseline_matches_fail_closed_behavior_on_each_acquisition_binding(data, mutation):
    _, prepared, source, ordinary, generic, _ = data
    receipt = next(r for r in prepared["receipts"] if ordinary.summary(r)["status"] == "insufficient")
    class BadSource:
        def capability(self, current, block):
            return "authorization_not_granted" if mutation == "denied" else "authorized"
        def read(self, current, block):
            response = source.read(current, block)
            if mutation == "snapshot": response["snapshot_sha256"] = "0"*64
            if mutation == "request": response["request_receipt_sha256"] = "0"*64
            if mutation == "case": response["case_id"] = "wrong-id"
            if mutation == "activities": response["activities"] = []
            if mutation == "incomplete": response["complete"] = False
            if mutation == "value": response["value"] = "unsupported profile"
            return response
    left, right = ordinary.execute(receipt, BadSource()), generic.execute(receipt, BadSource())
    assert left == right
    assert left["action"] == "unresolved" and not left["replacement_verified"]


def test_invalid_old_boolean_is_rejected_before_source_access(data):
    _, prepared, source, ordinary, generic, _ = data
    receipt = deepcopy(prepared["receipts"][0])
    receipt["verdict"] = not receipt["verdict"]
    class NoSource:
        def capability(self, *args):
            pytest.fail("Invalid admission must precede capability/source reads")
    assert ordinary.execute(receipt, NoSource()) == generic.execute(receipt, NoSource())
    assert ordinary.execute(receipt, NoSource())["action"] == "invalid_receipt"


def test_integrity_consistent_ordinary_response_tampering_fails_independent_check(data, tmp_path):
    config, prepared, source, ordinary, _, _ = data
    generated = ordinary.construct_reports(prepared, config)
    ledger, counts, fingerprint = paired.recovery(prepared, source, generated, ordinary, "ordinary_worklist")
    rows = [json.loads(line) for line in gzip.decompress(ledger).decode().splitlines()]
    row = next(r for r in rows if r["accepted_responses"])
    row["accepted_responses"][0]["request_receipt_sha256"] = "0"*64
    output = tmp_path/"tampered"
    manifest, _ = shared.persist_artifacts(output, generated, shared.gzip_rows(rows), counts, fingerprint)
    with pytest.raises(ValueError, match="response binding/source literal"):
        shared.verify_persisted(output, manifest, prepared, source, config)


def test_native_scaling_keeps_fixed_N_or_K_without_duplicate_records(data):
    _, _, _, _, _, all_receipts = data
    for settings, count, classes in (("n:1000",1000,20),("n:10000",10000,20),("k:1",1000,1),("k:5",1000,5),("k:10",1000,10)):
        chosen = paired.select(all_receipts, settings)
        assert len(chosen["receipts"]) == len(chosen["by_id"]) == count
        assert len(chosen["classes"]) == classes


def test_ordinary_summary_covers_PT_weakening_and_changed_singletons_without_hidden_old_boolean(data):
    config, prepared, _, _, _, _ = data
    independent = shared.independent_checker(config)
    # Alternative targets are semantic regression tests, not additional timed workloads.
    for target in independent.TARGETS:
        catalog = independent.CATALOGS[target]
        ordinary = OrdinaryWorkflow(shared.read_json(ROOT/config["old_catalog"]), catalog)
        problem = Problem("procurement_regression", catalog_from_content(catalog))
        for receipt in prepared["receipts"]:
            got = ordinary.summary(receipt)
            expected = raw_summary(problem, receipt_query(receipt), receipt, "cartesian:v1", "cartesian:v1")
            assert {k:v for k,v in got.items() if k != "labeled_witnesses"} == {k:v for k,v in expected.items() if k != "labeled_witnesses"}
