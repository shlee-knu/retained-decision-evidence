"""Integrated output-boundary tests, including integrity-consistent tampering."""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_workflow", ROOT / "scripts/benchmark_audit_workflow.py")
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


@pytest.fixture(scope="module")
def transaction(tmp_path_factory):
    from logistics_validation.receipt_repair import PublicSnapshot
    protocol = workflow.read_json(workflow.PROTOCOL)
    all_receipts = workflow.load_receipts(protocol)
    receipts = [row["receipt"] for row in all_receipts["classes"]]
    prepared = workflow.group_receipts(receipts, protocol)
    source = PublicSnapshot(ROOT / protocol["snapshot_source"],
                            protocol["pinned_files"][protocol["snapshot_source"]],
                            capabilities={"profile": "authorized", "first_times": "authorized"})
    generated = workflow.construct_reports(prepared, protocol)
    ledger, counts, fingerprint = workflow.recover_and_encode(prepared, source, generated)
    folder = tmp_path_factory.mktemp("workflow") / "output"
    manifest_hash, _ = workflow.persist_artifacts(folder, generated, ledger, counts, fingerprint)
    return protocol, prepared, source, folder, manifest_hash


def rebind_changed_payload(folder, name):
    """Recompute integrity to test semantic checks, not merely checksum failure."""
    manifest = workflow.read_json(folder / "manifest.json")
    path = folder / name
    manifest["files"][name] = {"sha256": workflow.sha(path), "bytes": path.stat().st_size}
    (folder / "manifest.json").write_bytes(workflow.json_bytes(manifest))
    return workflow.sha(folder / "manifest.json")


def test_complete_transaction_checks_every_existing_native_observation_class(transaction):
    protocol, prepared, source, folder, manifest_hash = transaction
    result = workflow.verify_persisted(folder, manifest_hash, prepared, source, protocol)
    assert result["reports"] == result["receipts"] == 20
    assert result["affected_ids"] == result["counts"]["profile_reads"] == 3
    assert result["counts"]["replacements"] == 20
    assert result["independent_predicate_and_completion_check"]


def test_retained_store_duplicate_id_fails_before_class_grouping(transaction):
    protocol, prepared, *_ = transaction
    repeated = [prepared["receipts"][0], deepcopy(prepared["receipts"][0])]
    with pytest.raises(ValueError, match="duplicate retained ID"):
        workflow.group_receipts(repeated, protocol)


def test_external_manifest_pin_cannot_be_replaced(transaction, tmp_path):
    protocol, prepared, source, original, manifest_hash = transaction
    folder = tmp_path / "tampered"
    shutil.copytree(original, folder)
    (folder / "manifest.json").write_text("{}\n")
    with pytest.raises(ValueError, match="external manifest digest"):
        workflow.verify_persisted(folder, manifest_hash, prepared, source, protocol)


def test_missing_exact_id_rejected_even_with_consistent_checksums(transaction, tmp_path):
    protocol, prepared, source, original, _ = transaction
    folder = tmp_path / "tampered"
    shutil.copytree(original, folder)
    name = "affected_receipt_ids.jsonl.gz"
    with gzip.open(folder / name, "rt") as stream:
        rows = [json.loads(line) for line in stream]
    (folder / name).write_bytes(workflow.gzip_rows(rows[1:]))
    manifest_hash = rebind_changed_payload(folder, name)
    with pytest.raises(ValueError, match="independent exact affected ID set"):
        workflow.verify_persisted(folder, manifest_hash, prepared, source, protocol)


def test_bad_replacement_rejected_even_with_consistent_checksums(transaction, tmp_path):
    protocol, prepared, source, original, _ = transaction
    folder = tmp_path / "tampered"
    shutil.copytree(original, folder)
    name = "repair_ledger.jsonl.gz"
    with gzip.open(folder / name, "rt") as stream:
        rows = [json.loads(line) for line in stream]
    rows[0]["replacement_receipt"]["verdict"] = not rows[0]["replacement_receipt"]["verdict"]
    (folder / name).write_bytes(workflow.gzip_rows(rows))
    manifest_hash = rebind_changed_payload(folder, name)
    with pytest.raises(ValueError, match="independent replacement sufficiency"):
        workflow.verify_persisted(folder, manifest_hash, prepared, source, protocol)


def test_bad_source_response_rejected_even_with_consistent_checksums(transaction, tmp_path):
    protocol, prepared, source, original, _ = transaction
    folder = tmp_path / "tampered"
    shutil.copytree(original, folder)
    name = "repair_ledger.jsonl.gz"
    with gzip.open(folder / name, "rt") as stream:
        rows = [json.loads(line) for line in stream]
    next(row for row in rows if row["accepted_responses"])["accepted_responses"][0]["request_receipt_sha256"] = "0" * 64
    (folder / name).write_bytes(workflow.gzip_rows(rows))
    manifest_hash = rebind_changed_payload(folder, name)
    with pytest.raises(ValueError, match="response binding/source literal"):
        workflow.verify_persisted(folder, manifest_hash, prepared, source, protocol)
