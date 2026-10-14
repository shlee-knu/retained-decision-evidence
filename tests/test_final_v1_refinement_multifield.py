"""Meaningful falsification checks for the new independent functional readback."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_final_v1_refinement_multifield as checker
import run_final_v1_refinement_multifield as runner


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    output = tmp_path_factory.mktemp("multifield") / "run"
    runner.run(output)
    return output


def test_same_native_pairs_three_conditions_are_independently_checked(observed):
    got = checker.verify_run(observed)
    assert got["status"] == "passed"
    assert got["summary"]["selected_case_target_pairs"] == got["summary"]["distinct_source_ids"] == 114
    assert got["summary"]["selected_per_target"] == {"edge_p0_a0_b1": 0, "required_p2_a3": 113, "edge_p2_a0_b2": 0, "edge_p2_a2_b3": 1}
    assert got["total_replay_rows"] == 684
    for condition, expected in (("all_authorized", (114, 85, 85)), ("times_unavailable", (29, 0, 0)), ("times_wrong_request", (29, 85, 0))):
        row = got["summary"]["scenarios"][condition]
        assert (row["verified_replacements"], row["attempted_reads"].get("first_times", 0), row["successful_reads"].get("first_times", 0)) == expected


@pytest.mark.parametrize("mutation", ["accepted_request", "rejected_request_trace", "replacement_label", "false_success", "missing_row", "duplicate_id", "robust_set", "summary_counts"])
def test_semantic_tampering_rejected_after_payload_manifest_is_refreshed(observed, tmp_path, mutation):
    import shutil
    target = tmp_path / "copy"
    shutil.copytree(observed, target)
    folder = target / "ordinary_worklist"
    if mutation in {"accepted_request", "rejected_request_trace", "replacement_label", "false_success", "missing_row"}:
        ledger = checker.rows(folder / "repair_ledger.jsonl.gz")
        if mutation == "accepted_request":
            ledger[0]["accepted_responses"][0]["request_receipt_sha256"] = "0" * 64
        elif mutation == "rejected_request_trace":
            row = next(r for r in ledger if r["reason"] == "read_request_mismatch")
            row["source_calls"][-1]["returned"]["request_receipt_sha256"] = row["source_calls"][-1]["request_receipt_sha256"]
        elif mutation == "replacement_label":
            ledger[0]["replacement_receipt"]["verdict"] = not ledger[0]["replacement_receipt"]["verdict"]
        elif mutation == "false_success":
            row = next(r for r in ledger if r["reason"] == "source_unavailable")
            row["replacement_verified"] = True
        else:
            ledger.pop()
        (folder / "repair_ledger.jsonl.gz").write_bytes(runner.shared.gzip_rows(ledger))
    elif mutation == "duplicate_id":
        selected = checker.load(folder / "selected_ids.json")
        selected[-1] = selected[0]
        (folder / "selected_ids.json").write_bytes(runner.shared.json_bytes(selected))
    elif mutation == "robust_set":
        bundles = checker.load(folder / "class_reports.json")
        bundle = bundles["required_p2_a3"]
        report = next(r for r in bundle["reports"] if r["robust_additional_sets"] == [["profile", "first_times"]])
        report["robust_additional_sets"] = [["profile"]]
        report["report_sha256"] = checker.digest({k: v for k, v in report.items() if k != "report_sha256"})
        bundle["bundle_sha256"] = checker.digest({k: v for k, v in bundle.items() if k != "bundle_sha256"})
        (folder / "class_reports.json").write_bytes(runner.shared.json_bytes(bundles))
    else:
        summary = checker.load(folder / "summary.json")
        summary["scenarios"]["times_wrong_request"]["successful_reads"]["first_times"] = 85
        (folder / "summary.json").write_bytes(runner.shared.json_bytes(summary))
    manifest = checker.load(folder / "manifest.json")
    for name in manifest["files"]:
        p = folder / name
        manifest["files"][name] = {"sha256": checker.ind.sha(p), "bytes": p.stat().st_size}
    (folder / "manifest.json").write_bytes(runner.shared.json_bytes(manifest))
    with pytest.raises(ValueError, match="Independent|Replay row"):
        checker.verify_run(target)
