#!/usr/bin/env python3
"""Reconcile all stored equal-workflow execution hashes after measurements.

This is a byte-integrity/reconciliation audit. The semantic readback was run
inside every child and recorded there; this script does not rerun that costly
checker or treat repeated measurements as new independent source records.
"""
from collections import defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/access_practical_revision_20261012/workflow"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def check(base=BASE):
    children, per_selection, source_pins = [], defaultdict(list), []
    for mode in ("paired", "scaling", "profile"):
        folder = base / mode
        freeze = json.loads((folder / "execution_freeze.json").read_text())
        need(all(sha(ROOT/name) == expected for name, expected in freeze["files"].items()), "Frozen source/input mismatch: " + mode)
        source_pins.append(freeze["files"])
        summary = json.loads((folder / "summary.json").read_text())
        need(summary["status"] == "passed", "Missing successful summary: " + mode)
        for record_path in sorted(folder.glob("*.json")):
            row = json.loads(record_path.read_text())
            if "method" not in row:
                continue
            output = folder / record_path.stem
            need(sha(output / "manifest.json") == row["manifest_sha256"], "Manifest changed: " + str(record_path))
            manifest = json.loads((output / "manifest.json").read_text())
            need(row["payload_files"] == manifest["files"], "Child payload inventory changed")
            for name, facts in manifest["files"].items():
                file_path = output/name
                need(sha(file_path) == facts["sha256"] and file_path.stat().st_size == facts["bytes"], "Payload changed: " + str(file_path))
            need(row["verification"]["status"] == "passed" and row["verification"]["independent_predicate_and_completion_check"] is True, "Semantic readback did not pass")
            need(row["replacement_stream_sha256"] == manifest["replacement_stream_sha256"], "Replacement fingerprint inconsistent")
            need(row["verification"]["counts"] == manifest["counts"] and row["verification"]["status_counts"] == manifest["status_counts"], "Counts inconsistent")
            per_selection[row["selection"]].append((row, manifest))
            children.append({"mode":mode,"name":record_path.stem,"method":row["method"],"selection":row["selection"],"manifest_sha256":row["manifest_sha256"],"record_sha256":sha(record_path),"profiling_artifacts":{name:sha(output/name) for name in ("recovery_profile.pstats","recovery_profile.txt")} if row["profiling"] else {}})
    need(all(pins == source_pins[0] for pins in source_pins), "Measured source/input pins differ across modes")
    equivalence = {}
    for selection, rows in sorted(per_selection.items()):
        need(len({row["selected_receipt_ids_sha256"] for row,_ in rows}) == 1, "Source ID set changed")
        need(len({json.dumps(manifest["files"],sort_keys=True) for _,manifest in rows}) == 1, "Complete payloads differ between implementations/runs")
        need(len({json.dumps(row["verification"],sort_keys=True) for row,_ in rows}) == 1, "Verified obligations differ")
        row, manifest = rows[0]
        equivalence[selection] = {"executions":len(rows),"receipts_per_execution":row["verification"]["receipts"],"classes":row["verification"]["reports"],"counts":row["verification"]["counts"],"all_three_payloads_byte_identical":True,"payload_files":manifest["files"]}
    need(len(children) == 44, "Expected 12 paired + 30 scaling + 2 profile children")
    return {"status":"passed","child_processes":len(children),"source_files_per_freeze":len(source_pins[0]),"summary_sha256":{mode:sha(base/mode/"summary.json") for mode in ("paired","scaling","profile")},"all_frozen_source_and_input_hashes_match":True,"selections":equivalence,"children":children,"checker_sha256":sha(Path(__file__).resolve()),"scope":"Integrity and recorded-check reconciliation; every child already ran independent semantic readback. Repeated executions/subsets are not additional independent data or deployments."}


if __name__ == "__main__":
    result = check()
    (BASE / "evidence_verification.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in {"children","selections"}},indent=2))
