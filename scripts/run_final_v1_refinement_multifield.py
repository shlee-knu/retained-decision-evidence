#!/usr/bin/env python3
"""New functional coverage for the immutable FINAL_V1 workflow implementations."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import gzip
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
import benchmark_audit_workflow as shared
from ordinary_audit_workflow import OrdinaryWorkflow
from logistics_validation.audit_report import (
    ROBUST_REQUIREMENT, SCHEMA, SCOPE, SOURCE_FILES, canonical, catalog_from_content,
    digest, file_digest, make_bundle, mock_envelope, receipt_query, verify_bundle,
)
from logistics_validation.catalog_audit import catalog_json, generated_catalogs
from logistics_validation.focused_diagnostics import Problem
from logistics_validation.receipt_repair import PublicSnapshot, ReceiptRepair

PROTOCOL = "configs/final_v1_refinement_multifield_protocol.json"
METHODS = ("checked_api", "ordinary_worklist")
NEW_FILES = (PROTOCOL, "scripts/run_final_v1_refinement_multifield.py",
             "scripts/check_final_v1_refinement_multifield.py",
             "tests/test_final_v1_refinement_multifield.py")


def write(path, value):
    with path.open("xb") as stream:
        stream.write(shared.json_bytes(value))


def ordinary_bundle(prepared, engine, target, protocol, provenance):
    """New generic report wrapper; the ordinary semantic/repair engine is unchanged."""
    artifacts, reports = {}, []

    def artifact(kind, identity, body):
        row = {"kind": kind, "identity": identity, "content": deepcopy(body), "content_sha256": digest(body)}
        key = digest(row)
        artifacts[key] = row
        return key

    domain = {"id": "cartesian:v1", "alphabet": ["create", "receive", "invoice", "clear"],
              "profiles": ["3-way match, invoice after GR", "3-way match, invoice before GR", "2-way match", "Consignment"],
              "clock_domain": "all canonical weak orders of complete first timestamps", "guarantees": []}
    bindings = {"old_rule": artifact("catalog", protocol["old_catalog"], engine.old_catalog),
                "new_rule": artifact("catalog", "authored:" + target, engine.target_catalog),
                "old_domain": artifact("completion_domain", "cartesian:v1", domain),
                "new_domain": artifact("completion_domain", "cartesian:v1", domain)}
    for item in prepared["classes"]:
        receipt, query = deepcopy(item["receipt"]), deepcopy(item["query"])
        shared.check(digest(receipt_query(receipt)) == digest(query), "report receipt query")
        shared.check(receipt["catalog_sha256"] == engine.old_digest and receipt["domain_version"] == "cartesian:v1", "old binding")
        report = {"schema_version": SCHEMA, "request_id": "class:" + str(item["class_index"]),
                  "receipt_id": receipt["receipt_id"], "problem": "procurement_" + target,
                  "query": query, "receipt": receipt, "receipt_sha256": digest(receipt),
                  "observed_sha256": digest({"query": query, "receipt": receipt}),
                  "snapshot_sha256": receipt["snapshot_sha256"], "bindings": deepcopy(bindings),
                  "adapter_envelope": mock_envelope(receipt["snapshot_sha256"], ["activity_projection"] + list(receipt["observed"])),
                  "conditional_scope": SCOPE, "robust_requirement": ROBUST_REQUIREMENT,
                  **engine.summary(receipt, witnesses=True)}
        report["report_sha256"] = digest(report)
        reports.append(report)
    bundle = {"schema_version": SCHEMA, "artifacts": artifacts, "reports": reports,
              "provenance": provenance, "source_hashes": {name: file_digest(ROOT / name) for name in SOURCE_FILES}}
    bundle["bundle_sha256"] = digest(bundle)
    return json.loads(canonical(bundle))


class ScenarioSource:
    """Trace actual callbacks, including a rejected response, without hidden source reads."""
    def __init__(self, source, scenario):
        self.source, self.scenario, self.calls = source, scenario, []

    def capability(self, receipt, block):
        state = "source_unavailable" if self.scenario == "times_unavailable" and block == "first_times" else "authorized"
        self.calls.append({"operation": "capability", "block": block,
                           "request_receipt_sha256": digest(receipt), "returned": state})
        return state

    def read(self, receipt, block):
        response = self.source.read(receipt, block)
        if self.scenario == "times_wrong_request" and block == "first_times":
            response["request_receipt_sha256"] = "0" * 64
        self.calls.append({"operation": "read", "block": block,
                           "request_receipt_sha256": digest(receipt), "returned": deepcopy(response)})
        return response


def aggregate(rows):
    return {"episodes": len(rows), "actions": dict(Counter(row["action"] for row in rows)),
            "reasons": dict(Counter(row["reason"] for row in rows)),
            "attempted_reads": dict(Counter(block for row in rows for block in row["attempted_reads"])),
            "successful_reads": dict(Counter(block for row in rows for block in row["successful_reads"])),
            "verified_replacements": sum(row["replacement_verified"] for row in rows)}


def run(output):
    shared.check(not output.exists(), "Preserve earlier output; use a new folder")
    protocol = shared.read_json(ROOT / PROTOCOL)
    shared_config = shared.read_json(shared.PROTOCOL)
    pins = dict(shared_config["pinned_files"])
    pins.update({name: file_digest(ROOT / name) for name in NEW_FILES +
                 ("scripts/ordinary_audit_workflow.py", "scripts/benchmark_audit_workflow.py",
                  "configs/audit_workflow_cost_protocol.json",
                  "results/repair_revision_20261010/methods/independent_expected_cases.json")})
    shared.check(all(file_digest(ROOT / name) == value for name, value in pins.items()), "Input/source pin mismatch")
    output.mkdir(parents=True)
    write(output / "execution_freeze.json", {"protocol": protocol, "files": pins,
          "scope": "Frozen before this functional run; historical 114/29/85 outcomes were already known."})
    prepared = shared.load_receipts(shared_config)
    source = PublicSnapshot(ROOT / shared_config["snapshot_source"], pins[shared_config["snapshot_source"]],
                            capabilities={"profile": "authorized", "first_times": "authorized"})
    catalogs = {name: catalog_json(body) for name, body, _ in generated_catalogs() if name in protocol["targets"]}
    shared.check(set(catalogs) == set(protocol["targets"]), "Target coverage")
    summaries = {}
    for method in METHODS:
        folder = output / method
        folder.mkdir()
        bundles, selected, engines = {}, [], {}
        for target in protocol["targets"]:
            body = catalogs[target]
            provenance = {"kind": "existing native two-block functional coverage",
                          "class_definition": "normalized retained observation plus old verdict",
                          "native_receipts": len(prepared["receipts"]),
                          "receipt_store_sha256": pins[shared_config["receipt_source"]]}
            if method == "checked_api":
                problem = Problem("procurement_" + target, catalog_from_content(body))
                specs = [{"problem": problem, "query": row["query"], "receipt": row["receipt"],
                          "request_id": "class:" + str(row["class_index"]),
                          "old_identity": shared_config["old_catalog"], "new_identity": "authored:" + target}
                         for row in prepared["classes"]]
                bundle = make_bundle(specs, provenance)
                engines[target] = ReceiptRepair("procurement_" + target, catalog_from_content(body))
            else:
                engines[target] = OrdinaryWorkflow(shared.read_json(ROOT / shared_config["old_catalog"]), body, "procurement_" + target)
                bundle = ordinary_bundle(prepared, engines[target], target, shared_config, provenance)
            shared.check(verify_bundle(bundle)["status"] == "passed", "Portable report verification")
            bundles[target] = bundle
            reports = {int(row["request_id"].split(":")[1]): row for row in bundle["reports"]}
            for rid, index in prepared["mapping"]:
                report = reports[index]
                if report["robust_additional_sets"] == [["profile", "first_times"]]:
                    shared.check(report["status"] == "insufficient", "Selected class status")
                    selected.append({"target": target, "receipt_id": rid, "class_index": index,
                                     "robust_additional_sets": report["robust_additional_sets"]})
        rows = []
        for scenario in protocol["scenarios"]:
            for item in selected:
                receipt = prepared["by_id"][item["receipt_id"]]
                traced = ScenarioSource(source, scenario)
                row = engines[item["target"]].execute(receipt, traced)
                row.update(scenario=scenario, change_target=item["target"], class_index=item["class_index"], source_calls=traced.calls)
                rows.append(row)
        write(folder / "class_reports.json", bundles)
        write(folder / "selected_ids.json", selected)
        with (folder / "repair_ledger.jsonl.gz").open("xb") as stream:
            stream.write(shared.gzip_rows(rows))
        summary = {"retained_receipts": len(prepared["receipts"]), "classes_per_target": len(prepared["classes"]),
                   "target_class_reports": sum(len(bundle["reports"]) for bundle in bundles.values()),
                   "selected_case_target_pairs": len(selected), "distinct_source_ids": len({r["receipt_id"] for r in selected}),
                   "selected_per_target": {target: sum(row["target"] == target for row in selected) for target in protocol["targets"]},
                   "scenarios": {scenario: aggregate([r for r in rows if r["scenario"] == scenario]) for scenario in protocol["scenarios"]},
                   "per_target_scenarios": {target: {scenario: aggregate([r for r in rows if r["scenario"] == scenario and r["change_target"] == target])
                                                     for scenario in protocol["scenarios"]} for target in protocol["targets"]}}
        write(folder / "summary.json", summary)
        write(folder / "manifest.json", {"files": {p.name: {"sha256": file_digest(p), "bytes": p.stat().st_size}
                                                     for p in sorted(folder.iterdir()) if p.is_file()}})
        summaries[method] = summary
    shared.check(all(file_digest(ROOT / name) == value for name, value in pins.items()), "Source changed during functional run")
    check = subprocess.run([sys.executable, str(ROOT / "scripts/check_final_v1_refinement_multifield.py"),
                            "--run", str(output), "--output", str(output / "independent_verification.json")],
                           cwd=ROOT, capture_output=True, text=True)
    write(output / "independent_checker_process.json", {"returncode": check.returncode, "stdout": check.stdout, "stderr": check.stderr})
    shared.check(check.returncode == 0, "Independent checker failed; inspect preserved log")
    write(output / "summary.json", {"status": "passed", "methods": summaries,
          "scope": protocol["purpose"], "limits": protocol["limits"],
          "independent_verification_sha256": file_digest(output / "independent_verification.json")})
    print(json.dumps({"status": "passed", "summary": summaries[METHODS[0]], "output": str(output)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)
