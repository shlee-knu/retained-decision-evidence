#!/usr/bin/env python3
"""Replay saved native OPA logs through the conditional procurement importer.

Public source/request reconciliation is setup outside the importer. The importer
receives only an exported event and its supplied binding, never hidden values.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from logistics_validation.audit_report import SOURCE_FILES, digest, file_digest, receipt_query
from logistics_validation.catalog_audit import BASELINE, catalog_json, reference_verdict
from logistics_validation.opa_log_adapter import BINDING_SCHEMA, import_decision_log, plan_followup


def load(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", type=Path, default=ROOT / "results/platform_revision_20261010/opa/run/native_logs")
    parser.add_argument("--output", type=Path, default=ROOT / "results/platform_revision_20261010/log_adapter")
    args = parser.parse_args()
    check(not args.output.exists(), "Output already exists; preserve the saved evidence and choose a new destination")
    native = args.native_dir.resolve()
    manifest_path = native / "manifest.json"
    manifest = load(manifest_path)
    for name, expected in manifest["files"].items():
        check(Path(name).name == name, "Native file name escapes its directory")
        check(file_digest(native / name) == expected, "Native file hash mismatch: " + name)
    check(manifest["domain_version"] == "cartesian:v1", "Unsupported native domain")
    source_path = ROOT / manifest["snapshot_path"]
    check(file_digest(source_path) == manifest["snapshot_sha256"], "Public snapshot hash mismatch")
    check(file_digest(ROOT / manifest["baseline_catalog_path"]) == manifest["baseline_catalog_sha256"], "Catalog file hash mismatch")
    catalog_hash = digest(catalog_json(BASELINE))
    check(manifest["baseline_catalog_canonical_sha256"] == catalog_hash, "Baseline catalog mapping mismatch")
    check(file_digest(ROOT / manifest["normalization_source"]) == manifest["normalization_source_sha256"], "Normalizer source hash mismatch")
    bundle_path = native / "baseline_bundle.tar.gz"
    check(file_digest(bundle_path) == manifest["bundle_sha256"], "Bundle archive hash mismatch")
    with tarfile.open(bundle_path, "r:gz") as archive:
        bundle_manifest = json.load(archive.extractfile(".manifest"))
        bundled_data = json.load(archive.extractfile("data.json"))
        policy_body = archive.extractfile("predicates.rego").read()
        mask_body = archive.extractfile("log_mask.rego").read()
    check(bundle_manifest["revision"] == manifest["bundle_revision"], "Archived revision mismatch")
    expected_wire = [{"required": sorted(rule.required), "forbidden": sorted(rule.forbidden),
                      "edges": sorted([list(edge) for edge in rule.edges])} for rule in BASELINE]
    check(bundled_data == {"catalogs": {"baseline": expected_wire}}, "Archived catalog semantics mismatch")
    check(digest(expected_wire) == manifest["bundled_catalog_wire_sha256"], "Archived wire digest mismatch")
    source_case = None
    with gzip.open(source_path, "rt") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("case_id") == manifest["source_case_id"]:
                source_case = row
                break
    check(source_case is not None, "Native case absent from pinned public snapshot")
    raw = {name: source_case[name] for name in ("activities", "profile", "first_times")}
    check(len(raw["activities"]) == manifest["source_activity_count"], "Source sequence length mismatch")
    original_verdict = reference_verdict(raw, BASELINE)
    complete_receipt = {"schema_version": 1, "receipt_id": source_case["case_id"],
                        "snapshot_sha256": manifest["snapshot_sha256"], "catalog_sha256": catalog_hash,
                        "domain_version": "cartesian:v1", "activities": raw["activities"],
                        "observed": {name: raw[name] for name in ("profile", "first_times")}, "verdict": original_verdict}
    query = receipt_query(complete_receipt)
    aliases = {"base": list(query["base"]), "profile": query["observed"][0], "ranks": list(query["observed"][1])}
    expectations = {"native_strict_profile_masked": "insufficient", "native_full_retention": "safe",
                    "insufficient_old_both_masked": "invalid_receipt"}
    args.output.mkdir(parents=True)
    rows = []
    for name, expected_status in expectations.items():
        event, response, request = [load(native / f"{name}.{kind}.json") for kind in ("decision", "response", "request")]
        check(event["decision_id"] == response["decision_id"], "Response/log correlation mismatch")
        check(type(event["result"]) is bool and type(response["result"]) is bool
              and event["result"] == response["result"] == original_verdict, "Historical result mismatch")
        check({key: request[key] for key in raw} == raw and request["record"] == aliases
              and request["case_id"] == source_case["case_id"], "Pre-mask request/source reconciliation failed")
        check(len(event["bundles"]) == 1, "Unexpected number of native bundles")
        bundle_name = next(iter(event["bundles"]))
        check(bundle_name in manifest["bundle_names"], "Unpinned native bundle name")
        binding = {"schema_version": BINDING_SCHEMA, "event_sha256": digest(event), "decision_id": response["decision_id"],
                   "source_case_id": source_case["case_id"], "decision_path": "audit/predicates/logged_old_decision",
                   "bundle": {"name": bundle_name, "revision": manifest["bundle_revision"],
                              "archive_sha256": manifest["bundle_sha256"], "catalog_sha256": catalog_hash},
                   "snapshot_sha256": manifest["snapshot_sha256"], "domain_version": "cartesian:v1",
                   "source_assertions": {"source_case_id": source_case["case_id"], "snapshot_sha256": manifest["snapshot_sha256"],
                                         "complete_fields": {"activities": True, "profile": True, "first_times": True},
                                         "normalized_aliases": True}}
        # Only event and sidecar cross the import boundary. The request/source
        # above verifies the public fixture producer, and supplies no completion.
        imported = import_decision_log(event, binding)
        check(imported["summary"]["status"] == expected_status, "Unexpected native import classification")
        plans = {"no_access_declared": plan_followup(imported),
                 "profile_authorized_and_available": plan_followup(imported, authorized_and_available=["profile"]),
                 "profile_unavailable": plan_followup(imported, unavailable=["profile"]),
                 "profile_unauthorized": plan_followup(imported, unauthorized=["profile"]),
                 "profile_read_failed": plan_followup(imported, authorized_and_available=["profile"], read_failures=["profile"])}
        if expected_status == "insufficient":
            check(imported["summary"]["robust_additional_sets"] == [["profile"]], "Unexpected robust set")
            check(plans["profile_authorized_and_available"]["action"] == "acquire", "Available profile not planned")
            check(all(plans[key]["action"] == "unresolved" for key in plans if key != "profile_authorized_and_available"), "Unavailable acquisition misclassified")
        check(all(not plan["acquisition_completed"] and not plan["reads_performed"] for plan in plans.values()), "Planner claimed recovery")
        write(args.output / f"{name}.input.json", {"event": event, "binding": binding})
        write(args.output / f"{name}.output.json", {"import": imported, "followup_plans": plans})
        rows.append({"name": name, "decision_id": imported["decision_id"], "source_case_id": imported["source_case_id"],
                     "status": expected_status, "retained_blocks": sorted(imported["receipt"]["observed"]),
                     "robust_additional_sets": imported["summary"]["robust_additional_sets"]})
    command = [sys.executable, "-m", "pytest", "-q", "tests/test_opa_log_adapter.py"]
    tests = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    with (args.output / "pytest.stdout.txt").open("x") as stream:
        stream.write(tests.stdout)
    with (args.output / "pytest.stderr.txt").open("x") as stream:
        stream.write(tests.stderr)
    sources = sorted(set(SOURCE_FILES) | {"src/logistics_validation/opa_log_adapter.py",
                                        "scripts/check_opa_log_adapter.py", "tests/test_opa_log_adapter.py"})
    output = {"schema_version": 1, "status": "passed" if tests.returncode == 0 else "failed",
              "scope": "Three genuine local OPA decision logs for one public archive case; separate integration controls outside the primary 941 class requests. Conditional binding checks, not issuer authentication. No source acquisition or portable-bundle export is performed by the importer/planner.",
              "native_manifest": {"path": str(manifest_path), "sha256": file_digest(manifest_path)},
              "source_reconciliation": {"snapshot_sha256": manifest["snapshot_sha256"], "case_id": source_case["case_id"],
                                        "complete_original_blocks_match_requests": True, "normalized_aliases_match_raw": True,
                                        "source_in_heldout_receipt_cohort": manifest["source_in_heldout_receipt_cohort"]},
              "archived_policy_sha256": hashlib.sha256(policy_body).hexdigest(),
              "archived_mask_policy_sha256": hashlib.sha256(mask_body).hexdigest(),
              "native_controls": rows, "tests": {"command": command, "returncode": tests.returncode, "stdout": tests.stdout},
              "source_hashes": {name: file_digest(ROOT / name) for name in sources},
              "files": {p.name: file_digest(p) for p in sorted(args.output.iterdir()) if p.is_file()}}
    write(args.output / "verification.json", output)
    print(json.dumps({"status": output["status"], "native_controls": rows, "tests": tests.stdout.strip(), "output": str(args.output)}, indent=2))
    return tests.returncode


if __name__ == "__main__":
    raise SystemExit(main())
