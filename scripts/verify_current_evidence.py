#!/usr/bin/env python3
"""Check current saved scientific evidence without Git, absolute paths or PDF tools.

This stage reconciles saved hashes/records. It does not regenerate diagnoses;
scripts/reproduce_current.py separately executes the independent census,
portable semantic verifier, regression tests and optional actual OPA replay.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import traceback

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT / "results/platform_revision_20261010"
CONFIG = ROOT / "configs/current_reproduction.json"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def rows(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    checks, pins, measurements = [], {}, {}
    configuration = load(CONFIG)
    archived_code = []

    def check(condition, name):
        checks.append({"check": name, "passed": bool(condition)})

    def pin(path, expected):
        path = path.resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("Evidence path escapes this extracted repository")
        name = path.relative_to(ROOT).as_posix()
        actual = sha(path) if path.is_file() else None
        if actual:
            pins[name] = actual
        check(actual == expected, "SHA-256 " + name)

    def mapping(base, values, *, historical_sources=False):
        for name, expected in values.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Manifest entry is not a safe relative path: " + name)
            override = configuration["archived_source_overrides"].get(name) if historical_sources and base == ROOT else None
            if override:
                check(override["sha256"] == expected, "declared historical source digest: " + name)
                pin(ROOT / override["preserved_path"], expected)
                archived_code.append({"current_source": name, "current_sha256": sha(ROOT / name),
                                      "historical_sha256": expected, "preserved_path": override["preserved_path"]})
            else:
                pin(base / relative, expected)

    def stage(name, function):
        try:
            function()
        except Exception:
            checks.append({"check": name, "passed": False, "error": traceback.format_exc()})

    def compact():
        folder = ROOT / "results/compact_revision/evidence"
        manifest = load(folder / "manifest.json")
        pin(ROOT / "scripts/verify_compact_evidence.py", manifest["script_sha256"])
        mapping(ROOT, manifest["input_sha256"])
        mapping(ROOT, manifest["nonimported_context_code_sha256"])
        mapping(folder, manifest["output_sha256"])
        summary = load(folder / "summary.json")
        census = summary["census"]
        check(summary["status"] == "passed", "saved compact evidence passed")
        check(census["target_class_status_and_complete_robust_family_comparisons"] == 834880,
              "saved census contains 834,880 comparisons")
        measurements["saved_census_comparisons"] = census["target_class_status_and_complete_robust_family_comparisons"]

    def platform():
        run = PLATFORM / "opa/run"
        manifest, protocol, summary = (load(run / name) for name in ("manifest.json", "protocol.json", "summary.json"))
        mapping(ROOT, manifest["source_hashes"], historical_sources=True)
        mapping(run, manifest["artifacts"])
        pin(run / "protocol.json", manifest["protocol_sha256"])
        check(protocol["source_hashes"] == manifest["source_hashes"] and protocol["frozen_before_execution"] is True,
              "OPA protocol pins and sources agree")
        check(summary["status"] == "passed" and summary["primary_diagnoses"] == protocol["primary_queries"] == 941,
              "saved OPA run contains the declared 941 diagnoses")
        reports = rows(run / "class_reports.jsonl.gz")
        counts = Counter(row["report"]["status"] for row in reports)
        check(len(reports) == len({(r["model"], r["class_index"]) for r in reports}) == 941,
              "941 unique OPA target/class records")
        check(counts == {"safe": 140, "stale_verdict": 65, "insufficient": 736}, "saved OPA status census")
        occurrence, repair = (rows(run / name) for name in ("occurrence_index.jsonl.gz", "repair_index.jsonl.gz"))
        previous = rows(ROOT / "results/perspective_revision/audit_reports/affected_receipt_ids.jsonl.gz")
        ids = {row["receipt_id"] for row in repair}
        check(len(occurrence) == len({row["receipt_id"] for row in occurrence}) == 50931,
              "50,931 unique source occurrences")
        check(len(repair) == len(ids) == 33489 and ids == {row["receipt_id"] for row in previous},
              "exact 33,489 affected-ID agreement")
        check(ids == {row["receipt_id"] for row in occurrence if row["status"] == "insufficient"},
              "repair IDs equal the insufficient occurrence subset")
        partials = [load(p) for p in sorted((run / "native_partial").glob("*.replay.json"))]
        check(len(partials) == 8 and sum(p["compatible_completion_count"] for p in partials) == 432
              and all(p["independent_raw_verdict_parity"] is True for p in partials), "eight residuals record 432 completion checks")
        adapter_folder = PLATFORM / "log_adapter"
        adapter = load(adapter_folder / "verification.json")
        mapping(ROOT, adapter["source_hashes"], historical_sources=True)
        mapping(adapter_folder, adapter["files"])
        # The archived path records the original machine. Resolve the known
        # artifact in this extraction; its exact digest still must agree.
        pin(run / "native_logs/manifest.json", adapter["native_manifest"]["sha256"])
        check(adapter["status"] == "passed" and adapter["tests"]["returncode"] == 0, "saved importer checks passed")
        check({r["name"]: r["status"] for r in adapter["native_controls"]} == {
            "native_strict_profile_masked": "insufficient", "native_full_retention": "safe",
            "insufficient_old_both_masked": "invalid_receipt"}, "three native log admission controls")
        measurements.update(saved_opa_diagnoses=len(reports), saved_opa_status_counts=dict(counts),
                            saved_native_occurrences=len(occurrence), saved_affected_ids=len(ids))

    def portable():
        folder = ROOT / configuration["portable_bundle"]["path"]
        manifest = load(folder / "manifest.json")
        mapping(folder, manifest["files"])
        mapping(ROOT, manifest["source_artifacts"])
        check(manifest["bundle_sha256"] == configuration["portable_bundle"]["logical_sha256"],
              "portable logical bundle matches explicit expected digest")

    for name, function in (("compact saved evidence", compact), ("OPA saved evidence", platform), ("portable saved evidence", portable)):
        stage(name, function)
    result = {"schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
              "status": "passed" if all(c["passed"] for c in checks) else "failed",
              "scope": "Saved scientific artifact hashes and record reconciliation; no Git history, document build, benchmark rerun, source authentication or original XES reparse.",
              "repository_root": str(ROOT), "checks": checks, "check_count": len(checks),
              "failed_checks": [c for c in checks if not c["passed"]], "checked_file_hashes": pins,
              "measurements": measurements, "historical_source_bindings": archived_code,
              "configuration_sha256": sha(CONFIG), "checker_sha256": sha(Path(__file__))}
    (out / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "check_count", "failed_checks", "measurements")}, indent=2))
    return int(result["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
