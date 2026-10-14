#!/usr/bin/env python3
"""One current entry point for saved evidence, audit tests and actual OPA replay.

All destinations are new. No historical ledger, PDF or Git reference is edited.
The 'platform' scope includes 'audit', which includes 'evidence'. External FHIR
validators, original XES acquisition and timing remeasurement remain separate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/current_reproduction.json"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", choices=("evidence", "audit", "platform"), default="evidence")
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or later is required (the clean replay was tested on 3.12)")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    config = json.loads(CONFIG.read_text())
    record = {"schema_version": 1, "status": "running", "scope": args.scope,
              "started_utc": datetime.now(timezone.utc).isoformat(), "repository_root": str(ROOT),
              "python": sys.version, "executable": sys.executable, "prefix": sys.prefix,
              "base_prefix": sys.base_prefix, "platform": platform.platform(), "commands": [],
              "configuration_sha256": sha(CONFIG), "runner_sha256": sha(Path(__file__)),
              "limits": "Finite scientific evidence and selected implementation regressions; no fresh timing comparison, original archive reparse, external FHIR validator, Git-history proof or document-build certification."}
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"

    def run(name, arguments):
        command = [sys.executable, *arguments]
        started = time.perf_counter()
        stdout, stderr = output / (name + ".stdout.txt"), output / (name + ".stderr.txt")
        print("Running " + name, flush=True)
        with stdout.open("x") as out, stderr.open("x") as err:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err, check=False)
        row = {"name": name, "command": command, "returncode": result.returncode,
               "elapsed_seconds_not_a_benchmark": time.perf_counter() - started,
               "stdout": stdout.name, "stderr": stderr.name,
               "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
        record["commands"].append(row)
        if result.returncode:
            raise RuntimeError(name + " failed; inspect " + str(stdout) + " and " + str(stderr))

    try:
        run("saved_evidence", ["scripts/verify_current_evidence.py", "--output", str(output / "saved_evidence")])
        run("independent_census", ["scripts/verify_compact_evidence.py", "--output", str(output / "independent_census")])
        run("portable_semantics", ["scripts/export_audit_report.py", "verify-report", "--bundle",
            config["portable_bundle"]["path"], "--verify-original-sources", "--expected-sha256",
            config["portable_bundle"]["logical_sha256"]])
        if args.scope in {"audit", "platform"}:
            record["installed_versions"] = {name: version(name) for name in ("pytest", "z3-solver")}
            tests = ["tests/test_audit_report.py", "tests/test_audit_witness_representations.py", "tests/test_focused_diagnostics.py",
                     "tests/test_focused_independent.py", "tests/test_revision_diagnostics.py",
                     "tests/test_opa_log_adapter.py"]
            if args.scope == "platform":
                run("opa_dependency", ["scripts/fetch_opa_dependency.py", "--verify-only"])
                tests.append("tests/test_opa_audit_integration.py")
            run("audit_tests", ["-m", "pytest", "-q", "--junitxml=" + str(output / "audit_tests.xml"), *tests])
        if args.scope == "platform":
            run("opa_reexecution", ["scripts/benchmark_opa_audit.py", "--output", str(output / "opa")])
            run("native_log_import", ["scripts/check_opa_log_adapter.py", "--native-dir",
                str(output / "opa/native_logs"), "--output", str(output / "native_log_import")])
        record["status"] = "passed"
    except Exception:
        record["status"] = "failed"
        record["error"] = traceback.format_exc()
    finally:
        record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"status": record["status"], "scope": args.scope,
                      "completed_commands": len(record["commands"]), "manifest": str(output / "manifest.json"),
                      **({"error": record["error"]} if "error" in record else {})}, indent=2), flush=True)
    return int(record["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
