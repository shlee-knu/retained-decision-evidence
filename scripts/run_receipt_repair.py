#!/usr/bin/env python3
"""Execute the predeclared capability-constrained public receipt replay.

Full source hashing/indexing is setup. Counted calls are logical block accesses,
not file I/O savings, network requests, production authorization, or latency.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from logistics_validation.audit_report import SOURCE_FILES, digest, file_digest, receipt_query
from logistics_validation.catalog_audit import generated_catalogs, reference_verdict
from logistics_validation.opa_log_adapter import import_decision_log
from logistics_validation.receipt_repair import PublicSnapshot, ReceiptRepair

PROTOCOL = "configs/repair_execution_protocol.json"
PROTOCOL_SHA256 = "d2cb49ff40bf3454eac1c227be949bc0f220e65cfbc3266a3330bb5f94e0520a"
SOURCE = "results/v03/bpi_compact.jsonl.gz"
RECEIPTS = "results/second/receipt_revalidation/native_receipts.jsonl.gz"
SELECTION = "results/perspective_revision/coverage/native_challenge_classes.json"
EXPECTED = "results/repair_revision_20261010/methods/independent_expected_cases.json"


def load(name):
    return json.loads((ROOT / name).read_text())


def write(path, content):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(content, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def jsonlines(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        yield from (json.loads(line) for line in stream)


def save_rows(path, rows):
    with path.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def aggregate(rows):
    return {"episodes": len(rows), "actions": dict(Counter(row["action"] for row in rows)),
            "initial_statuses": dict(Counter(row["initial_status"] for row in rows)),
            "reasons": dict(Counter(row["reason"] for row in rows)),
            "capability_checks": dict(Counter(check["block"] for row in rows for check in row["capability_checks"])),
            "attempted_reads": dict(Counter(block for row in rows for block in row["attempted_reads"])),
            "successful_reads": dict(Counter(block for row in rows for block in row["successful_reads"])),
            "verified_replacements": sum(row["replacement_verified"] for row in rows),
            "acquisition_completed": sum(row["acquisition_completed"] for row in rows),
            "raw_verdict_checks": sum(row.get("complete_source_verdict_checked", False) for row in rows)}


def execute_one(engine, receipt, source, strategy):
    row = engine.execute(receipt, source, strategy=strategy)
    replacement = row["replacement_receipt"]
    if replacement is not None:
        full = source.rows[receipt["receipt_id"]]
        raw = {key: full[key] for key in ("activities", "profile", "first_times")}
        assert reference_verdict(raw, engine.problem.catalog) == replacement["verdict"]
        assert all(raw[name] == value for name, value in replacement["observed"].items())
        row["complete_source_verdict_checked"] = True
    else:
        row["complete_source_verdict_checked"] = False
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/repair_revision_20261010/execution/run")
    args = parser.parse_args()
    assert not args.output.exists(), "Preserve previous evidence; choose a new output directory"
    assert file_digest(ROOT / PROTOCOL) == PROTOCOL_SHA256
    protocol = load(PROTOCOL)
    inputs = protocol["inputs"] | protocol["existing_context_code"]
    for name, expected in inputs.items():
        assert file_digest(ROOT / name) == expected, name
    new_sources = ["src/logistics_validation/receipt_repair.py", "scripts/run_receipt_repair.py", "tests/test_receipt_repair.py"]
    method_sources = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "results/repair_revision_20261010/methods").glob("*.py"))
    pinned = {name: file_digest(ROOT / name) for name in sorted(set(SOURCE_FILES) | set(new_sources + method_sources + [EXPECTED, PROTOCOL]))}
    args.output.mkdir(parents=True)
    write(args.output / "execution_freeze.json", {
        "prepared_utc": datetime.now(timezone.utc).isoformat(), "protocol_sha256": PROTOCOL_SHA256,
        "source_and_independent_check_hashes": pinned, "input_hashes": inputs,
        "known_reconciliation_targets": protocol["primary"]["known_reconciliation_targets"],
        "scope": "Source/test/checker hash freeze before replay; outcome counts already known from previous work."
    })
    catalogs = {name: catalog for name, catalog, _ in generated_catalogs()}
    source = PublicSnapshot(ROOT / SOURCE, inputs[SOURCE])
    receipts = [row["receipt"] for row in jsonlines(ROOT / RECEIPTS)]
    assert len(receipts) == len({row["receipt_id"] for row in receipts}) == 50931
    selected = []
    for item in load(SELECTION)["targets"]:
        keys = {digest(row["query"]) for row in item["affected_classes"]}
        for receipt in receipts:
            if digest(receipt_query(receipt)) in keys:
                selected.append((item["target"], receipt))
    expected_cases = load(EXPECTED)
    assert {(target, receipt["receipt_id"]) for target, receipt in selected} == {
        (row["target"], row["case_id"]) for row in expected_cases}
    assert len(selected) == 114
    write(args.output / "selection.json", {
        "case_target_pairs": len(selected), "distinct_cases": len({receipt["receipt_id"] for _, receipt in selected}),
        "targets": dict(Counter(target for target, _ in selected)),
        "independent_expected_sha256": file_digest(ROOT / EXPECTED),
        "selected_pairs": [{"target": target, "case_id": receipt["receipt_id"]} for target, receipt in selected],
        "exact_pair_set_matches_independent_selection": True,
    })
    engines = {target: ReceiptRepair("procurement_" + target, catalogs[target]) for target, _ in selected}
    primary = []
    all_rows = []
    for scenario in protocol["primary"]["scenarios"]:
        source.capabilities = {"profile": "authorized", "first_times": "authorized" if scenario == "all_authorized" else "source_unavailable"}
        for strategy in protocol["primary"]["strategies"]:
            rows = []
            for target, receipt in selected:
                row = execute_one(engines[target], receipt, source, strategy)
                row.update(scenario=scenario, target=target)
                rows.append(row)
            summary = {"scenario": scenario, "strategy": strategy, **aggregate(rows)}
            primary.append(summary)
            all_rows.extend(rows)
            print(json.dumps(summary), flush=True)
    save_rows(args.output / "primary_ledger.jsonl.gz", all_rows)
    expected_primary = {
        ("all_authorized", "adaptive_p_first"): (114, {"profile": 114, "first_times": 85}),
        ("all_authorized", "robust_all_first"): (114, {"profile": 114, "first_times": 114}),
        ("profile_only_times_unavailable", "adaptive_p_first"): (29, {"profile": 114}),
        ("profile_only_times_unavailable", "robust_all_first"): (0, {}),
    }
    for row in primary:
        replacements, reads = expected_primary[row["scenario"], row["strategy"]]
        assert row["verified_replacements"] == replacements and row["successful_reads"] == reads
        assert row["attempted_reads"] == reads
    source.capabilities = {"profile": "authorized", "first_times": "authorized"}
    strict_engine = ReceiptRepair("procurement_strict_consignment", catalogs["strict_consignment"])
    strict_rows = []
    for index, receipt in enumerate(receipts):
        strict_rows.append(execute_one(strict_engine, receipt, source, "adaptive_p_first"))
        if (index + 1) % 10000 == 0:
            print(json.dumps({"strict_receipts_processed": index + 1}), flush=True)
    strict = aggregate(strict_rows)
    assert strict["initial_statuses"] == {"safe": 17442, "insufficient": 33489}
    assert strict["verified_replacements"] == 50931 and strict["successful_reads"] == {"profile": 33489}
    save_rows(args.output / "strict_regression_ledger.jsonl.gz", strict_rows)
    native_rows = []
    for name in ("native_strict_profile_masked", "native_full_retention", "insufficient_old_both_masked"):
        artifact = load("results/platform_revision_20261010/log_adapter/" + name + ".input.json")
        imported = import_decision_log(artifact["event"], artifact["binding"])
        row = execute_one(strict_engine, imported["receipt"], source, "adaptive_p_first")
        row.update(control_name=name, decision_id=imported["decision_id"])
        native_rows.append(row)
    assert [row["reason"] for row in native_rows] == ["acquired_sufficient_evidence", "retained_sufficient_evidence", "old_admission_or_domain"]
    save_rows(args.output / "native_opa_ledger.jsonl.gz", native_rows)
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_receipt_repair.py"], cwd=ROOT, capture_output=True, text=True)
    write(args.output / "tests.json", {"returncode": tests.returncode, "stdout": tests.stdout, "stderr": tests.stderr})
    assert tests.returncode == 0
    assert pinned == {name: file_digest(ROOT / name) for name in pinned}, "Code changed during replay"
    result = {"schema_version": 1, "status": "passed", "primary": primary,
              "strict_regression": strict, "native_opa_controls": aggregate(native_rows),
              "source_setup": {"snapshot_path": SOURCE, "snapshot_sha256": inputs[SOURCE],
                               "full_source_rows_indexed": len(source.rows), "complete_file_hashed_and_scanned": True},
              "denominators": protocol["primary"]["denominators"],
              "limits": [protocol["novelty_boundary"], protocol["measurement"]["excluded"], protocol["contract"]["trust"],
                         "Raw reference verdict comparison uses the existing raw oracle also used by the receipt checker; a separately implemented independent primary check is reported separately.",
                         "Strict cohort is a regression and native OPA controls are the same three saved local logs, not new independent cases."],
              "files": {p.name: file_digest(p) for p in sorted(args.output.iterdir()) if p.is_file()}}
    write(args.output / "summary.json", result)
    print(json.dumps({"status": "passed", "strict_regression": strict, "output": str(args.output)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
