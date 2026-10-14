#!/usr/bin/env python3
"""Measure one integrated local audit/recovery transaction, including persistence.

All measured phases execute once, in dependency order. The source is fully
hashed and indexed before logical acquisitions; no physical-read savings or
online throughput claim follows. OS caches are shared across fresh processes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "configs/audit_workflow_cost_protocol.json"
sys.path.insert(0, str(ROOT / "src"))


def read_json(path):
    return json.loads(Path(path).read_text())


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def load_receipts(protocol):
    """Read, validate and group the actual retained store, without saved classes."""
    path = ROOT / protocol["receipt_source"]
    check(sha(path) == protocol["pinned_files"][protocol["receipt_source"]], "receipt source pin")
    with gzip.open(path, "rt") as stream:
        receipts = [json.loads(line)["receipt"] for line in stream]
    return group_receipts(receipts, protocol)


def group_receipts(receipts, protocol):
    from logistics_validation.audit_report import digest, receipt_query
    old_digest = digest(read_json(ROOT / protocol["old_catalog"]))
    classes, mapping, by_id = {}, [], {}
    for receipt in receipts:
        query = receipt_query(receipt)
        rid = receipt["receipt_id"]
        check(rid not in by_id, "duplicate retained ID")
        check(receipt["catalog_sha256"] == old_digest, "retained old catalog")
        check(receipt["domain_version"] == "cartesian:v1", "retained domain")
        check(receipt["snapshot_sha256"] == protocol["pinned_files"][protocol["snapshot_source"]], "retained snapshot")
        key = digest(query)
        if key not in classes:
            classes[key] = {"class_index": len(classes), "query": query, "receipt": receipt}
        index = classes[key]["class_index"]
        mapping.append((rid, index))
        by_id[rid] = receipt
    return {"receipts": receipts, "by_id": by_id,
            "classes": list(classes.values()), "mapping": mapping}


def construct_reports(prepared, protocol):
    """Create literal class witnesses/obligations and the full affected-ID set."""
    from logistics_validation.audit_report import catalog_from_content, digest, make_bundle
    from logistics_validation.focused_diagnostics import Problem
    target = catalog_from_content(read_json(ROOT / protocol["target_catalog"]))
    problem = Problem("procurement_workflow_strict", target)
    specs = [{"problem": problem, "query": row["query"], "receipt": row["receipt"],
              "request_id": "class:" + str(row["class_index"]),
              "old_identity": protocol["old_catalog"], "new_identity": protocol["target_catalog"]}
             for row in prepared["classes"]]
    bundle = make_bundle(specs, {"kind": "integrated local workflow",
                                "class_definition": "normalized retained observation plus old verdict",
                                "native_receipts": len(prepared["receipts"]),
                                "receipt_store_sha256": protocol["pinned_files"][protocol["receipt_source"]]})
    reports = {int(report["request_id"].split(":")[1]): report for report in bundle["reports"]}
    ids = [{"receipt_id": rid, "class_index": index, "obligation": "acquire profile"}
           for rid, index in prepared["mapping"] if reports[index]["status"] == "insufficient"]
    for row in ids:
        check(reports[row["class_index"]]["robust_additional_sets"] == [["profile"]], "strict obligation")
    counts = Counter(reports[index]["status"] for _, index in prepared["mapping"])
    return {"bundle": bundle, "ids": ids, "class_reports": reports,
            "status_counts": dict(counts), "target": target}


def recover_and_encode(prepared, source, generated):
    """Execute the unchanged checked repair API per record; gzip every full ledger."""
    from logistics_validation.receipt_repair import ReceiptRepair
    engine = ReceiptRepair("procurement_workflow_strict", generated["target"])
    buffer = io.BytesIO()
    counts = Counter()
    statuses = Counter()
    replacement_hash = hashlib.sha256()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as stream:
        for receipt, (rid, index) in zip(prepared["receipts"], prepared["mapping"]):
            check(receipt["receipt_id"] == rid, "retained order")
            row = engine.execute(receipt, source, strategy="adaptive_p_first")
            check(row["initial_status"] == generated["class_reports"][index]["status"], "class/recovery diagnosis mismatch")
            check(row["action"] == "replaced" and row["replacement_verified"], "workflow unresolved")
            row["class_index"] = index
            stream.write(json_bytes(row))
            replacement_hash.update(json_bytes(row["replacement_receipt"]))
            counts["replacements"] += 1
            counts["profile_reads"] += row["successful_reads"].count("profile")
            counts["first_times_reads"] += row["successful_reads"].count("first_times")
            statuses[row["initial_status"]] += 1
    check(dict(statuses) == generated["status_counts"], "workflow status totals")
    return buffer.getvalue(), dict(counts), replacement_hash.hexdigest()


def gzip_rows(rows):
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as stream:
        for row in rows:
            stream.write(json_bytes(row))
    return buffer.getvalue()


def persist_artifacts(folder, generated, ledger_bytes, counts, replacement_hash):
    """fsync each new file and its directory; do not claim hardware power-loss tests."""
    folder.mkdir(parents=True, exist_ok=False)
    payloads = {"bundle.json": json_bytes(generated["bundle"]),
                "affected_receipt_ids.jsonl.gz": gzip_rows(generated["ids"]),
                "repair_ledger.jsonl.gz": ledger_bytes}
    manifest = {"schema_version": 1,
                "bundle_sha256": generated["bundle"]["bundle_sha256"],
                "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                          for name, data in payloads.items()},
                "counts": counts, "status_counts": generated["status_counts"],
                "replacement_stream_sha256": replacement_hash}
    payloads["manifest.json"] = json_bytes(manifest)
    for name, data in payloads.items():
        with (folder / name).open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    for directory_path in (folder, folder.parent):
        directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    # The caller retains this independently of the serialized directory.
    return hashlib.sha256(payloads["manifest.json"]).hexdigest(), manifest


def independent_checker(protocol):
    """Existing stdlib-only predicate/completion checker, separate from executor."""
    path = ROOT / protocol["independent_checker"]
    spec = importlib.util.spec_from_file_location("workflow_independent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CATALOGS["workflow_strict"] = read_json(ROOT / protocol["target_catalog"])
    return module


def verify_persisted(folder, expected_manifest_sha256, prepared, source, protocol, independent=None):
    """Reopen outputs; independently reconstruct statuses, ID membership and repairs."""
    from logistics_validation.audit_report import digest, verify_bundle
    check(sha(folder / "manifest.json") == expected_manifest_sha256, "external manifest digest")
    manifest = read_json(folder / "manifest.json")
    check(set(manifest["files"]) == {"bundle.json", "affected_receipt_ids.jsonl.gz", "repair_ledger.jsonl.gz"}, "manifest payload set")
    for name, facts in manifest["files"].items():
        check(sha(folder / name) == facts["sha256"] and (folder / name).stat().st_size == facts["bytes"], "persisted payload integrity")
    bundle = read_json(folder / "bundle.json")
    verification = verify_bundle(bundle, expected_sha256=manifest["bundle_sha256"])
    check(verification["status"] == "passed", "portable verification")
    independent = independent or independent_checker(protocol)
    statuses, expected_ids, expected_mapping = Counter(), set(), dict(prepared["mapping"])
    query_statuses, independent_classes = {}, {}
    for receipt in prepared["receipts"]:
        rid = receipt["receipt_id"]
        query = independent.key(receipt)
        class_key = query + (receipt["verdict"],)
        if class_key not in independent_classes:
            independent_classes[class_key] = len(independent_classes)
        check(expected_mapping[rid] == independent_classes[class_key], "independent native class mapping")
        old, new, robust = independent.inspect_query(query, "workflow_strict")
        check(old == [receipt["verdict"]], "independent old admission")
        status = "insufficient" if len(new) == 2 else "safe" if new == old else "stale_verdict"
        statuses[status] += 1
        query_statuses[rid] = status
        if status == "insufficient":
            check(robust == [1], "independent profile obligation")
            expected_ids.add((rid, expected_mapping[rid]))
    with gzip.open(folder / "affected_receipt_ids.jsonl.gz", "rt") as stream:
        ids = [json.loads(line) for line in stream]
    check(len(ids) == len(expected_ids) and {(row["receipt_id"], row["class_index"]) for row in ids} == expected_ids,
          "independent exact affected ID set")
    check(all(row["obligation"] == "acquire profile" for row in ids), "affected obligation")
    check({report["request_id"] for report in bundle["reports"]} ==
          {"class:" + str(index) for index in independent_classes.values()}, "report class coverage")
    for report in bundle["reports"]:
        original = prepared["by_id"][report["receipt_id"]]
        check(report["request_id"] == "class:" + str(expected_mapping[report["receipt_id"]]), "report exemplar class")
        check(report["receipt"] == original, "report original binding")
        check(report["status"] == query_statuses[report["receipt_id"]], "independent report status")
        for witness in report["labeled_witnesses"]:
            raw = witness["raw"]
            check(raw["activities"] == original["activities"] and
                  all(raw[name] == value for name, value in original["observed"].items()), "independent witness literals")
            actual = independent.decision(tuple(dict.fromkeys(raw["activities"])), raw["profile"],
                                          independent.stamps(raw["first_times"]), "workflow_strict")
            check(actual == witness["new_verdict"], "independent witness label")
    seen, counts = set(), Counter()
    replacements = hashlib.sha256()
    target_digest = digest(read_json(ROOT / protocol["target_catalog"]))
    with gzip.open(folder / "repair_ledger.jsonl.gz", "rt") as stream:
        for line in stream:
            row = json.loads(line)
            rid = row["source_case_id"]
            check(rid in prepared["by_id"] and rid not in seen, "ledger ID coverage")
            seen.add(rid)
            original, full = prepared["by_id"][rid], source.rows[rid]
            check(row["original_receipt_sha256"] == digest(original), "ledger original digest")
            check(row["class_index"] == expected_mapping[rid], "ledger class mapping")
            check(row["initial_status"] == query_statuses[rid], "independent ledger status")
            check(full["activities"] == original["activities"] and
                  all(full[name] == value for name, value in original["observed"].items()), "source/retention consistency")
            wanted = ["profile"] if query_statuses[rid] == "insufficient" else []
            check(row["successful_reads"] == row["attempted_reads"] == wanted, "independent read obligations")
            check(row["capability_checks"] == [{"block": block, "state": "authorized"} for block in wanted], "declared capability")
            check(len(row["accepted_responses"]) == len(wanted), "response coverage")
            expanded = deepcopy(original)
            for block, response in zip(wanted, row["accepted_responses"]):
                check(set(response) == {"case_id", "snapshot_sha256", "request_receipt_sha256", "activities", "block", "complete", "value"}, "response schema")
                check(response["case_id"] == rid and response["snapshot_sha256"] == original["snapshot_sha256"] and
                      response["request_receipt_sha256"] == digest(expanded) and response["activities"] == original["activities"] and
                      response["block"] == block and response["complete"] is True and response["value"] == full[block], "response binding/source literal")
                expanded["observed"][block] = deepcopy(response["value"])
            replacement = row["replacement_receipt"]
            check(row["action"] == "replaced" and row["replacement_verified"] is True, "replacement disposition")
            check(row["acquisition_completed"] == bool(wanted), "replacement acquisition flag")
            check(replacement is not None and set(replacement) == set(original), "replacement schema")
            for field in ("receipt_id", "snapshot_sha256", "activities", "domain_version", "schema_version"):
                check(replacement[field] == original[field], "replacement binding")
            check(replacement["catalog_sha256"] == row["target_catalog_sha256"] == target_digest, "replacement target")
            check(replacement["observed"] == expanded["observed"], "replacement retained/acquired literals")
            labels = {item[2] for item in independent.completions(*independent.key(replacement), "workflow_strict")}
            check(labels == {replacement["verdict"]} and type(replacement["verdict"]) is bool, "independent replacement sufficiency")
            actual = independent.decision(tuple(dict.fromkeys(full["activities"])), full["profile"],
                                          independent.stamps(full["first_times"]), "workflow_strict")
            check(replacement["verdict"] == actual, "independent complete-source verdict")
            replacements.update(json_bytes(replacement))
            counts["replacements"] += 1
            counts["profile_reads"] += len(wanted)
            counts["first_times_reads"] += 0
    check(seen == set(prepared["by_id"]), "all retained records replaced")
    check(dict(statuses) == manifest["status_counts"] and dict(counts) == manifest["counts"], "persisted counts")
    check(replacements.hexdigest() == manifest["replacement_stream_sha256"], "replacement stream identity")
    return {"status": "passed", "reports": len(bundle["reports"]), "affected_ids": len(ids),
            "receipts": len(seen), "counts": dict(counts), "status_counts": dict(statuses),
            "independent_predicate_and_completion_check": True}


def execute_child(round_index, output, measured, limit=None):
    started = time.perf_counter_ns()
    protocol = read_json(PROTOCOL)
    affinity = sorted(os.sched_getaffinity(0))
    cpu = protocol["cpu_affinity"]
    check(cpu in affinity, "protocol CPU unavailable")
    os.sched_setaffinity(0, {cpu})
    from logistics_validation.receipt_repair import PublicSnapshot
    independent = independent_checker(protocol)
    setup_ms = (time.perf_counter_ns() - started) / 1e6
    stages = []

    def timed(name, operation):
        wall, cpu_start = time.perf_counter_ns(), time.process_time_ns()
        value = operation()
        stages.append({"stage": name, "wall_ms": (time.perf_counter_ns() - wall) / 1e6,
                       "cpu_ms": (time.process_time_ns() - cpu_start) / 1e6,
                       "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
        return value

    wall, cpu_start = time.perf_counter_ns(), time.process_time_ns()
    prepared = timed("retained_store_read_validate_group", lambda: load_receipts(protocol))
    if limit is not None:
        prepared = group_receipts([row["receipt"] for row in prepared["classes"]], protocol)
    source = timed("snapshot_hash_read_index", lambda: PublicSnapshot(
        ROOT / protocol["snapshot_source"], protocol["pinned_files"][protocol["snapshot_source"]],
        capabilities={"profile": "authorized", "first_times": "authorized"}))
    generated = timed("class_reports_and_exact_id_list", lambda: construct_reports(prepared, protocol))
    ledger, counts, replacement_hash = timed("checked_recovery_and_ledger_encoding", lambda: recover_and_encode(prepared, source, generated))
    manifest_hash, manifest = timed("artifact_serialization_and_fsync", lambda: persist_artifacts(output, generated, ledger, counts, replacement_hash))
    verified = timed("persisted_readback_semantic_verification", lambda: verify_persisted(
        output, manifest_hash, prepared, source, protocol, independent))
    total = {"wall_ms": (time.perf_counter_ns() - wall) / 1e6,
             "cpu_ms": (time.process_time_ns() - cpu_start) / 1e6,
             "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    if limit is None:
        check(verified["reports"] == protocol["expected"]["observation_classes"], "class denominator")
        check(verified["receipts"] == protocol["expected"]["receipts"] and
              verified["affected_ids"] == protocol["expected"]["affected_ids"] and
              verified["counts"] == protocol["expected"]["counts"] and
              verified["status_counts"] == protocol["expected"]["status_counts"], "full-cohort reconciliation")
    result = {"round": round_index, "measured": measured and limit is None,
              "mode": "functional_check" if limit is not None else "measured" if measured else "excluded_warmup",
              "import_protocol_setup_ms": setup_ms, "stages": stages, "integrated_total": total,
              "verification": verified, "manifest_sha256": manifest_hash,
              "payload_files": manifest["files"], "source_rows_indexed": len(source.rows),
              "environment": {"python": sys.version, "platform": platform.platform(), "pid": os.getpid(),
                              "affinity": sorted(os.sched_getaffinity(0)), "hash_seed": os.environ.get("PYTHONHASHSEED"),
                              "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                                                 if line.startswith("model name")), platform.processor()),
                              "filesystem_block_size": os.statvfs(output).f_bsize}}
    if limit is not None:
        for name in ("import_protocol_setup_ms", "stages", "integrated_total"):
            result.pop(name)
    return result


def describe(values):
    return {"median": statistics.median(values), "min": min(values), "max": max(values), "rounds": len(values)}


def run(output):
    protocol = read_json(PROTOCOL)
    check(not output.exists(), "preserve previous run; choose new output")
    pins = protocol["pinned_files"] | {str(Path(__file__).relative_to(ROOT)): sha(__file__),
                                      str(PROTOCOL.relative_to(ROOT)): sha(PROTOCOL),
                                      "tests/test_audit_workflow.py": sha(ROOT / "tests/test_audit_workflow.py")}
    check(all(sha(ROOT / name) == wanted for name, wanted in pins.items()), "frozen source/input mismatch")
    output.mkdir(parents=True)
    (output / "execution_freeze.json").write_bytes(json_bytes({"files": pins, "protocol": protocol,
                                                              "created_unix_ns": time.time_ns()}))
    rows = []
    for index in range(protocol["excluded_warmup_processes"] + protocol["measured_processes"]):
        measured = index >= protocol["excluded_warmup_processes"]
        round_index = index - protocol["excluded_warmup_processes"] if measured else -1
        label = f"round_{round_index + 1}" if measured else "warmup"
        wall = time.perf_counter_ns()
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child", str(round_index),
                                    "--output", str(output / label), "--measured" if measured else "--warmup"],
                                   cwd=ROOT, env={**os.environ, "PYTHONHASHSEED": "0"}, capture_output=True, text=True)
        if completed.returncode:
            (output / f"{label}_failure.txt").write_text(completed.stdout + completed.stderr)
            raise RuntimeError("Child failed; full evidence preserved in " + str(output))
        row = json.loads(completed.stdout)
        row["subprocess_wall_ms"] = (time.perf_counter_ns() - wall) / 1e6
        row["stderr"] = completed.stderr
        (output / f"{label}.json").write_bytes(json_bytes(row))
        rows.append(row)
        check(all(sha(ROOT / name) == wanted for name, wanted in pins.items()), "sources changed during run")
        print(json.dumps({"completed": label, "total_wall_ms": row["integrated_total"]["wall_ms"]}), flush=True)
    measured_rows = [row for row in rows if row["measured"]]
    summary = {name: {metric: describe([next(s[metric] for s in row["stages"] if s["stage"] == name)
                                      for row in measured_rows]) for metric in ("wall_ms", "cpu_ms")}
               for name in (s["stage"] for s in measured_rows[0]["stages"])}
    summary["integrated_total"] = {metric: describe([row["integrated_total"][metric] for row in measured_rows])
                                   for metric in ("wall_ms", "cpu_ms", "process_peak_rss_kib")}
    manifests = {row["manifest_sha256"] for row in rows}
    check(len(manifests) == 1, "process outputs differ")
    report = {"status": "passed", "protocol_sha256": sha(PROTOCOL), "script_sha256": sha(__file__),
              "summary": summary, "verification": measured_rows[0]["verification"],
              "all_processes_same_manifest_sha256": next(iter(manifests)),
              "payload_files": measured_rows[0]["payload_files"],
              "source_rows_indexed": measured_rows[0]["source_rows_indexed"],
              "environment": measured_rows[0]["environment"], "scope": protocol["measurement_boundaries"],
              "subprocess_wall_ms": describe([row["subprocess_wall_ms"] for row in measured_rows])}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["Phase | Median wall s | Wall range s | Median CPU s", "--- | ---: | ---: | ---:"]
    for name, facts in summary.items():
        w, c = facts["wall_ms"], facts["cpu_ms"]
        lines.append(f"{name} | {w['median']/1000:.3f} | {w['min']/1000:.3f}–{w['max']/1000:.3f} | {c['median']/1000:.3f}")
    lines += ["", "One excluded warmup and five fresh measured processes; one logical CPU; shared OS caches.",
              "Single integrated all-50,931 transaction; stage medians need not sum to the median total.",
              "Complete 251,734-row snapshot indexing and retained-store reading are included; acquisitions use that local memory index.",
              "Every output file and directory is fsynced. Immediate readback can hit OS cache; no power-loss or cold-I/O claim.",
              "Readback uses the existing independent declarative checker plus portable witness verification. No new source authentication or operational throughput claim."]
    (output / "table_and_scope.txt").write_text("\n".join(lines) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="functional all-class check, not timing evidence")
    parser.add_argument("--child", type=int)
    parser.add_argument("--measured", action="store_true")
    parser.add_argument("--warmup", action="store_true")
    args = parser.parse_args()
    if args.check:
        result = execute_child(0, args.output.resolve(), False, limit=20)
    elif args.child is not None:
        result = execute_child(args.child, args.output.resolve(), args.measured)
    else:
        result = run(args.output.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
