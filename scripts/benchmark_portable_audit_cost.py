"""Bounded costs of the existing portable report APIs, without saved diagnoses.

Run ``--check`` for correctness only, or ``--output PATH`` for one excluded
warmup process and five fresh measured processes. Validation timings overlap;
they are alternative scopes, not additive phases of a deployment estimate.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "configs/portable_audit_cost_protocol.json"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))


def read_json(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reconstruct_inputs(reference):
    """Extract input fields only. No status, robust set, or witness is reused."""
    from logistics_validation.audit_report import catalog_from_content
    from logistics_validation.focused_diagnostics import Problem
    specs = []
    for report in reference["reports"]:
        artifacts = {side: reference["artifacts"][key]
                     for side, key in report["bindings"].items()}
        procurement = report["problem"].startswith("procurement_")
        target = (catalog_from_content(artifacts["new_rule"]["content"])
                  if procurement else None)
        spec = {"problem": Problem(report["problem"], target),
                "query": report["query"], "request_id": report["request_id"],
                "old_domain": artifacts["old_domain"]["identity"],
                "new_domain": artifacts["new_domain"]["identity"],
                "old_identity": artifacts["old_rule"]["identity"],
                "new_identity": artifacts["new_rule"]["identity"],
                "envelope": report["adapter_envelope"]}
        if procurement:
            spec["receipt"] = report["receipt"]
        else:
            spec.update(receipt_id=report["receipt_id"],
                        snapshot_sha256=report["snapshot_sha256"])
        specs.append(spec)
    return specs


def construct_exact_ids(bundle, prepared):
    """Filter all native mappings using freshly generated strict diagnoses."""
    reports = {r["receipt_id"]: r for r in bundle["reports"]
               if r["request_id"].startswith("strict:")}
    affected = {index for index, receipt in enumerate(prepared["exemplars"])
                if reports[receipt["receipt_id"]]["status"] == "insufficient"}
    return [{"receipt_id": rid, "class_index": index,
             "obligation": "acquire profile"}
            for rid, index in prepared["weighted_requests"] if index in affected]


def serialize_payloads(bundle, ids):
    """Use the exporter's JSON format and deterministic gzip in memory."""
    from logistics_validation.audit_report import canonical
    bundle_bytes = (json.dumps(bundle, indent=2, ensure_ascii=False) + "\n").encode()
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as stream:
        for row in ids:
            stream.write(canonical(row) + b"\n")
    return bundle_bytes, buffer.getvalue()


def validate_outputs(protocol, bundle, ids, payloads):
    from logistics_validation.audit_report import digest, require
    require(bundle["bundle_sha256"] == protocol["expected_bundle_sha256"],
            "generated report semantics/bindings differ")
    require(len(bundle["reports"]) == 25, "report denominator")
    require(len(ids) == len({r["receipt_id"] for r in ids}) == 33489,
            "exact ID denominator/uniqueness")
    require(digest(ids) == protocol["expected_id_content_sha256"], "exact ID content")
    for body, expected in zip(payloads, protocol["expected_serialized_sha256"]):
        require(hashlib.sha256(body).hexdigest() == expected, "serialized payload differs")


def cpu_model():
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def execute_child(round_index, measured, check_only=False):
    child_start = time.perf_counter_ns()
    protocol = read_json(PROTOCOL)
    allowed = sorted(os.sched_getaffinity(0))
    cpu = protocol["cpu_affinity"]
    if cpu not in allowed:
        raise ValueError(f"protocol CPU {cpu} not available: {allowed}")
    os.sched_setaffinity(0, {cpu})
    before_load = time.perf_counter_ns()
    from export_audit_report import verify_directory
    from logistics_validation.audit_report import make_bundle, verify_bundle
    import_load_ms = (time.perf_counter_ns() - before_load) / 1e6
    before_load = time.perf_counter_ns()
    folder = ROOT / protocol["reference_directory"]
    reference = read_json(folder / "bundle.json")
    prepared = read_json(ROOT / protocol["mapping_source"])
    specs = reconstruct_inputs(reference)
    input_setup_ms = (time.perf_counter_ns() - before_load) / 1e6
    stages = []

    def timed(name, function):
        started = time.perf_counter_ns()
        value = function()
        stages.append({"stage": name, "elapsed_ms": (time.perf_counter_ns() - started) / 1e6})
        return value

    bundle = timed("report_construction", lambda: make_bundle(specs, reference["provenance"]))
    ids = timed("exact_id_construction", lambda: construct_exact_ids(bundle, prepared))
    payloads = timed("payload_serialization", lambda: serialize_payloads(bundle, ids))
    validate_outputs(protocol, bundle, ids, payloads)
    operations = [
        ("detached_bundle_verification", lambda: verify_bundle(
            bundle, expected_sha256=protocol["expected_bundle_sha256"])),
        ("directory_verification", lambda: verify_directory(
            folder, verify_sources=False, expected_sha256=protocol["expected_bundle_sha256"])),
        ("directory_with_original_source_reconciliation", lambda: verify_directory(
            folder, verify_sources=True, expected_sha256=protocol["expected_bundle_sha256"]))]
    # Construction has real dependencies. Rotate only the three independent
    # verification scopes; no claim of a fully balanced experimental design.
    offset = round_index % len(operations)
    operations = operations[offset:] + operations[:offset]
    if check_only:
        operations = [operations[next(i for i, row in enumerate(operations)
                                      if row[0] == "detached_bundle_verification")]]
    verification = {}
    for name, operation in operations:
        value = timed(name, operation)
        if value["status"] != "passed" or value["reports"] != 25:
            raise ValueError("verification did not pass")
        verification[name] = value
    result = {
        "round": round_index, "measured": measured and not check_only,
        "mode": "correctness_check" if check_only else "measured" if measured else "warmup",
        "import_load_ms": import_load_ms, "input_setup_ms": input_setup_ms,
        "child_body_ms": (time.perf_counter_ns() - child_start) / 1e6,
        "stages": stages, "verification": verification,
        "payload_bytes": {"bundle_json": len(payloads[0]), "affected_ids_gzip": len(payloads[1])},
        "generated_bundle_sha256": bundle["bundle_sha256"],
        "generated_id_content_sha256": protocol["expected_id_content_sha256"],
        "strict_class_status_counts": dict(Counter(
            r["status"] for r in bundle["reports"] if r["request_id"].startswith("strict:"))),
        "environment": {"python": sys.version, "executable": sys.executable,
                        "platform": platform.platform(), "cpu_model": cpu_model(),
                        "affinity": sorted(os.sched_getaffinity(0)), "pid": os.getpid(),
                        "perf_counter": vars(time.get_clock_info("perf_counter")),
                        "hash_seed": os.environ.get("PYTHONHASHSEED")},
    }
    if check_only:
        # Correctness checks are not benchmark measurements.
        for key in ("import_load_ms", "input_setup_ms", "child_body_ms", "stages"):
            result.pop(key)
    return result


def describe(values):
    return {"median_ms": statistics.median(values), "min_ms": min(values),
            "max_ms": max(values), "rounds": len(values)}


def run(output):
    protocol = read_json(PROTOCOL)
    if output.exists():
        raise ValueError("output already exists")
    for path, expected in protocol["pinned_files"].items():
        if sha256(ROOT / path) != expected:
            raise ValueError("protocol source changed: " + path)
    output.mkdir(parents=True)
    rows = []
    for index in range(protocol["excluded_warmup_processes"] + protocol["measured_processes"]):
        measured = index >= protocol["excluded_warmup_processes"]
        round_index = index - protocol["excluded_warmup_processes"] if measured else -1
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--child", str(round_index),
             "--measured" if measured else "--warmup"],
            cwd=ROOT, env={**os.environ, "PYTHONHASHSEED": "0"},
            text=True, capture_output=True, check=True)
        subprocess_ms = (time.perf_counter_ns() - started) / 1e6
        row = json.loads(completed.stdout)
        row["subprocess_wall_ms"] = subprocess_ms
        row["stderr"] = completed.stderr
        label = f"round_{round_index + 1}" if measured else "warmup"
        (output / f"{label}.json").write_text(json.dumps(row, indent=2) + "\n")
        rows.append(row)
    measured_rows = [r for r in rows if r["measured"]]
    names = [s["stage"] for s in measured_rows[0]["stages"]]
    summary = {name: describe([next(s["elapsed_ms"] for s in r["stages"] if s["stage"] == name)
                               for r in measured_rows]) for name in names}
    for name in ("import_load_ms", "input_setup_ms", "child_body_ms", "subprocess_wall_ms"):
        summary[name] = describe([r[name] for r in measured_rows])
    report = {"protocol": "configs/portable_audit_cost_protocol.json",
              "protocol_sha256": sha256(PROTOCOL), "script_sha256": sha256(__file__),
              "summary": summary, "payload_bytes": measured_rows[0]["payload_bytes"],
              "environment": measured_rows[0]["environment"],
              "verification": "All six processes reproduced pinned report semantics, regenerated JSON/ID bytes, and passed every verification scope.",
              "nonadditive_scopes": protocol["nonadditive_scopes"],
              "source_sha256": protocol["pinned_files"],
              "measurement_boundaries": protocol["measurement_boundaries"]}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    table = ["Stage | Median ms | Min–max ms", "--- | ---: | ---:"]
    for name, stats in summary.items():
        table.append(f"{name} | {stats['median_ms']:.3f} | {stats['min_ms']:.3f}–{stats['max_ms']:.3f}")
    table.extend(["", "Five fresh measured processes after one excluded warmup process; one logical CPU; shared OS caches.",
                  "The three verification scopes overlap and must not be added. Construction timings are not the monolithic exporter runtime.",
                  "No durable writes, remote I/O, user interaction, or authentication cost is measured. No cross-host speedup is inferred."])
    (output / "table_and_scope.txt").write_text("\n".join(table) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=int)
    parser.add_argument("--measured", action="store_true")
    parser.add_argument("--warmup", action="store_true")
    args = parser.parse_args()
    if args.check:
        result = execute_child(0, False, check_only=True)
    elif args.child is not None:
        result = execute_child(args.child, args.measured)
    elif args.output:
        result = run(args.output.resolve())
    else:
        parser.error("choose --check or --output")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
