"""Reproduce the frozen equal-output diagnostic-service benchmark.

prepare constructs transparent workload inputs; run requires a fresh directory,
records all child jobs, and never changes existing scientific evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
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
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from compare_catalogs import read_catalog
from logistics_validation.catalog_audit import BASELINE, reference_verdict
from logistics_validation.focused_diagnostics import (
    FiniteDiagnostics, Problem, RawVerifier, SMTDiagnostics, freeze, projection,
)
from logistics_validation.standards_core import CompiledModel
from logistics_validation.standards_epcis import build_models
from revalidate_receipt import catalog_digest, receipt_key

PROTOCOL = ROOT / "configs/focused_diagnostic_protocol.json"


def sha(path):
    return hashlib.file_digest(Path(path).open("rb"), "sha256").hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def timer():
    return time.process_time_ns(), time.perf_counter_ns()


def elapsed(start):
    now = timer()
    return {"cpu_ns": now[0] - start[0], "wall_ns": now[1] - start[1]}


def fingerprints():
    names = ["configs/focused_diagnostic_protocol.json", "requirements-focused.txt",
             "src/logistics_validation/focused_diagnostics.py",
             "scripts/benchmark_focused_diagnostics.py", "tests/test_focused_diagnostics.py",
             "src/logistics_validation/catalog_audit.py", "src/logistics_validation/standards_core.py",
             "src/logistics_validation/standards_epcis.py", "scripts/revalidate_receipt.py",
             "scripts/compare_catalogs.py"]
    config = json.loads(PROTOCOL.read_text())
    names += list(config["procurement_targets"].values()) + [config["receipt_source"]]
    return {name: sha(ROOT / name) for name in names}


def prepare(output):
    output.mkdir(parents=True, exist_ok=False)
    config = json.loads(PROTOCOL.read_text())
    assert sha(ROOT / config["receipt_source"]) == config["receipt_source_sha256"]
    inputs, indices, queries, requests, exemplars = [], {}, [], [], []
    expected_old = catalog_digest(BASELINE)
    with gzip.open(ROOT / config["receipt_source"], "rt") as stream:
        for line in stream:
            receipt = json.loads(line)["receipt"]
            mask, (order, profile, ranks) = receipt_key(receipt)
            assert receipt["catalog_sha256"] == expected_old
            assert receipt["domain_version"] == "cartesian:v1"
            assert receipt["snapshot_sha256"] == "3fdfe926a29d35c87a2652447df420bb5c726ab2c996f6317c830d75cc4a1b3b"
            observed = projection((profile, ranks), mask)
            key = order, mask, observed, receipt["verdict"]
            if key not in indices:
                indices[key] = len(queries)
                queries.append(dict(base=order, mask=mask, observed=observed, old_verdict=receipt["verdict"]))
                exemplars.append(receipt)
            requests.append([receipt["receipt_id"], indices[key]])
    assert len(queries) == 20 and len(requests) == 50931
    for target, path in config["procurement_targets"].items():
        name = "procurement_" + target
        value = dict(name=name, target=path, queries=queries, weighted_requests=requests,
                     weights_are_empirical=True, original_source=config["receipt_source"], exemplars=exemplars)
        write(output / (name + ".json"), value)
        inputs.append(dict(name=name, unique=len(queries), weighted=len(requests)))
    for spec in build_models():
        model = CompiledModel(spec)
        indices, queries = {}, []
        for index, mask in model.observation_classes():
            observed = projection(model.states[index], mask)
            key = mask, observed
            indices[key] = len(queries)
            queries.append(dict(base=[], mask=mask, observed=observed, old_verdict=model.old_labels[index]))
        requests = []
        for index, state in enumerate(model.states):
            retained, _ = model.recover(index, version="old")
            requests.append([str(index), indices[retained, projection(state, retained)]])
        name = spec["name"]
        value = dict(name=name, target=None, queries=queries, weighted_requests=requests,
                     weights_are_empirical=False, original_source="Authored complete finite selected-clause domain")
        write(output / (name + ".json"), value)
        inputs.append(dict(name=name, unique=len(queries), weighted=len(requests)))
    write(output / "manifest.json", dict(created_utc=datetime.now(timezone.utc).isoformat(),
          protocol_sha256=sha(PROTOCOL), source_hashes=fingerprints(), inputs=inputs,
          input_hashes={i["name"]: sha(output / (i["name"] + ".json")) for i in inputs}))
    print(json.dumps(inputs), flush=True)


def child(args):
    if hasattr(os, "sched_getaffinity"):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    data = json.loads(Path(args.input).read_text())
    name = data["name"]
    problem = Problem(name, read_catalog(ROOT / data["target"]) if data["target"] else None)
    requests = ([(str(i), i) for i in range(len(data["queries"]))] if args.workload == "unique"
                else data["weighted_requests"])
    raw_receipts = None
    if problem.procurement:
        if args.workload == "unique":
            raw_receipts = data["exemplars"]
        else:
            with gzip.open(ROOT / data["original_source"], "rt") as stream:
                raw_receipts = [json.loads(line)["receipt"] for line in stream]
            assert [r["receipt_id"] for r in raw_receipts] == [r[0] for r in requests]
    baseline_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = timer()
    setup_start = timer()
    dependency_import = {"cpu_ns": 0, "wall_ns": 0}
    if args.method == "incremental_smt":
        import_start = timer()
        __import__("z3")
        dependency_import = elapsed(import_start)
    engine = FiniteDiagnostics(problem) if args.method == "finite_fibers" else SMTDiagnostics(problem)
    setup = elapsed(setup_start)
    rss_setup = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    cache, results = {}, {}
    serialization = Counter()
    statuses, report_bytes = Counter(), 0
    digest = hashlib.sha256()
    first = None
    first_rss = None
    for occurrence, (request_id, query_id) in enumerate(requests):
        first_start = timer() if first is None else None
        if args.workload == "weighted" and query_id in cache:
            result = cache[query_id]
        else:
            result = engine.diagnose(data["queries"][query_id])
            if args.workload == "weighted":
                cache[query_id] = result
            results[query_id] = result
        # Per-request literal lifting cannot be cached by semantic class: two
        # source receipts may share ranks yet retain different clock strings.
        report = problem.report(data["queries"][query_id], result,
                                raw_receipts[occurrence] if raw_receipts is not None else None)
        serialization_start = timer()
        blob = encode(dict(request_id=request_id, **report))
        delta = elapsed(serialization_start)
        serialization.update(delta)
        report_bytes += len(blob)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
        statuses[result["status"]] += 1
        if first is None:
            first = elapsed(first_start)
            first_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    batch = elapsed(start)
    rss_batch = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    verification_start = timer()
    oracle = RawVerifier(problem)
    for query_id, result in results.items():
        oracle.verify(data["queries"][query_id], result)
    lifted_witness_checks = 0
    if raw_receipts is not None:
        verified_digest = hashlib.sha256()
        for occurrence, (request_id, query_id) in enumerate(requests):
            receipt = raw_receipts[occurrence]
            report = problem.report(data["queries"][query_id], results[query_id], receipt)
            for label, witness in zip((False, True), report["witnesses"] or []):
                assert witness["activities"] == receipt["activities"]
                assert all(witness[field] == value for field, value in receipt["observed"].items())
                assert reference_verdict(witness, problem.catalog) == label
                lifted_witness_checks += 3
            blob = encode(dict(request_id=request_id, **report))
            verified_digest.update(len(blob).to_bytes(8, "big")); verified_digest.update(blob)
        assert verified_digest.hexdigest() == digest.hexdigest()
    verification = elapsed(verification_start)
    report = dict(name=name, method=args.method, workload=args.workload, setup=setup,
        dependency_import=dependency_import,
        core_setup={k: setup[k] - dependency_import[k] for k in setup},
        core_batch={k: batch[k] - dependency_import[k] for k in batch},
        first_report=first, setup_plus_first={k: setup[k] + first[k] for k in first},
        batch=batch, serialization=dict(serialization), independent_raw_validation=verification,
        checks=oracle.checks + lifted_witness_checks, lifted_witness_checks=lifted_witness_checks,
        failures=0, requests=len(requests),
        diagnosed_classes=len(results), status_counts=dict(statuses), output_bytes=report_bytes,
        output_sha256=digest.hexdigest(), process_peak_rss_kib=dict(before_setup=baseline_rss,
           after_setup=rss_setup, after_first_report=first_rss, after_batch=rss_batch),
        python=platform.python_version(), z3_solver=importlib.metadata.version("z3-solver"),
        affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None)
    # Include all unique results once per job. The parent writes them after the
    # child's method and independent verification timers have finished.
    write(args.output, dict(timing=report, diagnostics=results))


def run(output, inputs):
    manifest = json.loads((inputs / "manifest.json").read_text())
    assert manifest["source_hashes"] == fingerprints(), "Source changed after prepare; preserve and reprepare"
    for name, wanted in manifest["input_hashes"].items():
        assert sha(inputs / (name + ".json")) == wanted
    assert importlib.metadata.version("z3-solver") == "4.15.4.0"
    output.mkdir(parents=True, exist_ok=False)
    config = json.loads(PROTOCOL.read_text())
    write(output / "run_manifest.json", dict(protocol=config, source_hashes=fingerprints(),
          input_manifest=manifest, created_utc=datetime.now(timezone.utc).isoformat(),
          environment=dict(platform=platform.platform(), python=platform.python_version(),
          cpu=platform.processor(), initial_affinity=sorted(os.sched_getaffinity(0)))))
    cells = [(i["name"], workload) for i in manifest["inputs"] for workload in ("unique", "weighted")]
    rows = []
    for round_no in range(-1, config["timing"]["measured_rounds"]):
        shifted = cells[(round_no + 1) % len(cells):] + cells[:(round_no + 1) % len(cells)]
        methods = config["methods"] if round_no % 2 == 0 else list(reversed(config["methods"]))
        position = 0
        for name, workload in shifted:
            for method in methods:
                path = output / f"r{round_no}_{name}_{workload}_{method}.json"
                subprocess.run([sys.executable, __file__, "child", "--input", str(inputs / (name + ".json")),
                    "--method", method, "--workload", workload, "--output", str(path)], check=True, cwd=ROOT)
                data = json.loads(path.read_text())
                row = dict(data["timing"], round=round_no, phase="warmup" if round_no < 0 else "measured", execution_position=position)
                rows.append(row)
                position += 1
                print(json.dumps({"round": round_no, "name": name, "workload": workload,
                      "method": method, "cpu_ms": row["batch"]["cpu_ns"] / 1e6,
                      "checks": row["checks"]}), flush=True)
    write(output / "timings.json", rows)
    cells_summary = []
    for name, workload in cells:
        finite = [r for r in rows if r["name"] == name and r["workload"] == workload and r["method"] == "finite_fibers" and r["round"] >= 0]
        smt = [r for r in rows if r["name"] == name and r["workload"] == workload and r["method"] == "incremental_smt" and r["round"] >= 0]
        assert all(a["status_counts"] == b["status_counts"] for a, b in zip(finite, smt))
        item = dict(name=name, workload=workload, requests=finite[0]["requests"],
                    diagnosed_classes=finite[0]["diagnosed_classes"], status_counts=finite[0]["status_counts"], methods={})
        for method, chosen in (("finite_fibers", finite), ("incremental_smt", smt)):
            values = {}
            for field in ("setup", "dependency_import", "core_setup", "first_report", "setup_plus_first", "batch", "core_batch", "serialization", "independent_raw_validation"):
                values[field] = {clock: statistics.median(r[field][clock] for r in chosen) for clock in ("cpu_ns", "wall_ns")}
            values["process_peak_rss_kib"] = statistics.median(r["process_peak_rss_kib"]["after_batch"] for r in chosen)
            values["output_bytes"] = [r["output_bytes"] for r in chosen]
            item["methods"][method] = values
        item["paired_finite_minus_smt_batch_ns"] = {clock: [a["batch"][clock] - b["batch"][clock] for a, b in zip(finite, smt)] for clock in ("cpu_ns", "wall_ns")}
        # Semantic equality includes complete robust sets; concrete witness values
        # need not be identical, but each has been independently checked.
        for round_no in range(-1, 5):
            reports = [json.loads((output / f"r{round_no}_{name}_{workload}_{m}.json").read_text())["diagnostics"] for m in config["methods"]]
            assert reports[0].keys() == reports[1].keys()
            for key in reports[0]:
                a, b = reports[0][key], reports[1][key]
                assert a["status"] == b["status"] and a["robust_masks"] == b["robust_masks"]
        cells_summary.append(item)
    assert manifest["source_hashes"] == fingerprints()
    write(output / "summary.json", dict(status="passed", cells=cells_summary, jobs=len(rows),
          measured_jobs=sum(r["round"] >= 0 for r in rows), independent_checks=sum(r["checks"] for r in rows),
          failures=0, output_semantics="Equal statuses and complete minimal robust sets; opposed witnesses validated independently, not required byte-identical",
          source_hashes=fingerprints(), protocol_sha256=sha(PROTOCOL)))
    print("COMPLETE " + str(output / "summary.json"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("run"); p.add_argument("--output", type=Path, required=True); p.add_argument("--inputs", type=Path, required=True)
    p = sub.add_parser("child"); p.add_argument("--input"); p.add_argument("--output"); p.add_argument("--method"); p.add_argument("--workload")
    args = parser.parse_args()
    if args.command == "prepare": prepare(args.output)
    elif args.command == "run": run(args.output, args.inputs)
    else: child(args)


if __name__ == "__main__":
    main()
