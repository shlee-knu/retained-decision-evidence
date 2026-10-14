"""Frozen three-engine follow-up; original evidence is read-only.

prepare fixes complete census and selected timing queries. coverage recomputes
raw truth vectors independently and cross-checks all insufficient engine rows.
run launches fresh sequential jobs. Summaries retain every measured round.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
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
from benchmark_focused_diagnostics import encode, elapsed, sha, timer, write
from compare_catalogs import read_catalog
from logistics_validation.catalog_audit import BASELINE, generated_catalogs, reference_verdict
from logistics_validation.focused_diagnostics import Problem, RawVerifier, freeze, projection
from logistics_validation.revision_diagnostics import ValidatedDiagnostics, validate_query
from revalidate_receipt import receipt_key

PROTOCOL = ROOT / "configs/revision_diagnostic_protocol.json"
STATUS = ("safe", "stale_verdict", "insufficient")


def read(path):
    path = Path(path)
    with (gzip.open(path, "rt") if path.suffix == ".gz" else path.open()) as stream:
        return json.load(stream)


def write_gzip(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Explicit mtime and filename make the compressed artifact reproducible.
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            stream.write(encode(value))


def config():
    return read(PROTOCOL)


def fingerprints():
    names = ["configs/revision_diagnostic_protocol.json", "requirements-focused.txt",
             "scripts/benchmark_revision_diagnostics.py", "tests/test_revision_benchmark.py",
             "src/logistics_validation/revision_diagnostics.py",
             "src/logistics_validation/focused_diagnostics.py",
             "src/logistics_validation/catalog_audit.py",
             "src/logistics_validation/standards_core.py",
             "src/logistics_validation/standards_epcis.py",
             "scripts/revalidate_receipt.py", "scripts/compare_catalogs.py",
             "scripts/benchmark_focused_diagnostics.py", config()["saved_tables"]]
    prior = ROOT / config()["existing_inputs"]
    names += [str(path.relative_to(ROOT)) for path in sorted(prior.glob("*.json"))]
    for path in sorted(prior.glob("*.json")):
        data = read(path)
        if "queries" in data:
            if data.get("target"):
                names.append(data["target"])
            if data.get("weights_are_empirical"):
                names.append(data["original_source"])
    return {name: sha(ROOT / name) for name in sorted(set(names))}


def old_classes(states, old):
    """Canonical mask-first classes; states use saved (base, ranks, profile)."""
    queries, fibers = [], []
    for mask in range(4):
        groups = defaultdict(list)
        for index, (base, ranks, profile) in enumerate(states):
            groups[(tuple(base), projection((profile, tuple(ranks)), mask))].append(index)
        for (base, observed), ids in groups.items():
            outcomes = {bool(old[i]) for i in ids}
            if len(outcomes) == 1:
                queries.append(dict(base=base, mask=mask, observed=observed, old_verdict=outcomes.pop()))
                fibers.append(ids)
    return queries, fibers


def expected_result(query, ids, states, labels):
    values = {bool(labels[i]) for i in ids}
    if len(values) == 1:
        return ("safe" if values == {query["old_verdict"]} else "stale_verdict"), [0]
    sufficient = []
    for add in range(4):
        if add & query["mask"]:
            continue
        groups = defaultdict(set)
        for i in ids:
            _, ranks, profile = states[i]
            groups[projection((profile, tuple(ranks)), add)].add(bool(labels[i]))
        if all(len(v) == 1 for v in groups.values()):
            sufficient.append(add)
    minimal = [a for a in sufficient if not any(a != b and a & b == b for b in sufficient)]
    return "insufficient", minimal


def selected_ids(queries, results, selection):
    chosen = {i for i, (status, _) in enumerate(results) if status == "insufficient"}
    for wanted in selection["control_statuses"]:
        candidates = [i for i, (status, _) in enumerate(results) if status == wanted]
        candidates.sort(key=lambda i: (hashlib.sha256(encode(queries[i])).hexdigest(), i))
        chosen.update(candidates[:selection["controls_per_status"]])
    return sorted(chosen)


def census_summary(results):
    histogram, families = Counter(), Counter()
    for status, robust in results:
        if status == "insufficient":
            histogram.update(m.bit_count() for m in robust)
            families[",".join(map(str, robust))] += 1
    return dict(status_counts=dict(Counter(s for s, _ in results)),
                insufficient_robust_cardinalities=dict(histogram),
                insufficient_robust_families=dict(families))


def prepare(output):
    output.mkdir(parents=True, exist_ok=False)
    cfg = config()
    table = read(ROOT / cfg["saved_tables"])
    states, old = table["states"], table["catalogs"]["baseline"]["labels"]
    queries, fibers = old_classes(states, old)
    assert len(states) == 8612 and len(queries) == 10436
    write(output / "observation_classes.json", queries)
    native = read(ROOT / cfg["existing_inputs"] / "procurement_identity.json")
    lookup = {encode(q): i for i, q in enumerate(queries)}
    native_ids = [lookup[encode(q)] for q in native["queries"]]
    native_weights = Counter(q for _, q in native["weighted_requests"])
    rows, details, two_block = {}, [], []
    catalogs = {name: (rules, meta) for name, rules, meta in generated_catalogs() if meta["edits"] == 1}
    for name, (rules, meta) in catalogs.items():
        labels = table["catalogs"][name]["labels"]
        results = [expected_result(q, ids, states, labels) for q, ids in zip(queries, fibers)]
        rows[name] = results
        ids = selected_ids(queries, results, cfg["selection"])
        old_new = {(bool(a), bool(b)) for a, b in zip(old, labels)}
        direction = ("mixed" if (True, False) in old_new and (False, True) in old_new else
                     "strengthening" if (True, False) in old_new else
                     "weakening" if (False, True) in old_new else "equivalent")
        item = dict(target=name, edit=meta, direction=direction, **census_summary(results),
                    three_engine_crosscheck_rows=len(ids),
                    native_unique_status_counts=dict(Counter(results[i][0] for i in native_ids)),
                    native_weighted_status_counts=dict(Counter({status: sum(native_weights[j] for j, i in enumerate(native_ids) if results[i][0] == status) for status in STATUS})))
        details.append(item)
        for i, (status, robust) in enumerate(results):
            if status == "insufficient" and robust == [3]:
                two_block.append(dict(target=name, class_id=i, query=queries[i], robust_masks=robust))
    assert len(rows) == 80 and len(two_block) == 16
    assert sum(d["status_counts"].get("insufficient", 0) for d in details) == 2535
    write_gzip(output / "saved_census_rows.json.gz", rows)
    write(output / "census.json", dict(source=cfg["saved_tables"], states=len(states),
        old_valid_classes=len(queries), targets=len(rows), target_class_rows=len(queries)*len(rows),
        status_counts=dict(sum((Counter(d["status_counts"]) for d in details), Counter())),
        insufficient_robust_cardinalities=dict(sum((Counter(d["insufficient_robust_cardinalities"]) for d in details), Counter())),
        two_block_cases=two_block, details=details))
    inputs = []
    for path in sorted((ROOT / cfg["existing_inputs"]).glob("*.json")):
        data = read(path)
        if "queries" not in data:
            continue
        data["suite"] = "native" if data["weights_are_empirical"] else "authored_epcis"
        data["workloads"] = ["unique", "weighted"]
        write(output / path.name, data)
        inputs.append(dict(name=data["name"], workloads=data["workloads"], suite=data["suite"],
                           unique=len(data["queries"]), weighted=len(data["weighted_requests"])))
    for name in cfg["challenge_targets"]:
        ids = selected_ids(queries, rows[name], cfg["selection"])
        data = dict(name="procurement_" + name, generated_target=name, target=None,
                    suite="challenge", workloads=["unique"], queries=[queries[i] for i in ids],
                    full_domain_class_ids=ids, weights_are_empirical=False,
                    full_domain_classes=len(queries),
                    selection=cfg["selection"], selected_status_counts=dict(Counter(rows[name][i][0] for i in ids)))
        write(output / (data["name"] + ".json"), data)
        inputs.append(dict(name=data["name"], workloads=data["workloads"], suite=data["suite"],
                           unique=len(ids), selected_status_counts=data["selected_status_counts"]))
    write(output / "manifest.json", dict(created_utc=datetime.now(timezone.utc).isoformat(),
        protocol_sha256=sha(PROTOCOL), source_hashes=fingerprints(), inputs=inputs,
        input_hashes={p.name: sha(p) for p in sorted(output.iterdir())}))
    print(json.dumps(inputs), flush=True)


def verify_freeze(inputs):
    manifest = read(inputs / "manifest.json")
    assert manifest["source_hashes"] == fingerprints(), "Source changed after prepare; preserve and reprepare"
    for name, expected in manifest["input_hashes"].items():
        assert sha(inputs / name) == expected, name
    return manifest


def make_problem(data):
    if data.get("generated_target"):
        target = next(r for n, r, _ in generated_catalogs() if n == data["generated_target"])
    else:
        target = read_catalog(ROOT / data["target"]) if data.get("target") else None
    return Problem(data["name"], target)


def coverage(output, inputs):
    manifest = verify_freeze(inputs)
    output.mkdir(parents=True, exist_ok=False)
    table = read(ROOT / config()["saved_tables"])
    states = table["states"]
    queries = read(inputs / "observation_classes.json")
    saved = read(inputs / "saved_census_rows.json.gz")
    catalog_map = {n: c for n, c, meta in generated_catalogs() if meta["edits"] == 1}
    # Independent raw truth is evaluated before any engine is constructed.
    identity = Problem("procurement_identity", BASELINE)
    raw_states = [identity.raw(tuple(base), (profile, tuple(ranks))) for base, ranks, profile in states]
    old = [reference_verdict(raw, BASELINE) for raw in raw_states]
    assert old == [bool(v) for v in table["catalogs"]["baseline"]["labels"]]
    raw_queries, fibers = old_classes(states, old)
    assert encode(raw_queries) == encode(queries)
    checked, all_reports = [], {}
    for name, rules in catalog_map.items():
        labels = [reference_verdict(raw, rules) for raw in raw_states]
        assert labels == [bool(v) for v in table["catalogs"][name]["labels"]]
        actual = [expected_result(q, ids, states, labels) for q, ids in zip(queries, fibers)]
        assert encode(actual) == encode(saved[name]), name
        chosen = selected_ids(queries, actual, config()["selection"])
        problem = Problem("procurement_" + name, rules)
        oracle = RawVerifier(problem)
        engines = {m: ValidatedDiagnostics(problem, m) for m in config()["methods"]}
        reports = {}
        for i in chosen:
            reports[i] = {}
            for method, engine in engines.items():
                result = engine.diagnose(queries[i])
                assert (result["status"], result["robust_masks"]) == actual[i], (name, i, method)
                oracle.verify(queries[i], result)
                reports[i][method] = result
        all_reports[name] = reports
        item = dict(target=name, raw_truth_labels=len(labels), raw_class_results=len(actual),
                    engine_classes=len(chosen), engine_diagnostics=len(chosen)*len(engines),
                    engine_status_counts=dict(Counter(actual[i][0] for i in chosen)),
                    raw_verifier_assertions=oracle.checks, failures=0)
        checked.append(item)
        print(json.dumps(item), flush=True)
    write_gzip(output / "three_engine_reports.json.gz", all_reports)
    verify_freeze(inputs)
    write(output / "summary.json", dict(status="passed", failures=0,
        raw_old_truth_labels=len(old), raw_new_truth_labels=sum(r["raw_truth_labels"] for r in checked),
        raw_class_results=sum(r["raw_class_results"] for r in checked),
        engine_classes=sum(r["engine_classes"] for r in checked),
        engine_diagnostics=sum(r["engine_diagnostics"] for r in checked),
        raw_verifier_assertions=sum(r["raw_verifier_assertions"] for r in checked),
        crosschecked_insufficient_rows=sum(r["engine_status_counts"].get("insufficient", 0) for r in checked),
        scope="Raw predicates validate full census; three engines crosschecked on all insufficient classes and frozen safe/stale controls only.",
        targets=checked, source_hashes=manifest["source_hashes"], input_hashes=manifest["input_hashes"]))


def child(args):
    if hasattr(os, "sched_getaffinity"):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    loading_start = timer()
    data = read(args.input)
    problem = make_problem(data)
    requests = ([(str(i), i) for i in range(len(data["queries"]))] if args.workload == "unique"
                else data["weighted_requests"])
    raw_receipts = None
    if problem.procurement and data["suite"] == "native":
        if args.workload == "unique":
            raw_receipts = data["exemplars"]
        else:
            with gzip.open(ROOT / data["original_source"], "rt") as stream:
                raw_receipts = [json.loads(line)["receipt"] for line in stream]
            assert [r["receipt_id"] for r in raw_receipts] == [r[0] for r in requests]
    loading = elapsed(loading_start)
    normalization_start = timer()
    queries = [validate_query(problem, q) for q in data["queries"]]
    if raw_receipts is not None:
        for receipt, (_, qid) in zip(raw_receipts, requests):
            mask, (base, profile, ranks) = receipt_key(receipt)
            q = validate_query(problem, dict(base=base, mask=mask,
                observed=projection((profile, ranks), mask), old_verdict=receipt["verdict"]))
            assert q == queries[qid]
    normalization = elapsed(normalization_start)
    baseline_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = timer()
    setup_start = timer()
    dependency_import = {"cpu_ns": 0, "wall_ns": 0}
    if args.method == "incremental_smt":
        import_start = timer()
        __import__("z3")
        dependency_import = elapsed(import_start)
    engine = ValidatedDiagnostics(problem, args.method)
    setup = elapsed(setup_start)
    rss_setup = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    cache, results = {}, {}
    serialization, statuses = Counter(), Counter()
    report_bytes, digest = 0, hashlib.sha256()
    first = first_rss = None
    for occurrence, (request_id, qid) in enumerate(requests):
        first_start = timer() if first is None else None
        if args.workload == "weighted" and qid in cache:
            result = cache[qid]
        else:
            result = engine.diagnose(queries[qid])
            if args.workload == "weighted":
                cache[qid] = result
            results[qid] = result
        report = problem.report(queries[qid], result,
            raw_receipts[occurrence] if raw_receipts is not None else None)
        serialization_start = timer()
        blob = encode(dict(request_id=request_id, **report))
        serialization.update(elapsed(serialization_start))
        report_bytes += len(blob)
        digest.update(len(blob).to_bytes(8, "big")); digest.update(blob)
        statuses[result["status"]] += 1
        if first is None:
            first = elapsed(first_start)
            first_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    batch = elapsed(start)
    rss_batch = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    validation_start = timer()
    oracle = RawVerifier(problem)
    for qid, result in results.items():
        oracle.verify(queries[qid], result)
    lifted_checks = 0
    replay_digest = hashlib.sha256()
    for occurrence, (request_id, qid) in enumerate(requests):
        receipt = raw_receipts[occurrence] if raw_receipts is not None else None
        report = problem.report(queries[qid], results[qid], receipt)
        if receipt is not None:
            for label, witness in zip((False, True), report["witnesses"] or []):
                assert witness["activities"] == receipt["activities"]
                assert all(witness[field] == value for field, value in receipt["observed"].items())
                assert reference_verdict(witness, problem.catalog) == label
                lifted_checks += 3
        blob = encode(dict(request_id=request_id, **report))
        replay_digest.update(len(blob).to_bytes(8, "big")); replay_digest.update(blob)
    assert replay_digest.hexdigest() == digest.hexdigest()
    validation = elapsed(validation_start)
    timing = dict(name=data["name"], suite=data["suite"], method=args.method, workload=args.workload,
        input_loading=loading, input_normalization=normalization, setup=setup,
        dependency_import=dependency_import,
        core_setup={k: setup[k]-dependency_import[k] for k in setup},
        core_batch={k: batch[k]-dependency_import[k] for k in batch},
        first_report=first, setup_plus_first={k: setup[k]+first[k] for k in first},
        core_setup_plus_first={k: setup[k]+first[k]-dependency_import[k] for k in first},
        batch=batch, serialization=dict(serialization), independent_raw_validation=validation,
        checks=oracle.checks+lifted_checks, lifted_witness_checks=lifted_checks, failures=0,
        requests=len(requests), diagnosed_classes=len(results), status_counts=dict(statuses),
        output_bytes=report_bytes, output_sha256=digest.hexdigest(),
        process_peak_rss_kib=dict(before_setup=baseline_rss, after_setup=rss_setup,
            after_first_report=first_rss, after_batch=rss_batch),
        python=platform.python_version(), z3_solver=importlib.metadata.version("z3-solver"),
        affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None)
    write(args.output, dict(timing=timing, diagnostics=results))


def summarize(rows, cells, methods):
    summaries = []
    fields = ("input_loading", "input_normalization", "setup", "dependency_import", "core_setup",
              "first_report", "setup_plus_first", "core_setup_plus_first", "batch", "core_batch",
              "serialization", "independent_raw_validation")
    for name, workload in cells:
        chosen = {method: sorted([r for r in rows if r["name"] == name and r["workload"] == workload
                    and r["method"] == method and r["round"] >= 0], key=lambda r: r["round"]) for method in methods}
        reference = chosen[methods[0]][0]
        item = dict(name=name, workload=workload, suite=reference["suite"], requests=reference["requests"],
            diagnosed_classes=reference["diagnosed_classes"], status_counts=reference["status_counts"],
            methods={}, paired_deltas={})
        for method, selected in chosen.items():
            assert len(selected) == config()["timing"]["measured_rounds"]
            assert all(r["status_counts"] == reference["status_counts"] for r in selected)
            metrics = {field: {clock: statistics.median(r[field][clock] for r in selected)
                       for clock in ("cpu_ns", "wall_ns")} for field in fields}
            metrics["process_peak_rss_kib"] = statistics.median(r["process_peak_rss_kib"]["after_batch"] for r in selected)
            metrics["round_costs_ns"] = {}
            for boundary, generation in (("core_plus_research_oracle", "core_batch"),
                                          ("cold_plus_research_oracle", "batch")):
                values = {clock: [r[generation][clock]+r["independent_raw_validation"][clock] for r in selected]
                          for clock in ("cpu_ns", "wall_ns")}
                metrics["round_costs_ns"][boundary] = values
                metrics[boundary] = {clock: statistics.median(v) for clock, v in values.items()}
            item["methods"][method] = metrics
        for left_index, left in enumerate(methods):
            for right in methods[left_index+1:]:
                pairs = {}
                for field in ("core_batch", "batch", "first_report", "setup_plus_first", "core_setup_plus_first",
                              "core_plus_research_oracle", "cold_plus_research_oracle"):
                    pairs[field] = {}
                    for clock in ("cpu_ns", "wall_ns"):
                        if field.endswith("research_oracle"):
                            a = item["methods"][left]["round_costs_ns"][field][clock]
                            b = item["methods"][right]["round_costs_ns"][field][clock]
                        else:
                            a = [r[field][clock] for r in chosen[left]]
                            b = [r[field][clock] for r in chosen[right]]
                        pairs[field][clock] = [x-y for x, y in zip(a, b)]
                item["paired_deltas"][left+"_minus_"+right] = pairs
        summaries.append(item)
    return summaries


def run(output, inputs):
    manifest = verify_freeze(inputs)
    assert importlib.metadata.version("z3-solver") == "4.15.4.0"
    output.mkdir(parents=True, exist_ok=False)
    cfg = config()
    write(output / "run_manifest.json", dict(protocol=cfg, input_manifest=manifest,
        created_utc=datetime.now(timezone.utc).isoformat(), environment=dict(platform=platform.platform(),
        python=platform.python_version(), cpu=platform.processor(), initial_affinity=sorted(os.sched_getaffinity(0)))))
    cells = [(entry["name"], workload) for entry in manifest["inputs"] for workload in entry["workloads"]]
    rows = []
    for round_no in range(-1, cfg["timing"]["measured_rounds"]):
        offset = (round_no+1) % len(cells)
        ordered_cells = cells[offset:]+cells[:offset]
        position = 0
        for cell_position, (name, workload) in enumerate(ordered_cells):
            methods = cfg["methods"]
            offset = (round_no+1+cell_position) % len(methods)
            for method in methods[offset:]+methods[:offset]:
                path = output / f"r{round_no}_{name}_{workload}_{method}.json"
                subprocess.run([sys.executable, __file__, "child", "--input", str(inputs/(name+".json")),
                    "--method", method, "--workload", workload, "--output", str(path)], check=True, cwd=ROOT)
                data = read(path)
                row = dict(data["timing"], round=round_no, phase="warmup" if round_no < 0 else "measured", execution_position=position)
                rows.append(row); position += 1
                print(json.dumps(dict(round=round_no, name=name, workload=workload, method=method,
                    batch_cpu_ms=row["batch"]["cpu_ns"]/1e6, checks=row["checks"])), flush=True)
            reports = [read(output / f"r{round_no}_{name}_{workload}_{m}.json")["diagnostics"] for m in cfg["methods"]]
            assert all(r.keys() == reports[0].keys() for r in reports)
            for key, ref in reports[0].items():
                assert all(r[key]["status"] == ref["status"] and r[key]["robust_masks"] == ref["robust_masks"] for r in reports)
    write(output / "timings.json", rows)
    verify_freeze(inputs)
    summaries = summarize(rows, cells, cfg["methods"])
    minima = {}
    for field in ("core_batch", "batch", "first_report", "setup_plus_first", "core_setup_plus_first",
                  "core_plus_research_oracle", "cold_plus_research_oracle"):
        minima[field] = {clock: dict(Counter(min(cfg["methods"], key=lambda method: cell["methods"][method][field][clock])
                                            for cell in summaries)) for clock in ("cpu_ns", "wall_ns")}
    write(output / "summary.json", dict(status="passed", failures=0, jobs=len(rows),
        measured_jobs=sum(r["round"] >= 0 for r in rows), cells=summaries,
        median_minimum_counts=minima, census=read(inputs/"census.json"), workloads=manifest["inputs"],
        independent_checks=sum(r["checks"] for r in rows), source_hashes=manifest["source_hashes"],
        protocol_sha256=sha(PROTOCOL), output_semantics="Equal statuses and complete robust families; independently checked opposed witnesses, no byte-identity requirement."))
    print("COMPLETE " + str(output/"summary.json"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("--output", type=Path, required=True)
    for command in ("coverage", "run"):
        p = sub.add_parser(command); p.add_argument("--output", type=Path, required=True); p.add_argument("--inputs", type=Path, required=True)
    p = sub.add_parser("child")
    for name in ("input", "output", "method", "workload"):
        p.add_argument("--"+name, required=True)
    args = parser.parse_args()
    if args.command == "prepare": prepare(args.output)
    elif args.command == "coverage": coverage(args.output, args.inputs)
    elif args.command == "run": run(args.output, args.inputs)
    else: child(args)


if __name__ == "__main__":
    main()
