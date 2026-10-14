#!/usr/bin/env python3
"""Reconcile the expanded paper's saved evidence, current files, and tests.

This is an artifact-consistency check, not a new raw-data experiment, a new
oracle replay, a scientific-validity proof, or an editorial acceptance review.
Compact procurement records and stored access traces are read to reconstruct
counts; external experiment summaries are reconciled with their raw timing
rows and pinned source/implementation hashes. Run --run-tests only after all
timing, text, document builds and rendered-document reviews are finalized.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import gzip
import hashlib
from itertools import zip_longest
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/expanded"
TITLE = "Auditing Metadata Access for Event Validation Across Three Public Logs"
ENGINE_SHA = "bff6c408496d747523c70029066cd82a600b7e5efa2da27d7534c66684cc4fd7"
HISTORICAL_MAIN_SHA = "8263a613aace054c68673108a24a6b17d5d8f25d9654f9cca37d60577d48747e"


class Audit:
    def __init__(self):
        self.failures = []
        self.counts = Counter()
        self.hashes = {}
        self.facts = {}

    def check(self, condition, label, section="consistency"):
        self.counts[section] += 1
        if not condition:
            self.failures.append(label)

    def same(self, actual, expected, label, section="consistency"):
        if isinstance(expected, bool):
            result = actual is expected or actual == str(expected)
        elif isinstance(expected, (int, float)):
            try:
                result = math.isclose(float(actual), expected, rel_tol=1e-11, abs_tol=1e-9)
            except (TypeError, ValueError):
                result = False
        elif expected is None:
            result = actual in (None, "")
        else:
            result = actual == expected
        self.check(result, f"{label}: observed={actual!r}, expected={expected!r}", section)

    def digest(self, name):
        path = ROOT / name
        key = path.relative_to(ROOT).as_posix()
        if key not in self.hashes:
            h = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
            self.hashes[key] = h.hexdigest()
        return self.hashes[key]

    def pin(self, name, expected, label=None):
        self.same(self.digest(name), expected, label or f"SHA256 {name}", "hashes")

    def load(self, name):
        self.digest(name)
        return json.loads((ROOT / name).read_text())

    def read(self, name):
        self.digest(name)
        return (ROOT / name).read_text()

    def hashes_match(self, mapping):
        for name, expected in mapping.items():
            self.pin(name, expected)

    def csv(self, name, rows, keys):
        self.digest(name)
        with (ROOT / name).open(newline="") as stream:
            actual = list(csv.DictReader(stream))
        self.same(len(actual), len(rows), name + " rows", "csv")
        indexed = {tuple(str(row[k]) for k in keys): row for row in actual}
        self.same(len(indexed), len(actual), name + " unique keys", "csv")
        for row in rows:
            key = tuple(str(row[k]) for k in keys)
            self.check(key in indexed, name + " key " + repr(key), "csv")
            if key in indexed:
                for field, value in row.items():
                    if isinstance(value, (str, int, float, bool)) or value is None:
                        self.same(indexed[key].get(field), value, f"{name}/{key}/{field}", "csv")


def split(document, salt=17):
    value = int.from_bytes(hashlib.sha256(f"projection-audit-v03:{salt}:{document}".encode()).digest()[:8], "big") % 100
    return "train" if value < 60 else "calibration" if value < 80 else "test"


def procurement(a):
    report = a.load("results/expanded/procurement_cost/benchmark.json")
    native = a.load("results/v03/acquisition_results.json")
    historical = a.load("results/v03/verification.json")
    regression = a.load("results/expanded/catalog_regression.json")
    a.pin("src/logistics_validation/acquisition.py", ENGINE_SHA)
    a.pin("paper/manuscript_v03.md", HISTORICAL_MAIN_SHA, "preserved v0.3 manuscript")
    for value in (report["engine_sha256"], native["code_sha256"], historical["engine_sha256"]):
        a.same(value, ENGINE_SHA, "unchanged procurement engine", "hashes")
    a.pin("scripts/benchmark_acquisition_cost.py", report["benchmark_sha256"])
    a.pin("scripts/stress_acquisition.py", report["independent_oracle_sha256"])
    for value in (report["source_sha256"], native["source_compact_sha256"], historical["source_compact_sha256"]):
        a.pin("results/v03/bpi_compact.jsonl.gz", value)
    a.pin(regression["source"], regression["source_sha256"])
    a.pin("results/v03/acquisition_access_traces.jsonl.gz", native["trace_sha256"])
    a.pin("results/v03/acquisition_stress_fixtures.jsonl.gz", report["verification"]["controlled_stress"]["source_sha256"])
    a.same(historical["status"], "passed", "historical v03 verification")
    a.same(historical["native_independent_oracle_cases"], 251734, "historical oracle scope")
    a.same(historical["native_label_disagreements"], 0, "historical oracle agreement")
    aggregates = defaultdict(Counter)
    documents = set()
    ids = []
    totals = Counter()
    partitions = {salt: Counter() for salt in (17, 29, 43, 71, 101)}
    transitions = Counter()
    with gzip.open(ROOT / "results/v03/bpi_compact.jsonl.gz", "rt") as cases, gzip.open(ROOT / native_path(), "rt") as traces:
        for line, saved in zip_longest(cases, traces):
            if line is None or saved is None:
                a.check(False, "compact/trace lengths differ", "procurement-source")
                break
            case, trace = json.loads(line), json.loads(saved)
            a.check(case["case_id"] == trace["case_id"] and case["document"] == trace["document"], "compact/access-trace identity", "procurement-source")
            a.same(case["violation"], trace["violation"], "stored label agreement", "procurement-source")
            pb = len(json.dumps({"profile": case["profile"]}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
            tb = len(json.dumps({"first_times": case["first_times"]}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
            a.check(pb == trace["profile_bytes"] and tb == trace["time_bytes"], "reconstructed P/T byte encoding", "procurement-source")
            documents.add(case["document"])
            totals.update(cases=1, events=len(case["full_activities"]), milestones=len(case["activities"]), rejected=int(case["violation"]))
            for salt, count in partitions.items():
                count[split(case["document"], salt)] += 1
            test = split(case["document"]) == "test"
            if test:
                ids.append(case["case_id"])
                transitions[(trace["masks"]["permissive"]["structural_order"], trace["masks"]["strict_consignment"]["structural_order"])] += 1
            for variant, policies in trace["masks"].items():
                for policy, mask in policies.items():
                    values = dict(n=1, profile_queries=int(bool(mask & 1)), time_queries=int(bool(mask & 2)),
                                  no_metadata_cases=int(mask == 0), one_block_cases=int(mask in (1, 2)), two_block_cases=int(mask == 3),
                                  payload_bytes=pb * bool(mask & 1) + tb * bool(mask & 2), disagreements=0)
                    aggregates[("native", variant, policy)].update(values)
                    if test:
                        aggregates[("test", variant, policy)].update(values)
    for field, expected in dict(cases=251734, events=1595923, milestones=988984, rejected=55270).items():
        a.same(totals[field], expected, "compact " + field, "procurement-source")
    a.same(len(documents), 76349, "compact purchasing documents", "procurement-source")
    a.same(len(ids), 50931, "canonical salt17 workload", "procurement-source")
    a.same(hashlib.sha256("\n".join(ids).encode()).hexdigest(), report["selected_case_ids_sha256"], "benchmark case ID digest", "hashes")
    representation = a.load("results/v03/representation_audit.json")
    for saved in representation["splits"]:
        a.same(dict(partitions[saved["seed"]]), saved["case_counts"], "document split population " + str(saved["seed"]))
    for scope, rows in (("native", native["native"]), ("test", [r for r in native["holdout"] if r["seed"] == 17])):
        for row in rows:
            key = (scope, row["variant"], row["policy"])
            if key in aggregates:
                for field, value in aggregates[key].items():
                    a.same(row[field], value, "/".join(key) + "/" + field, "procurement-counts")
    labels = {0: "none", 1: "profile", 2: "timestamps", 3: "profile+timestamps"}
    reconstructed = {(labels[b], labels[c]): n for (b, c), n in transitions.items()}
    a.same(reconstructed, {(r["before"], r["after"]): r["cases"] for r in regression["transitions"]}, "paired catalog mask transitions")
    for side, pos in (("before", 0), ("after", 1)):
        dist = Counter()
        for masks, n in transitions.items():
            dist[str(int(bool(masks[pos] & 1)) + int(bool(masks[pos] & 2)))] += n
        a.same(dict(dist), regression["query_count_distribution_" + side], "catalog query distribution " + side)
        a.same(sum(int(k) * n for k, n in dist.items()), regression["separate_calls_" + side], "catalog calls " + side)
    permissive = aggregates[("test", "permissive", "structural_order")]
    strict = aggregates[("test", "strict_consignment", "structural_order")]
    a.same(strict["profile_queries"] - permissive["profile_queries"], 27884, "encoding-independent profile delta")
    a.same(strict["time_queries"] - permissive["time_queries"], 0, "unchanged timestamp queries")
    a.same(strict["payload_bytes"] - permissive["payload_bytes"], regression["additional_payload_bytes"], "paired payload delta")
    a.facts["procurement"] = dict(compact_cases=totals["cases"], source_events=totals["events"], documents=len(documents),
                                rejected=totals["rejected"], accepted=totals["cases"]-totals["rejected"], salt17_test_cases=len(ids),
                                label_scope="Stored compact labels reconciled; independent native oracle replay is preserved in results/v03/verification.json, not rerun here.")
    return report, native, aggregates


def native_path():
    return "results/v03/acquisition_access_traces.jsonl.gz"


def distribution(values):
    q = statistics.quantiles(values, n=4, method="inclusive")
    return dict(n=len(values), minimum=min(values), q1=q[0], median=statistics.median(values), q3=q[2], maximum=max(values),
                mean=statistics.mean(values), standard_deviation=statistics.stdev(values), values=values)


def procurement_timing(a, report, aggregates):
    prefix = "results/expanded/procurement_cost/"
    rows = [json.loads(line) for line in a.read(prefix + "rounds.jsonl").splitlines()]
    a.same(report["n"], 50931, "procurement benchmark N")
    a.same(report["warmup_rounds"], 2, "procurement warmups")
    a.same(report["measured_rounds"], 9, "procurement measured repeats")
    a.same(len(rows), 198, "procurement timing rows")
    for repetition in range(-2, 9):
        selected = [r for r in rows if r["round"] == repetition]
        a.same(len(selected), 18, f"procurement round {repetition} jobs")
        a.same({r["execution_position"] for r in selected}, set(range(18)), f"procurement round {repetition} positions")
        a.same(len({(r["variant"], r["method"]) for r in selected}), 18, f"procurement round {repetition} unique jobs")
        a.check(all(r["phase"] == ("warmup" if repetition < 0 else "measured") for r in selected), "procurement phase labeling")
    methods = {"direct_full_once": "always_both", "certificate_full_once": "always_both", "certificate_always_both": "always_both",
               "certificate_profile_first": "profile_first", "hand_profile_first": "profile_first", "certificate_time_first": "time_first",
               "hand_time_first": "time_first", "certificate_structural": "structural_order", "hand_structural": "structural_order"}
    a.same(len(report["results"]), 18, "procurement method/catalog cells")
    csv_rows = []
    for result in report["results"]:
        variant, method = result["variant"], result["method"]
        selected = sorted([r for r in rows if r["variant"] == variant and r["method"] == method and r["phase"] == "measured"], key=lambda r: r["round"])
        base = sorted([r for r in rows if r["variant"] == variant and r["method"] == "direct_full_once" and r["phase"] == "measured"], key=lambda r: r["round"])
        a.same([r["round"] for r in selected], list(range(9)), f"procurement repeats {variant}/{method}")
        a.same(len(base), 9, f"procurement baseline repeats {variant}")
        ledger = aggregates[("test", variant, methods[method])]
        for field in ("n", "profile_queries", "time_queries", "payload_bytes", "no_metadata_cases", "one_block_cases", "two_block_cases"):
            a.same(result[field], ledger[field], f"procurement native ledger {variant}/{method}/{field}")
        for r in [r for r in rows if r["variant"] == variant and r["method"] == method]:
            for field in ("n", "profile_queries", "time_queries", "payload_bytes", "no_metadata_cases", "one_block_cases", "two_block_cases"):
                a.same(r[field], ledger[field], f"timed ledger {variant}/{method}/{r['round']}/{field}")
            a.same(r["mismatches"], 0, "timed procurement mismatches")
            a.same(r["accepted"], 39142, "timed procurement pass count")
            a.same(r["json_decodes"], r["profile_queries"] + r["time_queries"], "decode per actual read")
            for timer in ("cpu", "wall"):
                a.same(r[timer + "_ns_per_case"], r[timer + "_ns"] / r["n"], "timed per-case normalization")
        for field in ("cpu_ns_per_case", "wall_ns_per_case"):
            for key, value in distribution([r[field] for r in selected]).items():
                a.same(result[field][key], value, f"procurement distribution {variant}/{method}/{field}/{key}", "timing")
        differences = [r["cpu_ns"] - b["cpu_ns"] for r, b in zip(selected, base)]
        for key, value in distribution(differences).items():
            a.same(result["paired_cpu_delta_ns"][key], value, f"paired differences {variant}/{method}/{key}", "timing")
        p, t = 50931-result["profile_queries"], 50931-result["time_queries"]
        a.same(result["avoided_profile_reads"], p, "avoided P reads")
        a.same(result["avoided_time_reads"], t, "avoided T reads")
        threshold = max(0, statistics.median(differences)) / (p+t) if p+t else None
        a.same(result["model_equal_separable_query_break_even_ns"], threshold, f"paired CPU-equivalent threshold {variant}/{method}", "timing")
        a.same(result["model_joint_full_vs_separate_policy_extra_rpcs"], result["profile_queries"]+result["time_queries"]-50931, "bundled endpoint counterexample")
        csv_rows.append(dict(variant=variant, method=method, **{k: result[k] for k in ("n", "profile_queries", "time_queries", "payload_bytes", "mismatches")},
            cpu_us_per_case_median=result["cpu_ns_per_case"]["median"]/1000, cpu_us_per_case_q1=result["cpu_ns_per_case"]["q1"]/1000,
            cpu_us_per_case_q3=result["cpu_ns_per_case"]["q3"]/1000, wall_us_per_case_median=result["wall_ns_per_case"]["median"]/1000,
            paired_cpu_extra_us_per_case=statistics.median(differences)/50931/1000,
            modeled_equal_separable_query_threshold_us=None if threshold is None else threshold/1000,
            extra_rpcs_vs_one_joint_fetch=result["model_joint_full_vs_separate_policy_extra_rpcs"]))
    a.csv(prefix + "summary.csv", csv_rows, ("variant", "method"))
    a.same(a.load(prefix + "verification.json"), report["verification"], "embedded/separate cost correctness evidence")
    checks = a.load(prefix + "summary_checks.json")
    a.pin(prefix + "summary.csv", checks["summary_csv_sha256"])
    v = report["verification"]
    a.same(v["bounded"]["evaluations"], 24*75*4*2*9, "bounded procurement evaluations")
    a.same(v["controlled_stress"]["evaluations"], 14404*9, "procurement stress calls")
    a.same(v["native_policy_evaluations"], 50931*2*9, "native procurement method calls")
    a.check(v["bounded"]["mismatches"] == v["controlled_stress"]["mismatches"] == v["native_mismatches"] == 0, "cost oracle mismatches")
    a.facts["procurement_cost"] = dict(native_method_calls=916758, bounded_calls=129600, controlled_calls=129636,
                                     measured_rows=162, warmup_rows=36, mismatches=0,
                                     threshold_scope="Recomputed paired CPU-equivalent algebra, not measured network latency.")


def external(a):
    prefix = "results/expanded/external_contracts/"
    native = a.load(prefix + "native_summary.json")
    runtime = a.load(prefix + "runtime.json")
    fixtures = a.load(prefix + "counterfactuals.json")
    manifest = a.load(prefix + "source_manifest.json")
    inventory = a.load(prefix + "verification.json")
    a.same(inventory["status"], "passed", "external final inventory status")
    a.hashes_match(inventory["files_sha256"])
    a.hashes_match(inventory["implementation_sha256"])
    for report in (native, runtime, fixtures):
        a.hashes_match(report["implementation_sha256"])
    for item in manifest["sources"]:
        a.pin(item["path"], item["sha256"])
        a.same((ROOT / item["path"]).stat().st_size, item["bytes"], "external archive size")
        a.same(hashlib.md5((ROOT / item["path"]).read_bytes()).hexdigest(), item["md5"], "external archive MD5")
        a.same(item["hashes_verified"], True, "source hash verification declaration")
    rows = native["rows"]
    key = lambda r: (r["dataset"], r["contract"], r["granularity"], r["policy"])
    indexed = {key(r): r for r in rows}
    a.same(len(indexed), len(rows), "external native unique keys")
    a.same(len(rows), 24, "four external contracts by two granularities by three policies")
    a.same(sum(r["cases"] for r in rows), inventory["checks"]["native_policy_case_checks"], "external native policy-case accounting")
    for cohort in native["cohorts"]:
        ckey = (cohort["dataset"], cohort["contract"], cohort["granularity"])
        source = next(s for s in manifest["sources"] if s["dataset"] == cohort["dataset"])
        for field in ("cases", "events"):
            a.same(cohort[field], source[field], "external complete-source cohort " + field)
        full = indexed[(*ckey, "full_once")]
        a.same(cohort["prepared_payload_bytes"], full["bytes"], "all prepared bytes read by external full-once")
        a.same(cohort["prepared_blocks"], full["queries"], "all prepared blocks read by external full-once")
        for policy in ("full_once", "hand_guard", "generic_certificate"):
            r = indexed[(*ckey, policy)]
            a.same(sum(r[f] for f in ("pass", "fail", "nonapplicable", "unsupported")), cohort["cases"], "external outcome partition")
            for field in ("pass", "fail", "nonapplicable", "unsupported"):
                a.same(r[field], cohort["oracle_outcomes"].get(field, 0), "external native oracle totals")
            a.same(r["cases_with_reads"] + r["cases_without_reads"], r["cases"], "external read case partition")
            a.same(r["oracle_disagreements"], 0, "external native disagreement")
            a.same(r["outcome_stream_sha256"], full["outcome_stream_sha256"], "external policy outcome streams")
            a.same(r["query_saving_fraction"], 1-r["queries"]/full["queries"], "external query saving")
            a.same(r["byte_saving_fraction"], 1-r["bytes"]/full["bytes"], "external payload saving")
            a.same(r["bytes_per_case"], r["bytes"]/r["cases"], "external bytes/case")
        hand, generic = indexed[(*ckey, "hand_guard")], indexed[(*ckey, "generic_certificate")]
        for field in ("queries", "bytes", "outcome_stream_sha256"):
            a.same(hand[field], generic[field], "ordinary guard/generic equivalence " + field)
        if cohort["contract"] in ("traffic_cumulative", "travel_first_approval"):
            a.same(generic["guard_generic_trace_order_differences"], 0, "main-predicate guard/generic read-order agreement")
    a.csv(prefix + "native_results.csv", rows, ("dataset", "contract", "granularity", "policy"))
    counts = fixtures["counts"]
    a.same(counts["fixtures"], 4282, "external constructed fixture count")
    a.same(counts["fixture_contract_pairs"], 10834, "external fixture/contract pairs")
    a.same(counts["policy_calls"], counts["fixture_contract_pairs"]*2*2*3, "external constructed policy calls")
    a.same(sum(counts.get("oracle_"+s, 0) for s in ("pass", "fail", "nonapplicable", "unsupported")), counts["fixture_contract_pairs"], "external constructed outcome partition")
    a.same(sum(v for k,v in counts.items() if k.startswith("condition_")), counts["fixture_contract_pairs"], "external fixture category partition")
    a.same(fixtures["oracle_disagreements"], 0, "external constructed disagreements")
    a.same(fixtures["ambiguous_returned_certificate_groups"], 0, "bounded observed certificate ambiguity")
    runs = runtime["runs"]
    a.same(runtime["settings"]["repeats"], 7, "external measured repeats")
    a.same(runtime["settings"]["warmups"], 2, "external warmups")
    a.same(len(runs), 216, "external timing rows")
    a.same(sum(r["warmup"] for r in runs), 48, "external warmup rows")
    a.same(len(runtime["summary"]), 24, "external runtime cells")
    rkey = lambda r: (r["dataset"], r["granularity"], r["mode"], r["policy"])
    groups = defaultdict(list)
    schedules = defaultdict(list)
    for r in runs:
        schedules[(r["dataset"], r["granularity"], r["repetition"])].append(r)
        a.same(r["warmup"], r["repetition"] < 0, "external warmup label")
        ref = indexed[key(r)]
        for field in ("cases", "queries", "bytes"):
            a.same(r[field], ref[field], "external timed native ledger " + field)
        a.same(r["cpu_cases_per_second"], r["cases"]/r["cpu_seconds"], "external timed throughput")
        if not r["warmup"]:
            groups[rkey(r)].append(r)
    for k, schedule in schedules.items():
        a.same(len(schedule), 6, "external round jobs " + str(k))
        a.same({r["position_in_randomized_round"] for r in schedule}, set(range(6)), "external round positions")
    for summary in runtime["summary"]:
        k = rkey(summary)
        selected = groups[k]
        a.same(sorted(r["repetition"] for r in selected), list(range(7)), "external measured repetition set " + str(k))
        cpu = [r["cpu_seconds"] for r in selected]
        wall = [r["wall_seconds"] for r in selected]
        base = groups[(*k[:3], "full_once")]
        hand = groups[(*k[:3], "hand_guard")]
        median, baseline, guard = statistics.median(cpu), statistics.median(r["cpu_seconds"] for r in base), statistics.median(r["cpu_seconds"] for r in hand)
        avoided = base[0]["queries"] - selected[0]["queries"]
        expected = dict(cases=selected[0]["cases"], repeats=7, median_cpu_seconds=median, min_cpu_seconds=min(cpu), max_cpu_seconds=max(cpu),
                        median_wall_seconds=statistics.median(wall), median_cpu_ratio_to_full_once=median/baseline,
                        median_cpu_ratio_to_hand_guard=median/guard, extra_cpu_seconds_vs_hand_guard=median-guard,
                        queries_difference_vs_hand_guard=selected[0]["queries"]-hand[0]["queries"], median_cpu_cases_per_second=selected[0]["cases"]/median,
                        avoided_queries=avoided, extra_cpu_seconds_vs_full_once=median-baseline,
                        sequential_per_avoided_query_break_even_microseconds=max(0,median-baseline)/avoided*1e6 if avoided else None)
        for field, value in expected.items():
            a.same(summary[field], value, "external timing " + str(k) + "/" + field, "timing")
    a.csv(prefix + "runtime_raw.csv", runs, ("dataset", "granularity", "mode", "policy", "repetition"))
    a.csv(prefix + "runtime_summary.csv", runtime["summary"], ("dataset", "granularity", "mode", "policy"))
    a.facts["external"] = dict(traffic_cases=150370, traffic_events=561470, travel_cases=7065, travel_events=86581,
                              unique_source_cases=150370+7065, saved_native_policy_case_checks=sum(r["cases"] for r in rows),
                              constructed_fixtures=4282, fixture_contract_pairs=10834, policy_calls=130008,
                              measured_timing_rows=168, warmup_timing_rows=48,
                              independent_oracle_scope="Pinned saved native/stress results and source hashes reconciled; no raw XES rerun in this final verifier.")
    return native, runtime


def figures(a, benchmark, runtime):
    report = a.load("results/expanded/figure_data.json")
    a.hashes_match(report["sources"])
    a.pin("scripts/plot_expanded_costs.py", report["script_sha256"])
    expected = []
    for variant in ("permissive", "strict_consignment"):
        values = []
        for method in ("direct_full_once", "hand_structural", "certificate_structural"):
            row = next(r for r in benchmark["results"] if r["variant"] == variant and r["method"] == method)
            values.append({field: row["cpu_ns_per_case"][field]/1000 for field in ("median", "q1", "q3")})
        expected.append((9, values))
    for dataset in ("traffic", "travel"):
        values = []
        for policy in ("full_once", "hand_guard", "generic_certificate"):
            runs = [r["cpu_seconds"]/r["cases"]*1e6 for r in runtime["runs"] if r["dataset"] == dataset and r["granularity"] == "coarse" and r["mode"] == "json" and r["policy"] == policy and not r["warmup"]]
            d = distribution(runs)
            values.append({field: d[field] for field in ("median", "q1", "q3")})
        expected.append((7, values))
    a.same(len(report["panels"]), 4, "cost figure panel count", "figures")
    for panel, (repeats, values) in zip(report["panels"], expected):
        a.same(panel["repeats"], repeats, "cost figure repetitions", "figures")
        a.same(len(panel["data"]), 3, "cost figure implementation count", "figures")
        for actual, expected_value in zip(panel["data"], values):
            for field, value in expected_value.items():
                a.same(actual[field], value, "cost figure " + panel["label"] + "/" + field, "figures")


def table_rows(text, number):
    match = re.search(r"^Table " + re.escape(str(number)) + r"\.[^\n]*\n\s*\n((?:\|[^\n]*\n)+)", text, re.M)
    if not match:
        raise ValueError(f"Missing Markdown Table {number}")
    return [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in match[1].splitlines()][2:]


def bibliography(text):
    parts = re.split(r"^## References\s*$", text, maxsplit=1, flags=re.M)
    if len(parts) != 2:
        raise ValueError("Exactly one References heading required")
    body, refs = parts
    entries = re.findall(r"^\[(\d+)\]\s+(.+)$", refs, re.M)
    return body, {int(k): v.strip() for k, v in entries}, [int(k) for k,v in entries]


def citations(text):
    for match in re.finditer(r"\[(\d+)\](?:[–-]\[(\d+)\])?", text):
        first, last = int(match[1]), int(match[2] or match[1])
        yield from range(first, last+1)


def paper(a, benchmark, acquisition, external_native, external_runtime, *, main_table_numbers=(2, 3, 4), generated_evidence=()):
    main = a.read("paper/manuscript_ieee_access_applied.md")
    supp = a.read("paper/supplement_ieee_access_applied.md")
    letter = a.read("paper/cover_letter_ieee_access_applied.md")
    a.same(main.splitlines()[0], "# " + TITLE, "main title", "documents")
    a.same(supp.splitlines()[0], "# Supplementary Material: " + TITLE, "supplement title", "documents")
    a.check(TITLE in letter, "cover letter exact title", "documents")
    abstract = main.split("## Abstract", 1)[1].split("Index Terms", 1)[0].strip()
    abstract_words = len(re.findall(r"\S+", abstract))
    a.check(150 <= abstract_words <= 250, f"IEEE abstract word count: {abstract_words}", "documents")
    a.check(not list(citations(abstract)), "self-contained abstract without citations", "documents")
    terms = re.search(r"^Index Terms[—–-](.+)$", main, re.M)[1].split(",")
    a.check(3 <= len(terms) <= 10, "IEEE index term count", "documents")
    body, refs, order = bibliography(main)
    sbody, srefs, sorder = bibliography(supp)
    first_use = list(dict.fromkeys(citations(body)))
    a.same(order, list(range(1, len(refs)+1)), "contiguous ordered main bibliography", "references")
    a.same(first_use, list(range(1, len(refs)+1)), "main references ordered by first appearance", "references")
    a.same(len(sorder), len(srefs), "unique supplementary references", "references")
    for n, value in srefs.items():
        a.same(value, refs.get(n), f"supplement bibliography [{n}] matches main", "references")
    a.check(set(citations(sbody)) <= set(srefs), "supplement cited references defined", "references")
    variants = {"Permissive": "permissive", "Strict": "strict_consignment"}
    policies = {"Fetch-both": "always_both", "Profile-first": "profile_first", "Time-first": "time_first", "Structural-order": "structural_order", "Train-cost-order": "train_cost_order"}
    countrows = table_rows(main, main_table_numbers[0])
    a.same(len(countrows), 10, "main Table 2 row count", "paper-tables")
    for row in countrows:
        v, p = variants[row[0]], policies[row[1]]
        result = next(r for r in acquisition["holdout"] if r["seed"] == 17 and r["variant"] == v and r["policy"] == p)
        expected = [row[0], row[1], *(f"{result[k]:,}" for k in ("profile_queries", "time_queries", "payload_bytes")), f"{(1-result['payload_bytes']/9469292)*100:.2f}%"]
        a.same(row, expected, "main Table 2 " + row[0] + "/" + row[1], "paper-tables")
    methods = {"Direct-full once": "direct_full_once", "Hand-structural": "hand_structural", "Certificate-structural": "certificate_structural"}
    costrows = table_rows(main, main_table_numbers[1])
    a.same(len(costrows), 6, "main Table 3 row count", "paper-tables")
    for row in costrows:
        result = next(r for r in benchmark["results"] if r["variant"] == variants[row[0]] and r["method"] == methods[row[1]])
        d = result["cpu_ns_per_case"]
        expected = f"{d['median']/1000:.2f} [{d['q1']/1000:.2f}, {d['q3']/1000:.2f}]"
        a.same(row[2], expected, "main Table 3 CPU " + "/".join(row[:2]), "paper-tables")
        threshold = result["model_equal_separable_query_break_even_ns"]
        a.same(row[3], "—" if threshold is None else f"{threshold/1000:.2f}", "main Table 3 threshold " + "/".join(row[:2]), "paper-tables")
    extrows = table_rows(main, main_table_numbers[2])
    a.same(len(extrows), 8, "main external table row count", "paper-tables")
    for row in extrows:
        dataset, granularity = row[0].lower(), row[1].lower()
        policy = "full_once" if row[2] == "Full-once" else "hand_guard"
        contract = "traffic_cumulative" if dataset == "traffic" else "travel_first_approval"
        result = next(r for r in external_native["rows"] if (r["dataset"], r["contract"], r["granularity"], r["policy"]) == (dataset, contract, granularity, policy))
        a.same(row[3:], [f"{result['queries']:,}", f"{result['bytes']:,}", f"{result['byte_saving_fraction']*100:.2f}%"], "main external table " + "/".join(row[:3]), "paper-tables")
    sensitivity = {"Every source-order cumulative equation": "traffic_cumulative", "Final recorded total": "traffic_final",
                   "Exact-time groups with maximum recorded total": "traffic_timestamp_groups"}
    for row in table_rows(supp, "S6"):
        result = next(r for r in external_native["rows"] if r["contract"] == sensitivity[row[0]] and r["granularity"] == "coarse" and r["policy"] == "full_once")
        a.same(row[1:], [f"{result[k]:,}" for k in ("nonapplicable", "pass", "fail")], "supplement Table S6 " + row[0], "paper-tables")
    all_methods = {"Direct-full once": "direct_full_once", "Certificate-full once": "certificate_full_once", "Certificate fetch-both": "certificate_always_both",
                   "Certificate P-first": "certificate_profile_first", "Certificate T-first": "certificate_time_first", "Certificate structural": "certificate_structural",
                   "Hand P-first": "hand_profile_first", "Hand T-first": "hand_time_first", "Hand structural": "hand_structural"}
    complete_costs = table_rows(supp, "S7")
    a.same(len(complete_costs), 18, "supplement Table S7 row count", "paper-tables")
    for row in complete_costs:
        result = next(r for r in benchmark["results"] if r["variant"] == variants[row[0]] and r["method"] == all_methods[row[1]])
        d, threshold = result["cpu_ns_per_case"], result["model_equal_separable_query_break_even_ns"]
        expected = [f"{d['median']/1000:.2f} [{d['q1']/1000:.2f}, {d['q3']/1000:.2f}]", "—" if threshold is None else f"{threshold/1000:.2f}"]
        a.same(row[2:], expected, "supplement Table S7 " + "/".join(row[:2]), "paper-tables")
    complete_external = table_rows(supp, "S8")
    a.same(len(complete_external), 8, "supplement Table S8 row count", "paper-tables")
    for row in complete_external:
        dataset, granularity, mode = [v.lower() for v in row[:3]]
        chosen = {r["policy"]: r for r in external_runtime["summary"] if (r["dataset"], r["granularity"], r["mode"]) == (dataset, granularity, mode)}
        expected = [f"{chosen[p]['median_cpu_seconds']/chosen[p]['cases']*1e6:.3f}" for p in ("full_once", "hand_guard", "generic_certificate")]
        expected.append(f"{chosen['generic_certificate']['median_cpu_ratio_to_full_once']:.3f}")
        a.same(row[3:], expected, "supplement Table S8 " + "/".join(row[:3]), "paper-tables")
    a.check("results/expanded/external_contracts/runtime.json" in supp, "supplement links external runtime evidence", "documents")
    a.check("results/expanded/procurement_cost/benchmark.json" in supp, "supplement links procurement cost evidence", "documents")
    for text, source in ((main, "main"), (supp, "supplement")):
        for local in re.findall(r"(?:paper/|results/|docs/|scripts/|src/|tests/)[A-Za-z0-9_./-]+\.(?:jsonl\.gz|jsonl|json|csv|xml|py|md|png)(?![A-Za-z0-9_])", text):
            # These are outputs of this invocation, written after this check.
            if local not in {"results/expanded/pytest.xml", "results/expanded/verification.json",
                             "results/strong/pytest.xml", "results/strong/verification.json", *generated_evidence}:
                a.check((ROOT / local).exists(), source + " evidence path exists: " + local, "documents")
        for relative in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text):
            a.digest("paper/" + relative)
    a.facts["paper"] = dict(title=TITLE, abstract_words=abstract_words, index_terms=len(terms), references=len(refs),
                           main_tables_checked=list(main_table_numbers), supplementary_tables_checked=["S6", "S7", "S8"], reference_scope="Main first appearance; supplementary entries share main numbering.")


def documents(a):
    build = a.load("results/ieee_access_applied/build_manifest.json")
    review = a.load("results/ieee_access_applied/document_review.json")
    a.pin("scripts/build_ieee_access.py", build["builder_sha256"])
    if "builder_sha256" in review:
        a.same(review["builder_sha256"], build["builder_sha256"], "review matches builder", "documents")
    a.pin(build["template"], build["template_sha256"])
    a.pin("paper/author_metadata.json", build["author_metadata_sha256"])
    authors = a.load("paper/author_metadata.json")
    if "official_template_sha256" in review:
        a.same(review["official_template_sha256"], build["template_sha256"], "reviewed official template", "documents")
    a.check(review["status"].startswith("passed"), "document review passed", "documents")
    visual = review["visual_review"]
    a.same(visual.get("all_pages_inspected_via_contact_sheets", visual.get("all_pages_overview")), True, "all-pages visual overview recorded", "documents")
    content_ref = review["independent_content_verification"]
    a.pin(content_ref["path"], content_ref["sha256"])
    content = a.load(content_ref["path"])
    a.same(content["status"], "passed", "final document content checks passed", "documents")
    a.same(content["files"], review["files"], "content and visual reviews key the same files", "documents")
    a.pin("paper/author_metadata.json", content["author_metadata_sha256"])
    a.same(content["main_references_in_first_citation_order"], list(range(1, a.facts["paper"]["references"]+1)), "content review reference order", "documents")
    checked = []
    for item in build["files"]:
        reviewed = next((r for r in review["files"] if r["source"] == item["source"]), None)
        a.check(reviewed is not None, "built document has keyed review " + item["source"], "documents")
        if reviewed is None:
            continue
        for field in ("source", "docx", "pdf"):
            a.pin(item[field], item[field + "_sha256"])
            a.same(reviewed[field], item[field], "review current artifact path", "documents")
            a.same(reviewed[field+"_sha256"], item[field+"_sha256"], "review current artifact hash", "documents")
        a.same(reviewed["pages"], item["pages"], "review page count", "documents")
        a.same(item.get("lost_body_blocks", []), [], "build source preservation", "documents")
        a.same(reviewed.get("lost_body_blocks", []), [], "review source preservation", "documents")
        a.same(reviewed.get("missing_formatted_numbers_in_pdf", {}), {}, "review PDF numeric preservation", "documents")
        a.same(reviewed.get("removed_template_sample_markers_still_present", []), [], "template sample data removed", "documents")
        for figure in item.get("figures", []):
            a.pin(figure["path"], figure["sha256"])
        if item["source"].endswith("/manuscript_ieee_access_applied.md"):
            a.same(item["title"], TITLE, "build main title", "documents")
            with zipfile.ZipFile(ROOT / item["docx"]) as package:
                document = ET.fromstring(package.read("word/document.xml"))
            word_text = " ".join(element.text or "" for element in document.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"))
            for author in authors["authors"]:
                a.check(author["name"] in word_text, "provided author in final DOCX: " + author["name"], "documents")
                a.check(author["affiliation"] in word_text, "provided affiliation in final DOCX", "documents")
            if authors.get("email"):
                a.check(authors["email"] in word_text, "provided corresponding email in final DOCX", "documents")
        checked.append(dict(pdf=item["pdf"], sha256=item["pdf_sha256"], pages=item["pages"]))
    a.same(len(checked), 3, "three final documents built/reviewed", "documents")
    a.facts["documents"] = dict(review_status=review["status"], keyed_pdfs=checked,
                                scope="Hashes tie the existing rendered-document review to current PDFs; this verifier performs no new visual inspection.")


def provenance(a):
    item = a.load("results/expanded/provenance/bpi2019_deposit_verification.json")
    a.pin(item["metadata_path"], item["metadata_sha256"])
    raw_present = (ROOT / item["raw_path"]).is_file()
    if raw_present:
        a.pin(item["raw_path"], item["raw_sha256"])
        a.same((ROOT / item["raw_path"]).stat().st_size, item["raw_size"], "original procurement archive size", "provenance")
    a.check(item["size_matches"] and item["md5_matches"], "original procurement deposit checksum reconciliation", "provenance")
    a.same(item["original_archive_redownloaded"], False, "no claim of second original download", "provenance")
    metadata = a.load(item["metadata_path"])
    deposit = next(f for f in metadata["files"] if f["id"] == item["deposit_file"]["id"])
    a.same(deposit["size"], item["raw_size"], "deposit metadata bytes", "provenance")
    a.same(deposit["computed_md5"], item["raw_md5"], "deposit metadata MD5", "provenance")
    a.facts["procurement_original_provenance"] = dict(raw_file_present=raw_present, raw_rehashed=raw_present,
        metadata_checked=True, raw_path=item["raw_path"], scope=(
            "Current complete local raw file rehashed and size-checked; recorded MD5 and size reconciled with pinned original-deposit metadata. No XML reparse or new download."
            if raw_present else "Raw procurement file is excluded from this package and absent locally. Only the saved raw-file manifest and original-deposit metadata were reconciled; original raw bytes were not independently rehashed in this invocation."))


def run_tests(a):
    standard_fixture = "data/standards/epcis-context.jsonld"
    if not (ROOT / standard_fixture).is_file():
        message = "Full-suite prerequisite missing: data/standards/epcis-context.jsonld. Run .venv/bin/python scripts/download_standards.py before --run-tests. The pinned standards fixture is intentionally excluded from the review package."
        a.check(False, message, "tests")
        return {"run": False, "reason": message}
    a.digest(standard_fixture)
    xml_path = OUT / "pytest.xml"
    output_path = OUT / "pytest.txt"
    command = [str(ROOT / ".venv/bin/python"), "-m", "pytest", "--junitxml", str(xml_path)]
    started = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output_path.write_text(result.stdout)
    a.digest(output_path.relative_to(ROOT))
    a.check(result.returncode == 0, "complete pytest suite return code", "tests")
    summary = dict(command=command, returncode=result.returncode, elapsed_seconds=time.perf_counter()-started,
                   output=output_path.relative_to(ROOT).as_posix(), junit=xml_path.relative_to(ROOT).as_posix())
    if xml_path.exists():
        a.digest(xml_path.relative_to(ROOT))
        root = ET.parse(xml_path).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        for field in ("tests", "failures", "errors", "skipped"):
            summary[field] = sum(int(s.get(field, "0")) for s in suites)
        summary["passed"] = summary["tests"]-summary["failures"]-summary["errors"]-summary["skipped"]
        a.check(summary["tests"] > 0 and summary["failures"] == summary["errors"] == 0, "complete pytest XML totals", "tests")
    else:
        a.check(False, "pytest XML missing", "tests")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-tests", action="store_true", help="Run the full suite once, only after final text/build/timing is frozen")
    parser.add_argument("--output", type=Path, help="Default: verification.json with tests; preflight.json without tests")
    args = parser.parse_args()
    output = args.output or OUT / ("verification.json" if args.run_tests else "preflight.json")
    started = time.perf_counter()
    a = Audit()
    try:
        benchmark, acquisition, aggregates = procurement(a)
        print("Procurement compact counts and original access traces reconciled", flush=True)
        procurement_timing(a, benchmark, aggregates)
        native, runtime = external(a)
        figures(a, benchmark, runtime)
        print("New native and timing evidence reconciled", flush=True)
        paper(a, benchmark, acquisition, native, runtime)
        documents(a)
        provenance(a)
    except Exception as error:
        a.check(False, f"Verifier exception: {type(error).__name__}: {error}", "exceptions")
        traceback.print_exc()
    # Test every current implementation file, even if an artifact is stale.
    tests = run_tests(a) if args.run_tests else {"run": False, "reason": "Preflight only; final full-suite execution requires --run-tests after the final-build signal."}
    for tree in ("src", "scripts", "tests"):
        for path in sorted((ROOT / tree).rglob("*.py")):
            a.digest(path.relative_to(ROOT))
    for path in ("pyproject.toml", "requirements.lock", "docs/procurement_cost_evidence.md", "docs/expanded_novelty_audit.md",
                 "docs/expanded_final_review.md", "docs/reproduce_expanded.md"):
        if (ROOT / path).exists():
            a.digest(path)
    status = "failed" if a.failures else ("passed" if args.run_tests else "passed_without_tests")
    result = dict(status=status, created_utc=datetime.now(timezone.utc).isoformat(),
                  scope="Current artifact consistency, saved-result arithmetic, compact-record/access-trace accounting, file provenance, document-build/review alignment, and implementation tests. Not a new raw-source experiment, complete independent oracle rerun, business-anomaly validation, deployment measurement or journal acceptance assessment.",
                  checks=sum(a.counts.values()), checks_by_category=dict(a.counts), failures=a.failures,
                  facts=a.facts, pytest=tests, checked_file_hashes=dict(sorted(a.hashes.items())),
                  elapsed_seconds=time.perf_counter()-started)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "checks", "failures", "pytest", "elapsed_seconds")}, indent=2))
    return 0 if not a.failures else 1


if __name__ == "__main__":
    sys.exit(main())
