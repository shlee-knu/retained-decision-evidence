#!/usr/bin/env python3
"""Reproduce full-original cross-domain authored-contract acquisition experiments.

Run --stage evaluate before the isolated --stage benchmark. No raw data are
published; missing originals can be fetched from pinned primary archive URLs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import gc
import gzip
import hashlib
from itertools import product, permutations
import json
import os
from pathlib import Path
import platform
import random
import resource
import statistics
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logistics_validation.external_contracts import POLICIES, evaluate, prepare_record
from logistics_validation.external_contracts_oracle import direct_oracle

OUT = ROOT / "results/expanded/external_contracts"
SOURCES = {
    "traffic": {"path": "data/external/road_traffic_fine/Road_Traffic_Fine_Management_Process.xes.gz",
                "url": "https://ndownloader.figshare.com/files/24018146",
                "doi": "10.4121/uuid:270fd440-1057-4fb9-89a9-b699b47990f5",
                "sha256": "dc9e0e65c964c8ce2a720687ecf17d8204a5cced5db2267c717ed39ada665da8",
                "md5": "dc4cae9a592938af92932ca6c043baeb", "bytes": 3454978,
                "cases": 150370, "events": 561470, "license": "4TU General Terms of Use; noncommercial"},
    "travel": {"path": "data/external/bpi2020/PermitLog.xes.gz",
               "url": "https://ndownloader.figshare.com/files/24075929",
               "doi": "10.4121/uuid:ea03d361-a7cd-4f5e-83d8-5fbdf0362550",
               "sha256": "9e23befe5394c13caff4428c00a6cee08647b1749f270a78cd05d99f861c5a8b",
               "md5": "b6e9ff00d946f6ad4c91eb6fb550aee4", "bytes": 1938192,
               "cases": 7065, "events": 86581, "license": "CC BY-NC 4.0"},
}
MAIN = {"traffic": "traffic_cumulative", "travel": "travel_first_approval"}
ALL = {"traffic": ("traffic_cumulative", "traffic_final", "traffic_timestamp_groups"),
       "travel": ("travel_first_approval",)}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def source_records(fetch):
    records = []
    for dataset, spec in SOURCES.items():
        path = ROOT / spec["path"]
        if not path.exists():
            if not fetch:
                raise FileNotFoundError(f"{path}; rerun with --fetch to obtain the pinned full original")
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".part")
            with urllib.request.urlopen(spec["url"], timeout=120) as response, temporary.open("wb") as stream:
                while chunk := response.read(1024 * 1024):
                    stream.write(chunk)
            data = temporary.read_bytes()
            if hashlib.sha256(data).hexdigest() != spec["sha256"] or hashlib.md5(data).hexdigest() != spec["md5"]:
                raise ValueError(f"Downloaded source hash mismatch: {temporary}")
            temporary.replace(path)
        data = path.read_bytes()
        if len(data) != spec["bytes"] or hashlib.sha256(data).hexdigest() != spec["sha256"] or hashlib.md5(data).hexdigest() != spec["md5"]:
            raise ValueError(f"Pinned original changed: {path}")
        records.append({"dataset": dataset, **spec, "hashes_verified": True})
    save(OUT / "source_manifest.json", {"verified_utc": datetime.now(timezone.utc).isoformat(), "sources": records,
        "redistribution": "Originals and case-level derivatives retain source terms. This evidence directory contains aggregate results and no copies of raw event logs."})


def raw_traces(path):
    with gzip.open(path, "rb") as stream:
        context = ET.iterparse(stream, events=("start", "end"))
        _, root = next(context)
        for kind, element in context:
            if kind == "end" and element.tag.rsplit("}", 1)[-1] == "trace":
                attrs, events = {}, []
                for child in element:
                    if child.tag.rsplit("}", 1)[-1] == "event":
                        events.append({a.attrib["key"]: a.attrib.get("value") for a in child})
                    elif "key" in child.attrib:
                        attrs[child.attrib["key"]] = child.attrib.get("value")
                yield attrs.get("concept:name"), events
                root.remove(element)


def provenance():
    paths = ("scripts/evaluate_external_contracts.py", "src/logistics_validation/external_contracts.py",
             "src/logistics_validation/external_contracts_oracle.py", "tests/test_external_contracts.py")
    return {path: sha256(ROOT / path) for path in paths if (ROOT / path).exists()}


def load(dataset, contract, granularity):
    records, labels, cases, event_count = [], [], set(), 0
    start = time.perf_counter()
    for case_id, events in raw_traces(ROOT / SOURCES[dataset]["path"]):
        if case_id in cases:
            raise ValueError("Duplicate raw case identifier")
        cases.add(case_id)
        event_count += len(events)
        labels.append(direct_oracle(events, contract))
        records.append(prepare_record(case_id, events, contract, granularity))
    if len(records) != SOURCES[dataset]["cases"] or event_count != SOURCES[dataset]["events"]:
        raise ValueError("Full source count mismatch")
    info = {"dataset": dataset, "contract": contract, "granularity": granularity,
            "cases": len(records), "events": event_count, "oracle_outcomes": dict(Counter(labels)),
            "preparation_seconds": time.perf_counter() - start,
            "prepared_payload_bytes": sum(sum(len(v) for v in r._wire.values()) for r in records),
            "prepared_blocks": sum(len(r._wire) for r in records),
            "peak_process_rss_kib_after_preparation": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    return records, labels, info


def native():
    rows, cohorts = [], []
    for dataset, contracts in ALL.items():
        for contract in contracts:
            for granularity in ("coarse", "fine"):
                records, labels, info = load(dataset, contract, granularity)
                if info["oracle_outcomes"].get("unsupported", 0):
                    raise ValueError("Native domain contains unsupported relevant data; do not silently filter")
                cohorts.append(info)
                meters = {policy: Counter() for policy in POLICIES}
                digest = {policy: hashlib.sha256() for policy in POLICIES}
                trace_disagreements = 0
                for record, expected in zip(records, labels):
                    answers = {}
                    for policy in POLICIES:
                        answer = evaluate(record, policy, audit=True)
                        if answer.outcome != expected:
                            raise AssertionError((dataset, contract, granularity, record.case_id, policy, answer, expected))
                        meter = meters[policy]
                        meter[answer.outcome] += 1
                        meter["queries"] += answer.queries
                        meter["bytes"] += answer.bytes
                        meter["cases_with_reads"] += bool(answer.queries)
                        meter["cases_without_reads"] += not answer.queries
                        meter["atoms_checked"] += answer.atoms_checked
                        digest[policy].update(f"{record.case_id}\t{answer.outcome}\n".encode())
                        answers[policy] = answer
                    guard, generic = answers["hand_guard"], answers["generic_certificate"]
                    assert guard.queries == generic.queries and guard.bytes == generic.bytes
                    trace_disagreements += guard.trace != generic.trace
                    if contract in MAIN.values():
                        assert guard.trace == generic.trace
                for policy in POLICIES:
                    meter, full = meters[policy], meters["full_once"]
                    rows.append({"dataset": dataset, "contract": contract, "granularity": granularity, "policy": policy,
                        "cases": len(records), **{k: meter[k] for k in (
                            "pass", "fail", "nonapplicable", "unsupported", "queries", "bytes", "cases_with_reads", "cases_without_reads", "atoms_checked")},
                        "oracle_disagreements": 0, "outcome_stream_sha256": digest[policy].hexdigest(),
                        "query_saving_fraction": 1 - meter["queries"] / full["queries"],
                        "byte_saving_fraction": 1 - meter["bytes"] / full["bytes"],
                        "bytes_per_case": meter["bytes"] / len(records),
                        "guard_generic_trace_order_differences": trace_disagreements})
                print(json.dumps({**info, "status": "all_policies_match_independent_raw_oracle"}), flush=True)
                del records, labels
                gc.collect()
    save(OUT / "native_summary.json", {"created_utc": datetime.now(timezone.utc).isoformat(),
        "implementation_sha256": provenance(), "cohorts": cohorts, "rows": rows,
        "scope": "All pinned raw cases, no label-based filtering. Labels are authored observation predicates. Native relevant metadata independently audited as supported. Complete activity projection is a pre-existing input, not free to acquire in a deployment.",
        "byte_encoding": "Actual UTF-8 lengths of json.dumps(block,ensure_ascii=False,separators=(',',':'),allow_nan=False). Source values remain lexical strings. No activity strings, source positions, case identifiers, protocol headers or response envelopes are charged. Projection/adaptation and serialization occur before policy evaluation.",
        "equivalence": "For the two main predicates, hand_guard and generic_certificate have identical decisions and exact block-read traces on every native case. The generic engine is ordinary conditional conjunction evaluation, not a new acquisition algorithm.",
        "unsupported_precedence": "Exact cross-policy verdict claims are restricted to the audited relevant-valid completion domain. Invalid unseen later blocks may be skipped after a false atom; this is not a general schema-validation substitute."})
    with (OUT / "native_results.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def once(records, policy, mode):
    labels, queries, nbytes = [], 0, 0
    for record in records:
        answer = evaluate(record, policy, mode=mode)
        labels.append(answer.outcome)
        queries += answer.queries
        nbytes += answer.bytes
    return labels, queries, nbytes


def benchmark(repeats, warmups, seed):
    if repeats < 7 or warmups < 1:
        raise ValueError("At least 7 measured repetitions and 1 warmup required")
    if not (OUT / "native_summary.json").exists():
        raise ValueError("Run --stage evaluate before timing")
    verified = json.loads((OUT / "native_summary.json").read_text())
    if verified["implementation_sha256"] != provenance():
        raise ValueError("Code differs from the native correctness evidence; rerun evaluate")
    rows, preparations = [], []
    rng = random.Random(seed)
    for dataset, contract in MAIN.items():
        for granularity in ("coarse", "fine"):
            records, expected, info = load(dataset, contract, granularity)
            preparations.append(info)
            options = [(policy, mode) for policy in POLICIES for mode in ("cached", "json")]
            for repetition in range(-warmups, repeats):
                order = options[:]
                rng.shuffle(order)
                for position, (policy, mode) in enumerate(order):
                    gc.collect()
                    cpu_before = time.process_time_ns()
                    wall_before = time.perf_counter_ns()
                    labels, queries, nbytes = once(records, policy, mode)
                    wall_ns = time.perf_counter_ns() - wall_before
                    cpu_ns = time.process_time_ns() - cpu_before
                    if labels != expected:
                        raise AssertionError("Timed pass differs from the independent reference vector")
                    row = {"dataset": dataset, "contract": contract, "granularity": granularity,
                           "policy": policy, "mode": mode, "repetition": repetition,
                           "warmup": repetition < 0, "position_in_randomized_round": position,
                           "cases": len(records), "cpu_seconds": cpu_ns / 1e9,
                           "wall_seconds": wall_ns / 1e9, "queries": queries, "bytes": nbytes,
                           "cpu_cases_per_second": len(records) / (cpu_ns / 1e9),
                           "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
                    rows.append(row)
                print(json.dumps({"timing": dataset, "granularity": granularity, "round": repetition}), flush=True)
            del records, expected
            gc.collect()
    summaries = []
    for dataset in MAIN:
        for granularity in ("coarse", "fine"):
            for mode in ("cached", "json"):
                baseline = [r for r in rows if r["dataset"] == dataset and r["granularity"] == granularity
                            and r["mode"] == mode and r["policy"] == "full_once" and not r["warmup"]]
                baseline_cpu = statistics.median(r["cpu_seconds"] for r in baseline)
                hand_rows = [r for r in rows if r["dataset"] == dataset and r["granularity"] == granularity
                             and r["mode"] == mode and r["policy"] == "hand_guard" and not r["warmup"]]
                hand_cpu = statistics.median(r["cpu_seconds"] for r in hand_rows)
                for policy in POLICIES:
                    selected = [r for r in rows if r["dataset"] == dataset and r["granularity"] == granularity
                                and r["mode"] == mode and r["policy"] == policy and not r["warmup"]]
                    cpu = [r["cpu_seconds"] for r in selected]
                    wall = [r["wall_seconds"] for r in selected]
                    median = statistics.median(cpu)
                    avoided = baseline[0]["queries"] - selected[0]["queries"]
                    extra_cpu = median - baseline_cpu
                    summaries.append({"dataset": dataset, "granularity": granularity, "mode": mode, "policy": policy,
                        "cases": selected[0]["cases"], "repeats": repeats, "median_cpu_seconds": median,
                        "min_cpu_seconds": min(cpu), "max_cpu_seconds": max(cpu),
                        "median_wall_seconds": statistics.median(wall),
                        "median_cpu_ratio_to_full_once": median / baseline_cpu,
                        "median_cpu_ratio_to_hand_guard": median / hand_cpu,
                        "extra_cpu_seconds_vs_hand_guard": median - hand_cpu,
                        "queries_difference_vs_hand_guard": selected[0]["queries"] - hand_rows[0]["queries"],
                        "median_cpu_cases_per_second": selected[0]["cases"] / median,
                        "avoided_queries": avoided, "extra_cpu_seconds_vs_full_once": extra_cpu,
                        "sequential_per_avoided_query_break_even_microseconds": max(0, extra_cpu) / avoided * 1e6 if avoided else None,
                        "break_even_scope": "Algebraic sequential per-block CPU-cost scenario only; no measured network latency or deployment cost."})
    runtime = {"created_utc": datetime.now(timezone.utc).isoformat(), "implementation_sha256": provenance(),
        "environment": {"python": sys.version, "platform": platform.platform(), "logical_cpus": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "processor": platform.processor(), "timer": "process_time_ns and perf_counter_ns", "gc": "enabled; gc.collect before each pass"},
        "settings": {"repeats": repeats, "warmups": warmups, "seed": seed,
                     "order": "Policy × access-mode order independently shuffled within each full-cohort round; cohort order fixed."},
        "included": "Complete activity projection scanning, direct/generic rule-plan construction, per-case Reader/Decision allocation, block cache lookup, lookup/byte counters, exact numeric/time parsing, predicate evaluation, and common outcome-vector construction. JSON mode additionally decodes each queried pre-serialized block exactly once per case.",
        "excluded": "Raw source IO/decompression/XML parsing, source-schema audit/reference oracle, projection/block construction and JSON serialization, network/storage delay, request headers, certificate read-trace collection, and correctness-vector comparison after the timer.",
        "cache": "Warm source files and prepared in-memory payloads. A fresh per-case Reader cache is created for every decision. No cross-case parsed-value or decision cache.",
        "memory": "ru_maxrss is whole-process high-water RSS, including prepared records and prior cohorts; it is not isolated per-method incremental memory and must not be compared as such.",
        "preparations": preparations, "summary": summaries, "runs": rows}
    save(OUT / "runtime.json", runtime)
    for filename, values in (("runtime_raw.csv", rows), ("runtime_summary.csv", summaries)):
        with (OUT / filename).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(values[0]))
            writer.writeheader()
            writer.writerows(values)


def stress():
    """Constructed numeric/time counterfactuals, never counted as native cases."""
    counts, cases = Counter(), []
    for length in (1, 2, 3):
        for initial in (0, 1):
            for values in product((-1, 0, 1), repeat=length * 2):
                amounts, totals = values[:length], values[length:]
                for ties in (True, False):
                    events = [{"concept:name": "Create Fine", "totalPaymentAmount": str(initial)}]
                    events += [{"concept:name": "Payment", "paymentAmount": str(a), "totalPaymentAmount": str(t),
                                "time:timestamp": f"2020-01-0{1 if ties else i + 1}T00:00:00Z"}
                               for i, (a, t) in enumerate(zip(amounts, totals))]
                    cases.append(("bounded_numeric_tied" if ties else "bounded_numeric_distinct", events,
                                  ("traffic_cumulative", "traffic_final", "traffic_timestamp_groups")))
    clocks = ("2020-01-01T00:00:00Z", "2020-01-01t01:00:00+01:00", "2020-01-01T00:00:00.0000000000001Z",
              "2019-12-31T23:59:59.999999999999999Z", "2020-01-02T00:00:00Z")
    roles = ("Start trip", "Permit FINAL_APPROVED by SUPERVISOR", "Permit FINAL_APPROVED by DIRECTOR")
    for order in permutations(roles):
        for stamps in product(clocks, repeat=3):
            cases.append(("temporal_permutation_repeat_approval", [
                {"concept:name": name, "time:timestamp": stamp} for name, stamp in zip(order, stamps)], ("travel_first_approval",)))
    for order in (("Start trip", "Start trip", "Permit FINAL_APPROVED by SUPERVISOR"),
                  ("Permit FINAL_APPROVED by SUPERVISOR", "Start trip", "Start trip")):
        for stamps in product(clocks, repeat=3):
            cases.append(("temporal_repeated_planned_start", [
                {"concept:name": name, "time:timestamp": stamp} for name, stamp in zip(order, stamps)], ("travel_first_approval",)))
    cases += [("base_nonapplicable", [{"concept:name": "Create Fine", "totalPaymentAmount": "0"}], ("traffic_cumulative",)),
              ("base_nonapplicable", [{"concept:name": "Other"}], ("travel_first_approval",)),
              ("base_missing_approval", [{"concept:name": "Start trip", "time:timestamp": clocks[0]}], ("travel_first_approval",)),
              ("numeric_over_28_digits", [{"concept:name": "Create Fine", "totalPaymentAmount": "1000000000000000000000000000000"},
                  {"concept:name": "Payment", "paymentAmount": ".000000000000000000000000000001",
                   "totalPaymentAmount": "1000000000000000000000000000000.000000000000000000000000000001"}], ("traffic_cumulative",))]
    for approval, start in (("0001-01-01T00:00:00+01:00", "0001-01-01T00:00:00Z"),
                            ("9999-12-31T23:59:59-01:00", "9999-12-31T23:59:59Z")):
        cases.append(("UTC_year_boundary", [{"concept:name": "Permit FINAL_APPROVED by SUPERVISOR", "time:timestamp": approval},
                                           {"concept:name": "Start trip", "time:timestamp": start}], ("travel_first_approval",)))
    grouped_truth = {}
    for index, (condition, events, contracts) in enumerate(cases):
        counts["fixtures"] += 1
        for contract in contracts:
            expected = direct_oracle(events, contract)
            assert expected != "unsupported"
            counts["fixture_contract_pairs"] += 1
            counts[f"oracle_{expected}"] += 1
            counts[f"condition_{condition}"] += 1
            for granularity, mode in product(("coarse", "fine"), ("cached", "json")):
                record = prepare_record(f"constructed/{index}", events, contract, granularity)
                results = {}
                for policy in POLICIES:
                    answer = evaluate(record, policy, mode, audit=True)
                    counts["policy_calls"] += 1
                    if answer.outcome != expected:
                        raise AssertionError((condition, contract, events, policy, answer, expected))
                    assert answer.queries == len(answer.trace)
                    assert answer.bytes == sum(len(record._wire[k]) for k in answer.trace)
                    results[policy] = answer
                if contract in MAIN.values():
                    assert results["hand_guard"].trace == results["generic_certificate"].trace
                result = results["generic_certificate"]
                observed = tuple((key, record._wire[key]) for key in result.trace)
                signature = (record.activities, contract, granularity, observed)
                grouped_truth.setdefault(signature, set()).add(expected)
    assert all(len(labels) == 1 for labels in grouped_truth.values())
    save(OUT / "counterfactuals.json", {"created_utc": datetime.now(timezone.utc).isoformat(),
        "implementation_sha256": provenance(), "counts": dict(counts), "oracle_disagreements": 0,
        "ambiguous_returned_certificate_groups": 0, "observed_certificate_groups": len(grouped_truth),
        "scope": "Wholly constructed bounded-domain fixtures, not additional real cases. Numeric initial values {0,1}, amounts/totals {-1,0,1}, lengths1–3, tied/distinct timestamps; temporal permutations with two approvals and repeated starts, exact ties, lowercase t/z, offset equivalence, sub-microsecond differences; explicit no-trigger and >28-digit fixtures.",
        "certificate_check": "Within this enumerated fixture domain, group by visible activity projection and actual queried block bytes. Each returned certificate group has exactly one independent-oracle outcome. This bounded check is not a completeness or optimality proof for arbitrary predicate domains.",
        "invalid_values": "Visible malformed/missing numbers, invalid dates/offsets, Unicode and hidden-later-invalid domain limitations are separately exercised by tests/test_external_contracts.py."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--stage", choices=("evaluate", "benchmark", "stress", "all"), default="evaluate")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20261007)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    source_records(args.fetch)
    if args.stage in ("evaluate", "all"):
        native()
        stress()
    if args.stage == "stress":
        stress()
    if args.stage in ("benchmark", "all"):
        benchmark(args.repeats, args.warmups, args.seed)


if __name__ == "__main__":
    main()
