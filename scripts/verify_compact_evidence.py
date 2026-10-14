"""Read-only reproduction of the compact revision's three evidence additions.

Run from the repository root:
  .venv/bin/python scripts/verify_compact_evidence.py --output NEW_DIRECTORY

No repository modules are imported. The finite state enumeration and its block
encoding are shared declared inputs, but raw rule evaluation, observation
grouping, status classification, and robust-set derivation are written here.
The old truth/result ledgers are comparison targets, never answer inputs.
Performance intervals are read from the saved run; this is not a new benchmark.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
ACTIVITIES = ("create", "receive", "invoice", "clear")
INPUTS = [
    "examples/baseline_catalog.json",
    "configs/revision_diagnostic_protocol.json",
    "results/strong/catalog_audit/finite_tables.json.gz",
    "results/perspective_revision/inputs/observation_classes.json",
    "results/perspective_revision/inputs/saved_census_rows.json.gz",
    "results/perspective_revision/inputs/census.json",
    "results/perspective_revision/diagnostics/timings.json",
    "results/v03/bpi_compact.jsonl.gz",
    "results/v03/acquisition_access_traces.jsonl.gz",
    "results/second/receipt_revalidation/native_receipts.jsonl.gz",
    "results/panel_review_20261009/evidence_native_check.py",
    "results/panel_review_20261009/evidence_native_check.json",
    "results/panel_review_20261009/root_descriptive_checks.json",
]
CONTEXT_CODE = [
    "scripts/benchmark_revision_diagnostics.py",
    "src/logistics_validation/catalog_audit.py",
    "src/logistics_validation/focused_diagnostics.py",
    "src/logistics_validation/revision_diagnostics.py",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name):
    path = ROOT / name
    with gzip.open(path, "rt") if path.suffix == ".gz" else path.open() as stream:
        return json.load(stream)


def jsonl(name):
    with gzip.open(ROOT / name, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def save(path, obj):
    with path.open("x") as stream:
        json.dump(obj, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def raw_label(catalog, activities, clocks, profile):
    """Evaluate declared atoms on named events, without certificate helpers.

    All required/forbidden atoms and all edges are evaluated, including edges
    whose target is absent. First-event positions and clocks are independent.
    """
    rule = catalog[profile]
    requirements = [name in activities for name in rule["required"]]
    exclusions = [name not in activities for name in rule["forbidden"]]
    precedence = []
    for earlier, later in rule["edges"]:
        if later not in activities:
            precedence.append(True)
        elif earlier not in activities:
            precedence.append(False)
        else:
            precedence.append(activities.index(earlier) < activities.index(later)
                              and clocks[earlier] <= clocks[later])
    return all(requirements + exclusions + precedence)


def declared_targets(baseline):
    """Expand the declared single-edit grammar directly on named JSON rules."""
    targets = {}
    for p, profile in enumerate(baseline):
        for field in ("required", "forbidden", "edges"):
            atoms = (list(product(ACTIVITIES, repeat=2)) if field == "edges"
                     else list(ACTIVITIES))
            for atom in atoms:
                if field == "edges" and atom[0] == atom[1]:
                    continue
                changed = deepcopy(baseline)
                value = list(atom) if field == "edges" else atom
                values = changed[profile][field]
                if value in values:
                    # The declared forbidden edits are additions only.
                    assert field != "forbidden"
                    values.remove(value)
                else:
                    values.append(value)
                if field == "edges":
                    name = f"edge_p{p}_a{ACTIVITIES.index(atom[0])}_b{ACTIVITIES.index(atom[1])}"
                else:
                    name = f"{field}_p{p}_a{ACTIVITIES.index(atom)}"
                targets[name] = changed
    return targets


def state_bits(indices):
    bits = 0
    for index in indices:
        bits |= 1 << index
    return bits


def bit_indices(bits):
    while bits:
        smallest = bits & -bits
        yield smallest.bit_length() - 1
        bits ^= smallest


def group_states(states):
    """Build all four observation partitions once, as membership bitsets."""
    groups = defaultdict(int)
    for i, (base, ranks, profile) in enumerate(states):
        for reveal_profile, reveal_time in product((False, True), repeat=2):
            mask = int(reveal_profile) + 2 * int(reveal_time)
            key = (base, mask, profile if reveal_profile else None,
                   ranks if reveal_time else None)
            groups[key] |= 1 << i
    return dict(groups)


def query_key(query):
    """Decode the saved JSON wire shape only; do not infer any verdict."""
    mask = query["mask"]
    observed = query["observed"]
    assert mask in range(4)
    assert len(observed) == mask.bit_count()
    return (tuple(query["base"]), mask,
            observed[0] if mask & 1 else None,
            tuple(observed[-1]) if mask & 2 else None)


def difference_masks(positive, negative, states):
    """Compute opposed-pair difference types in linear, not quadratic, time.

    States in one observation class have the same structural base. An opposed
    pair can differ only in P (mask 1), only in T (2), or both (3). Count pairs
    agreeing on P or T by joins of their marginal counts. An opposed pair
    cannot agree on both because the declared state tuples are unique.
    """
    pp, pt, np, nt = Counter(), Counter(), Counter(), Counter()
    for bits, profiles, times in ((positive, pp, pt), (negative, np, nt)):
        for i in bit_indices(bits):
            _, ranks, profile = states[i]
            profiles[profile] += 1
            times[ranks] += 1
    equal_profile = sum(count * np[value] for value, count in pp.items())
    equal_time = sum(count * nt[value] for value, count in pt.items())
    both_different = positive.bit_count() * negative.bit_count() - equal_profile - equal_time
    assert both_different >= 0
    return tuple(mask for mask, count in ((1, equal_time), (2, equal_profile),
                                          (3, both_different)) if count)


def hit_all_differences(differences, observed_mask):
    """Minimal additional masks must hit every opposed-pair difference."""
    assert differences and all(d & observed_mask == 0 for d in differences)
    minimum = []
    for candidate in (0, 1, 2, 3):
        if candidate & observed_mask:
            continue
        if all(candidate & difference for difference in differences):
            if not any(candidate & earlier == earlier for earlier in minimum):
                minimum.append(candidate)
    return minimum


def check_pair_join():
    """Check the linear pair join against literal opposed pairs on a tiny grid.

    All 64 Boolean functions on a 2 by 3 product and every observation class
    are covered, including non-Boolean block values and alternative robust sets.
    """
    states = [((), (t,), p) for p in range(2) for t in range(3)]
    groups = group_states(states)
    checked = 0
    for labels in range(64):
        for (_, mask, _, _), fiber in groups.items():
            yes, no = fiber & labels, fiber & ~labels
            if not yes or not no:
                continue
            literal = set()
            for i in bit_indices(yes):
                for j in bit_indices(no):
                    literal.add(int(states[i][2] != states[j][2])
                                + 2 * int(states[i][1] != states[j][1]))
            actual = difference_masks(yes, no, states)
            assert set(actual) == literal
            # Independently check each proposed acquisition by disjoint
            # positive/negative projections, then remove strict supersets.
            resolving = []
            for add in range(4):
                if add & mask:
                    continue
                def values(bits):
                    return {(states[i][2] if add & 1 else None,
                             states[i][1] if add & 2 else None)
                            for i in bit_indices(bits)}
                if values(yes).isdisjoint(values(no)):
                    resolving.append(add)
            want = [a for a in resolving if not any(b != a and b | a == a for b in resolving)]
            assert hit_all_differences(actual, mask) == want
            checked += 1
    return {"tiny_grid_functions": 64, "mixed_observation_checks": checked,
            "pair_join_and_minimal_hitting_masks": "passed"}


def independent_census(output, log):
    table = load("results/strong/catalog_audit/finite_tables.json.gz")
    states = [(tuple(b), tuple(t), p) for b, t, p in table["states"]]
    assert len(states) == len(set(states)) == 8612
    baseline = load("examples/baseline_catalog.json")
    profiles = list(baseline)
    raw = [(tuple(ACTIVITIES[a] for a in b),
            {ACTIVITIES[a]: rank for a, rank in zip(b, t)}, profiles[p])
           for b, t, p in states]
    old_labels = [raw_label(baseline, *record) for record in raw]
    old_true = state_bits(i for i, label in enumerate(old_labels) if label)
    partitions = group_states(states)
    classes = {}
    for key, fiber in partitions.items():
        positive = fiber & old_true
        if positive == 0 or positive == fiber:
            classes[key] = (fiber, positive == fiber)
    assert len(classes) == 10436
    targets = declared_targets(baseline)
    assert len(targets) == 80

    # Derive the entire answer map before loading any saved census answers.
    derived, summaries, two_block, truth_checks = {}, [], [], 0
    for name, catalog in sorted(targets.items()):
        labels = [raw_label(catalog, *record) for record in raw]
        positives = state_bits(i for i, value in enumerate(labels) if value)
        rows, statuses, cardinalities, families = {}, Counter(), Counter(), Counter()
        for key, (fiber, old_verdict) in classes.items():
            yes = fiber & positives
            if yes == 0 or yes == fiber:
                answer = ("safe" if (yes == fiber) == old_verdict else "stale_verdict", (0,))
            else:
                robust = tuple(hit_all_differences(difference_masks(yes, fiber ^ yes, states), key[1]))
                answer = ("insufficient", robust)
                cardinalities.update(m.bit_count() for m in robust)
                families[",".join(map(str, robust))] += 1
                if robust == (3,):
                    assert key[1] == 0
                    two_block.append({"target": name, "base": list(key[0]), "mask": 0,
                                      "old_verdict": old_verdict, "robust_masks": [3]})
            rows[key] = answer
            statuses[answer[0]] += 1
        derived[name] = rows
        # Saved truth vectors are comparison targets only, after derivation.
        assert labels == [bool(v) for v in table["catalogs"][name]["labels"]], name
        truth_checks += len(labels)
        summaries.append({"target": name, "status_counts": dict(statuses),
                          "insufficient_robust_cardinalities": dict(cardinalities),
                          "insufficient_robust_families": dict(families)})
    assert old_labels == [bool(v) for v in table["catalogs"]["baseline"]["labels"]]

    queries = load("results/perspective_revision/inputs/observation_classes.json")
    saved = load("results/perspective_revision/inputs/saved_census_rows.json.gz")
    keys = [query_key(q) for q in queries]
    assert len(keys) == len(set(keys)) and set(keys) == set(classes)
    assert all(q["old_verdict"] == classes[key][1] for q, key in zip(queries, keys))
    assert set(saved) == set(derived)
    checked, mismatches, row_digest = 0, [], hashlib.sha256()
    for name in sorted(derived):
        assert len(saved[name]) == len(keys)
        for i, key in enumerate(keys):
            status, robust = derived[name][key]
            actual = [status, list(robust)]
            row_digest.update(json.dumps([name, i, actual], separators=(",", ":")).encode() + b"\n")
            if actual != saved[name][i]:
                mismatches.append({"target": name, "class_id": i,
                                   "derived": actual, "saved": saved[name][i]})
            checked += 1
    result = {
        "status": "passed" if not mismatches else "failed",
        "states": len(states), "targets": len(targets), "old_valid_classes": len(classes),
        "raw_old_truth_labels_compared": len(old_labels),
        "raw_target_truth_labels_compared": truth_checks,
        "target_class_status_and_complete_robust_family_comparisons": checked,
        "status_counts": dict(sum((Counter(s["status_counts"]) for s in summaries), Counter())),
        "insufficient_robust_cardinalities": dict(sum((Counter(s["insufficient_robust_cardinalities"]) for s in summaries), Counter())),
        "two_block_classes": two_block,
        "failures": len(mismatches), "mismatches": mismatches,
        "derived_rows_in_saved_class_order_sha256": row_digest.hexdigest(),
        "per_target": summaries,
        "algorithm": "Independent named-atom raw predicates; observation membership bitsets; truth-bit intersections for status; linear marginal joins recover opposed-pair difference types; minimal hitting masks give complete robust sets.",
        "independence": {
            "repository_modules_imported": [],
            "separately_written": ["single-edit catalog construction", "raw predicates", "observation grouping", "old-valid class selection", "status classification", "complete robust-family derivation"],
            "shared_declared_inputs": ["saved finite state enumeration", "four-activity and profile/rank block interpretation", "baseline JSON rules", "80-single-edit grammar", "saved observation JSON encoding for comparison"],
            "comparison_only": ["saved truth labels", "saved observation/verdict ledger", "saved census status/robust rows"],
            "limitations": "Finite declared procurement domain only; no independent proof of domain completeness, encoder adequacy, raw-log fidelity, solver independence, or organizational representativeness. This run compares census answers, not 834880 executions of each engine."
        },
    }
    save(output / "independent_census.json", result)
    log(f"Independent census: {checked} status/complete-robust rows; {len(mismatches)} mismatches")
    assert not mismatches
    assert result["status_counts"] == {"safe": 821432, "stale_verdict": 10913, "insufficient": 2535}
    return result, states, targets, two_block


def native_check(output, states, catalogs, two_block, log):
    """Recount archived affected IDs using newly derived two-block classes."""
    selected = ("edge_p0_a0_b1", "required_p2_a3", "edge_p2_a0_b2", "edge_p2_a2_b3")
    candidates = defaultdict(list)
    for row in two_block:
        assert row["target"] in selected
        candidates[tuple(ACTIVITIES[i] for i in row["base"])].append(row["target"])
    profiles = list(load("examples/baseline_catalog.json"))
    after_p = {}
    for row in two_block:
        target, base = row["target"], tuple(row["base"])
        activities = tuple(ACTIVITIES[i] for i in base)
        for p, profile in enumerate(profiles):
            outcomes = set()
            for b, ranks, sp in states:
                if b == base and sp == p:
                    clocks = dict(zip(activities, ranks))
                    outcomes.add(raw_label(catalogs[target], activities, clocks, profile))
            assert outcomes
            after_p[target, activities, profile] = len(outcomes) == 2
    retained = {}
    for row in jsonl("results/second/receipt_revalidation/native_receipts.jsonl.gz"):
        receipt = row["receipt"]
        assert receipt["receipt_id"] not in retained
        retained[receipt["receipt_id"]] = receipt
    cohorts = {scope: {target: {"counts": Counter(), "profiles": Counter(), "ids": set()}
                       for target in selected} for scope in ("full_archive", "heldout_receipts")}
    seen = set()
    for source, trace in zip(jsonl("results/v03/bpi_compact.jsonl.gz"),
                             jsonl("results/v03/acquisition_access_traces.jsonl.gz"), strict=True):
        case_id = source["case_id"]
        assert case_id == trace["case_id"] and case_id not in seen
        seen.add(case_id)
        activities = tuple(dict.fromkeys(source["activities"]))
        if trace["masks"]["permissive"]["structural_order"] != 0:
            continue
        for target in candidates[activities]:
            needs_time = after_p[target, activities, source["profile"]]
            for scope in ["full_archive"] + (["heldout_receipts"] if case_id in retained else []):
                if scope == "heldout_receipts":
                    assert retained[case_id]["observed"] == {} and retained[case_id]["verdict"] is False
                item = cohorts[scope][target]
                item["ids"].add(case_id)
                item["profiles"][source["profile"]] += 1
                item["counts"].update({"affected": 1, "P_reads": 1,
                                       "T_reads_after_P": int(needs_time),
                                       "stop_after_P": int(not needs_time)})
    assert set(retained) <= seen
    actual = {}
    for scope, by_target in cohorts.items():
        counts = sum((v["counts"] for v in by_target.values()), Counter())
        denominator = len(seen) if scope == "full_archive" else len(retained)
        ids = set().union(*(v["ids"] for v in by_target.values()))
        actual[scope] = {
            "case_denominator_per_target": denominator,
            "four_target_case_pairs": 4 * denominator,
            "distinct_affected_ids": len(ids),
            "affected_target_case_pairs": counts["affected"],
            "P_first_additional_logical_reads": counts["P_reads"] + counts["T_reads_after_P"],
            "aggregates": dict(counts),
            "targets": {target: {"counts": dict(item["counts"]), "profiles": dict(item["profiles"]),
                         "sorted_affected_ids_sha256": hashlib.sha256("\n".join(sorted(item["ids"])).encode()).hexdigest()}
                        for target, item in by_target.items()},
        }
        assert len(ids) == counts["affected"]  # Target ID sets are disjoint here.
    previous = load("results/panel_review_20261009/evidence_native_check.json")
    matches = actual == previous["cohorts"]
    result = {"status": "passed" if matches else "failed", "cohorts": actual,
              "matches_panel_check_including_target_id_hashes": matches,
              "two_block_classes_derived_by_new_census": len(two_block),
              "scope": "Post hoc descriptive recount of four authored changes and archived structural-order retention. Full archive is not a new independent holdout; no organizational migration or performance claim. Robust {P,T} guarantees every completion; P-first may stop after P for a particular observed value.",
              "previous_analysis": "results/panel_review_20261009/evidence_native_check.py and .json"}
    save(output / "native_check.json", result)
    log(f"Native recount: {actual['heldout_receipts']['aggregates']}; full archive: {actual['full_archive']['aggregates']}; panel match={matches}")
    assert matches
    return result


def timing_sums(output, log):
    rows = load("results/perspective_revision/diagnostics/timings.json")
    grouped = defaultdict(list)
    for row in rows:
        if row["phase"] != "measured":
            continue
        assert row["failures"] == 0
        grouped[row["name"], row["workload"], row["method"]].append(row)
    def median(values):
        assert len(values) == 5
        return sorted(values)[2]
    cells = []
    for name, workload in sorted({(n, w) for n, w, m in grouped}):
        methods = {}
        for method in ("finite_fibers", "incremental_smt", "direct_residual"):
            runs = sorted(grouped[name, workload, method], key=lambda r: r["round"])
            assert [r["round"] for r in runs] == list(range(5))
            intervals = []
            for row in runs:
                interval = {"round": row["round"]}
                for scale in ("cpu_ns", "wall_ns"):
                    parts = {part: row[part][scale] for part in ("input_loading", "input_normalization", "batch")}
                    interval[scale] = {**parts, "sum": sum(parts.values()),
                                       "core_batch": row["core_batch"][scale]}
                intervals.append(interval)
            methods[method] = {"rounds": 5, "per_round_disjoint_intervals": intervals}
            for scale in ("cpu", "wall"):
                methods[method][f"{scale}_ms_median_of_recorded_loading_normalization_cold_batch_sum"] = median([v[f"{scale}_ns"]["sum"] for v in intervals]) / 1e6
                methods[method][f"{scale}_ms_core_batch_median"] = median([v[f"{scale}_ns"]["core_batch"] for v in intervals]) / 1e6
        metric = "cpu_ms_median_of_recorded_loading_normalization_cold_batch_sum"
        cells.append({"name": name, "workload": workload, "methods": methods,
                      "minimum_sum_method": min(methods, key=lambda m: methods[m][metric])})
    assert len(cells) == 18
    panel = load("results/panel_review_20261009/root_descriptive_checks.json")
    previous = {(c["name"], c["workload"]): c for c in panel["cells"]}
    for cell in cells:
        prior = previous[cell["name"], cell["workload"]]
        assert cell["minimum_sum_method"] == prior["minimum_sum_method"]
        for method, values in prior["methods"].items():
            assert all(cell["methods"][method][key] == value for key, value in values.items())
    strict = next(c for c in cells if c["name"] == "procurement_strict" and c["workload"] == "weighted")
    residual, finite = strict["methods"]["direct_residual"], strict["methods"]["finite_fibers"]
    reductions = {"generation_core_only": 100 * (finite["cpu_ms_core_batch_median"] - residual["cpu_ms_core_batch_median"]) / finite["cpu_ms_core_batch_median"],
                  "recorded_loading_normalization_cold_batch_sum": 100 * (finite[metric] - residual[metric]) / finite[metric]}
    result = {"status": "passed", "cells": cells, "measured_rows": sum(map(len, grouped.values())),
              "warmup_rows_excluded": sum(r["phase"] != "measured" for r in rows),
              "minimum_sum_wins": dict(Counter(c["minimum_sum_method"] for c in cells)),
              "strict_weighted_residual_reduction_vs_finite_percent": reductions,
              "matches_all_panel_cpu_summaries": True,
              "scope": "Post hoc sums within each saved measured round, then median across five rounds. No fresh benchmark. Batch includes setup, cold dependency import and serialization; serialization is not added again. Source recovery, hardened portable-envelope validation, durable writes and service overhead are excluded."}
    save(output / "timing_sums.json", result)
    log(f"Saved timing sums: 18 cells, 270 measured rows; strict weighted residual={residual[metric]:.6f} ms, finite={finite[metric]:.6f} ms")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/compact_revision/evidence")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started, start = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    before = {name: digest(ROOT / name) for name in INPUTS + CONTEXT_CODE}
    script_hash = digest(Path(__file__))
    with (output / "run.log").open("x") as stream:
        def log(message):
            print(message, flush=True)
            stream.write(message + "\n")
            stream.flush()
        try:
            selfcheck = check_pair_join()
            log(f"Pair-join selfcheck: {selfcheck}")
            census, states, targets, two_block = independent_census(output, log)
            native = native_check(output, states, targets, two_block, log)
            timing = timing_sums(output, log)
            assert before == {name: digest(ROOT / name) for name in INPUTS + CONTEXT_CODE}
            summary = {"status": "passed", "failures": 0, "selfcheck": selfcheck,
                       "census": {k: census[k] for k in ("states", "targets", "old_valid_classes", "target_class_status_and_complete_robust_family_comparisons", "status_counts", "insufficient_robust_cardinalities")},
                       "native_cohorts": {k: {key: row[key] for key in ("case_denominator_per_target", "four_target_case_pairs", "distinct_affected_ids", "P_first_additional_logical_reads", "aggregates")} for k, row in native["cohorts"].items()},
                       "timing_cells": len(timing["cells"]), "minimum_sum_wins": timing["minimum_sum_wins"],
                       "strict_weighted_residual_reduction_vs_finite_percent": timing["strict_weighted_residual_reduction_vs_finite_percent"]}
            save(output / "summary.json", summary)
            log("All compact evidence checks passed; immutable input hashes unchanged.")
        except Exception as exc:
            log(traceback.format_exc())
            save(output / "failure.json", {"status": "failed", "exception": repr(exc)})
            raise
        finally:
            stream.flush()
            save(output / "manifest.json", {
                "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
                "verification_elapsed_seconds_not_a_benchmark": time.perf_counter() - start,
                "python": platform.python_version(),
                "command": [sys.executable, "scripts/verify_compact_evidence.py", "--output", str(output)],
                "script_sha256": script_hash,
                "input_sha256": {name: before[name] for name in INPUTS},
                "nonimported_context_code_sha256": {name: before[name] for name in CONTEXT_CODE},
                "output_sha256": {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()},
            })


if __name__ == "__main__":
    main()
