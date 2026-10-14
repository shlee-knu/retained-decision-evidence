"""Post hoc descriptive referee check; never rewrites manuscript/source results.

Run from repository root with .venv/bin/python and a NEW output filename:
  .venv/bin/python results/panel_review_20261009/evidence_native_check.py OUTPUT
No live performance, organizational migration frequency, or independent holdout
is estimated. Old retention masks come from the archived authored policy.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
NAMES = ["create", "receive", "invoice", "clear"]
INPUTS = [
    "paper/manuscript_ieee_access_applied.md",
    "paper/supplement_ieee_access_applied.md",
    "examples/baseline_catalog.json",
    "results/v03/bpi_compact.jsonl.gz",
    "results/v03/acquisition_access_traces.jsonl.gz",
    "results/second/receipt_revalidation/native_receipts.jsonl.gz",
    "results/perspective_revision/inputs/census.json",
    "results/perspective_revision/coverage/native_challenge_classes.json",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads((ROOT / path).read_text())


def rows(path):
    with gzip.open(ROOT / path, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def weak_orders(n):
    # Independent exhaustive weak-order construction; n <= 4 here.
    if n == 0:
        return [()]
    return [r for r in product(range(n), repeat=n)
            if set(r) == set(range(max(r) + 1))]


def label(rules, base, ranks, profile):
    rule = rules[profile]
    positions = {name: index for index, name in enumerate(base)}
    if not set(rule["required"]).issubset(positions):
        return False
    if set(rule["forbidden"]).intersection(positions):
        return False
    for a, b in rule["edges"]:
        if b not in positions:
            continue
        if a not in positions or positions[a] >= positions[b]:
            return False
        if ranks[positions[a]] > ranks[positions[b]]:
            return False
    return True


def main(output):
    before = {name: digest(ROOT / name) for name in INPUTS}
    baseline = load("examples/baseline_catalog.json")
    profiles = list(baseline)
    changes = {
        "edge_p0_a0_b1": (0, "edges", ["create", "receive"]),
        "required_p2_a3": (2, "required", "clear"),
        "edge_p2_a0_b2": (2, "edges", ["create", "invoice"]),
        "edge_p2_a2_b3": (2, "edges", ["invoice", "clear"]),
    }
    catalogs = {}
    for target, (p, field, value) in changes.items():
        rules = deepcopy(baseline)
        rules[profiles[p]][field].remove(value)
        catalogs[target] = rules
    cases = load("results/perspective_revision/inputs/census.json")["two_block_cases"]
    candidates = defaultdict(list)
    for row in cases:
        assert row["query"]["mask"] == 0 and row["robust_masks"] == [3]
        base = tuple(NAMES[i] for i in row["query"]["base"])
        candidates[base].append(row["target"])
        # Check every selected two-block class using independently coded rules.
        states = [(p, ranks, label(catalogs[row["target"]], base, ranks, p))
                  for p in profiles for ranks in weak_orders(len(base))]
        assert {label(baseline, base, ranks, p) for p, ranks, _ in states} == {False}
        assert {v for _, _, v in states} == {False, True}
        by_p, by_t = defaultdict(set), defaultdict(set)
        for p, ranks, verdict in states:
            by_p[p].add(verdict)
            by_t[ranks].add(verdict)
        assert any(len(v) == 2 for v in by_p.values())
        assert any(len(v) == 2 for v in by_t.values())
    holdout = {}
    for row in rows("results/second/receipt_revalidation/native_receipts.jsonl.gz"):
        receipt = row["receipt"]
        assert receipt["receipt_id"] not in holdout
        holdout[receipt["receipt_id"]] = receipt
    cohorts = {scope: {target: {"counts": Counter(), "ids": set(), "profiles": Counter()}
                       for target in changes} for scope in ["full_archive", "heldout_receipts"]}
    n = 0
    for source, trace in zip(rows("results/v03/bpi_compact.jsonl.gz"),
                             rows("results/v03/acquisition_access_traces.jsonl.gz"), strict=True):
        n += 1
        case_id = source["case_id"]
        assert case_id == trace["case_id"]
        base = tuple(dict.fromkeys(source["activities"]))
        if trace["masks"]["permissive"]["structural_order"] != 0:
            continue
        for target in candidates.get(base, []):
            outcomes_after_p = {label(catalogs[target], base, ranks, source["profile"])
                                for ranks in weak_orders(len(base))}
            needs_t = len(outcomes_after_p) == 2
            for scope in ["full_archive"] + (["heldout_receipts"] if case_id in holdout else []):
                if scope == "heldout_receipts":
                    assert holdout[case_id]["observed"] == {}
                    assert holdout[case_id]["verdict"] is False
                item = cohorts[scope][target]
                item["ids"].add(case_id)
                item["counts"]["affected"] += 1
                item["counts"]["P_reads"] += 1
                item["counts"]["T_reads_after_P"] += int(needs_t)
                item["counts"]["stop_after_P"] += int(not needs_t)
                item["profiles"][source["profile"]] += 1
    out = {"analysis": "post hoc descriptive referee check",
           "scope": "Authored four-target changes applied to archived structural-order retention; no observed organizational migrations, live performance, or independent holdout.",
           "denominator_note": "Per-target denominators are 251734 full cases or 50931 held-out receipts. Four-target pair denominators are four times those counts. Unique affected IDs across targets are reported separately and are disjoint here.",
           "input_sha256": before, "script_sha256": digest(Path(__file__)),
           "cohorts": {}, "two_block_classes_independently_checked": len(cases)}
    for scope, targets in cohorts.items():
        union = set().union(*(item["ids"] for item in targets.values()))
        aggregates = sum((item["counts"] for item in targets.values()), Counter())
        denominator = n if scope == "full_archive" else len(holdout)
        out["cohorts"][scope] = {
            "case_denominator_per_target": denominator,
            "four_target_case_pairs": 4 * denominator,
            "distinct_affected_ids": len(union),
            "affected_target_case_pairs": aggregates["affected"],
            "P_first_additional_logical_reads": aggregates["P_reads"] + aggregates["T_reads_after_P"],
            "aggregates": dict(aggregates),
            "targets": {target: {"counts": dict(item["counts"]), "profiles": dict(item["profiles"]),
                         "sorted_affected_ids_sha256": hashlib.sha256("\n".join(sorted(item["ids"])).encode()).hexdigest()}
                        for target, item in targets.items()},
        }
    assert out["cohorts"]["full_archive"]["distinct_affected_ids"] == 524
    assert out["cohorts"]["heldout_receipts"]["distinct_affected_ids"] == 114
    recorded = load("results/perspective_revision/coverage/native_challenge_classes.json")
    for row in recorded["targets"]:
        assert sum(item["receipt_occurrences"] for item in row["affected_classes"]) == cohorts["heldout_receipts"][row["target"]]["counts"]["affected"]
    assert before == {name: digest(ROOT / name) for name in INPUTS}
    out["finished_utc"] = datetime.now(timezone.utc).isoformat()
    with output.open("x") as stream:
        json.dump(out, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps(out["cohorts"], indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
