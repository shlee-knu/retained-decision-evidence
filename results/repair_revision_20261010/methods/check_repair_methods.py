#!/usr/bin/env python3
"""Independent native P/T cohort reconstruction; uses the Python standard library.

This checker imports no repair, diagnosis, raw-oracle or projection implementation.
It reads the original 50,931 receipts and public derivative, and reconstructs
Cartesian fibers from the declarative JSON catalog and native retained literals.
Selection and outcomes are therefore independent of the executor's class IDs.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
from functools import lru_cache
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
ACTIVITIES = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR",
            "2-way match", "Consignment")
SOURCE = "results/v03/bpi_compact.jsonl.gz"
RECEIPTS = "results/second/receipt_revalidation/native_receipts.jsonl.gz"
CATALOG = "examples/baseline_catalog.json"
TARGETS = ("edge_p0_a0_b1", "required_p2_a3", "edge_p2_a0_b2", "edge_p2_a2_b3")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def load_catalogs():
    old = json.loads((ROOT / CATALOG).read_text())
    catalogs = {"old": old}
    for target in TARGETS:
        body = deepcopy(old)
        parts = target.split("_")
        profile = PROFILES[int(parts[1][1:])]
        a = ACTIVITIES[int(parts[2][1:])]
        if parts[0] == "required":
            body[profile]["required"].remove(a)
        else:
            b = ACTIVITIES[int(parts[3][1:])]
            body[profile]["edges"].remove([a, b])
        catalogs[target] = body
    return catalogs


CATALOGS = load_catalogs()


def decision(base, profile, clocks, target):
    rule = CATALOGS[target][profile]
    if any(a not in base for a in rule["required"]) or any(a in base for a in rule["forbidden"]):
        return False
    for a, b in rule["edges"]:
        if b in base and (a not in base or base.index(a) >= base.index(b) or clocks[a] > clocks[b]):
            return False
    return True


def stamps(times):
    # The pinned native derivative has millisecond precision. This parser is
    # deliberately independent of the executor's general rational RFC3339 code.
    for value in times.values():
        if "." in value:
            assert len(value.split(".", 1)[1].rstrip("Z")) <= 6, "Native checker precision boundary"
    return {name: datetime.fromisoformat(value.replace("Z", "+00:00")) for name, value in times.items()}


def key(receipt):
    base = tuple(dict.fromkeys(receipt["activities"]))
    observed = receipt["observed"]
    if "first_times" in observed:
        times = stamps(observed["first_times"])
        levels = {value: index for index, value in enumerate(sorted(set(times.values())))}
        ranks = tuple(levels[times[name]] for name in base)
    else:
        ranks = None
    return base, observed.get("profile"), ranks


@lru_cache(None)
def completions(base, observed_profile, observed_ranks, target):
    if observed_ranks is None:
        ranks = (r for r in product(range(len(base)), repeat=len(base))
                 if not r or set(r) == set(range(max(r) + 1)))
    else:
        ranks = (observed_ranks,)
    profiles = PROFILES if observed_profile is None else (observed_profile,)
    return tuple((profile, times, decision(base, profile, dict(zip(base, times)), target))
                 for times in ranks for profile in profiles)


@lru_cache(None)
def inspect_query(query, target):
    base, profile, ranks = query
    before = completions(base, profile, ranks, "old")
    after = completions(base, profile, ranks, target)
    old_labels = sorted({row[2] for row in before})
    new_labels = sorted({row[2] for row in after})
    robust = []
    for add in range(4):
        if profile is not None and add & 1 or ranks is not None and add & 2:
            continue
        groups = defaultdict(set)
        for p, t, verdict in after:
            groups[(p if add & 1 else None, t if add & 2 else None)].add(verdict)
        if groups and all(len(labels) == 1 for labels in groups.values()):
            if not any(previous & add == previous for previous in robust):
                robust.append(add)
    return old_labels, new_labels, robust


def main():
    pins = {name: sha(ROOT / name) for name in (SOURCE, RECEIPTS, CATALOG)}
    assert pins[SOURCE] == "3fdfe926a29d35c87a2652447df420bb5c726ab2c996f6317c830d75cc4a1b3b"
    assert pins[RECEIPTS] == "d08fbc83a4ef278e750f200f0cd30c0c8683b86cda93ac544fecdb1bfec1ead0"
    selected = {}
    total = 0
    counts = Counter()
    with gzip.open(ROOT / RECEIPTS, "rt") as stream:
        for line in stream:
            receipt = json.loads(line)["receipt"]
            assert receipt["snapshot_sha256"] == pins[SOURCE]
            total += 1
            query = key(receipt)
            for target in TARGETS:
                old_labels, new_labels, robust = inspect_query(query, target)
                assert old_labels == [receipt["verdict"]], "Original receipt insufficient"
                if robust == [3]:
                    assert new_labels == [False, True]
                    assert receipt["observed"] == {}
                    identity = (target, receipt["receipt_id"])
                    assert identity not in selected
                    selected[identity] = {"target": target, "case_id": receipt["receipt_id"],
                                          "activities": receipt["activities"], "receipt": receipt}
                    counts[target] += 1
    assert total == 50931
    source_count = 0
    needed = {case for target, case in selected}
    source = {}
    with gzip.open(ROOT / SOURCE, "rt") as stream:
        for line in stream:
            case = json.loads(line)
            source_count += 1
            if case["case_id"] in needed:
                assert case["case_id"] not in source
                source[case["case_id"]] = case
    assert source_count == 251734 and set(source) == needed
    expected = []
    for (target, case_id), item in sorted(selected.items()):
        actual = source[case_id]
        assert actual["activities"] == item["activities"]
        receipt = item["receipt"]
        base = tuple(dict.fromkeys(actual["activities"]))
        after_p = completions(base, actual["profile"], None, target)
        candidates = sorted({row[2] for row in after_p})
        raw_target_verdict = decision(base, actual["profile"], stamps(actual["first_times"]), target)
        assert decision(base, actual["profile"], stamps(actual["first_times"]), "old") == receipt["verdict"]
        if len(candidates) == 1:
            assert candidates == [raw_target_verdict]
        expected.append({"target": target, "case_id": case_id, "profile": actual["profile"],
                         "activity_count": len(actual["activities"]), "base": list(base),
                         "old_verdict": receipt["verdict"], "new_verdict": raw_target_verdict,
                         "new_candidates_after_p": candidates,
                         "needs_t_after_p": len(candidates) == 2})
    stops = sum(not item["needs_t_after_p"] for item in expected)
    assert len(expected) == 114 and stops == 29
    expected_path = OUT / "independent_expected_cases.json"
    write(expected_path.name, expected)
    summary = {"status": "passed", "source_cases_scanned": source_count,
               "old_receipts_checked": total, "target_receipt_pairs_checked": total * len(TARGETS),
               "independent_query_target_evaluations": inspect_query.cache_info().currsize,
               "selected_by_target": {target: counts[target] for target in TARGETS},
               "selected_cases": len(expected), "unique_case_ids": len(needed),
               "p_first_stop": stops, "t_needed_after_p": len(expected) - stops,
               "all_available_logical_reads": len(expected) * 2 - stops,
               "all_available_new_verdicts": dict(Counter(str(x["new_verdict"]) for x in expected)),
               "p_only_expected": {"completed": stops, "unresolved": len(expected) - stops,
                                   "successful_reads": len(expected)},
               "robust_both_upfront_p_only_expected": {"completed": 0, "unresolved": len(expected),
                                                     "successful_reads": 0},
               "inputs": pins, "expected_cases_sha256": sha(expected_path),
               "checker_sha256": sha(Path(__file__)),
               "scope": "Independent stdlib reconstruction of the existing post hoc cohort and known 114/29/85 outcomes; no new holdout, prevalence, optimal-access or timing claim."}
    write("independent_population_check.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
