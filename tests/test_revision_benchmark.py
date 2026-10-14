"""Regressions for challenge coverage and honest cost aggregation."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_revision_diagnostics as benchmark


def test_challenge_selection_keeps_every_insufficient_and_hash_controls():
    queries = [dict(base=[i], mask=0, observed=[], old_verdict=False) for i in range(9)]
    results = [("safe", [0])]*3 + [("stale_verdict", [0])]*3 + [("insufficient", [3])]*3
    spec = dict(control_statuses=["safe", "stale_verdict"], controls_per_status=1)
    actual = benchmark.selected_ids(queries, results, spec)
    rank = lambda i: hashlib.sha256(benchmark.encode(queries[i])).hexdigest()
    assert actual == sorted([min(range(3), key=rank), min(range(3, 6), key=rank), 6, 7, 8])


def test_two_blocks_required_when_opposed_pairs_exist_in_each_coordinate():
    states = [([0], [time], profile) for profile in range(2) for time in range(2)]
    query = dict(base=[0], mask=0, observed=[], old_verdict=False)
    assert benchmark.expected_result(query, list(range(4)), states, [False, False, False, True]) == ("insufficient", [3])
    assert benchmark.expected_result(query, list(range(4)), states, [False, False, True, True]) == ("insufficient", [1])


def test_old_classes_exclude_ambiguous_retained_observation():
    states = [([0], [0], 0), ([0], [0], 1)]
    queries, fibers = benchmark.old_classes(states, [False, True])
    assert {q["mask"] for q in queries} == {1, 3}
    assert len(queries) == 4
    assert all(len(f) == 1 for f in fibers)


def test_research_oracle_added_within_round_before_median(monkeypatch):
    monkeypatch.setattr(benchmark, "config", lambda: {"timing": {"measured_rounds": 3}})
    fields = ("input_loading", "input_normalization", "setup", "dependency_import", "core_setup",
              "first_report", "setup_plus_first", "core_setup_plus_first", "batch", "core_batch",
              "serialization", "independent_raw_validation")
    rows = []
    for method in ("a", "b"):
        for rnd, (generation, oracle) in enumerate(((1, 100), (2, 1), (100, 2))):
            row = dict(name="example", workload="unique", method=method, round=rnd,
                       suite="challenge", requests=1, diagnosed_classes=1, status_counts={"safe": 1},
                       process_peak_rss_kib={"after_batch": 20})
            row.update({field: {"cpu_ns": generation, "wall_ns": generation} for field in fields})
            row["independent_raw_validation"] = {"cpu_ns": oracle, "wall_ns": oracle}
            rows.append(row)
    result = benchmark.summarize(rows, [("example", "unique")], ["a", "b"])[0]
    assert result["methods"]["a"]["core_plus_research_oracle"]["cpu_ns"] == 101
    assert result["methods"]["a"]["round_costs_ns"]["core_plus_research_oracle"]["cpu_ns"] == [101, 3, 102]
    assert result["paired_deltas"]["a_minus_b"]["core_plus_research_oracle"]["cpu_ns"] == [0, 0, 0]
