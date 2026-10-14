"""Guard against target/record confusion and incomplete workload summaries."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import draw_native_change_impact as figure


def fixture_target(safe=3, stale=0, insufficient=0, preserved=0):
    statuses = {"safe": safe, "stale_verdict": stale, "insufficient": insufficient}
    return {"native_cases": sum(statuses.values()), "status_counts": statuses,
            "complete_input_verdict_changes": stale + insufficient - preserved,
            "insufficient_records_with_preserved_complete_verdict": preserved,
            "native_observation_classes": [
                {"census_class_id": i, "native_records": count, "status": status}
                for i, (status, count) in enumerate(statuses.items()) if count]}


def test_cross_tab_is_target_level_and_includes_zero_workloads():
    # 'both' has one changed stale record and a DIFFERENT insufficient record
    # with its complete-input verdict preserved. Still the target is yes/yes.
    targets = {"neither": fixture_target(),
               "verdict": fixture_target(safe=2, stale=1),
               "evidence": fixture_target(safe=2, insufficient=1, preserved=1),
               "both": fixture_target(safe=1, stale=1, insufficient=1, preserved=1)}
    result = figure.summarize(targets, list(targets))
    assert [row["targets"] for row in result["cross_tab"]] == [1, 1, 1, 1]
    assert result["workload_frequencies"] == [
        {"insufficient_records_per_target": 0, "targets": 2},
        {"insufficient_records_per_target": 1, "targets": 2}]
    assert result["target_count"] == 4
    assert result["native_records_per_target"] == 3
    assert result["insufficient_target_record_pairs"] == 2


@pytest.mark.parametrize("mutation", ["duplicate_target", "wrong_class_count", "duplicate_class", "wrong_changed_count"])
def test_inconsistent_source_aggregates_are_rejected(mutation):
    target = deepcopy(fixture_target(safe=1, stale=1, insufficient=1, preserved=1))
    names = ["a"]
    if mutation == "duplicate_target":
        names.append("a")
    elif mutation == "wrong_class_count":
        target["native_observation_classes"][0]["native_records"] += 1
    elif mutation == "duplicate_class":
        target["native_observation_classes"][1]["census_class_id"] = 0
    else:
        target["complete_input_verdict_changes"] = 0
    with pytest.raises(ValueError):
        figure.summarize({"a": target}, names)
