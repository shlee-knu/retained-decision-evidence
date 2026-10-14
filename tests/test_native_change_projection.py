"""Independent small-domain and source-join checks for native projection."""
from copy import deepcopy
from itertools import product
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import analyze_native_change_projection as audit


def test_all_small_grid_functions_match_literal_outcome_and_projection_oracle():
    states = [((), (t,), p) for p in range(2) for t in range(3)]
    partitions = audit.oracle.group_states(states)
    for truth_code in range(64):
        truth = [bool(truth_code & (1 << i)) for i in range(6)]
        for key, fiber in partitions.items():
            indices = [i for i in range(6) if fiber & (1 << i)]
            outcomes = {truth[i] for i in indices}
            for old in (False, True):
                status, robust = audit.classify(key, fiber, truth_code, old, states)
                expected_status = ("insufficient" if len(outcomes) == 2 else
                                   "safe" if outcomes == {old} else "stale_verdict")
                assert status == expected_status
                resolving = []
                for mask in range(4):
                    if mask & key[1]:
                        continue
                    observations = {}
                    for i in indices:
                        value = (states[i][2] if mask & 1 else None, states[i][1] if mask & 2 else None)
                        observations.setdefault(value, set()).add(truth[i])
                    if all(len(labels) == 1 for labels in observations.values()):
                        resolving.append(mask)
                expected = [mask for mask in resolving if not any(other != mask and other | mask == mask for other in resolving)]
                assert robust == expected


def test_robust_two_blocks_can_stop_adaptively_after_one_value():
    states = [((), (t,), p) for p, t in product(range(2), repeat=2)]
    partitions = audit.oracle.group_states(states)
    key = ((), 0, None, None)
    positives = 1 << 3  # P=1 AND T=1: both blocks globally essential.
    assert audit.classify(key, partitions[key], positives, False, states) == ("insufficient", [3])
    assert audit.adaptive_reads(key, states[0], partitions, positives) == (["P"], False)
    assert audit.adaptive_reads(key, states[2], partitions, positives) == (["P", "T"], False)
    assert audit.adaptive_reads(key, states[3], partitions, positives) == (["P", "T"], True)


def source_fixture():
    source = {"case_id": "a", "activities": ["create", "receive", "receive"], "profile": "p0",
              "first_times": {"create": "2020-01-01T00:00:00Z", "receive": "2020-01-01T00:00:01Z"}}
    receipt = {"receipt_id": "a", "activities": list(source["activities"]),
               "observed": {"first_times": deepcopy(source["first_times"])} }
    trace = {"case_id": "a", "masks": {"permissive": {"structural_order": 2}}}
    return receipt, source, trace


def test_unread_profile_is_excluded_and_timestamp_rank_keeps_exact_subnanoseconds():
    receipt, source, trace = source_fixture()
    old = audit.check_source_match(receipt, source, trace, ["p0", "p1"])
    source["profile"] = "p1"
    assert audit.check_source_match(receipt, source, trace, ["p0", "p1"]) == old
    assert old == ((0, 1), 2, None, (0, 1))
    clocks = {"create": "2020-01-01T00:00:00.0000000002Z", "receive": "2020-01-01T00:00:00.0000000001Z"}
    assert audit.observation_key(["create", "receive"], {"first_times": clocks}, ["p0"])[-1] == (1, 0)
    assert audit.timestamp("2020-01-01T01:00:00+01:00") == audit.timestamp("2020-01-01T00:00:00Z")


@pytest.mark.parametrize("mutation", ["wrong_id", "wrong_mask", "wrong_literal", "activity_repetition", "incomplete_block"])
def test_source_binding_rejects_wrong_record_or_retained_evidence(mutation):
    receipt, source, trace = source_fixture()
    if mutation == "wrong_id":
        source["case_id"] = "b"
    elif mutation == "wrong_mask":
        trace["masks"]["permissive"]["structural_order"] = 0
    elif mutation == "wrong_literal":
        receipt["observed"]["first_times"]["create"] = "2020-01-01T00:00:02Z"
    elif mutation == "activity_repetition":
        receipt["activities"].pop()
    else:
        del receipt["observed"]["first_times"]["receive"]
    with pytest.raises(ValueError):
        audit.check_source_match(receipt, source, trace, ["p0", "p1"])


def test_union_ids_are_not_target_case_pairs_and_zero_targets_enter_median():
    summaries = {}
    for name, count in (("a", 2), ("b", 2), ("c", 0)):
        summaries[name] = {"status_counts": {"safe": 3-count, "stale_verdict": 0, "insufficient": count},
            "additional_requirements": {"P": count, "T": 0, "PT": 0},
            "adaptive_additional_reads": {"P": count, "T": 0, "total": count}}
    result = audit.selection_summary(["a", "b", "c"], summaries,
        {"a": {"x", "y"}, "b": {"y", "z"}, "c": set()},
        {"a": {1}, "b": {1, 2}, "c": set()}, 3)
    assert result["target_case_pairs"] == 9
    assert result["status_counts"]["insufficient"] == 4
    assert result["distinct_insufficient_case_ids"] == 3
    assert result["targets_with_insufficient_records"] == 2
    assert result["insufficient_records_per_target_all"] == {"minimum": 0, "median": 2, "maximum": 2}
    assert result["insufficient_records_per_target_nonzero"] == {"minimum": 2, "median": 2, "maximum": 2}
