"""Guard the streaming parser and the sensitivity-set denominator semantics."""
from io import StringIO
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import analyze_census_robustness as audit


@pytest.mark.parametrize("chunk_size", [1, 2, 7, 65536])
def test_streamed_json_handles_boundaries_and_unicode(chunk_size):
    value = {"a\\\"b": [["safe", [0]], ["insufficient", [3]]], "유": [12345, -4.25, True, None], "last": []}
    assert dict(audit.stream_object_items(StringIO(json.dumps(value)), chunk_size)) == value


@pytest.mark.parametrize("text", ['{"a":[],"a":[]}', '{"a":[]', '{"a":[],}', '{"a":[]} true', '{"a":[] "b":[]}'])
def test_streamed_json_rejects_broken_or_duplicate_input(text):
    with pytest.raises((ValueError, json.JSONDecodeError)):
        list(audit.stream_object_items(StringIO(text), 2))


def test_tally_counts_each_target_observation_once_and_masks_separately():
    rows = [["safe", [0]], ["stale_verdict", [0]], ["insufficient", [1]],
            ["insufficient", [2]], ["insufficient", [3]]]
    assert audit.tally(rows) == {
        "status_counts": {"safe": 1, "stale_verdict": 1, "insufficient": 3},
        "additional_requirements": {"P": 1, "T": 1, "PT": 1}, "rows": 5}


@pytest.mark.parametrize("rows", [[["insufficient", [0]]], [["safe", [1]]], [["insufficient", [1, 2]]], [["unknown", [0]]]])
def test_tally_rejects_wrong_diagnosis_or_noncartesian_robust_family(rows):
    with pytest.raises(ValueError):
        audit.tally(rows)


def test_exact_semantic_groups_and_intersection_keep_baseline_family():
    # z and a are aliases. b is baseline-equivalent, but stays eligible;
    # only c has an unsatisfiable profile. Selection never weights aliases.
    vectors = {"z": bytes([1, 0]), "c": bytes([0, 0]), "a": bytes([1, 0]), "b": bytes([0, 1])}
    groups = audit.exact_groups(vectors)
    assert groups == [["a", "z"], ["b"], ["c"]]
    valid = {"a", "z", "b"}
    for dedup, profile, expected in ((False, False, ["a", "b", "c", "z"]),
                                   (False, True, ["a", "b", "z"]),
                                   (True, False, ["a", "b", "c"]),
                                   (True, True, ["a", "b"])):
        assert audit.select_targets({"semantic_deduplication": dedup, "profile_filter": profile}, groups, valid) == expected
    summaries = {name: audit.tally([["safe", [0]], ["insufficient", [1]]]) for name in vectors}
    group_ids = {"a": "g1", "z": "g1", "b": "g2", "c": "g3"}
    result = audit.combine(["a", "b"], summaries, group_ids, 2)
    assert result["target_class_combinations"] == 4
    assert result["targets"] == result["semantic_families"] == 2
    assert result["status_counts"] == {"safe": 2, "stale_verdict": 0, "insufficient": 2}
