"""Check observation-only choices, unsupported domains and negative controls."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("retention", ROOT / "scripts/analyze_retention_robustness.py")
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


@pytest.fixture(scope="module")
def oracle():
    return retention.RawOracle(*[json.loads((ROOT / name).read_text()) for name in
                                ("examples/baseline_catalog.json", "examples/strict_consignment_catalog.json")])


def case(profile="3-way match, invoice after GR"):
    return {"activities": ["create", "receive", "invoice", "clear"], "profile": profile,
            "first_times": {name: f"2020-01-01T00:00:0{i}Z" for i, name in enumerate(retention.ALPHABET)}}


def test_old_true_does_not_remove_opposite_new_completion(oracle):
    raw = case()
    observed, reads, old = retention.acquire_old(raw["activities"], raw.__getitem__, oracle, "cartesian", "time_first", 2)
    assert reads == ["first_times"] and old
    assert oracle.labels(raw["activities"], observed, "cartesian", 1) == {False, True}
    action, _, added, label = retention.diagnose_and_repair(raw["activities"], observed, old, raw.__getitem__, oracle, "cartesian")
    assert (action, added, label) == ("acquire", ["profile"], True)


def test_full_retention_changes_boolean_without_acquisition(oracle):
    raw = case("Consignment")
    observed, reads, old = retention.acquire_old(raw["activities"], raw.__getitem__, oracle, "cartesian", "always_both", 2)
    action, _, added, label = retention.diagnose_and_repair(raw["activities"], observed, old, raw.__getitem__, oracle, "cartesian")
    assert reads == ["profile", "first_times"] and old
    assert (action, added, label) == ("update", [], False)


def test_exclusion_is_conditional_and_removes_this_ambiguity(oracle):
    raw = case()
    observed, _, old = retention.acquire_old(raw["activities"], raw.__getitem__, oracle, "consignment_exclusion", "time_first", 2)
    assert retention.diagnose_and_repair(raw["activities"], observed, old, raw.__getitem__, oracle, "consignment_exclusion")[0] == "retain"
    assert not retention.supported(case("Consignment"), "consignment_exclusion")


def test_base_only_stop_avoids_callback_but_full_policy_retains(oracle):
    raw = {"activities": [], "profile": "Consignment", "first_times": {}}
    def forbidden_read(_):
        raise AssertionError("No optional block is needed for this base")
    observed, reads, label = retention.acquire_old([], forbidden_read, oracle, "cartesian", "profile_first", 1)
    assert (observed, reads, label) == ({}, [], False)
    assert retention.acquire_old([], raw.__getitem__, oracle, "cartesian", "always_both", 1)[1] == ["profile", "first_times"]


def test_timestamp_offset_and_long_fraction_are_exact():
    assert retention.timestamp("2020-01-01T01:00:00.123456789+01:00") == retention.timestamp("2020-01-01T00:00:00.123456789Z")
    assert retention.timestamp("2020-01-01T00:00:00.123456789Z") < retention.timestamp("2020-01-01T00:00:00.123456790Z")


def test_invalid_old_boolean_cannot_be_repaired(oracle):
    raw = case()
    observed = {"profile": raw["profile"], "first_times": raw["first_times"]}
    with pytest.raises(AssertionError, match="Old observation"):
        retention.diagnose_and_repair(raw["activities"], observed, False, raw.__getitem__, oracle, "cartesian")
