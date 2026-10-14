"""Semantic and hidden-read tests for the new receipt migration boundary."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import revalidate_receipt as tool
from compare_catalogs import read_catalog
from logistics_validation.catalog_audit import ALPHABET, PROFILES, concrete, reference_verdict
from stress_acquisition import raw_time

SPECS = json.loads((ROOT / "examples/second_receipt_cases.json").read_text())["cases"]


def engine(spec):
    return tool.Revalidator(read_catalog(ROOT / spec["before_catalog"]), read_catalog(ROOT / spec["after_catalog"]),
                            spec["before_domain"], spec["after_domain"], spec["receipt"]["snapshot_sha256"])


def named(name):
    return deepcopy(next(s for s in SPECS if s["name"] == name))


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s["name"])
def test_constructed_classifications_and_literal_witnesses(spec):
    checker = engine(spec)
    result = checker.revalidate(spec["receipt"])
    assert result["status"] == spec["expected_status"]
    tool.verify_concrete(result, spec["receipt"], checker.before, checker.after)
    if result["status"] == "insufficient":
        assert {w["after_verdict"] for w in result["compatible_new_completions"]} == {True, False}
    if spec["name"].startswith("withdraw_"):
        assert any(not w["before_domain_member"] for w in result["compatible_new_completions"])
    assert "does not establish hidden-domain membership" in result["conditional_scope"]


@pytest.mark.parametrize("field,value", [
    ("catalog_sha256", "f" * 64), ("snapshot_sha256", "f" * 64),
    ("domain_version", "both:v1"), ("domain_version", "cartesian:v2"),
    ("verdict", 1), ("schema_version", True), ("activities", ["unknown"]),
    ("profile", "Consignment"),
])
def test_invalid_schema_or_binding_rejected(field, value):
    spec = named("identity_full_receipt")
    receipt = deepcopy(spec["receipt"])
    receipt[field] = value
    with pytest.raises(ValueError):
        engine(spec).revalidate(receipt)


@pytest.mark.parametrize("bad", ["2018-01-02T21:36:60Z", "2018-01-02T21:36:00-00:00", "2018-01-02T21:36:00", "２０１８-01-02T21:36:00Z"])
def test_observed_clock_domain_strict(bad):
    spec = named("identity_full_receipt")
    spec["receipt"]["observed"]["first_times"]["create"] = bad
    with pytest.raises(ValueError):
        engine(spec).revalidate(spec["receipt"])


@pytest.mark.parametrize("extra", [False, True])
def test_t_block_must_match_visible_activity_set(extra):
    spec = named("identity_full_receipt")
    if extra:
        spec["receipt"]["observed"]["first_times"]["unseen"] = "2020-01-01T00:00:00Z"
    else:
        del spec["receipt"]["observed"]["first_times"]["invoice"]
    with pytest.raises(ValueError):
        engine(spec).revalidate(spec["receipt"])


@pytest.mark.parametrize("domain", list(tool.DOMAIN_VERSIONS))
def test_identity_never_invalidates_valid_partial_receipt(domain):
    spec = named("identity_full_receipt")
    spec["before_domain"] = spec["after_domain"] = domain
    spec["receipt"]["domain_version"] = domain
    assert engine(spec).revalidate(spec["receipt"])["status"] == "safe"


def test_recovery_reads_only_missing_profile_and_preserves_literals():
    spec = named("original_catalog_migration")
    checker = engine(spec)
    before = deepcopy(spec["receipt"])
    requested = []

    def fetch(name):
        requested.append(name)
        assert name == "profile"
        return "3-way match, invoice after GR"

    result = checker.recover(before, fetch)
    assert result["status"] == "safe" and result["verdict"] is True
    assert requested == result["requested_blocks"] == ["profile"]
    assert before == spec["receipt"]
    assert result["retained_observed"]["first_times"] == before["observed"]["first_times"]


@pytest.mark.parametrize("name", ["equivalent_catalog_safe", "label_flip_remains_fully_sufficient",
                                  "new_domain_excludes_complete_observation", "old_domain_empty_not_vacuously_valid"])
def test_determined_or_invalid_receipt_never_reads_hidden_values(name):
    spec = named(name)

    def forbidden_read(_):
        raise AssertionError("An unneeded hidden read occurred")

    result = engine(spec).recover(spec["receipt"], forbidden_read)
    assert result["requested_blocks"] == []
    assert result["status"] == spec["expected_status"]


def test_recovery_after_withdrawal_evaluates_new_domain_only():
    spec = named("withdraw_chronological_same_catalog")
    checker = engine(spec)
    reversed_times = {"create": "2020-01-01T00:00:01.000000001Z",
                      "receive": "2020-01-01T00:00:01.000000000Z",
                      "invoice": "2020-01-01T00:00:02Z", "clear": "2020-01-01T00:00:03Z"}
    calls = []

    def fetch(name):
        calls.append(name)
        assert name == "first_times"
        return reversed_times

    result = checker.recover(spec["receipt"], fetch)
    assert calls == ["first_times"]
    assert result["status"] == "stale_verdict" and result["verdict"] is False
    assert result["old_domain_still_compatible"] is False
    # The historical receipt remains valid conditionally. New observations expose
    # an old-guarantee violation; they are not retrospectively its observed data.
    assert checker.revalidate(spec["receipt"])["status"] == "insufficient"


def test_partial_safe_does_not_check_hidden_admission():
    spec = named("narrowing_common_observation_safe")
    # No unknown P value can be read from a receipt that only retains T.
    result = engine(spec).revalidate(spec["receipt"])
    assert result["status"] == "safe"
    assert "actual input belonging" in result["conditional_scope"]


def independent_membership(value, domain):
    times = [raw_time(value["first_times"][a]) for a in dict.fromkeys(value["activities"])]
    chrono = all(a <= b for a, b in zip(times, times[1:]))
    exclusion = value["profile"] != "Consignment" or not set(value["activities"]) & {"invoice", "clear"}
    return {"cartesian:v1": True, "chronological:v1": chrono,
            "consignment_exclusion:v1": exclusion, "both:v1": chrono and exclusion}[domain]


@lru_cache(maxsize=None)
def independent_fibers(activities, observed_json, catalog_path):
    """Explicit raw completions; no candidate abstraction, domain or truth calls."""
    observed = json.loads(observed_json)
    order = tuple(dict.fromkeys(activities))
    catalog = read_catalog(ROOT / catalog_path)
    output = {domain: [] for domain in tool.DOMAIN_VERSIONS}
    clock_seen = None
    if "first_times" in observed:
        values = [raw_time(observed["first_times"][a]) for a in order]
        levels = sorted(set(values))
        clock_seen = tuple(levels.index(v) for v in values)
    for state in tool.states():
        if tuple(ALPHABET[a] for a in state.order) != order:
            continue
        if "profile" in observed and PROFILES[state.profile] != observed["profile"]:
            continue
        if clock_seen is not None and state.ranks != clock_seen:
            continue
        raw = concrete(state)
        raw["activities"] = list(activities)
        raw.update(deepcopy(observed))
        label = reference_verdict(raw, catalog)
        for domain in output:
            if independent_membership(raw, domain):
                output[domain].append(label)
    return output


@pytest.mark.parametrize("before_domain", list(tool.DOMAIN_VERSIONS))
@pytest.mark.parametrize("after_domain", list(tool.DOMAIN_VERSIONS))
def test_receipt_outcomes_against_independently_filtered_raw_completions(before_domain, after_domain):
    prototypes = [named(n)["receipt"] for n in ("identity_full_receipt", "label_flip_remains_fully_sufficient",
                                                "new_domain_excludes_complete_observation")]
    for template in prototypes:
        for mask in range(4):
            r = deepcopy(template)
            r["domain_version"] = before_domain
            r["observed"] = {k: v for k, v in r["observed"].items()
                             if (1 if k == "profile" else 2) & mask}
            key = tuple(r["activities"]), json.dumps(r["observed"], sort_keys=True)
            old = independent_fibers(*key, "examples/baseline_catalog.json")[before_domain]
            new = independent_fibers(*key, "examples/strict_consignment_catalog.json")[after_domain]
            if not old or set(old) != {r["verdict"]}:
                wanted = "invalid_receipt"
            elif not new:
                wanted = "unsupported"
            elif len(set(new)) > 1:
                wanted = "insufficient"
            else:
                wanted = "safe" if new[0] == r["verdict"] else "stale_verdict"
            checker = tool.Revalidator(read_catalog(ROOT / "examples/baseline_catalog.json"),
                                       read_catalog(ROOT / "examples/strict_consignment_catalog.json"),
                                       before_domain, after_domain, r["snapshot_sha256"])
            result = checker.revalidate(r)
            assert result["status"] == wanted
            assert result["before_compatible_classes"] == len(old)
            assert result["after_compatible_classes"] == len(new)


def test_equivalent_catalog_control_complete_truth_vector():
    old = read_catalog(ROOT / "examples/baseline_catalog.json")
    new = read_catalog(ROOT / "examples/second_equivalent_catalog.json")
    # Full raw reference execution; not only equality on native support.
    for state in tool.states():
        raw = concrete(state)
        assert reference_verdict(raw, old) == reference_verdict(raw, new)


def test_cli_requires_versions_and_refuses_overwrite(tmp_path):
    dest = tmp_path / "result.json"
    command = [sys.executable, str(ROOT / "scripts/revalidate_receipt.py"),
               "--receipt", str(ROOT / "examples/second_receipt_withdrawal.json"),
               "--before", str(ROOT / "examples/baseline_catalog.json"),
               "--after", str(ROOT / "examples/baseline_catalog.json"),
               "--snapshot-sha256", "0" * 64, "--output", str(dest)]
    assert subprocess.run(command, capture_output=True).returncode != 0
    command += ["--before-domain", "chronological:v1", "--after-domain", "cartesian:v1"]
    completed = subprocess.run(command, capture_output=True)
    assert completed.returncode == 0, completed.stderr.decode()
    original = dest.read_bytes()
    assert json.loads(original)["status"] == "insufficient"
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert dest.read_bytes() == original
