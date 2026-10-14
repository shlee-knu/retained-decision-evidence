"""The public JSON boundary and concrete witness must preserve audit semantics."""
import importlib.util
import json
from pathlib import Path
import pytest

from logistics_validation.catalog_audit import BASELINE, PROFILES, catalog_json, reference_verdict

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("compare_catalogs", ROOT / "scripts/compare_catalogs.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def test_same_json_catalog_proves_no_symbolic_change():
    before = cli.read_catalog(ROOT / "examples/baseline_catalog.json")
    result = cli.compare(before, before)
    assert result["globally_equivalent"]
    assert result["counts"]["changed_verdict_states"] == 0
    assert result["counts"]["states_with_invalidated_certificate"] == 0
    assert result["lost_certificate_witness"] is None


def test_serialized_witness_is_indistinguishable_but_changes_new_verdict():
    before = cli.read_catalog(ROOT / "examples/baseline_catalog.json")
    after = cli.read_catalog(ROOT / "examples/strict_consignment_catalog.json")
    result = json.loads(json.dumps(cli.compare(before, after)))
    w = result["lost_certificate_witness"]
    a, b = w["anchor"], w["completion"]
    assert a["activities"] == b["activities"]
    for block in w["observed_blocks"]:
        key = {"P": "profile", "T": "first_times"}[block]
        assert a[key] == b[key]
    assert reference_verdict(a, before) == reference_verdict(b, before)
    assert reference_verdict(a, before) == reference_verdict(a, after)
    assert reference_verdict(a, after) != reference_verdict(b, after)


@pytest.mark.parametrize("bad", ["unknown_profile", "unknown_activity", "self_edge", "extra_predicate"])
def test_rejects_json_outside_the_proved_fragment(tmp_path, bad):
    body = catalog_json(BASELINE)
    if bad == "unknown_profile":
        body["inferred department"] = body[PROFILES[0]]
    elif bad == "unknown_activity":
        body[PROFILES[0]]["required"].append("cancel")
    elif bad == "self_edge":
        body[PROFILES[0]]["edges"].append(["create", "create"])
    else:
        body[PROFILES[0]]["absolute_deadline"] = "2020-01-01"
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(body))
    with pytest.raises(ValueError):
        cli.read_catalog(p)


def test_reports_unsatisfiable_profile_instead_of_discarding_it(tmp_path):
    body = catalog_json(BASELINE)
    body[PROFILES[0]]["forbidden"].append("create")
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(body))
    result = cli.compare(BASELINE, cli.read_catalog(p))
    assert PROFILES[0] in result["unsatisfiable_profiles"]["after"]
    assert result["counts"]["changed_verdict_states"] > 0
