"""Published guard replay, sufficiency boundaries and provenance tamper checks."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("public_change", ROOT / "scripts/analyze_public_procurement_change.py")
change = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(change)


@pytest.fixture(scope="module")
def guards():
    protocol, _, _ = change.verified_inputs()
    return change.make_guards(protocol)


@pytest.mark.parametrize("state,old_pass,new_pass", [
    (("Closed", True), False, True),
    (("Closed", False), False, False),
    (("Cancelled", True), False, False),
    (("Cancelled", False), False, False),
    (("To Bill", True), True, True),
    (("To Bill", False), True, True),
])
def test_upstream_guard_boundaries_and_no_real_side_effects(guards, state, old_pass, new_pass):
    """Execute upstream code; the blocked/open/return boundaries must survive."""
    for guard, expected in zip(guards, (old_pass, new_pass)):
        result = guard.execute(state)
        assert result["guard_passed"] is expected
        updates = [e for e in result["events"] if e["operation"] == "update_ordered_qty_stub"]
        assert len(updates) == int(expected)
        assert guard.metadata["ast_transformed"] is False


def test_retained_closed_status_has_opposed_source_completions(guards):
    before, after = guards
    engine = change.FiniteDiagnostics(change.GuardProblem())
    query = {"base": (), "mask": 1, "observed": ("Closed",), "old_verdict": False}
    got = engine.diagnose(query)
    assert got["status"] == "insufficient"
    assert got["robust_masks"] == [2]
    labels = {s: (before.execute(s)["guard_passed"], after.execute(s)["guard_passed"]) for s in change.STATES}
    change.check_witnesses(query, got, labels)
    assert {s[1] for s in got["witnesses"]} == {False, True}
    # Acquiring a return flag distinguishes update-needed from safe reuse; it
    # does not always preserve the old false verdict.
    for value, expected in ((False, "safe"), (True, "stale_verdict")):
        extended = dict(query, mask=3, observed=("Closed", value))
        assert engine.diagnose(extended)["status"] == expected


def test_wrong_old_boolean_cannot_be_silently_repaired():
    engine = change.FiniteDiagnostics(change.GuardProblem())
    query = {"base": (), "mask": 1, "observed": ("Closed",), "old_verdict": True}
    assert engine.diagnose(query) == {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}


def test_source_checker_rejects_forged_witness(guards):
    before, after = guards
    labels = {s: (before.execute(s)["guard_passed"], after.execute(s)["guard_passed"]) for s in change.STATES}
    query = {"base": (), "mask": 1, "observed": ("Closed",), "old_verdict": False}
    got = change.FiniteDiagnostics(change.GuardProblem()).diagnose(query)
    forged = deepcopy(got)
    forged["witnesses"][1] = ("To Bill", True)
    with pytest.raises(AssertionError, match="changed retained evidence"):
        change.check_witnesses(query, forged, labels)
    forged = deepcopy(got)
    forged["witnesses"][1] = ("Closed", False)
    with pytest.raises(AssertionError, match="opposed witness labels"):
        change.check_witnesses(query, forged, labels)


def test_exhaustive_offline_analysis_and_full_information_control(tmp_path):
    result = change.run(tmp_path)
    assert result["complete_states"] == 6
    assert result["source_model_disagreements"] == result["diagnostic_disagreements"] == 0
    assert result["observation_queries_including_both_old_claims"] == 24
    assert result["all_query_status_counts"] == {
        "invalid_receipt": 15, "safe": 7, "insufficient": 1, "stale_verdict": 1}
    status, full = result["retention"]
    assert status["observation_counts"] == {"safe": 2, "insufficient": 1}
    assert full["observation_counts"] == {"safe": 5, "stale_verdict": 1}
    assert "insufficient" not in full["complete_input_counts"]
    assert len((tmp_path / "retention_ledger.jsonl").read_text().splitlines()) == 12


def test_archived_source_tamper_stops_before_execution(tmp_path):
    shutil.copytree(change.DEFAULT_OUT / "sources", tmp_path / "sources")
    for name in ("source_manifest.json", "protocol_lock.json"):
        shutil.copyfile(change.DEFAULT_OUT / name, tmp_path / name)
    manifest = json.loads((tmp_path / "source_manifest.json").read_text())
    source = next(e for e in manifest["files"] if e["path"].endswith("buying_controller.py"))
    path = tmp_path / source["path"]
    path.write_bytes(path.read_bytes() + b"\n# modified\n")
    with pytest.raises(ValueError, match="source hash mismatch"):
        change.verified_inputs(tmp_path)
