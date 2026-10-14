"""Focused semantic regressions for the independent equal-output service."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compare_catalogs import read_catalog
from logistics_validation.focused_diagnostics import (
    FiniteDiagnostics, Problem, RawVerifier, SMTDiagnostics,
)


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_strict_same_retained_times_need_profile_without_hidden_values(engine):
    p = Problem("procurement_strict", read_catalog(ROOT / "examples/strict_consignment_catalog.json"))
    service = engine(p)
    q = dict(base=[0, 1, 2, 3], mask=2, observed=[[0, 1, 2, 3]], old_verdict=True)
    got = service.diagnose(q)
    assert got["status"] == "insufficient"
    assert got["robust_masks"] == [1]
    assert got["witnesses"][0][0] == 3
    RawVerifier(p).verify(q, got)


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_old_label_cannot_shrink_new_domain(engine):
    p = Problem("procurement_strict", read_catalog(ROOT / "examples/strict_consignment_catalog.json"))
    service = engine(p)
    # With only the four-activity base, old truth is not determined. Asserting
    # the alleged old PASS as a domain restriction would conceal this invalidity.
    q = dict(base=[0, 1, 2, 3], mask=0, observed=[], old_verdict=True)
    got = service.diagnose(q)
    assert got == {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_no_unread_actual_values_in_strict_report(engine):
    p = Problem("procurement_strict", read_catalog(ROOT / "examples/strict_consignment_catalog.json"))
    service = engine(p)
    q = dict(base=[0, 1], mask=1, observed=[3], old_verdict=True)
    # In the old domain increasing and decreasing clocks exist, so a claimed
    # positive receipt with only its profile is invalid despite some PASS rows.
    assert service.diagnose(q)["status"] == "invalid_receipt"


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
@pytest.mark.parametrize("name,observed,mask,bizbit", [
    ("epcis_object_profile", ["ADD", "nonempty"], 3, 16),
    ("epcis_aggregation_profile", ["DELETE", "present"], 3, 16),
    ("epcis_transformation_profile", ["present", "nonempty"], 3, 32),
])
def test_gs1_robust_set_is_unread_bizstep(engine, name, observed, mask, bizbit):
    p = Problem(name)
    q = dict(base=[], mask=mask, observed=observed, old_verdict=True)
    got = engine(p).diagnose(q)
    assert got["status"] == "insufficient"
    assert got["robust_masks"] == [bizbit]
    RawVerifier(p).verify(q, got)


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_known_absence_is_not_unread(engine):
    p = Problem("epcis_object_profile")
    service = engine(p)
    q = dict(base=[], mask=6, observed=["absent", "absent"], old_verdict=False)
    assert service.diagnose(q) == {"status": "safe", "witnesses": None, "robust_masks": [0]}
    q["mask"], q["observed"] = 0, []
    assert service.diagnose(q)["status"] == "invalid_receipt"


@pytest.mark.parametrize("engine", [FiniteDiagnostics, SMTDiagnostics])
def test_stale_verdict_is_not_insufficient(engine):
    p = Problem("epcis_object_profile")
    q = dict(base=[], mask=19, observed=["ADD", "nonempty", "vendor"], old_verdict=True)
    got = engine(p).diagnose(q)
    assert got == {"status": "stale_verdict", "witnesses": None, "robust_masks": [0]}
    RawVerifier(p).verify(q, got)
