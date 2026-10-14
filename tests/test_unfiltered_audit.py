"""Known-answer checks for the separate raw-source census implementation."""
import importlib.util
from pathlib import Path
from decimal import Decimal

path=Path(__file__).resolve().parents[1]/"scripts/audit_bpi_unfiltered.py"
spec=importlib.util.spec_from_file_location("unfiltered_audit",path)
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_raw_audit_parser_keeps_nanoseconds_and_timezone_equivalence():
    a=audit.exact_time("2018-01-01t00:00:00.000000001z")
    b=audit.exact_time("2018-01-01T01:00:00.000000002+01:00")
    assert b-a==Decimal("0.000000001")
    assert audit.exact_time("2018-01-01T00:00:00Z")==audit.exact_time("2017-12-31T19:00:00-05:00")


def test_raw_audit_parser_does_not_fabricate_unknown_times():
    assert audit.exact_time("2018-01-01T00:00:00-00:00") is None
    assert audit.exact_time("2018-01-01T00:00:60Z") is None
    assert audit.exact_time("2018-02-31T00:00:00Z") is None
    assert audit.exact_time(None) is None


def test_equal_time_position_conflict_is_not_a_clock_inversion():
    result=audit.summarize_predicates({"create":(1,Decimal(0)),"receive":(0,Decimal(0))},
                                      ("create","receive"),(("create","receive"),))
    assert result["position"]==[("create","receive")]
    assert result["equal_position"]==[("create","receive")]
    assert result["clock"]==[]
    assert not result["compatible"]


def test_invoice_before_receipt_only_conflicts_with_the_fixed_chain():
    first={"create":(0,Decimal(0)),"invoice":(1,Decimal(1)),"receive":(2,Decimal(2)),"clear":(3,Decimal(3))}
    required,edges=audit.PROFILES["3-way match, invoice before GR"]
    assert audit.summarize_predicates(first,required,edges)["compatible"]
    assert not audit.summarize_predicates(first,audit.FIXED_REQUIRED,audit.FIXED_EDGES)["compatible"]


def test_missing_target_is_reported_as_absence_not_a_time_violation():
    result=audit.summarize_predicates({"create":(0,Decimal(0))},("create","receive"),(("create","receive"),))
    assert result["missing"]==("receive",)
    assert result["clock"]==result["position"]==[]
    assert result["per_edge"]["create->receive"]=={"target_observed":0,"both_observed":0}
