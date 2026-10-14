"""Adversarial engine checks; decisions are not inferred from fault names."""
from copy import deepcopy
from datetime import datetime
from decimal import Decimal
from itertools import product

import pytest

pytest.importorskip("Declare4Py")

from logistics_validation.declarative_baseline import exact_timestamp, mp_declare_issues
from logistics_validation.model import Case, Event, uri
from logistics_validation.constraints import SchemaChecker, indexed_issues
from logistics_validation.mutations import FAULTS, fault, benign


def case_for(sequence=("accept", "deliver"), cid="example"):
    obj = uri("object", cid)
    events = [Event(uri("event", f"{cid}:{i}"), obj, activity,
                    f"2020-01-01T00:00:{i:02d}Z") for i, activity in enumerate(sequence)]
    return Case(cid, "lade", "test", "delivery", "fixture", events,
                [("accept", "deliver")], ["accept", "deliver"], {"object_id": obj})


def invalid(case, scope="full"):
    return bool(mp_declare_issues([case], scope)[case.case_id])


@pytest.mark.parametrize("name", FAULTS)
def test_all_six_faults_through_real_engine_and_schema(name):
    case = fault(case_for(), name)
    assert invalid(case) or not SchemaChecker().valid(case)


@pytest.mark.parametrize("variant", range(5))
def test_valid_variants_through_real_engine(variant):
    case, name = benign(case_for(), variant)
    assert not invalid(case), name
    assert SchemaChecker().valid(case), name


def test_exhaustive_order_missing_and_repeated_milestones():
    # A separate direct predicate is the oracle, with uniform timestamps so
    # time, IDs and refs cannot mask a control-flow mismatch.
    cases = []
    expected = {}
    for length in range(5):
        for seq in product(("accept", "deliver", "other"), repeat=length):
            case = case_for(seq, f"bounded-{len(cases)}")
            for event in case.events:
                event.time = "2020-01-01T00:00:00Z"
            expected[case.case_id] = (
                "accept" not in seq or "deliver" not in seq
                or seq.index("accept") >= seq.index("deliver")
            )
            cases.append(case)
    actual = mp_declare_issues(cases)
    assert {cid: bool(x) for cid, x in actual.items()} == expected


def test_first_repetition_semantics_does_not_silently_strengthen_contract():
    case = case_for(("accept", "deliver", "accept", "deliver"))
    # Later activity timestamps may precede first timestamps under this
    # deliberately limited first-occurrence contract.
    case.events[-1].time = "1999-01-01T00:00:00Z"
    assert not invalid(case)
    assert not indexed_issues(case)
    late_predecessor = case_for(("deliver", "accept", "deliver"))
    assert invalid(late_predecessor)


@pytest.mark.parametrize("left,right,should_fail", [
    ("2020-01-01t00:00:01z", "2020-01-01t00:00:00z", True),
    ("2020-01-01T00:00:00.000000002Z", "2020-01-01T00:00:00.000000001Z", True),
    ("2020-01-01T00:00:00.000000001Z", "2020-01-01T00:00:00.000000002Z", False),
    ("2020-01-01T09:00:00+09:00", "2020-01-01T00:00:00Z", False),
    ("2020-01-01T09:00:01+09:00", "2020-01-01T00:00:00Z", True),
    ("1969-12-31T23:59:59.9Z", "1970-01-01T00:00:00Z", False),
])
def test_signed_exact_time_with_equivalent_lexical_forms(left, right, should_fail):
    case = case_for()
    case.events[0].time, case.events[1].time = left, right
    assert SchemaChecker().valid(case)
    assert invalid(case) == should_fail


def test_arbitrary_fraction_precision_retained():
    a = exact_timestamp("2020-01-01T00:00:00.123456789012345678901234567891Z")
    b = exact_timestamp("2020-01-01T00:00:00.123456789012345678901234567892Z")
    assert a < b
    assert exact_timestamp("1970-01-01t00:00:00.000000001z") == Decimal("0.000000001")


def test_native_absolute_duration_alone_does_not_express_signed_order():
    from Declare4Py.ProcessModels.DeclareModel import DeclareModel
    from Declare4Py.Utils.Declare.Checkers import ConstraintChecker
    from Declare4Py.Utils.Declare.TraceStates import TraceState
    from pm4py.objects.log.obj import Trace, Event as PMEvent

    model = DeclareModel().parse_from_string(
        "activity accept\nactivity deliver\nPrecedence[accept, deliver] | | | 0,10,s"
    )
    trace = Trace([
        PMEvent({"concept:name": "accept", "time:timestamp": datetime(2020, 1, 1, 0, 0, 1)}),
        PMEvent({"concept:name": "deliver", "time:timestamp": datetime(2020, 1, 1, 0, 0, 0)}),
    ])
    native = ConstraintChecker().check_trace_conformance(trace, model, True, "concept:name")
    assert native[0].state == TraceState.SATISFIED
    # This does not establish an engine defect: native duration is absolute by
    # definition. Correct signed-order encoding adds a data correlation.
    assert invalid(fault(case_for(), "time_inversion"), "process")


def test_refs_include_forward_and_self_but_reject_cross_case():
    a = case_for(cid="a")
    a.events[0].ref = a.events[-1].event_id  # Contract is existence, not previous position.
    a.events[-1].ref = a.events[-1].event_id
    assert not invalid(a)
    b = case_for(cid="b")
    b.events[-1].ref = a.events[0].event_id
    out = mp_declare_issues([a, b])
    assert not out[a.case_id]
    assert out[b.case_id] == {"dangling_reference"}


def test_empty_reference_is_absent_under_current_contract():
    case = case_for()
    case.events[-1].ref = ""
    assert not invalid(case)


def test_scope_gap_is_explicit_not_attributed_to_engine_inability():
    for name in ("duplicate_id", "dangling_reference", "malformed_uri"):
        case = fault(case_for(), name)
        assert not invalid(case, "process")
        assert invalid(case, "full")


def test_identity_consistency_is_not_just_schema_validity():
    case = case_for()
    case.events[-1].object_id = uri("object", "different")
    assert SchemaChecker().valid(case)
    assert mp_declare_issues([case])[case.case_id] == {"object_identity"}


def test_duplicate_case_keys_fail_instead_of_overwriting_predictions():
    case = case_for()
    with pytest.raises(ValueError, match="unique"):
        mp_declare_issues([case, deepcopy(case)])


def test_absent_optional_milestone_is_vacuously_valid():
    case = case_for(("accept",))
    case.required = ["accept"]
    assert not invalid(case)


def test_adapter_does_not_mutate_input_or_sort_timestamps():
    case = fault(case_for(), "time_inversion")
    before = case.digest()
    assert invalid(case)
    assert case.digest() == before
