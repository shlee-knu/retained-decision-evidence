"""Independent arithmetic/time and hidden-field certificate checks."""
from collections import defaultdict
from fractions import Fraction
from itertools import product

import pytest

from logistics_validation.external_contracts import (
    POLICIES, Reader, Unsupported, clock, evaluate, number, prepare_record,
)
from logistics_validation.external_contracts_oracle import direct_oracle


def money(amounts, totals, initial="0", times=None):
    events = [{"concept:name": "Create Fine", "totalPaymentAmount": str(initial)}]
    for i, (amount, total) in enumerate(zip(amounts, totals)):
        events.append({"concept:name": "Payment", "paymentAmount": str(amount),
                       "totalPaymentAmount": str(total), "time:timestamp": times[i] if times else "2020-01-01T00:00:00Z"})
    return events


def travel(approval, start, *, extra_approvals=(), extra_starts=()):
    events = []
    if approval is not None:
        events.append({"concept:name": "Permit FINAL_APPROVED by SUPERVISOR", "time:timestamp": approval})
    events.extend({"concept:name": "Permit FINAL_APPROVED by DIRECTOR", "time:timestamp": t} for t in extra_approvals)
    if start is not None:
        events.append({"concept:name": "Start trip", "time:timestamp": start})
    events.extend({"concept:name": "Start trip", "time:timestamp": t} for t in extra_starts)
    return events


def verify(events, contract, expected):
    assert direct_oracle(events, contract) == expected
    for granularity, mode in product(("coarse", "fine"), ("cached", "json")):
        record = prepare_record("fixture", events, contract, granularity)
        answers = {policy: evaluate(record, policy, mode, audit=True) for policy in POLICIES}
        assert {a.outcome for a in answers.values()} == {expected}
        if expected != "unsupported":
            assert answers["hand_guard"].queries == answers["generic_certificate"].queries
            assert answers["hand_guard"].bytes == answers["generic_certificate"].bytes
        for result in answers.values():
            assert result.queries == len(set(result.trace))
            assert result.bytes == sum(len(record._wire[key]) for key in result.trace)
        if expected != "unsupported" and contract in ("traffic_cumulative", "travel_first_approval"):
            assert answers["hand_guard"].trace == answers["generic_certificate"].trace


def test_exhaustive_small_numeric_traces_and_certificate_completions():
    """All 1/2-payment completions over a finite independent integer domain."""
    certificates = defaultdict(set)
    checked = 0
    for length in (1, 2):
        for initial in (0, 1):
            for values in product((-1, 0, 1), repeat=2 * length):
                amounts, totals = values[:length], values[length:]
                expected = "pass" if all(initial + sum(amounts[:i + 1]) == totals[i] for i in range(length)) else "fail"
                events = money(amounts, totals, initial)
                verify(events, "traffic_cumulative", expected)
                final_expected = "pass" if initial + sum(amounts) == totals[-1] else "fail"
                verify(events, "traffic_final", final_expected)
                for granularity in ("coarse", "fine"):
                    record = prepare_record("fixture", events, "traffic_cumulative", granularity)
                    result = evaluate(record, "generic_certificate", audit=True)
                    observed = tuple((key, record._wire[key]) for key in result.trace)
                    certificates[(record.activities, granularity, observed)].add(expected)
                checked += 1
    assert checked == 180
    assert all(len(outcomes) == 1 for outcomes in certificates.values())


@pytest.mark.parametrize("events,expected", [
    (money([], []), "nonapplicable"),
    (money([2, 3], [7, 10], initial=5), "pass"),
    (money([-3], [2], initial=5), "pass"),
    (money(["1e1", ".00000000000001"], ["10", "10.00000000000001"]), "pass"),
    (money(["1e1", ".00000000000001"], ["10", "10"]), "fail"),
    (money([".000000000000000000000000000001"],
           ["1000000000000000000000000000000.000000000000000000000000000001"],
           initial="1000000000000000000000000000000"), "pass"),
    (money([".000000000000000000000000000001"], ["1000000000000000000000000000000"],
           initial="1000000000000000000000000000000"), "fail"),
    ([{"concept:name": "Payment", "paymentAmount": "1", "totalPaymentAmount": "1"}], "unsupported"),
    (list(reversed(money([1], [1]))), "unsupported"),
])
def test_numeric_boundaries_and_base_gates(events, expected):
    verify(events, "traffic_cumulative", expected)


def test_snapshot_semantics_are_distinct_from_row_semantics():
    events = money([49, 87], [136, 136])
    verify(events, "traffic_cumulative", "fail")
    verify(events, "traffic_final", "pass")
    verify(events, "traffic_timestamp_groups", "pass")


def test_timestamp_groups_normalize_offsets_and_do_not_infer_source_sort():
    # Source order is later time first; time-group predicate deliberately sorts
    # normalized instants. The row predicate deliberately uses source order.
    events = money([2, 1], [3, 1], times=["2020-01-02T00:00:00Z", "2020-01-01T01:00:00+01:00"])
    verify(events, "traffic_cumulative", "fail")
    verify(events, "traffic_timestamp_groups", "pass")
    tied = money([49, 87], [136, 136], times=["2020-01-01T00:00:00Z", "2020-01-01t01:00:00+01:00"])
    verify(tied, "traffic_timestamp_groups", "pass")


@pytest.mark.parametrize("approval,start,expected", [
    (None, "2020-01-01T00:00:00Z", "fail"),
    ("2020-01-01T00:00:00Z", None, "nonapplicable"),
    ("2020-01-01t00:00:00z", "2020-01-01T01:00:00+01:00", "pass"),
    ("2020-01-01T00:00:00.0000000000001Z", "2020-01-01T00:00:00Z", "fail"),
    ("2019-12-31T23:59:59.999999999999999Z", "2020-01-01T00:00:00Z", "pass"),
    ("2020-01-02T00:00:00Z", "2020-01-01T00:00:00Z", "fail"),
    ("0001-01-01T00:00:00+01:00", "0001-01-01T00:00:00Z", "pass"),
    ("9999-12-31T23:59:59-01:00", "9999-12-31T23:59:59Z", "fail"),
])
def test_temporal_boundaries(approval, start, expected):
    verify(travel(approval, start), "travel_first_approval", expected)


def test_first_approval_and_first_start_are_xml_occurrences_not_earliest_clocks():
    early, middle, late = (f"2020-01-0{i}T00:00:00Z" for i in (1, 2, 3))
    verify(travel(late, middle, extra_approvals=(early,)), "travel_first_approval", "fail")
    verify(travel(early, middle, extra_approvals=(late,)), "travel_first_approval", "pass")
    verify(travel(middle, late, extra_starts=(early,)), "travel_first_approval", "pass")
    # A start appearing first in source order is not evidence of a later time.
    events = list(reversed(travel(early, late)))
    verify(events, "travel_first_approval", "pass")


def test_no_clock_can_be_inferred_from_an_unchanged_activity_projection():
    early, late = "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z"
    a = prepare_record("a", travel(early, late), "travel_first_approval", "fine")
    b = prepare_record("b", travel(late, early), "travel_first_approval", "fine")
    assert a.activities == b.activities
    assert evaluate(a, "generic_certificate").outcome == "pass"
    assert evaluate(b, "generic_certificate").outcome == "fail"


@pytest.mark.parametrize("value", [None, "NaN", "Infinity", "1_0", "１２", " 1", "1 "])
def test_visible_unsupported_numbers(value):
    events = money([1], [1])
    events[1]["paymentAmount"] = value
    verify(events, "traffic_cumulative", "unsupported")


@pytest.mark.parametrize("value", [None, "2020-01-01", "２０２０-01-01T00:00:00Z", "2020-01-01T00:00:00-00:00",
                                    "2020-02-30T00:00:00Z", "2020-01-01T00:00:60Z", "2020-01-01T00:00:00+01:60"])
def test_visible_unsupported_clocks(value):
    events = travel("2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z")
    events[0]["time:timestamp"] = value
    verify(events, "travel_first_approval", "unsupported")


def test_invalid_unseen_later_data_are_explicitly_outside_certificate_guarantee():
    events = money([1, 1], [999, 2])
    events[-1]["paymentAmount"] = "NaN"
    assert direct_oracle(events, "traffic_cumulative") == "unsupported"
    for policy in POLICIES:
        answer = evaluate(prepare_record("outside-domain", events, "traffic_cumulative", "fine"), policy)
        assert answer.outcome == "fail"  # Not a claim of global schema validity.


def test_actual_accessor_reads_match_reported_certificate_trace(monkeypatch):
    seen = []
    original = Reader.get
    def observed(self, key):
        if key not in self.cache:
            seen.append(key)
        return original(self, key)
    monkeypatch.setattr(Reader, "get", observed)
    record = prepare_record("first-failure", money([1, 1, 1], [2, 2, 3]), "traffic_cumulative", "fine")
    answer = evaluate(record, "generic_certificate", audit=True)
    assert tuple(seen) == answer.trace == ("initial", "payment/0")
    assert answer.outcome == "fail"
    assert answer.bytes == sum(len(record._wire[key]) for key in seen)


def test_irrelevant_metadata_not_in_payload_and_exact_serialized_lengths():
    events = money([1], [1]); events[0]["vehicleClass"] = "hidden-but-irrelevant"
    record = prepare_record("identifier-not-charged", events, "traffic_cumulative", "coarse")
    payload = record._wire["amounts"]
    assert b"vehicleClass" not in payload and b"concept:name" not in payload and b"identifier-not-charged" not in payload
    assert payload == b'{"initial":{"totalPaymentAmount":"0"},"payments":[{"paymentAmount":"1","totalPaymentAmount":"1"}]}'
    assert evaluate(record, "full_once").bytes == len(payload)


def test_exact_number_and_timestamp_comparison_do_not_round():
    assert number("0.10000000000000000000000001") > Fraction(1, 10)
    assert clock("2020-01-01T00:00:00.1Z") == clock("2020-01-01T01:00:00.10000+01:00")
