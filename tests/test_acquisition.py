"""Soundness checks over finite completions, plus access-trace boundaries."""
from collections.abc import Mapping
from itertools import permutations, product

import pytest

from logistics_validation.acquisition import (
    DEFAULT_CATALOG, UNOBSERVED, acquire, exact_first_time, possible_outcomes, structural_order,
)

SMALL_CATALOG = {
    "a_only": (("a",), ()),
    "a_then_b": (("a", "b"), (("a", "b"),)),
    "b_then_a": (("a", "b"), (("b", "a"),)),
    "both_unordered": (("a", "b"), ()),
}


def stamp(rank):
    return f"2020-01-01T00:00:0{rank}Z"


def oracle(sequence, profile, ranks):
    """Direct integer/sequence predicate, independent of production evaluator."""
    required, edges = SMALL_CATALOG[profile]
    if not all(activity in sequence for activity in required):
        return "reject"
    for a, b in edges:
        if b in sequence:
            if a not in sequence or sequence.index(a) >= sequence.index(b):
                return "reject"
            if ranks[a] > ranks[b]:
                return "reject"
    return "accept"


def test_exhaustive_certificates_and_acquisition_on_two_activity_four_profile_catalog():
    # 31 sequences (length 0..4), all 4 profiles, and all 3-valued weak clock
    # orders. With at most 2 distinct events, ranks {0,1,2} cover every possible
    # ordering/equality relevant to the contract, not only a sample of clocks.
    for length in range(5):
        for sequence in product(("a", "b"), repeat=length):
            present = sorted(set(sequence))
            assignments = [dict(zip(present, values)) for values in product(range(3), repeat=len(present))]
            completions = [(profile, ranks, oracle(sequence, profile, ranks))
                           for profile in SMALL_CATALOG for ranks in assignments]
            base_expected = {label for _, _, label in completions}
            base = possible_outcomes(sequence, catalog=SMALL_CATALOG)
            assert set(base["possible_labels"]) == base_expected
            for profile, ranks, expected in completions:
                times = {activity: stamp(value) for activity, value in ranks.items()}
                p_only = possible_outcomes(sequence, profile=profile, catalog=SMALL_CATALOG)
                t_only = possible_outcomes(sequence, first_times=times, catalog=SMALL_CATALOG)
                both = possible_outcomes(sequence, profile=profile, first_times=times, catalog=SMALL_CATALOG)
                assert set(p_only["possible_labels"]) == {y for p, r, y in completions if p == profile}
                assert set(t_only["possible_labels"]) == {y for p, r, y in completions if r == ranks}
                assert both["possible_labels"] == [expected]
                features = {"activities": sequence, "profile": profile, "first_times": times}
                for policy in ("always_both", "profile_first", "time_first"):
                    result = acquire(features, policy, catalog=SMALL_CATALOG)
                    assert result["decision"] == expected
                    assert result["profile_queries"] <= 1 and result["time_queries"] <= 1


def test_default_catalog_all_first_orders_and_weak_clock_orders():
    # All 24 first-occurrence orders and all 75 weak orders (ties allowed) of
    # four clocks, across four real catalog profiles: 7,200 complete fixtures.
    names = ("create", "receive", "invoice", "clear")
    weak_orders = set()
    for assignment in product(range(4), repeat=4):
        normalize = {rank: i for i, rank in enumerate(sorted(set(assignment)))}
        weak_orders.add(tuple(normalize[rank] for rank in assignment))
    assert len(weak_orders) == 75
    for sequence in permutations(names):
        for weak_order in weak_orders:
            ranks = dict(zip(names, weak_order))
            times = {name: stamp(rank) for name, rank in ranks.items()}
            for profile, (required, edges) in DEFAULT_CATALOG.items():
                conforms = all(sequence.index(a) < sequence.index(b) and ranks[a] <= ranks[b]
                               for a, b in edges)
                features = {"activities": sequence, "profile": profile, "first_times": times}
                for forbidden in (None, {"Consignment": ("invoice", "clear")}):
                    # All four milestones appear in this fixture, so the strict
                    # policy rejects every Consignment completion independently
                    # of clocks. This oracle does not call the production rules.
                    prohibited = forbidden is not None and profile == "Consignment"
                    expected = "accept" if conforms and not prohibited else "reject"
                    for policy in ("always_both", "profile_first", "time_first"):
                        assert acquire(features, policy, forbidden=forbidden)["decision"] == expected


class SpyMapping(Mapping):
    def __init__(self, values):
        self.values = values
        self.reads = []

    def __getitem__(self, key):
        self.reads.append(key)
        return self.values[key]

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)


@pytest.mark.parametrize("policy", ("profile_first", "time_first"))
def test_universal_structural_rejection_does_not_peek_at_hidden_blocks(policy):
    features = SpyMapping({"activities": ("invoice",)})
    result = acquire(features, policy)
    assert result["decision"] == "reject"
    assert result["fetched_blocks"] == []
    assert features.reads == ["activities"]


def test_profile_first_can_stop_without_clock_lookup():
    features = SpyMapping({"activities": ("create", "receive"),
                           "profile": "3-way match, invoice after GR"})
    result = acquire(features, "profile_first")
    assert result["decision"] == "reject"
    assert features.reads == ["activities", "profile"]
    assert result["time_queries"] == 0


def test_time_first_can_stop_without_profile_lookup():
    features = SpyMapping({"activities": ("create", "receive"),
                           "first_times": {"create": stamp(1), "receive": stamp(0)}})
    result = acquire(features, "time_first")
    assert result["decision"] == "reject"
    assert features.reads == ["activities", "first_times"]


def test_time_first_can_accept_without_profile_when_every_catalog_profile_agrees():
    features = SpyMapping({"activities": ("create", "receive", "invoice", "clear"),
                           "first_times": {a: stamp(i) for i, a in enumerate(("create", "receive", "invoice", "clear"))}})
    result = acquire(features, "time_first")
    assert result["decision"] == "accept"
    assert result["fetched_blocks"] == ["first_times"]


def test_always_both_is_a_literal_fully_informed_reference():
    features = SpyMapping({"activities": ("invoice",), "profile": "2-way match",
                           "first_times": {"invoice": stamp(0)}})
    result = acquire(features, "always_both")
    assert result["decision"] == "reject"
    assert result["fetched_blocks"] == ["profile", "first_times"]
    assert features.reads == ["activities", "profile", "first_times"]


def test_missing_reference_metadata_cannot_be_hidden_by_later_certificate():
    features = {"activities": ("invoice",), "first_times": {"invoice": stamp(0)}}
    result = acquire(features, "always_both")
    assert result["decision"] == "unsupported"
    assert result["profile_queries"] == result["time_queries"] == 1


@pytest.mark.parametrize("bad", (None, "bad", "2020-01-01T00:00:00-00:00", "2020-01-01T00:00:60Z"))
def test_visible_invalid_clock_is_unsupported_even_if_structure_rejects(bad):
    result = possible_outcomes(("invoice",), first_times={"invoice": bad})
    assert result["status"] == "unsupported"


def test_unknown_visible_profile_is_unsupported():
    assert possible_outcomes(("invoice",), profile="not in catalog")["decision"] == "unsupported"


def test_hidden_outside_domain_values_cannot_be_claimed_validated():
    # This deliberately violates the trusted-domain precondition. Adaptive
    # rejection remains conditional and does not claim to detect hidden invalidity.
    features = {"activities": ("invoice",), "profile": "unknown",
                "first_times": {"invoice": "not a timestamp"}}
    result = acquire(features, "profile_first")
    assert result["decision"] == "reject"
    assert result["fetched_blocks"] == []
    assert result["assumptions"]
    assert acquire(features, "always_both")["decision"] == "unsupported"


def test_first_occurrence_and_equal_time_semantics_with_repetition():
    sequence = ("create", "receive", "create", "receive")
    result = possible_outcomes(sequence, profile="Consignment",
                               first_times={"create": stamp(0), "receive": stamp(0)})
    assert result["decision"] == "accept"
    assert possible_outcomes(("receive", "create", "receive"), profile="Consignment")["decision"] == "reject"


def test_exact_time_keeps_fractional_precision_case_and_offset_equivalence():
    assert exact_first_time("2020-01-01t00:00:00.000000002z") > exact_first_time("2020-01-01T00:00:00.000000001Z")
    assert exact_first_time("2020-01-01T09:00:00+09:00") == exact_first_time("2020-01-01T00:00:00Z")
    left = "2020-01-01T00:00:00.123456789012345678901234567891Z"
    right = "2020-01-01T00:00:00.123456789012345678901234567892Z"
    assert exact_first_time(left) < exact_first_time(right)


def test_input_alphabet_and_policy_are_explicit():
    assert possible_outcomes(("unmapped raw activity",))["status"] == "unsupported"
    with pytest.raises(ValueError):
        acquire({"activities": ()}, "unknown policy")


def test_strict_consignment_visible_profile_certifies_clock_free_rejection():
    strict = {"Consignment": ("invoice", "clear")}
    features = SpyMapping({"activities": ("create", "receive", "invoice", "clear"),
                           "profile": "Consignment"})
    result = acquire(features, "profile_first", forbidden=strict)
    assert result["decision"] == "reject"
    assert result["fetched_blocks"] == ["profile"]
    assert result["certificate"]["profile_results"]["Consignment"]["forbidden_present"] == ["invoice", "clear"]


def test_strict_consignment_hidden_profile_remains_ambiguous_until_acquired():
    strict = {"Consignment": ("invoice", "clear")}
    sequence = ("create", "receive", "invoice", "clear")
    times = {a: stamp(i) for i, a in enumerate(sequence)}
    assert possible_outcomes(sequence, first_times=times)["decision"] == "accept"
    partial = possible_outcomes(sequence, first_times=times, forbidden=strict)
    assert partial["possible_labels"] == ["accept", "reject"]
    for profile in DEFAULT_CATALOG:
        expected = "reject" if profile == "Consignment" else "accept"
        for policy in ("always_both", "profile_first", "time_first"):
            result = acquire({"activities": sequence, "profile": profile, "first_times": times},
                             policy, forbidden=strict)
            assert result["decision"] == expected


@pytest.mark.parametrize("invalid", [
    {"unknown": ("invoice",)}, {"Consignment": ("unmapped",)},
    {"Consignment": "invoice"}, ["invoice"],
])
def test_invalid_forbidden_configuration_is_explicitly_unsupported(invalid):
    assert possible_outcomes(("create",), forbidden=invalid)["status"] == "unsupported"


def test_rfc3339_numeric_fields_are_ascii_only():
    for value in ("２０２０-01-01T00:00:00Z", "2020-01-01T00:00:00.١Z", "2020-01-01T00:00:00+٠٠:00"):
        assert exact_first_time(value) is None
        certificate = possible_outcomes(("create", "receive"), profile="Consignment",
                                        first_times={"create": value, "receive": stamp(1)})
        assert certificate["status"] == "unsupported"


@pytest.mark.parametrize("sequence,forbidden,expected", [
    (("create", "receive", "invoice", "clear"), None, "time_first"),
    (("create", "receive"), None, "profile_first"),
    (("invoice",), None, "profile_first"),
    (("create", "receive", "invoice", "clear"), {"Consignment": ("invoice", "clear")}, "profile_first"),
])
def test_structural_order_is_a_pure_untrained_base_signature_rule(sequence, forbidden, expected):
    assert structural_order(sequence, forbidden=forbidden) == expected


def test_structural_order_rejects_unsupported_configuration():
    with pytest.raises(ValueError, match="unknown profile"):
        structural_order(("create",), forbidden={"unknown": ("invoice",)})
