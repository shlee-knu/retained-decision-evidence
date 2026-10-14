from itertools import product
import pytest

from logistics_validation.catalog_audit import (
    ALPHABET, BASELINE, PROFILES, CertificateTable, Rule, State, abstract, changes,
    concrete, generated_catalogs, loss_witness, observation, reference_time,
    reference_verdict, universe, verdict, weak_orders,
)


@pytest.fixture(scope="module")
def states():
    return universe()


def test_complete_quotient_counts_and_realization(states):
    assert [len(weak_orders(k)) for k in range(5)] == [1, 1, 3, 13, 75]
    assert len(states) == 8612
    assert len({(s.order, s.ranks) for s in states}) == 2153
    for state in states:
        assert abstract(concrete(state)) == state


def test_predeclared_grammar():
    catalogs = generated_catalogs()
    assert len(catalogs) == 82
    assert len({name for name, _, _ in catalogs}) == 82
    assert sum(d["kind"] == "toggle_required" for _, _, d in catalogs) == 16
    assert sum(d["kind"] == "add_forbidden" for _, _, d in catalogs) == 16
    assert sum(d["kind"] == "toggle_edge" for _, _, d in catalogs) == 48
    assert any(r.required & r.forbidden for _, cat, _ in catalogs for r in cat)


def test_reference_and_existing_engine_baseline_strict(states):
    from logistics_validation.acquisition import possible_outcomes, structural_order
    for name, catalog, _ in generated_catalogs()[:2]:
        forbid = {"Consignment": ("invoice", "clear")} if name != "baseline" else {}
        table = CertificateTable(states, [verdict(s, catalog) for s in states])
        for i, state in enumerate(states):
            raw = concrete(state)
            assert reference_verdict(raw, catalog) == bool(table.labels[i])
            selected = structural_order(raw["activities"], forbidden=forbid)
            assert table.policy_mask(i, "structural_order") == table.policy_mask(i, selected)
            for mask in range(4):
                kwargs = {"forbidden": forbid}
                if mask & 1:
                    kwargs["profile"] = raw["profile"]
                if mask & 2:
                    kwargs["first_times"] = raw["first_times"]
                got = possible_outcomes(raw["activities"], **kwargs)
                assert (got["status"] == "determined") == bool(table.sufficient[i] & (1 << mask))


def test_independent_brute_fibers_and_minimality(states):
    # Direct list filtering uses the observation definition, not table.fibers.
    small = tuple(s for s in states if set(s.order) <= {0, 1})
    for _, catalog, _ in generated_catalogs():
        truth = [reference_verdict(concrete(s), catalog) for s in small]
        table = CertificateTable(small, truth)
        for i, x in enumerate(small):
            for mask in range(4):
                possible = {truth[j] for j, y in enumerate(small)
                            if x.order == y.order and (not mask & 1 or x.profile == y.profile)
                            and (not mask & 2 or x.ranks == y.ranks)}
                assert bool(table.sufficient[i] & (1 << mask)) == (len(possible) == 1)
            for m in table.minimal[i]:
                assert not any(table.sufficient[i] & (1 << n) for n in range(4)
                               if n != m and n & m == n)


def test_all_catalog_masks_against_constructive_clock_reference(states):
    # Independent partial-information argument: all-tied clocks realize accept
    # after structural checks; any active edge can be inverted to realize reject.
    # Source-order structural checks ensure all active edges form a DAG.
    # This computes every mask without consulting CertificateTable.fibers.
    orders = {s.order for s in states}
    for _, catalog, _ in generated_catalogs():
        table = CertificateTable(states, [verdict(s, catalog) for s in states])
        hidden = {}
        for order in orders:
            for p in range(4):
                tied = State(order, (0,) * len(order), p)
                structural = reference_verdict(concrete(tied), catalog)
                active = any(a in order and b in order for a, b in catalog[p].edges)
                hidden[order, p] = ({False, True} if active else {True}) if structural else {False}
        for i, state in enumerate(states):
            empty_labels = set().union(*(hidden[state.order, p] for p in range(4)))
            time_labels = {verdict(State(state.order, state.ranks, p), catalog) for p in range(4)}
            expected = (int(len(empty_labels) == 1)
                        | (int(len(hidden[state.order, state.profile]) == 1) << 1)
                        | (int(len(time_labels) == 1) << 2) | 8)
            assert table.sufficient[i] == expected


def test_nonminimal_is_not_lost():
    states = tuple(State((0,), (0,), p) for p in range(4))
    before = CertificateTable(states, [True, False, False, False])
    after = CertificateTable(states, [True] * 4)
    assert before.minimal[0] == (1,)
    assert after.minimal[0] == (0,)
    assert changes(before, after, 0)["lost"] == ()
    assert changes(before, after, 0)["gained"] == (0, 2)


def test_globally_equivalent_catalogs_same_certificates(states):
    baseline = CertificateTable(states, [verdict(s) for s in states])
    # Add transitive create->clear edge to profile0: a genuine syntactic edit.
    rules = list(BASELINE)
    r = rules[0]
    rules[0] = Rule(r.required, r.forbidden, r.edges | {(0, 3)})
    other = CertificateTable(states, [verdict(s, rules) for s in states])
    assert baseline.labels == other.labels
    assert baseline.sufficient == other.sufficient
    assert baseline.minimal == other.minimal
    assert baseline.necessary == other.necessary


def test_strict_witness_and_repeated_native_lift(states):
    old = CertificateTable(states, [verdict(s) for s in states])
    strict = generated_catalogs()[1][1]
    new = CertificateTable(states, [verdict(s, strict) for s in states])
    witness = loss_witness(old, new)
    assert witness is not None
    i, j, m = (witness[k] for k in ("anchor_index", "completion_index", "lost_mask"))
    assert observation(states[i], m) == observation(states[j], m)
    assert old.labels[i] == new.labels[i] == old.labels[j]
    assert new.labels[j] != new.labels[i]
    for state in (states[i], states[j]):
        raw = concrete(state)
        raw["activities"] = [a for a in raw["activities"] for _ in range(3)]
        assert abstract(raw) == state
        assert reference_verdict(raw, strict) == verdict(state, strict)


def test_missing_first_predecessor_and_reversed_clock():
    raw = {"activities": ["receive", "create", "receive"], "profile": "Consignment",
           "first_times": {"create": "2020-01-01T00:00:00Z", "receive": "2020-01-01T00:00:01Z"}}
    assert not reference_verdict(raw)
    raw["activities"] = ["create", "receive", "create"]
    raw["first_times"]["create"] = "2020-01-01T00:00:02Z"
    assert not reference_verdict(raw)


def test_exact_clock_domain():
    assert reference_time("2020-01-01t01:00:00z") == reference_time("2020-01-01T02:00:00+01:00")
    assert reference_time("2020-01-01T00:00:00.00000000000000000000000000001Z") > reference_time("2020-01-01T00:00:00Z")
    assert reference_time("0001-01-01T00:00:00+01:00") < reference_time("0001-01-01T00:00:00Z")
    assert reference_time("9999-12-31T23:59:59-01:00") > reference_time("9999-12-31T23:59:59Z")
    for value in ("２０２０-01-01T00:00:00Z", "2020-01-01T00:00:60Z", "2020-01-01T00:00:00-00:00"):
        with pytest.raises(ValueError):
            reference_time(value)
