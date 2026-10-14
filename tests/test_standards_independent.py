"""Adversarial checks of the shared core against separately enumerated oracles.

Expected fibers and minimal sets below do not call the core's projection,
antichain, outcome, influence, or recovery helpers. These checks are finite-domain
correctness evidence, not validation of any clinical or operational outcome.
"""
from copy import deepcopy
import importlib.util
from itertools import product
import json
from pathlib import Path

import pytest

from logistics_validation.standards_core import CompiledModel


def spec(old, new, domains=None):
    domains = domains or ((False, True),) * 3
    return {
        "name": "independent-adversarial-model",
        "block_names": tuple("abc"[:len(domains)]),
        "domains": domains,
        "old_predicate": old,
        "new_predicate": new,
    }


def agrees(a, b, mask):
    return all(a[i] == b[i] for i in range(len(a)) if mask & (2 ** i))


def oracle_outcomes(states, predicate, anchor, mask):
    return frozenset(predicate(s) for s in states if agrees(anchor, s, mask))


def oracle_minimal_masks(states, predicate, anchor, retained=0):
    candidates = []
    for mask in range(2 ** len(anchor)):
        if mask & retained:
            continue
        labels = oracle_outcomes(states, predicate, anchor, retained | mask)
        if len(labels) == 1:
            candidates.append(mask)
    return {
        mask for mask in candidates
        if not any(other != mask and other & mask == other for other in candidates)
    }


PREDICATES = (
    lambda s: False,
    lambda s: True,
    lambda s: s[0],
    lambda s: not s[0],
    lambda s: s[0] and s[1],
    lambda s: s[0] or s[1],
    lambda s: s[0] != s[1],
    lambda s: s[0] or (s[1] and s[2]),
    lambda s: s[0] and (s[1] or s[2]),
    lambda s: (s[0] and not s[1]) or (s[2] and s[1]),
    lambda s: sum(s) >= 2,
)


@pytest.mark.parametrize("old", PREDICATES)
@pytest.mark.parametrize("new", PREDICATES)
def test_complete_three_block_truth_functions(old, new):
    model = CompiledModel(spec(old, new))
    states = tuple(product((False, True), repeat=3))
    assert model.states == states
    for i, anchor in enumerate(states):
        assert set(model.minimal_masks(i, "old")) == oracle_minimal_masks(states, old, anchor)
        assert set(model.minimal_masks(i)) == oracle_minimal_masks(states, new, anchor)
        for mask in range(8):
            expected_ids = tuple(j for j, state in enumerate(states) if agrees(anchor, state, mask))
            before = oracle_outcomes(states, old, anchor, mask)
            after = oracle_outcomes(states, new, anchor, mask)
            assert model.fiber(i, mask) == expected_ids
            assert model.outcomes(i, mask, "old") == before
            assert model.outcomes(i, mask) == after
            assert set(model.minimal_additions(i, mask)) == oracle_minimal_masks(
                states, new, anchor, retained=mask)
            for recorded in (False, True):
                expected = (
                    "invalid_receipt" if before != {recorded}
                    else "insufficient" if len(after) > 1
                    else "safe" if after == {recorded}
                    else "stale_verdict"
                )
                assert model.classify(i, mask, recorded) == expected
            witness = model.witness(i, mask)
            if len(after) == 1:
                assert witness is None
            else:
                left, right = witness
                assert agrees(anchor, states[left], mask)
                assert agrees(anchor, states[right], mask)
                assert new(states[left]) is False and new(states[right]) is True


def test_inclusion_minimal_does_not_mean_minimum_cardinality():
    model = CompiledModel(spec(lambda s: True, lambda s: s[0] or (s[1] and s[2])))
    i = model.states.index((True, True, True))
    assert set(model.minimal_masks(i)) == {1, 6}
    assert set(model.minimal_additions(i, 4)) == {1, 2}
    assert model.minimal_additions(i, 1) == (0,)


def test_confirmed_absence_is_an_observation_and_not_unread():
    model = CompiledModel(spec(
        lambda s: True, lambda s: s[0] == "absent",
        domains=(("absent", "present"), (False, True), (False, True))))
    index, mask = model.representative({"a": "absent"})
    assert mask == 1 and model.outcomes(index, mask) == {True}
    unseen, empty = model.representative({})
    assert empty == 0 and model.outcomes(unseen, empty) == {False, True}


def test_old_aggregate_failure_does_not_survive_removed_violation():
    model = CompiledModel(spec(lambda s: s[0] and s[1], lambda s: s[2] and s[1]))
    index = model.states.index((False, True, True))
    assert model.classify(index, 1, False) == "insufficient"
    assert model.classify(index, 7, False) == "stale_verdict"
    plan = model.static_delta_plan(("c",))
    assert plan[False]["reason"] == "all_new_dependencies_fallback"
    assert plan[False]["mask"] == 6
    assert plan[True]["reason"] == "verified_changed_dependencies"
    assert plan[True]["mask"] == 4


@pytest.mark.parametrize("old", PREDICATES)
@pytest.mark.parametrize("new", PREDICATES)
def test_static_delta_plans_are_sufficient_for_every_valid_receipt(old, new):
    model = CompiledModel(spec(old, new))
    for changed_mask in range(8):
        names = tuple(name for i, name in enumerate(model.block_names) if changed_mask & (2 ** i))
        plan = model.static_delta_plan(names)
        for index, state in enumerate(model.states):
            for retained in range(8):
                if oracle_outcomes(model.states, old, state, retained) != {old(state)}:
                    continue
                final_mask = retained | plan[old(state)]["mask"]
                assert oracle_outcomes(model.states, new, state, final_mask) == {new(state)}


@pytest.mark.parametrize("new", PREDICATES)
def test_recovery_never_uses_unread_values_to_select_next_block(new):
    model = CompiledModel(spec(lambda s: True, new))
    for retained in range(8):
        next_actions = {}
        for index, state in enumerate(model.states):
            final_mask, reads = model.recover(index, retained)
            assert len(reads) == len(set(reads))
            observed = retained
            for next_block in (*reads, None):
                # All states sharing current observations must take the same
                # next action, including stopping. Key is built independently.
                visible = tuple((i, state[i]) for i in range(3) if observed & (2 ** i))
                key = (observed, visible)
                if key in next_actions:
                    assert next_actions[key] == next_block
                else:
                    next_actions[key] = next_block
                if next_block is not None:
                    assert not observed & (2 ** next_block)
                    assert len(oracle_outcomes(model.states, new, state, observed)) == 2
                    observed |= 2 ** next_block
            assert observed == final_mask
            assert oracle_outcomes(model.states, new, state, final_mask) == {new(state)}


def good_receipt(model):
    return {
        "domain_sha256": model.domain_digest,
        "old_predicate_sha256": model.old_digest,
        "snapshot_sha256": "a" * 64,
        "observations": {"a": True},
        "verdict": True,
    }


@pytest.mark.parametrize("field", ("domain_sha256", "old_predicate_sha256", "snapshot_sha256"))
def test_receipt_bindings_cannot_be_reused_for_another_input_or_model(field):
    model = CompiledModel(spec(lambda s: s[0], lambda s: not s[0]))
    receipt = good_receipt(model)
    assert model.check_receipt(receipt, "a" * 64)["status"] == "stale_verdict"
    receipt[field] = "b" * 64
    assert model.check_receipt(receipt, "a" * 64)["status"] == "invalid_receipt"


@pytest.mark.parametrize("value", (True, False, 1, 0, None, "true"))
def test_recorded_decision_is_verified_without_coercion(value):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[1]))
    receipt = good_receipt(model)
    receipt["verdict"] = value
    expected = "insufficient" if value is True else "invalid_receipt"
    assert model.check_receipt(receipt, "a" * 64)["status"] == expected
    receipt["observations"] = {}
    assert model.check_receipt(receipt, "a" * 64)["status"] == "invalid_receipt"


@pytest.mark.parametrize("observations", ({"unknown": True}, {"a": "unsupported"}, None, ["a"], "a"))
def test_bad_observation_shapes_and_values_return_invalid_receipt(observations):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[1]))
    receipt = good_receipt(model)
    receipt["observations"] = observations
    assert model.check_receipt(receipt, "a" * 64)["status"] == "invalid_receipt"


@pytest.mark.parametrize("receipt", (None, [], "receipt", 1))
def test_bad_outer_receipt_shapes_return_invalid_receipt(receipt):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[1]))
    assert model.check_receipt(receipt, "a" * 64)["status"] == "invalid_receipt"


@pytest.mark.parametrize("bad_label", (None, 0, 1, "false", (False,)))
def test_predicate_errors_or_nonboolean_outputs_never_become_verdicts(bad_label):
    with pytest.raises(ValueError, match="bool"):
        CompiledModel(spec(lambda s: bad_label, lambda s: True))


@pytest.mark.parametrize("mask", (-1, 8, True, None, "1"))
def test_unsupported_masks_rejected(mask):
    model = CompiledModel(spec(lambda s: True, lambda s: True))
    with pytest.raises(ValueError):
        model.outcomes(0, mask)


def test_semantically_equivalent_rewrites_preserve_every_certificate():
    old = lambda s: s[0] and (s[1] or s[2])
    new = lambda s: (s[0] and s[1]) or (s[0] and s[2])
    model = CompiledModel(spec(old, new))
    assert model.old_digest == model.new_digest
    for index, state in enumerate(model.states):
        assert model.minimal_masks(index, "old") == model.minimal_masks(index, "new")
        for mask in range(8):
            if oracle_outcomes(model.states, old, state, mask) == {old(state)}:
                assert model.classify(index, mask, old(state)) == "safe"


def test_receipt_validation_does_not_mutate_retained_evidence():
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    receipt = good_receipt(model)
    before = deepcopy(receipt)
    assert model.check_receipt(receipt, "a" * 64)["status"] == "insufficient"
    assert receipt == before


def test_six_named_blocks_are_not_collapsed_into_the_original_two_blocks():
    predicate = lambda s: (s[0] and s[1]) or (s[2] and s[3]) or (s[4] and s[5])
    model = CompiledModel({
        "name": "six-independent-blocks",
        "block_names": ("value", "absence", "component", "member", "range", "unit"),
        "domains": ((False, True),) * 6,
        "old_predicate": lambda s: True,
        "new_predicate": predicate,
    })
    assert len(model.states) == 64
    index = model.states.index((True,) * 6)
    assert set(model.minimal_masks(index)) == {3, 12, 48}
    for i, state in enumerate(model.states):
        assert set(model.minimal_masks(i)) == oracle_minimal_masks(model.states, predicate, state)
        final, reads = model.recover(i)
        assert oracle_outcomes(model.states, predicate, state, final) == {predicate(state)}
        assert all(0 <= block < 6 for block in reads)


@pytest.fixture
def harness():
    path = Path(__file__).resolve().parents[1] / "scripts/audit_standards_extension.py"
    module_spec = importlib.util.spec_from_file_location("independently_loaded_standards_harness", path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def encoded(state):
    return {name: {"value": value, "note": "값"} for name, value in zip("abc", state)}


def test_codec_rejects_payloads_that_leak_hidden_blocks(harness):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))

    def leaking(state):
        payload = encoded(state)
        payload["a"]["hidden_b"] = state[1]
        return payload

    with pytest.raises(ValueError, match="unobserved block"):
        harness.BlockCodec(model, leaking)


def test_codec_rejects_indistinguishable_payloads_for_distinct_categories(harness):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))

    def collapsed(state):
        payload = encoded(state)
        payload["a"] = {"value": "same"}
        return payload

    with pytest.raises(ValueError, match="injective"):
        harness.BlockCodec(model, collapsed)


def test_codec_rejects_category_payload_corruption_and_snapshot_mixups(harness):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((True, True, False)))
    receipt = json.loads(record["receipt"])
    receipt["payloads"]["a"]["value"] = False
    with pytest.raises(ValueError, match="category"):
        codec.load_receipt(json.dumps(receipt), record["snapshot"])
    with pytest.raises(ValueError, match="binding"):
        codec.load_receipt(record["receipt"], "another immutable snapshot")


@pytest.mark.parametrize("strategy,expected_reads", (
    ("full_fragment", 3), ("fresh_guarded", 2), ("ordinary_cached", 1),
    ("static_delta", 1), ("receipt_audit", 1),
))
def test_replay_charges_only_actual_separate_source_fetches(harness, strategy, expected_reads):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((True, True, False)))
    fetches = []

    class TracedSource(dict):
        def __getitem__(self, name):
            fetches.append(name)
            return super().__getitem__(name)

    record["source"] = TracedSource(record["source"])
    result = harness.run_case(model, codec, record, strategy, "separate", model.static_delta_plan(("b",)))
    assert result["verdict"] is True
    assert len(fetches) == expected_reads == result["logical_blocks"] == result["source_requests"]
    assert result["source_bytes"] == sum(len(dict.__getitem__(record["source"], name).encode("utf-8")) for name in fetches)
    assert result["receipt_requests"] == int(strategy in {"ordinary_cached", "static_delta", "receipt_audit"})
    if strategy in {"ordinary_cached", "static_delta", "receipt_audit"}:
        assert fetches == ["b"]
        assert result["receipt_bytes"] == len(record["receipt"].encode("utf-8"))
    assert result["emitted_bytes"] > 0


@pytest.mark.parametrize("strategy", ("ordinary_cached", "static_delta", "receipt_audit"))
@pytest.mark.parametrize("layout", ("separate", "bundled"))
def test_certain_cached_failure_never_touches_source(harness, strategy, layout):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((False, True, False)))

    class ForbiddenSource(dict):
        def __getitem__(self, name):
            raise AssertionError("An unneeded source field was retrieved: " + name)

    record["source"] = ForbiddenSource(record["source"])
    result = harness.run_case(model, codec, record, strategy, layout, model.static_delta_plan(("b",)))
    assert result["verdict"] is False
    assert result["source_bytes"] == result["source_requests"] == result["logical_blocks"] == 0


def test_ordinary_replay_does_not_run_migration_diagnostics(harness, monkeypatch):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((True, True, False)))

    def forbidden(*args, **kwargs):
        raise AssertionError("Ordinary retained-value replay invoked diagnostic receipt classification")

    monkeypatch.setattr(model, "check_receipt", forbidden)
    result = harness.run_case(model, codec, record, "ordinary_cached", "separate", model.static_delta_plan(("b",)))
    assert result["verdict"] is True and result["status"] is None


def test_bundled_delivery_is_charged_completely_and_all_fields_become_known(harness):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((True, True, False)))
    results = {}
    for strategy in ("full_fragment", "fresh_guarded", "ordinary_cached", "static_delta", "receipt_audit"):
        result = harness.run_case(model, codec, record, strategy, "bundled", model.static_delta_plan(("b",)))
        assert result["verdict"] is True
        assert result["source_requests"] == result["explicitly_requested_blocks"] == 1
        assert result["source_bytes"] == len(record["bundled"].encode("utf-8"))
        assert result["logical_blocks"] == 3
        cached = strategy in {"ordinary_cached", "static_delta", "receipt_audit"}
        assert result["newly_observed_blocks"] == (2 if cached else 3)
        results[strategy] = result
    # The complete bundle now feeds the replacement receipt for every method.
    assert len({row["emitted_bytes"] for row in results.values()}) == 1


def test_ordinary_recomputation_does_not_require_old_verdict_to_remain_trustworthy(harness):
    model = CompiledModel(spec(lambda s: s[0], lambda s: s[0] and s[1]))
    codec = harness.BlockCodec(model, encoded)
    record = codec.record(model.states.index((True, True, False)))
    receipt = json.loads(record["receipt"])
    receipt["verdict"] = False  # Retained true values and binding are unchanged.
    record["receipt"] = json.dumps(receipt)
    ordinary = harness.run_case(model, codec, record, "ordinary_cached", "separate", model.static_delta_plan(("b",)))
    assert ordinary["verdict"] is True
    for strategy in ("static_delta", "receipt_audit"):
        with pytest.raises(ValueError, match="old evidence"):
            harness.run_case(model, codec, record, strategy, "separate", model.static_delta_plan(("b",)))
