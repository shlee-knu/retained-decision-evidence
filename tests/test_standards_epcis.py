"""Semantic boundaries that a schema-only or unread-as-absent adapter misses."""
from copy import deepcopy
from itertools import product
import json

import pytest

from logistics_validation.standards_epcis import (
    RESOURCE_DIR, build_models, build_schema_identity_model, document_from_state,
    independent_document_oracle,
)


def test_every_finite_state_matches_independent_raw_json_clauses():
    counts = []
    for model in build_models():
        count = 0
        for state in product(*model["domains"]):
            raw = document_from_state(model, state)
            oracle = independent_document_oracle(raw)
            assert oracle["supported"]
            assert model["old_predicate"](state) == oracle["compatible_selected"]
            assert model["new_predicate"](state) == oracle["compliant_selected"]
            assert not model["new_predicate"](state) or model["old_predicate"](state)
            count += 1
        counts.append(count)
    assert counts == [324, 216, 648]


def test_block_payloads_are_separable_and_categories_are_distinguishable():
    for model in build_models():
        observed = [{} for _ in model["domains"]]
        for state in product(*model["domains"]):
            encoded = model["encode_state"](state)
            for i, name in enumerate(model["block_names"]):
                wire = json.dumps(encoded[name], sort_keys=True)
                assert observed[i].setdefault(state[i], wire) == wire
        for domain, values in zip(model["domains"], observed):
            assert len(set(values.values())) == len(domain)


def test_object_empty_epc_list_is_not_an_object_observation_without_sensor_exception():
    model = build_models()[0]
    state = ("ADD", "empty", "absent", "absent", "receiving")
    raw = document_from_state(model, state)
    assert not independent_document_oracle(raw)["compatible_selected"]
    raw["epcisBody"]["eventList"][0]["quantityList"] = [{"epcClass": "https://example.org/class", "quantity": 2}]
    assert independent_document_oracle(raw)["compatible_selected"]


@pytest.mark.parametrize("action,expected", [("ADD", True), ("OBSERVE", False), ("DELETE", False)])
def test_present_even_empty_ilmd_obeys_action_requirement(action, expected):
    model = build_models()[0]
    raw = document_from_state(model, (action, "nonempty", "absent", "empty", "receiving"))
    assert independent_document_oracle(raw)["compatible_selected"] is expected


def test_aggregation_parent_and_delete_all_are_distinct_dependencies():
    model = build_models()[1]
    check = lambda s: independent_document_oracle(document_from_state(model, s))["compatible_selected"]
    assert check(("OBSERVE", "absent", "nonempty", "absent", "receiving"))
    assert not check(("ADD", "absent", "nonempty", "absent", "receiving"))
    assert check(("DELETE", "present", "absent", "absent", "receiving"))
    assert not check(("DELETE", "absent", "absent", "absent", "receiving"))


def test_transformation_identifier_changes_and_to_or_without_allowing_empty_event():
    model = build_models()[2]
    check = lambda s: independent_document_oracle(document_from_state(model, s))["compatible_selected"]
    assert not check(("absent", "nonempty", "absent", "absent", "empty", "receiving"))
    assert check(("present", "nonempty", "absent", "absent", "empty", "receiving"))
    assert not check(("present", "empty", "absent", "absent", "empty", "receiving"))
    assert check(("absent", "nonempty", "absent", "absent", "nonempty", "receiving"))


def test_profile_change_depends_on_value_not_presence_or_uri_spelling():
    model = build_models()[0]
    prefix = ("ADD", "nonempty", "absent", "absent")
    for value in ("receiving", "shipping", "receiving_uri"):
        assert model["old_predicate"](prefix + (value,))
        assert model["new_predicate"](prefix + (value,))
    assert model["old_predicate"](prefix + ("vendor",))
    assert not model["new_predicate"](prefix + ("vendor",))


def test_absence_and_malformed_values_are_not_false_supported_verdicts():
    model = build_models()[0]
    raw = document_from_state(model, ("ADD", "nonempty", "absent", "absent", "receiving"))
    missing_step = deepcopy(raw)
    missing_step["epcisBody"]["eventList"][0].pop("bizStep")
    assert not independent_document_oracle(missing_step)["supported"]
    malformed_array = deepcopy(raw)
    malformed_array["epcisBody"]["eventList"][0]["epcList"] = None
    assert not independent_document_oracle(malformed_array)["supported"]
    with pytest.raises(ValueError):
        model["encode_state"](("ADD", "unread", "absent", "absent", "receiving"))


def test_complete_multi_event_example_and_long_arrays_check_every_event():
    model = build_models()[0]
    raw = document_from_state(model, ("ADD", "nonempty", "absent", "absent", "receiving"))
    event = raw["epcisBody"]["eventList"][0]
    event["epcList"] *= 20  # Multiplicity is outside these selected occupancy predicates.
    raw["epcisBody"]["eventList"].append(deepcopy(event))
    assert independent_document_oracle(raw)["compatible_selected"]
    raw["epcisBody"]["eventList"][1]["epcList"] = []
    assert not independent_document_oracle(raw)["compatible_selected"]


@pytest.mark.skipif(not (RESOURCE_DIR / "2.0.1_epcis-json-schema.json").exists(), reason="Acquire pinned GS1 resources first")
def test_schema_identity_and_known_prose_coverage_gap():
    from jsonschema import Draft7Validator, FormatChecker
    identity = build_schema_identity_model()
    assert all(identity["old_predicate"](s) == identity["new_predicate"](s)
               for s in product(*identity["domains"]))
    validator = Draft7Validator(json.loads((RESOURCE_DIR / "2.0.1_epcis-json-schema.json").read_text()),
                               format_checker=FormatChecker())
    model = build_models()[1]
    doc = document_from_state(model, ("ADD", "absent", "nonempty", "absent", "receiving"))
    assert validator.is_valid(doc)
    assert not independent_document_oracle(doc)["compatible_selected"]
