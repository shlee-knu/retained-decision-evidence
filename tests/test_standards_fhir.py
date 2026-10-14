from copy import deepcopy
import pytest

from logistics_validation.standards_fhir import (
    BLOCK_NAMES, DOMAINS, abstract_resource, all_states, build_models,
    complete_resource, constraints_for, encode_state,
    raw_constraint_results, state_constraint_results,
)


def test_all_representatives_match_independent_complete_json_reference():
    for model in build_models():
        for version in {model["metadata"]["old_version"], model["metadata"]["new_version"]}:
            rules = constraints_for(model["metadata"]["profile"], version)
            for state in all_states():
                assert raw_constraint_results(complete_resource(state), rules) == state_constraint_results(state, rules)


def test_late_array_members_cannot_be_hidden_by_bounded_representatives():
    resource = complete_resource(("quantity_ucum", "absent", "different_code", "absent", "valid_ucum"))
    resource["referenceRange"] *= 1000
    resource["referenceRange"].append({"high": {"value": 1, "system": "https://example.org/local"}})
    resource["component"] *= 1000
    resource["component"].append({"code": deepcopy(resource["code"]), "valueString": "last member"})
    state = abstract_resource(resource)
    assert state[2] == "matching_code"
    assert state[4] == "valid_other"
    for version in ("6.1.0", "7.0.0"):
        rules = constraints_for("observation-lab", version)
        assert raw_constraint_results(resource, rules) == state_constraint_results(state, rules)


def test_no_bounds_and_non_ucum_in_distinct_members_preserve_both_failures():
    state = ("absent", "unknown", "absent", "absent", "invalid_bounds_other")
    resource = complete_resource(state)
    assert abstract_resource(resource) == state
    raw = raw_constraint_results(resource, constraints_for("observation-lab", "7.0.0"))
    assert raw["obs-3"] is False
    assert raw["us-core-22"] is False


def test_complete_absence_and_subsetted_response_are_different():
    state = ("absent", "unknown", "absent", "absent", "absent")
    payload = encode_state(state)
    assert payload["value"] == {"complete": True, "fields": {}}
    resource = complete_resource(state)
    assert abstract_resource(resource) == state
    resource["meta"] = {"tag": [{"system": "http://terminology.hl7.org/CodeSystem/v3-ObservationValue", "code": "SUBSETTED"}]}
    with pytest.raises(ValueError, match="completeness"):
        abstract_resource(resource)


def test_payloads_separable_injective_and_choice_is_not_silently_coerced():
    import json
    values = {name: {} for name in BLOCK_NAMES}
    for state in all_states():
        for i, (name, payload) in enumerate(encode_state(state).items()):
            encoded = json.dumps(payload, sort_keys=True)
            previous = values[name].setdefault(state[i], encoded)
            assert encoded == previous
    for i, name in enumerate(BLOCK_NAMES):
        assert len(set(values[name].values())) == len(DOMAINS[i])
    resource = complete_resource(("absent", "absent", "absent", "absent", "absent"))
    resource["valueCodeableConcept"] = {"text": "outside supported choices"}
    with pytest.raises(ValueError, match="value choice"):
        abstract_resource(resource)


def test_transitions_declared_strengthening_hold_exhaustively():
    for model in build_models():
        for state in all_states():
            old, new = model["old_predicate"](state), model["new_predicate"](state)
            assert old or not new
            if model["metadata"]["transition_kind"] == "identity":
                assert old == new


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(_valueString={"extension": [{"url": "urn:test", "valueString": "unknown"}]}),
    lambda r: r["valueQuantity"].update(_system={"extension": [{"url": "urn:test", "valueString": "unknown"}]}),
    lambda r: r["valueQuantity"].update(system=None),
    lambda r: r.update(component={"code": {"text": "wrong array type"}}),
    lambda r: r.update(referenceRange=[]),
    lambda r: r.update(referenceRange=[{"text": []}]),
])
def test_valid_fhir_special_forms_and_bad_shapes_are_outside_fragment(mutation):
    resource = complete_resource(("quantity_ucum", "absent", "absent", "absent", "absent"))
    mutation(resource)
    with pytest.raises(ValueError):
        abstract_resource(resource)
