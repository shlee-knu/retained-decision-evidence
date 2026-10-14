"""Exact finite adapter for a declared, versioned US Core invariant fragment.

This is not a FHIR validator. Complete grouped fields are observations; unread
fields are represented only by the generic partial-observation engine. A complete
absent field is encoded by ``fields={}``, never by an unread sentinel.
"""
from copy import deepcopy
from itertools import product
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/external/fhir_standards"
UCUM = "http://unitsofmeasure.org"
LOINC = "http://loinc.org"
BLOCK_NAMES = ("value", "dataAbsentReason", "component", "hasMember", "referenceRange")
DOMAINS = (
    ("absent", "string", "quantity_uncoded", "quantity_ucum", "quantity_other"),
    ("absent", "unknown"),
    ("absent", "different_code", "matching_code"),
    ("absent", "present"),
    ("absent", "text", "valid_ucum", "valid_other", "invalid_bounds", "invalid_bounds_other"),
)
SUPPORTED_KEYS = {"obs-6", "obs-7", "us-core-2", "us-core-3", "obs-3", "us-core-22"}
DEPENDENCIES = {
    "obs-6": ("value", "dataAbsentReason"),
    "obs-7": ("value", "component"),
    "us-core-2": ("value", "dataAbsentReason", "component", "hasMember"),
    "us-core-3": ("value",),
    "obs-3": ("referenceRange",),
    "us-core-22": ("referenceRange",),
}
EXPECTED_EXPRESSIONS = {
    "obs-6": {"dataAbsentReason.empty() or value.empty()"},
    "obs-7": {"value.empty() or component.code.where(coding.intersect(%resource.code.coding).exists()).empty()"},
    "us-core-2": {"(component.empty() and hasMember.empty()) implies (dataAbsentReason.exists() or value.exists())"},
    "us-core-3": {
        "value.ofType(Quantity).system.empty() or value.ofType(Quantity).system = 'http://unitsofmeasure.org'",
        "ofType(Quantity).system.empty() or ofType(Quantity).system = 'http://unitsofmeasure.org'",
    },
    "obs-3": {"low.exists() or high.exists() or text.exists()"},
    "us-core-22": {"(low.system.empty() or low.system = 'http://unitsofmeasure.org') and (high.system.empty() or high.system = 'http://unitsofmeasure.org')"},
}
EXPECTED_PATHS = {key: ("Observation.value[x]" if key == "us-core-3" else
                       "Observation.referenceRange" if key in {"obs-3", "us-core-22"} else
                       "Observation") for key in SUPPORTED_KEYS}


def load_profile(profile, version):
    return json.loads((DATA / f"profiles/{version}/StructureDefinition-us-core-{profile}.json").read_text())


def constraints_for(profile, version):
    constraints = []
    for element in load_profile(profile, version)["snapshot"]["element"]:
        for constraint in element.get("constraint", []):
            if constraint["key"] not in SUPPORTED_KEYS:
                continue
            expression = constraint["expression"]
            if (expression not in EXPECTED_EXPRESSIONS[constraint["key"]]
                    or element["path"] != EXPECTED_PATHS[constraint["key"]]
                    or constraint["severity"] != "error"):
                raise ValueError(f"Unreviewed expression: {profile} {version} {constraint['key']}: {expression}")
            constraints.append({"key": constraint["key"], "path": element["path"],
                                "expression": expression, "severity": constraint["severity"]})
    return tuple(constraints)


def encode_state(state):
    if len(state) != len(BLOCK_NAMES) or any(s not in d for s, d in zip(state, DOMAINS)):
        raise ValueError("State outside declared finite domains")
    value, reason, component, members, ranges = state
    fields = [{} for _ in BLOCK_NAMES]
    if value == "string":
        fields[0] = {"valueString": "synthetic result"}
    elif value.startswith("quantity_"):
        quantity = {"value": 1}
        if value != "quantity_uncoded":
            quantity.update(system=UCUM if value == "quantity_ucum" else "https://example.org/local-units", code="g/dL")
        fields[0] = {"valueQuantity": quantity}
    if reason != "absent":
        fields[1] = {"dataAbsentReason": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/data-absent-reason", "code": "unknown"}]}}
    if component != "absent":
        fields[2] = {"component": [{"code": {"coding": [{"system": LOINC, "code": "4548-4"}]}, "valueString": "synthetic component"}]}
        if component == "matching_code":
            fields[2]["component"].append({"code": {"coding": [{"system": LOINC, "code": "718-7"}]}, "valueString": "second component"})
    if members != "absent":
        fields[3] = {"hasMember": [{"reference": "Observation/synthetic-member"}]}
    good = {"low": {"value": 1, "system": UCUM, "code": "g/dL"}, "high": {"value": 2, "system": UCUM, "code": "g/dL"}}
    bad = {"low": {"value": 1, "system": "https://example.org/local-units", "code": "g/dL"}}
    no_bounds = {"age": {"low": {"value": 18, "system": UCUM, "code": "a"}}}
    range_values = {"text": [{"text": "synthetic text interval"}],
                    "valid_ucum": [good, {"text": "second complete interval"}],
                    "valid_other": [good, bad], "invalid_bounds": [no_bounds],
                    "invalid_bounds_other": [no_bounds, bad]}
    if ranges != "absent":
        fields[4] = {"referenceRange": range_values[ranges]}
    return {name: {"complete": True, "fields": item} for name, item in zip(BLOCK_NAMES, fields)}


def complete_resource(state, identifier="synthetic-observation"):
    resource = {"resourceType": "Observation", "id": identifier,
                "status": "final", "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category", "code": "laboratory"}]}],
                "code": {"coding": [{"system": LOINC, "code": "718-7"}]},
                "subject": {"reference": "Patient/example"},
                "effectiveDateTime": "2024-01-01T00:00:00Z"}
    for block in encode_state(state).values():
        resource.update(deepcopy(block["fields"]))
    return resource


def state_constraint_results(state, constraints):
    value, reason, component, members, ranges = state
    values = {
        "obs-6": value == "absent" or reason == "absent",
        "obs-7": value == "absent" or component != "matching_code",
        "us-core-2": component != "absent" or members != "absent" or value != "absent" or reason != "absent",
        "obs-3": ranges not in {"invalid_bounds", "invalid_bounds_other"},
        "us-core-22": ranges not in {"valid_other", "invalid_bounds_other"},
    }
    result = {}
    for constraint in constraints:
        key = constraint["key"]
        if key == "us-core-3":
            # Evaluate the published expression in its declared element context.
            # 6.1.0's value.ofType(Quantity) descends into Quantity.value (decimal),
            # hence no Quantity remains. 7.0.0 correctly tests the current value.
            result[key] = constraint["expression"].startswith("value.") or value != "quantity_other"
        else:
            result[key] = values[key]
    return result


def validate_fragment_resource(resource):
    """Reject valid-FHIR forms and malformed shapes outside our explicit fragment.

    Primitive extensions and modifier/ordinary extensions are deliberately not
    implemented. Structural checks here are domain guards, not FHIR validation.
    The complete root code is visible background, including for official examples.
    """
    if not isinstance(resource, dict) or resource.get("resourceType") != "Observation":
        raise ValueError("Only Observation supported")

    def check_tree(value):
        if value is None:
            raise ValueError("Null values outside supported fragment")
        if isinstance(value, dict):
            if any(k.startswith("_") or k in {"extension", "modifierExtension"} for k in value):
                raise ValueError("Primitive or other extensions outside supported fragment")
            for child in value.values():
                check_tree(child)
        elif isinstance(value, list):
            for child in value:
                check_tree(child)

    if any(k.startswith("_value") for k in resource):
        raise ValueError("Primitive extensions outside supported fragment")
    for key in ("code", "valueString", "valueQuantity", "dataAbsentReason", "component", "hasMember", "referenceRange"):
        if key in resource:
            check_tree(resource[key])
    if not isinstance(resource.get("code"), dict):
        raise ValueError("Complete code background required")
    for key in ("component", "hasMember", "referenceRange"):
        if key in resource and (not isinstance(resource[key], list) or not resource[key]
                                or any(not isinstance(x, dict) or not x for x in resource[key])):
            raise ValueError(f"Unsupported complete array shape: {key}")
    if "valueString" in resource and (not isinstance(resource["valueString"], str) or not resource["valueString"]):
        raise ValueError("Unsupported valueString shape")
    for quantity in ([resource["valueQuantity"]] if "valueQuantity" in resource else []) + [
            item[side] for item in resource.get("referenceRange", []) for side in ("low", "high") if side in item]:
        if not isinstance(quantity, dict) or not quantity:
            raise ValueError("Unsupported Quantity shape")
        if "system" in quantity and (not isinstance(quantity["system"], str) or not quantity["system"]):
            raise ValueError("Unsupported primitive system shape")
    for item in resource.get("referenceRange", []):
        if "text" in item and (not isinstance(item["text"], str) or not item["text"]):
            raise ValueError("Unsupported referenceRange.text shape")
    if "dataAbsentReason" in resource and (not isinstance(resource["dataAbsentReason"], dict) or not resource["dataAbsentReason"]):
        raise ValueError("Unsupported dataAbsentReason shape")
    for code in [resource["code"]] + [x.get("code") for x in resource.get("component", [])]:
        if not isinstance(code, dict):
            raise ValueError("Unsupported code shape")
        if "coding" in code and (not isinstance(code["coding"], list) or any(not isinstance(c, dict) or not c for c in code["coding"])):
            raise ValueError("Unsupported coding shape")


def raw_constraint_results(resource, constraints):
    """Independent direct JSON reference: does not call abstraction/state evaluator."""
    validate_fragment_resource(resource)
    values = [(name, value) for name, value in resource.items() if name.startswith("value")]
    components = resource.get("component", [])
    ranges = resource.get("referenceRange", [])
    codings = resource.get("code", {}).get("coding", [])
    results = {}
    for rule in constraints:
        key = rule["key"]
        if key == "obs-6":
            result = "dataAbsentReason" not in resource or not values
        elif key == "obs-7":
            result = not values or not any(any(coding == root for coding in item.get("code", {}).get("coding", []) for root in codings) for item in components)
        elif key == "us-core-2":
            result = bool(components or resource.get("hasMember", []) or "dataAbsentReason" in resource or values)
        elif key == "us-core-3":
            result = rule["expression"].startswith("value.") or "valueQuantity" not in resource or resource["valueQuantity"].get("system", UCUM) == UCUM
        elif key == "obs-3":
            result = all(any(name in entry for name in ("low", "high", "text")) for entry in ranges)
        elif key == "us-core-22":
            result = all(entry.get(bound, {}).get("system", UCUM) == UCUM for entry in ranges for bound in ("low", "high"))
        else:
            raise ValueError(f"Unsupported invariant {key}")
        results[key] = bool(result)
    return results


def abstract_resource(resource):
    """Map arbitrary-length *complete* root arrays to invariant-preserving categories.

    Caller attests complete selected roots; this function must never be called on
    a partial response as though omitted roots were confirmed absent. Explicit
    completeness lives in the accessor/receipt, not the JSON resource itself.
    """
    validate_fragment_resource(resource)
    if "SUBSETTED" in {c.get("code") for c in resource.get("meta", {}).get("tag", [])}:
        raise ValueError("Subsetted resource does not establish root completeness")
    value_keys = [key for key in resource if key.startswith("value")]
    if len(value_keys) > 1 or any(k not in {"valueString", "valueQuantity"} for k in value_keys):
        raise ValueError("Unsupported value choice")
    if not value_keys:
        value = "absent"
    elif value_keys[0] == "valueString":
        value = "string"
    else:
        quantity = resource["valueQuantity"]
        value = "quantity_uncoded" if "system" not in quantity else ("quantity_ucum" if quantity["system"] == UCUM else "quantity_other")
    reason = "unknown" if "dataAbsentReason" in resource else "absent"
    root_codes = resource.get("code", {}).get("coding", [])
    comps = resource.get("component", [])
    component = "absent" if not comps else ("matching_code" if any(
        code == root_code for item in comps for code in item.get("code", {}).get("coding", []) for root_code in root_codes) else "different_code")
    members = "present" if resource.get("hasMember", []) else "absent"
    ranges = resource.get("referenceRange", [])
    if not ranges:
        range_category = "absent"
    else:
        good_bounds = all(any(k in item for k in ("low", "high", "text")) for item in ranges)
        good_systems = all(item.get(side, {}).get("system", UCUM) == UCUM for item in ranges for side in ("low", "high"))
        if not good_bounds:
            range_category = "invalid_bounds" if good_systems else "invalid_bounds_other"
        elif not good_systems:
            range_category = "valid_other"
        else:
            range_category = "text" if all("low" not in item and "high" not in item for item in ranges) else "valid_ucum"
    return value, reason, component, members, range_category


def build_models():
    models = []
    for profile in ("observation-lab", "observation-clinical-result", "simple-observation"):
        for old_version, new_version in (("6.1.0", "7.0.0"), ("6.1.0", "6.1.0")):
            old = constraints_for(profile, old_version)
            new = constraints_for(profile, new_version)
            old_by_key = {r["key"]: r for r in old}
            changed = [r for r in new if old_by_key.get(r["key"]) != r]
            deps = lambda rules: tuple(name for name in BLOCK_NAMES if any(name in DEPENDENCIES[r["key"]] for r in rules))
            semantic_identity = old == new
            metadata = {
                "standard": "FHIR R4 / US Core", "profile": profile,
                "old_version": old_version, "new_version": new_version,
                "scope": "selected machine-readable invariant fragment; not whole-profile conformance",
                "old_constraints": old, "new_constraints": new,
                "new_dependencies": deps(new), "changed_dependencies": deps(changed),
                "transition_kind": "identity" if semantic_identity else "strengthening",
                "whole_profile_transition_kind": "not classified; full delta inventory retained",
                "array_scope": "unbounded complete root arrays, exists/all predicate abstraction; representatives have at most two members",
                "fragment_domain": "Well-typed selected roots without primitive/other extensions, nulls or empty serialized arrays; absent/string/Quantity value choices only. Complete code is visible background, fixed in the finite universe; native mapping uses each complete resource's code.",
                "cost_boundary": "old validation and fixture/projection preparation are already-incurred setup; only retained observations constitute receipt evidence",
                "source_urls": [f"https://hl7.org/fhir/us/core/{publication}/StructureDefinition-us-core-{profile}.json" for publication in ("STU6.1", "STU7")],
                "public_examples_manifest": "data/external/fhir_standards/examples_manifest.json",
            }
            models.append({"name": f"fhir_{profile.replace('-', '_')}_{old_version}_to_{new_version}",
                           "block_names": BLOCK_NAMES, "domains": DOMAINS,
                           "old_predicate": lambda state, rules=old: all(state_constraint_results(state, rules).values()),
                           "new_predicate": lambda state, rules=new: all(state_constraint_results(state, rules).values()),
                           "encode_state": encode_state, "metadata": metadata})
    return models


def all_states():
    return tuple(product(*DOMAINS))
