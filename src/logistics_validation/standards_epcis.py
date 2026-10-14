"""Finite, standard-native EPCIS clause models for observation-change audits.

These are selected requirements, not complete EPCIS/CBV conformance. Event type,
valid timestamps, the pinned context and absent sensor fields are visible base
facts. Each named block discloses one whole field, including its absence. The
local block interface is authored for this experiment, not an EPCIS API promise.
"""
from __future__ import annotations

from copy import deepcopy
from itertools import product
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESOURCE_DIR = ROOT / "data/external/epcis_extension/originals"
CONTEXT = "https://ref.gs1.org/standards/epcis/2.0.1/epcis-context.jsonld"
LIST_DOMAIN = ("absent", "empty", "nonempty")
BIZ_DOMAIN = ("receiving", "shipping", "receiving_uri", "vendor")
BIZ_VALUES = {
    "receiving": "receiving",
    "shipping": "shipping",
    "receiving_uri": "https://ref.gs1.org/cbv/BizStep-receiving",
    "vendor": "https://example.org/workflow/custom_step",
}
KNOWN_CBV = frozenset(("receiving", "shipping", "commissioning"))
OBJECT_ID = "urn:epc:id:sgtin:0614141.107346.2017"
OUTPUT_ID = "urn:epc:id:sgtin:0614141.107346.2018"
QUANTITY = {"epcClass": "urn:epc:class:lgtin:0614141.107346.101", "quantity": 2}


def _field_payload(field, category):
    if category == "absent":
        return {"present": False}
    if field == "bizStep":
        value = BIZ_VALUES[category]
    elif field == "action":
        value = category
    elif field == "parentID":
        value = "urn:epc:id:sscc:0614141.1234567890"
    elif field == "transformationID":
        value = "https://example.org/transformation/1"
    elif field == "ilmd":
        value = {} if category == "empty" else {"https://example.org/lot": "LOT-1"}
    elif category == "empty":
        value = []
    elif "Quantity" in field or field == "quantityList":
        value = [deepcopy(QUANTITY)]
    else:
        value = [OUTPUT_ID if field == "outputEPCList" else OBJECT_ID]
    return {"present": True, "value": value}


def document_from_blocks(event_type, blocks):
    """Reconstruct a complete single-event document from explicitly known blocks."""
    event = {"type": event_type, "eventTime": "2026-01-01T12:00:00Z",
             "eventTimeZoneOffset": "+00:00"}
    for field, payload in blocks.items():
        if payload["present"]:
            event[field] = deepcopy(payload["value"])
    return {"@context": [CONTEXT], "type": "EPCISDocument", "schemaVersion": "2.0",
            "creationDate": "2026-01-01T12:00:00Z", "epcisBody": {"eventList": [event]}}


def document_from_state(model, state):
    return document_from_blocks(model["metadata"]["event_type"], model["encode_state"](state))


def _make_model(name, event_type, fields, domains, clause_predicate, clauses):
    fields, domains = tuple(fields), tuple(tuple(d) for d in domains)

    def check(state):
        if len(state) != len(fields) or any(v not in d for v, d in zip(state, domains)):
            raise ValueError("State outside declared EPCIS finite domain")

    def encode(state):
        check(state)
        return {f: _field_payload(f, c) for f, c in zip(fields, state)}

    def old(state):
        check(state)
        return bool(clause_predicate(state))

    def new(state):
        check(state)
        return bool(clause_predicate(state) and state[-1] != "vendor")

    return {"name": name, "block_names": fields, "domains": domains,
            "old_predicate": old, "new_predicate": new, "encode_state": encode,
            "metadata": {
                "standard": "EPCIS 2.0.1 / CBV 2.0.0", "event_type": event_type,
                "old_contract": "Selected EPCIS clauses plus compatible present bizStep",
                "new_contract": "Same selected EPCIS clauses plus compliant present bizStep",
                "clauses": clauses + ["CBV 2.0.0 sections 5.1, 5.2, 7.1.2 (present values only)"],
                "visible_base": ["event type", "fixed valid event/document timestamps",
                                 "pinned context", "all fields outside named blocks absent"],
                "scope": "Finite selected-clause domain, not complete standards conformance",
                "new_dependencies": list(fields), "changed_dependencies": ["bizStep"],
                "transition_kind": "strengthening",
                "migration_status": "Authored profile comparison; no observed organizational migration",
                "block_interface": "Authored local whole-field accessor; absent is an explicit value",
                "array_boundary": "An array is one complete block, never a hidden or unknown prefix",
                "business_step_absence": "Excluded: CBV 5.1 SHALL / 7.1.2 SHOULD wording differs",
                "synthetic": True}}


def build_models():
    """Return three dependency-bearing profile transitions without file I/O."""
    return [
        _make_model(
            "epcis_object_profile", "ObjectEvent",
            ("action", "epcList", "quantityList", "ilmd", "bizStep"),
            (("ADD", "OBSERVE", "DELETE"), LIST_DOMAIN, LIST_DOMAIN, LIST_DOMAIN, BIZ_DOMAIN),
            lambda s: (s[1] == "nonempty" or s[2] == "nonempty")
                      and (s[3] == "absent" or s[0] == "ADD"),
            ["EPCIS 7.4.2 p.79 nonempty object/quantity list (sensor exception excluded)",
             "EPCIS 7.4.2 p.81 ilmd forbidden with OBSERVE/DELETE"]),
        _make_model(
            "epcis_aggregation_profile", "AggregationEvent",
            ("action", "parentID", "childEPCs", "childQuantityList", "bizStep"),
            (("ADD", "OBSERVE", "DELETE"), ("absent", "present"), LIST_DOMAIN, LIST_DOMAIN, BIZ_DOMAIN),
            lambda s: (s[0] == "OBSERVE" or s[1] == "present")
                      and (s[0] == "DELETE" or s[2] == "nonempty" or s[3] == "nonempty"),
            ["EPCIS 7.4.3 p.85 parentID required except OBSERVE",
             "EPCIS 7.4.3 p.85 nonempty child list except DELETE"]),
        _make_model(
            "epcis_transformation_profile", "TransformationEvent",
            ("transformationID", "inputEPCList", "inputQuantityList", "outputEPCList",
             "outputQuantityList", "bizStep"),
            (("absent", "present"), LIST_DOMAIN, LIST_DOMAIN, LIST_DOMAIN, LIST_DOMAIN, BIZ_DOMAIN),
            lambda s: ((s[1] == "nonempty" or s[2] == "nonempty")
                       or (s[3] == "nonempty" or s[4] == "nonempty"))
                      if s[0] == "present" else
                      ((s[1] == "nonempty" or s[2] == "nonempty")
                       and (s[3] == "nonempty" or s[4] == "nonempty")),
            ["EPCIS 7.4.5 p.95 transformationID controls input AND/OR output requirement"]),
    ]


def independent_document_oracle(document):
    """Check the selected prose clauses directly on JSON, without state categories.

    This deliberately does not call the model predicates/encoder or a schema.
    URI interpretation is limited to the supported CBV terms and external HTTPS
    vocabulary used by this experiment; absent bizStep is unsupported.
    """
    def unsupported(reason):
        return {"supported": False, "unsupported_reason": reason, "clauses": {},
                "compatible_selected": False, "compliant_selected": False,
                "business_step_is_selected_cbv": False}

    try:
        events = document["epcisBody"]["eventList"]
        if not isinstance(events, list) or not events or not all(isinstance(e, dict) for e in events):
            return unsupported("Expected a nonempty complete event list")
        if len(events) > 1:
            checks = [independent_document_oracle({"epcisBody": {"eventList": [event]}})
                      for event in events]
            supported = all(check["supported"] for check in checks)
            return {"supported": supported,
                    "clauses": {f"event_{index}.{key}": value for index, check in enumerate(checks)
                                for key, value in check["clauses"].items()},
                    "compatible_selected": supported and all(c["compatible_selected"] for c in checks),
                    "compliant_selected": supported and all(c["compliant_selected"] for c in checks),
                    "business_step_is_selected_cbv": all(c["business_step_is_selected_cbv"] for c in checks),
                    "unsupported_reason": "; ".join(c.get("unsupported_reason", "Unsupported vocabulary")
                                                     for c in checks if not c["supported"])}
        event = events[0]
        kind = event["type"]
    except (KeyError, TypeError):
        return unsupported("Unsupported document envelope")
    if kind not in ("ObjectEvent", "AggregationEvent", "TransformationEvent"):
        return unsupported("Unsupported event type")
    array_fields = ("epcList", "quantityList", "childEPCs", "childQuantityList",
                    "inputEPCList", "inputQuantityList", "outputEPCList", "outputQuantityList")
    if any(field in event and not isinstance(event[field], list) for field in array_fields):
        return unsupported("Array absence, empty array and malformed array are distinct")
    if "sensorElementList" in event:
        return unsupported("Sensor exception outside selected domain")
    if kind != "TransformationEvent" and event.get("action") not in ("ADD", "OBSERVE", "DELETE"):
        return unsupported("Unsupported action")
    if "ilmd" in event and not isinstance(event["ilmd"], dict):
        return unsupported("Unsupported ilmd type")
    if any(field in event and (not isinstance(event[field], str) or not event[field])
           for field in ("parentID", "transformationID")):
        return unsupported("Unsupported identifier type")
    clauses = {}
    step = event.get("bizStep")
    if not isinstance(step, str):
        return unsupported("Present string bizStep required by the selected domain")
    recognised = step in KNOWN_CBV or step in {
        "https://ref.gs1.org/cbv/BizStep-" + term for term in KNOWN_CBV}
    external = isinstance(step, str) and step.startswith("https://example.org/")
    supported = recognised or external
    if kind == "ObjectEvent":
        clauses["object_nonempty_what"] = bool(event.get("epcList") or event.get("quantityList"))
        clauses["object_ilmd_action"] = "ilmd" not in event or event.get("action") == "ADD"
    elif kind == "AggregationEvent":
        clauses["aggregation_parent"] = event.get("action") == "OBSERVE" or "parentID" in event
        clauses["aggregation_children"] = (event.get("action") == "DELETE"
                                             or bool(event.get("childEPCs") or event.get("childQuantityList")))
    elif kind == "TransformationEvent":
        occupied = [bool(event.get("inputEPCList") or event.get("inputQuantityList")),
                    bool(event.get("outputEPCList") or event.get("outputQuantityList"))]
        clauses["transformation_io"] = (any(occupied) if "transformationID" in event else all(occupied))
    else:
        raise ValueError("Unsupported event type")
    return {"supported": supported, "clauses": clauses,
            "compatible_selected": supported and all(clauses.values()),
            "compliant_selected": supported and recognised and all(clauses.values()),
            "business_step_is_selected_cbv": recognised}


def build_schema_identity_model(resource_dir=None):
    """Actual official JSON-schema labels, independently evaluated under both releases."""
    from jsonschema import Draft7Validator, FormatChecker

    resource_dir = Path(resource_dir or RESOURCE_DIR)
    model = build_models()[0]
    labels = []
    for version in ("2.0.0", "2.0.1"):
        schema = json.loads((resource_dir / f"{version}_epcis-json-schema.json").read_text())
        Draft7Validator.check_schema(schema)
        validator = Draft7Validator(schema, format_checker=FormatChecker())
        labels.append({state: validator.is_valid(document_from_state(model, state))
                       for state in product(*model["domains"])})
    result = dict(model)
    result.update(name="epcis_json_schema_identity", old_predicate=lambda s: labels[0][tuple(s)],
                  new_predicate=lambda s: labels[1][tuple(s)])
    result["metadata"] = dict(model["metadata"],
                              old_contract="Official EPCIS 2.0.0 JSON Schema",
                              new_contract="Official EPCIS 2.0.1 JSON Schema",
                              scope="JSON validation identity control; not RDF semantic identity",
                              clauses=["Official Draft-07 JSON Schema"], synthetic=True,
                              changed_dependencies=[], transition_kind="identity")
    return result
