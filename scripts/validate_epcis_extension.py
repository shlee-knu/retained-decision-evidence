"""Independent clause checks, official-schema coverage and pinned-version controls."""
from __future__ import annotations

import argparse
from copy import deepcopy
import csv
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
from importlib.metadata import version

from jsonschema import Draft7Validator, FormatChecker
from logistics_validation.standards_epcis import (
    CONTEXT, RESOURCE_DIR, build_models, document_from_state, independent_document_oracle,
)

ROOT = Path(__file__).resolve().parents[1]


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def check_resources():
    protocol = json.loads((ROOT / "configs/epcis_standards_protocol.json").read_text())
    for item in protocol["resources"]:
        content = (RESOURCE_DIR / item["file"]).read_bytes()
        if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError(f"Pinned source mismatch: {item['file']}")
    return protocol


def schema_validators():
    schemas, validators = {}, {}
    for release in ("2.0.0", "2.0.1"):
        schemas[release] = json.loads((RESOURCE_DIR / f"{release}_epcis-json-schema.json").read_text())
        Draft7Validator.check_schema(schemas[release])
        validators[release] = Draft7Validator(schemas[release], format_checker=FormatChecker())
    return schemas, validators


def example_cases():
    """Mutation recipes on preserved official examples; changed hash IDs removed."""
    for kind in ("object", "aggregation", "transformation"):
        original = json.loads((RESOURCE_DIR / f"{kind}_example.jsonld").read_text())
        yield kind, "official_unchanged", original
        recipes = [("vendor_bizstep", {"bizStep": "https://example.org/workflow/custom_step"}, ()),
                   ("absent_bizstep_outside_domain", {}, ("bizStep",))]
        if kind == "object":
            recipes += [
                ("observe_with_ilmd", {"action": "OBSERVE", "ilmd": {}}, ()),
                ("add_with_ilmd", {"action": "ADD", "ilmd": {"https://example.org/lot": "L1"}}, ()),
                ("empty_what", {"epcList": []}, ("quantityList",)),
            ]
        elif kind == "aggregation":
            recipes += [
                ("add_missing_parent", {"action": "ADD"}, ("parentID",)),
                ("observe_missing_parent", {"action": "OBSERVE"}, ("parentID",)),
                ("delete_all_children", {"action": "DELETE"}, ("childEPCs", "childQuantityList")),
                ("observe_empty_children", {"action": "OBSERVE", "childEPCs": []}, ("childQuantityList",)),
            ]
        else:
            recipes += [
                ("inputs_only_without_id", {}, ("outputEPCList", "outputQuantityList", "transformationID")),
                ("inputs_only_with_id", {"transformationID": "https://example.org/transformation/1"},
                 ("outputEPCList", "outputQuantityList")),
                ("empty_with_id", {"transformationID": "https://example.org/transformation/1"},
                 ("inputEPCList", "inputQuantityList", "outputEPCList", "outputQuantityList")),
                ("malformed_input_outside_domain", {"inputEPCList": None}, ()),
            ]
        for name, updates, removals in recipes:
            document = deepcopy(original)
            document["@context"][0] = CONTEXT
            event = document["epcisBody"]["eventList"][0]
            event.pop("eventID", None)  # An old content hash must not identify a changed event.
            event.update(updates)
            for field in removals:
                event.pop(field, None)
            yield kind, name, document


def artifact_comparison(schemas):
    a, b = deepcopy(schemas["2.0.0"]), deepcopy(schemas["2.0.1"])
    ids = {"2.0.0": a.pop("$id"), "2.0.1": b.pop("$id")}
    old = json.loads((RESOURCE_DIR / "2.0.0_epcis-context.jsonld").read_text())["@context"]
    new = json.loads((RESOURCE_DIR / "2.0.1_epcis-context.jsonld").read_text())["@context"]
    return {"schema_equal_except_id": a == b, "schema_ids": ids,
            "shacl_byte_equal": (RESOURCE_DIR / "2.0.0_epcis-shacl.ttl").read_bytes()
                                == (RESOURCE_DIR / "2.0.1_epcis-shacl.ttl").read_bytes(),
            "context_differences": {k: {"old": old.get(k), "new": new.get(k)}
                                    for k in old.keys() | new.keys() if old.get(k) != new.get(k)},
            "interpretation": "JSON validation identity control only; RDF URI expansion differs"}


def shacl_load_check():
    from rdflib import Graph
    from pyshacl import validate
    try:
        shapes = Graph().parse(RESOURCE_DIR / "2.0.1_epcis-shacl.ttl", format="turtle")
        validate(Graph(), shacl_graph=shapes, inference="none", advanced=False)
    except Exception as error:
        return {"loaded": False, "error_type": type(error).__name__, "message": str(error),
                "interpretation": "Execution failure, not a validation verdict; official file unmodified"}
    return {"loaded": True, "interpretation": "Shape load only; no full SHACL benchmark claimed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "results/standards_extension/epcis")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    protocol = check_resources()
    schemas, validators = schema_validators()
    rows, summaries, disagreements = [], [], []
    for model in build_models():
        model_rows = []
        for index, state in enumerate(product(*model["domains"])):
            document = document_from_state(model, state)
            oracle = independent_document_oracle(document)
            old, new = model["old_predicate"](state), model["new_predicate"](state)
            if not oracle["supported"] or (old, new) != (oracle["compatible_selected"], oracle["compliant_selected"]):
                raise AssertionError(f"Independent selected-clause oracle mismatch: {model['name']} {state}")
            schema_old, schema_new = [validators[v].is_valid(document) for v in ("2.0.0", "2.0.1")]
            if schema_old != schema_new:
                raise AssertionError("JSON-schema identity control failed")
            row = {"model": model["name"], "state_id": index, "state": json.dumps(state),
                   "old_selected_clauses": old, "new_selected_clauses": new,
                   "official_schema_200": schema_old, "official_schema_201": schema_new,
                   "schema_vs_selected_old_disagreement": schema_new != old,
                   "failed_prose_clauses": json.dumps([k for k, v in oracle["clauses"].items() if not v])}
            rows.append(row)
            model_rows.append(row)
            # Retain one independently reproducible witness for each clause/gap shape.
            signature = (model["name"], schema_new, old, row["failed_prose_clauses"])
            if schema_new != old and not any(item["signature"] == signature for item in disagreements):
                disagreements.append({"signature": signature, "state": list(state), "document": document,
                                      "interpretation": "Official-schema verdict and selected normative prose differ"})
        summaries.append({"model": model["name"], "states": len(model_rows), "blocks": len(model["block_names"]),
                          "old_pass": sum(r["old_selected_clauses"] for r in model_rows),
                          "new_pass": sum(r["new_selected_clauses"] for r in model_rows),
                          "official_schema_pass": sum(r["official_schema_201"] for r in model_rows),
                          "schema_vs_selected_old_disagreements": sum(r["schema_vs_selected_old_disagreement"] for r in model_rows),
                          "independent_oracle_mismatches": 0, "schema_version_label_changes": 0})
    examples = []
    for kind, mutation, document in example_cases():
        oracle = independent_document_oracle(document)
        examples.append({"source_example": kind, "case": mutation, "source_kind": "non_normative_example",
                         "complete_event_count": len(document["epcisBody"]["eventList"]),
                         "oracle_supported": oracle["supported"],
                         "unsupported_reason": oracle.get("unsupported_reason", "") if not oracle["supported"] else "",
                         "old_selected_clauses": oracle["compatible_selected"] if oracle["supported"] else "unsupported",
                         "new_selected_clauses": oracle["compliant_selected"] if oracle["supported"] else "unsupported",
                         "official_schema_201": validators["2.0.1"].is_valid(document),
                         "failed_prose_clauses": json.dumps([k for k, v in oracle["clauses"].items() if not v])})
    comparison = artifact_comparison(schemas)
    assert comparison["schema_equal_except_id"] and comparison["shacl_byte_equal"]
    summary = {"scope": protocol["transition"], "synthetic_finite_states": len(rows),
               "models": summaries, "example_cases": len(examples),
               "unchanged_official_examples": 3, "artifact_comparison": comparison,
               "shacl_load_check": shacl_load_check(),
               "versions": {"python": platform.python_version(), "jsonschema": version("jsonschema"),
                            "pyshacl": version("pyshacl")},
               "protocol_sha256": hashlib.sha256((ROOT / "configs/epcis_standards_protocol.json").read_bytes()).hexdigest(),
               "interpretation": "Representative finite clause workload and example derivatives; no business validity or population-rate estimate"}
    write_csv(args.output / "finite_clause_checks.csv", rows)
    write_csv(args.output / "official_example_checks.csv", examples)
    (args.output / "schema_prose_disagreements.json").write_text(json.dumps(disagreements, indent=2) + "\n")
    (args.output / "validation_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
