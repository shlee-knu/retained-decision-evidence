"""Regression tests for adversarial findings in the manuscript revision."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest

from logistics_validation.model import Case, Event, seconds, uri, CTX, BASE
from logistics_validation.constraints import SchemaChecker, indexed_issues
from logistics_validation.baselines import sql_issues

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("research_experiments",ROOT/"scripts/run_experiments.py")
experiments=importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiments)


@pytest.mark.parametrize("zone",["Z","z","+00:00"])
@pytest.mark.parametrize("separator",["T","t"])
def test_schema_valid_rfc3339_time_inversion_is_not_silently_skipped(zone,separator):
    obj=uri("object","lowercase")
    case=Case("clock","lade","fixture","delivery","independent boundary fixture",[
        Event(uri("event","before"),obj,"accept",f"2000-01-01{separator}00:00:01{zone}"),
        Event(uri("event","after"),obj,"deliver",f"2000-01-01{separator}00:00:00{zone}"),
    ],[("accept","deliver")],["accept","deliver"],{"object_id":obj})
    assert SchemaChecker().valid(case)
    assert indexed_issues(case)=={"time_precedence"}
    assert sql_issues([case])[case.case_id]=={"time_precedence"}


def test_invalid_timestamp_type_does_not_crash_semantic_layer():
    assert seconds(42) is None
    assert seconds(False) is None
    assert seconds("not a timestamp") is None
    assert seconds("2000-01-01T00:00:00") is None


def test_smoke_test_cannot_overwrite_full_study_by_default():
    assert experiments.output_root(True)==ROOT/"results/quick"
    assert experiments.output_root(False)==ROOT/"results"
    assert experiments.output_root(True)!=experiments.output_root(False)
    assert experiments.output_root(False,"results/revision")==ROOT/"results/revision"


def test_company_cluster_identity_survives_profile_changes():
    c=Case("c","bpi2019","profile_a","profile_a","fixture",[],[],[],{"source_company":"company_A"})
    other=deepcopy(c);other.group="profile_b";other.profile="profile_b"
    assert experiments.source_cluster(c)==experiments.source_cluster(other)


def test_bootstrap_keeps_a_company_together_across_profiles_and_discloses_few_clusters():
    rows=[]
    for profile in ("a","b"):
        for company in ("company_A","company_B"):
            # Deliberately use old v1 identifiers to verify archived predictions
            # can be audited without rewriting their bytes.
            rows.append(dict(dataset="bpi2019",group=profile,
                             cluster=f"bpi2019:{profile}:{company}",label=True,
                             **{m:company=="company_A" for m in experiments.METHODS}))
    result=experiments.bootstrap(pd.DataFrame(rows),100)
    assert result["clusters"]==2
    assert result["clusters_by_stratum"]=={"bpi2019:all_profiles":2}
    assert result["warnings"] and "only 2 source clusters" in result["warnings"][0]
    assert all(delta==[0.0,0.0] for delta in result["paired_delta_f1_ci"].values())


def test_jsonld_reference_is_an_iri_edge_to_the_event_node():
    from rdflib import Graph, URIRef
    obj=uri("object","rdf_reference")
    earlier=Event(uri("event","rdf_before"),obj,"accept","2000-01-01T00:00:00Z")
    later=Event(uri("event","rdf_after"),obj,"deliver","2000-01-01T00:00:01Z",ref=earlier.event_id)
    case=Case("rdf_case","lade","fixture","delivery","independent boundary fixture",[earlier,later],
              [("accept","deliver")],["accept","deliver"],{"object_id":obj})
    pinned=json.loads((ROOT/"data/standards/epcis-context.jsonld").read_text())
    doc={"@context":[pinned["@context"],CTX[1]],"@graph":[]}
    for e in case.events:
        obj=e.epcis();obj.pop("@context")
        doc["@graph"].append(obj)
    graph=Graph().parse(data=json.dumps(doc),format="json-ld")
    references=[e for e in case.events if e.ref]
    assert references
    for e in references:
        assert (URIRef(e.event_id),URIRef(BASE+"predecessor"),URIRef(e.ref)) in graph
        assert any(graph.triples((URIRef(e.ref),None,None)))
