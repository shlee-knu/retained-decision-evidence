"""Auxiliary normative SHACL pilot, not the full main comparative experiment."""
from collections import defaultdict
import json
from pathlib import Path
import pandas as pd
from rdflib import Graph
from pyshacl import validate
from rdflib import RDF, Namespace
from logistics_validation.model import Case, CTX
from logistics_validation.mutations import FAULTS, fault, benign

ROOT=Path(__file__).resolve().parents[1]

def conforms(case,context,shapes):
    # Embed pinned contexts; no network calls during RDF conversion.
    graph_data={"@context":[context["@context"],CTX[1]],"@graph":[]}
    for event in case.events:
        obj=event.epcis();obj.pop("@context",None);graph_data["@graph"].append(obj)
    graph=Graph().parse(data=json.dumps(graph_data),format="json-ld")
    result=validate(graph,shacl_graph=shapes,inference="none",advanced=False)
    return bool(result[0]),str(result[2])

def main():
    cases=[Case.from_dict(json.loads(x)) for x in (ROOT/"data/processed/cases.jsonl").read_text().splitlines()]
    selected={}
    for c in cases:selected.setdefault(c.dataset+":"+c.profile,c)
    context=json.loads((ROOT/"data/standards/epcis-context.jsonld").read_text())
    shapes=Graph().parse(ROOT/"data/standards/epcis-shacl.ttl",format="turtle")
    records=[];reports={}
    # A shape-loader error is a failed tool execution, never a nonconformance
    # decision. Check once before interpreting any fixture predictions.
    try:
        validate(Graph(),shacl_graph=shapes,inference="none",advanced=False)
    except Exception as e:
        sh=Namespace("http://www.w3.org/ns/shacl#")
        conflicting=[str(s) for s in shapes.subjects(RDF.type,sh.NodeShape) if (s,sh.path,None) in shapes]
        records.append(dict(profile="all",fixture="shape_loading_check",contract_fault=None,
                            standard_conforms=None,stage="SHACL_loading",engine_error=True))
        reports["shape_loading_error"]=f"{type(e).__name__}: {e}"
        reports["node_shapes_with_path"]=conflicting
        reports["interpretation"]="Pinned official shapes could not load in pyshacl; no accuracy score or normative validity decision can be reported. Source not silently patched."
        pd.DataFrame(records).to_csv(ROOT/"results/shacl_pilot.csv",index=False)
        (ROOT/"results/shacl_pilot_reports.json").write_text(json.dumps(reports,indent=2))
        print(reports["shape_loading_error"],flush=True)
        return
    for profile,case in selected.items():
        fixtures=[(case,"unmodified",False)]
        fixtures += [(fault(case,f),f,True) for f in FAULTS]
        fixtures += [(c,n,False) for c,n in (benign(case,i) for i in range(6))]
        for c,name,label in fixtures:
            try:
                valid,report=conforms(c,context,shapes)
                stage="SHACL"
            except Exception as e:
                valid=None;report=f"{type(e).__name__}: {e}";stage="execution_error"
            records.append(dict(profile=profile,fixture=name,contract_fault=label,standard_conforms=valid,stage=stage,engine_error=valid is None))
            if valid is not True:reports[profile+":"+name]=report
        print(f"Official SHACL pilot: {profile}",flush=True)
    pd.DataFrame(records).to_csv(ROOT/"results/shacl_pilot.csv",index=False)
    (ROOT/"results/shacl_pilot_reports.json").write_text(json.dumps(reports,indent=2))

if __name__=="__main__":main()
