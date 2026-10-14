"""Audit archived v1 predictions without changing them or rerunning methods.

Confusion counts and derived metrics are independently recomputed. Deterministic
suite reconstruction verifies fixtures, labels, mutation names and Case digests;
it is not a new independent scientific truth oracle. Case digests omit EPCIS
serialization/context details, which are therefore outside this hash check.
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import pandas as pd

from logistics_validation.model import Case
from run_experiments import METHODS, suite

ROOT=Path(__file__).resolve().parents[1]


def independently_count(frame,method):
    outcomes={(True,True):0,(False,True):0,(True,False):0,(False,False):0}
    for truth,predicted in zip(frame.label,frame[method]):
        outcomes[(bool(truth),bool(predicted))]+=1
    tp=outcomes[(True,True)];fp=outcomes[(False,True)]
    fn=outcomes[(True,False)];tn=outcomes[(False,False)]
    return dict(tp=tp,fp=fp,fn=fn,tn=tn,
                precision=tp/(tp+fp) if tp+fp else 0.0,
                recall=tp/(tp+fn) if tp+fn else 0.0,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0,
                false_positive_rate=fp/(fp+tn) if fp+tn else 0.0)


def main():
    failures=[];checks=0;conditions=[];rows_verified=0
    def require(condition,message):
        nonlocal checks
        checks+=1
        if not condition:failures.append(message)

    sample=ROOT/"data/processed/cases.jsonl"
    manifest=json.loads((ROOT/"results/run_manifest.json").read_text())
    cfg=json.loads((ROOT/"configs/protocol_v1.json").read_text())
    require(hashlib.sha256(sample.read_bytes()).hexdigest()==manifest["sample_sha256"],"sample SHA-256 mismatch")
    cases=[Case.from_dict(json.loads(x)) for x in sample.read_text().splitlines()]
    tables={name:pd.read_csv(ROOT/f"results/{name}.csv") for name in ["metrics","per_group","per_fault","controls"]}

    def match_one(table,keys,values):
        select=pd.Series(True,index=table.index)
        for key,value in keys.items():select &= table[key]==value
        found=table[select]
        require(len(found)==1,f"Expected exactly one result row: {keys}")
        if len(found)!=1:return
        actual=found.iloc[0]
        for key,value in values.items():
            require(math.isclose(float(actual[key]),float(value),rel_tol=1e-12,abs_tol=1e-12),
                    f"Mismatch {keys} field={key}: {actual[key]} != {value}")

    for seed in cfg["seeds"]:
        for prevalence in cfg["fault_prevalence"]:
            path=ROOT/f"results/predictions/seed{seed}_p{prevalence:.2f}.csv.gz"
            data=pd.read_csv(path)
            require(data.case_id.is_unique and len(data)==len(cases),f"Case count or duplicate ID {path.name}")
            require(all(pd.api.types.is_bool_dtype(data[column]) for column in ["label",*METHODS]),f"Non-boolean prediction column {path.name}")
            reconstructed,labels,kinds,_=suite(cases,seed,prevalence)
            expected={c.case_id:(c.digest(),bool(label),kind) for c,label,kind in zip(reconstructed,labels,kinds)}
            require(set(data.case_id)==set(expected),f"Case IDs mismatch {path.name}")
            for row in data.itertuples(index=False):
                require(expected.get(row.case_id)==(row.input_sha256,bool(row.label),row.fault_or_control),
                        f"Fixture, label or kind mismatch {path.name}/{row.case_id}")
            for method in METHODS:
                keys=dict(seed=seed,prevalence=prevalence,method=method)
                match_one(tables["metrics"],keys,independently_count(data,method))
                for (dataset,group),subset in data.groupby(["dataset","group"]):
                    match_one(tables["per_group"],dict(**keys,dataset=dataset,group=group),independently_count(subset,method))
                for kind,subset in data[data.label].groupby("fault_or_control"):
                    counts=independently_count(subset,method)
                    match_one(tables["per_fault"],dict(**keys,fault=kind),dict(n=len(subset),recall=counts["recall"]))
                for kind,subset in data[~data.label].groupby("fault_or_control"):
                    counts=independently_count(subset,method)
                    match_one(tables["controls"],dict(**keys,control=kind),dict(n=len(subset),fp=counts["fp"],false_positive_rate=counts["false_positive_rate"]))
            rows_verified+=len(data)
            conditions.append(dict(seed=seed,prevalence=prevalence,rows=len(data),prediction_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    result=dict(status="passed" if not failures else "failed",checks=checks,failures=failures,
                condition_count=len(conditions),prediction_rows_verified=rows_verified,
                independently_recomputed=["confusion counts","precision","recall","F1","false-positive rate","per-profile metrics","per-fault recall","control counts"],
                reconstructed=["case IDs","deterministic fixture digests","mutation/control names","generated labels"],
                limitations="Reconstruction reuses the suite generator and is not independent scientific labeling. Case hashes cover structured Case values, not EPCIS serialization context. Archived v1 source code, timestamp interpretation and cluster intervals remain historically distinct.",
                conditions=conditions)
    destination=ROOT/"results/revision/v1_prediction_verification.json"
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(result,indent=2))
    print(json.dumps({key:result[key] for key in ["status","checks","condition_count","prediction_rows_verified","failures"]},indent=2))
    if failures:raise SystemExit(1)


if __name__=="__main__":main()
