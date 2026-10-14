from __future__ import annotations
from collections import Counter, defaultdict
import argparse
import hashlib
import json
import platform
from pathlib import Path
import time
import numpy as np
import pandas as pd
from logistics_validation.model import Case
from logistics_validation.constraints import SchemaChecker, indexed_issues, fixed_profile
from logistics_validation.baselines import sql_issues, pm4py_valid
from logistics_validation.mutations import FAULTS, fault, benign

ROOT = Path(__file__).resolve().parents[1]
METHODS = ["GS1_schema","PM4Py_profile_plus_schema","SQL_profile_plus_schema","indexed_profile_plus_schema","fixed_profile_plus_schema"]

def metrics(y,p):
    y=np.asarray(y,dtype=bool);p=np.asarray(p,dtype=bool)
    tp=int((y&p).sum());fp=int((~y&p).sum());fn=int((y&~p).sum());tn=int((~y&~p).sum())
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0
    return dict(tp=tp,fp=fp,fn=fn,tn=tn,precision=precision,recall=recall,f1=f1,false_positive_rate=fp/(fp+tn) if fp+tn else 0.0)

def suite(cases,seed,prevalence):
    rng=np.random.default_rng(seed)
    grouped=defaultdict(list)
    for c in cases:
        grouped[c.dataset+":"+c.group].append(c)
    results=[];labels=[];types=[];originals=[]
    for key,group in sorted(grouped.items()):
        perm=rng.permutation(len(group))
        n=int(round(len(group)*prevalence))
        by_index={int(k):FAULTS[j%len(FAULTS)] for j,k in enumerate(perm[:n])}
        for j,c in enumerate(group):
            if j in by_index:
                mutant=fault(c,by_index[j]);label=True;kind=by_index[j]
            else:
                mutant,kind=benign(c,j+seed);label=False
            results.append(mutant);labels.append(label);types.append(kind);originals.append(c)
    return results,np.array(labels),types,originals

def source_cluster(c):
    if c.dataset=="lade":
        return c.dataset+":"+c.group+":"+c.attributes["source_courier_id"]
    # A company spanning multiple procurement profiles is one source cluster.
    return c.dataset+":"+str(c.attributes["source_company"])

def output_root(quick=False, destination=None):
    """Keep smoke-test outputs separate from full-study artifacts."""
    if destination is not None:
        path=Path(destination)
        return path if path.is_absolute() else ROOT/path
    return ROOT/"results"/"quick" if quick else ROOT/"results"

def bootstrap(frame,repeats):
    # LaDe courier clusters are sampled within city. BPI company clusters span
    # every profile: splitting a company by profile invents independence.
    # Resamples are paired. Few BPI companies cannot support population inference.
    rng=np.random.default_rng(20261007)
    strata={}
    work=frame.copy()
    # Rebuild BPI cluster identity for archived v1 frames whose old cluster key
    # contains a profile prefix. Source-company labels contain no colons.
    bpi=work.dataset=="bpi2019"
    work.loc[bpi,"cluster"]="bpi2019:"+work.loc[bpi,"cluster"].str.rsplit(":",n=1).str[-1]
    work["resampling_stratum"]=np.where(bpi,"all_profiles",work["group"])
    for key,g in work.groupby(["dataset","resampling_stratum"]):
        strata[key]=[x.index.to_numpy() for _,x in g.groupby("cluster")]
    values={m:[] for m in METHODS}
    differences={m:[] for m in METHODS if m!="indexed_profile_plus_schema"}
    for _ in range(repeats):
        index=np.concatenate([np.concatenate([clusters[i] for i in rng.integers(0,len(clusters),len(clusters))]) for clusters in strata.values()])
        f=work.loc[index]
        scores={m:metrics(f.label,f[m])["f1"] for m in METHODS}
        for m in METHODS:values[m].append(scores[m])
        for m in differences:differences[m].append(scores["indexed_profile_plus_schema"]-scores[m])
    cluster_counts={":".join(k):len(v) for k,v in strata.items()}
    warnings=[f"{k} has only {n} source clusters; the interval is descriptive resampling sensitivity, not a population confidence interval."
              for k,n in cluster_counts.items() if n<10]
    return dict(method_f1_ci={m:np.quantile(v,[.025,.975]).tolist() for m,v in values.items()},
                paired_delta_f1_ci={m:np.quantile(v,[.025,.975]).tolist() for m,v in differences.items()},
                repetitions=repeats,clusters=sum(len(c) for c in strata.values()),
                clusters_by_stratum=cluster_counts,warnings=warnings,
                resampling="Courier clusters within LaDe city; BPI company clusters jointly across all profiles; paired method resamples. Profile mixture can vary in BPI resamples.",
                interpretation="Conditional source-cluster resampling sensitivity; engineered errors and contract-qualified controls, not natural-anomaly performance or population confidence.")

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--quick",action="store_true")
    parser.add_argument("--output-dir",help="Result destination relative to repository root; defaults to results, or results/quick for a smoke test")
    args=parser.parse_args()
    cfg=json.loads((ROOT/"configs/protocol_v1.json").read_text())
    cases=[Case.from_dict(json.loads(x)) for x in (ROOT/"data/processed/cases.jsonl").read_text().splitlines()]
    if args.quick:cases=cases[:100]
    checker=SchemaChecker()
    cache={}
    reports=[];per_fault=[];per_group=[];controls=[];canonical=None
    result_root=output_root(args.quick,args.output_dir)
    dest=result_root/"predictions";dest.mkdir(parents=True,exist_ok=True)
    seeds=cfg["seeds"][:1] if args.quick else cfg["seeds"]
    prevalences=[.2] if args.quick else cfg["fault_prevalence"]
    for seed in seeds:
        for prevalence in prevalences:
            t0=time.perf_counter()
            mutants,y,kinds,orig=suite(cases,seed,prevalence)
            bad_schema=[]
            for c in mutants:
                digest=c.digest()
                if digest not in cache:cache[digest]=not checker.valid(c)
                bad_schema.append(cache[digest])
            bad_schema=np.array(bad_schema)
            idx=np.array([bool(indexed_issues(c)) for c in mutants])
            sql_result=sql_issues(mutants)
            sql=np.array([bool(sql_result[c.case_id]) for c in mutants])
            if not np.array_equal(idx,sql):
                mismatch=[c.case_id for c,a,b in zip(mutants,idx,sql) if a!=b]
                raise AssertionError(f"Indexed/SQL disagreement: {mismatch[:10]}")
            replay=pm4py_valid(mutants)
            pm=np.array([not replay[c.case_id] for c in mutants])
            fixed=np.array([bool(indexed_issues(fixed_profile(c))) for c in mutants])
            pred={"GS1_schema":bad_schema,"PM4Py_profile_plus_schema":bad_schema|pm,
                  "SQL_profile_plus_schema":bad_schema|sql,"indexed_profile_plus_schema":bad_schema|idx,
                  "fixed_profile_plus_schema":bad_schema|fixed}
            frame=pd.DataFrame(dict(case_id=[c.case_id for c in mutants],dataset=[c.dataset for c in mutants],
                                    group=[c.group for c in mutants],cluster=[source_cluster(c) for c in orig],
                                    label=y,fault_or_control=kinds,input_sha256=[c.digest() for c in mutants],**pred))
            frame.to_csv(dest/f"seed{seed}_p{prevalence:.2f}.csv.gz",index=False,compression="gzip")
            for m,p in pred.items():
                common=dict(seed=seed,prevalence=prevalence,method=m)
                reports.append(dict(**common,**metrics(y,p)))
                for kind in FAULTS:
                    select=np.array(kinds)==kind
                    per_fault.append(dict(**common,fault=kind,n=int(select.sum()),recall=float(p[select].mean()) if select.any() else None))
                for key,g in frame.groupby(["dataset","group"]):
                    per_group.append(dict(**common,dataset=key[0],group=key[1],**metrics(g.label,g[m])))
                for kind,g in frame[~frame.label].groupby("fault_or_control"):
                    controls.append(dict(**common,control=kind,n=len(g),fp=int(g[m].sum()),false_positive_rate=float(g[m].mean())))
            if seed==17 and prevalence==.2:canonical=frame
            print(f"seed={seed} p={prevalence}: {len(mutants)} cases; {(time.perf_counter()-t0):.1f}s; "+
                  ", ".join(f"{m} F1={metrics(y,p)['f1']:.4f}" for m,p in pred.items()),flush=True)
    for name,rows in [("metrics",reports),("per_fault",per_fault),("per_group",per_group),("controls",controls)]:
        pd.DataFrame(rows).to_csv(result_root/f"{name}.csv",index=False)
    if not args.quick:
        uncertainty=bootstrap(canonical,cfg["bootstrap_repeats"])
        (result_root/"uncertainty.json").write_text(json.dumps(uncertainty,indent=2))
        experiment=dict(protocol_sha256=hashlib.sha256((ROOT/"configs/protocol_v1.json").read_bytes()).hexdigest(),
                        extension_sha256=hashlib.sha256((ROOT/"configs/analysis_extension.json").read_bytes()).hexdigest(),
                        sample_sha256=hashlib.sha256((ROOT/"data/processed/cases.jsonl").read_bytes()).hexdigest(),
                        platform=platform.platform(),python=platform.python_version(),machine=platform.machine(),
                        cases=len(cases),experiments=len(seeds)*len(prevalences),
                        sql_indexed_disagreements=0,cache_entries=len(cache),
                        runtime_notes="Mutation-sweep schema cache enabled; do not interpret sweep elapsed time as method performance.")
        (result_root/"run_manifest.json").write_text(json.dumps(experiment,indent=2))

if __name__=="__main__":main()
