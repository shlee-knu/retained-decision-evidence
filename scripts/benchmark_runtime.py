"""Uncached wall times, with construction and parsing overhead made explicit."""
from __future__ import annotations
import json
from pathlib import Path
import time
import platform
import pandas as pd
from logistics_validation.model import Case
from logistics_validation.constraints import SchemaChecker, indexed_issues
from logistics_validation.baselines import sql_issues, pm4py_valid
from run_experiments import suite

ROOT=Path(__file__).resolve().parents[1]

def main():
    originals=[Case.from_dict(json.loads(x)) for x in (ROOT/"data/processed/cases.jsonl").read_text().splitlines()]
    cases,_,_,_=suite(originals,17,.2)
    checker=SchemaChecker()
    rows=[]
    engines={"indexed_rules":lambda x:[indexed_issues(c) for c in x],
             "SQLite_rules":sql_issues,"PM4Py_profile_control_flow":pm4py_valid}
    for n in [100,1000,len(cases)]:
        # Round-robin sorted datasets/profiles to avoid all-BPI prefix samples.
        groups={}
        for c in cases:groups.setdefault(c.dataset+":"+c.group,[]).append(c)
        balanced=[]
        for i in range(max(len(g) for g in groups.values())):
            for g in groups.values():
                if i<len(g):balanced.append(g[i])
        sample=balanced[:n]
        for rep in range(3):
            # Rotate engine order to reduce systematic cache/order confounding.
            order=list(engines);order=order[rep:]+order[:rep]
            for name in order:
                t=time.perf_counter();engines[name](sample);elapsed=time.perf_counter()-t
                rows.append(dict(engine=name,cases=n,events=sum(len(c.events) for c in sample),repeat=rep,seconds=elapsed))
        # Shared official-schema cost: 3 repeats for the 1000-case slice only.
        if n==1000:
            for rep in range(3):
                t=time.perf_counter();[checker.valid(c) for c in sample];elapsed=time.perf_counter()-t
                rows.append(dict(engine="GS1_schema_shared",cases=n,events=sum(len(c.events) for c in sample),repeat=rep,seconds=elapsed))
        print(f"Runtime completed: {n} cases",flush=True)
    pd.DataFrame(rows).to_csv(ROOT/"results/runtime.csv",index=False)
    (ROOT/"results/runtime_manifest.json").write_text(json.dumps(dict(
        platform=platform.platform(),python=platform.python_version(),processor=platform.processor(),
        repetitions=3,hardware_cpu=next((x.split(":",1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),"unknown"),
        measurement="time.perf_counter; uncached rules; SQL includes connection/inserts/indexes; PM4Py includes net/log construction; schema time is shared and separately measured",
        exclusions="raw-data download, disk reads and source adapter conversion; schema engine initialization outside timers; no peak RSS measurement",
        interpretation="Local implementation comparison only; PM4Py has narrower semantics; shared-machine contention and three repetitions limit timing generalization"),indent=2))

if __name__=="__main__":main()
