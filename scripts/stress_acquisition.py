"""Bounded counterfactual stress on seed-17 document-held-out BPI cases.

Synthetic clock/profile edits test structural assumptions, not natural drift.
The expected contract is independently evaluated with Fraction timestamps and
explicit position enumeration. Candidate certificate code never supplies truth.
Train-only empirical lookups never consume test labels during fitting.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from collections.abc import Mapping
from copy import deepcopy
from datetime import date,datetime,timedelta
from fractions import Fraction
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from audit_representations import part
from logistics_validation.acquisition import acquire

RULES={
    "3-way match, invoice after GR": (("create","receive","invoice","clear"),(("create","receive"),("receive","invoice"),("invoice","clear"))),
    "3-way match, invoice before GR": (("create","receive","invoice","clear"),(("create","receive"),("create","invoice"),("receive","clear"),("invoice","clear"))),
    "2-way match": (("create","invoice","clear"),(("create","invoice"),("invoice","clear"))),
    "Consignment": (("create","receive"),(("create","receive"),)),
}
STAMP=re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")
POLICIES=("always_both","profile_first","time_first")
REPRESENTATIONS=("profile_first_order","first_order")
SEED=17


def raw_time(value):
    """Independent exact Fraction arithmetic, without candidate normalization."""
    match=STAMP.fullmatch(value)
    if not match:raise ValueError(f"Unsupported fixture timestamp {value}")
    y,mo,d,h,mi,s=map(int,match.groups()[:6]);fraction,zone=match.groups()[6:]
    if h>23 or mi>59 or s>59 or zone=="-00:00":raise ValueError(value)
    days=date(y,mo,d).toordinal()-date(1970,1,1).toordinal()
    offset=0
    if zone.upper()!="Z":
        hour,minute=map(int,zone[1:].split(":"))
        if hour>23 or minute>59:raise ValueError(value)
        offset=(hour*3600+minute*60)*(1 if zone[0]=="+" else -1)
    return Fraction(days*86400+h*3600+mi*60+s-offset)+Fraction(int(fraction or "0"),10**len(fraction or ""))


def expected_violation(case,strict=False):
    """Full-observation oracle with explicit raw occurrence positions."""
    required,edges=RULES[case["profile"]]
    positions={activity:[i for i,value in enumerate(case["activities"]) if value==activity]
               for activity in ("create","receive","invoice","clear")}
    if any(not positions[a] for a in required):return True
    if strict and case["profile"]=="Consignment" and (positions["invoice"] or positions["clear"]):return True
    for a,b in edges:
        if positions[b] and (not positions[a] or min(positions[a])>=min(positions[b])):return True
        if positions[a] and positions[b]:
            if raw_time(case["first_times"][a])>raw_time(case["first_times"][b]):return True
    return False


def signature(case,representation):
    first=tuple(dict.fromkeys(case["activities"]))
    return (case["profile"],first) if representation=="profile_first_order" else first


def rank(case,family):
    return hashlib.sha256(f"acquisition-stress-v03:{SEED}:{family}:{case['case_id']}".encode()).hexdigest()


class ReadTrace(Mapping):
    def __init__(self,case):
        self.values={name:case[name] for name in ("activities","profile","first_times")}
        self.accessed=[]
    def __getitem__(self,key):
        self.accessed.append(key)
        return self.values[key]
    def __iter__(self):raise AssertionError("Policy attempted bulk feature iteration")
    def __len__(self):return 3


def snapshot(case):
    return {key:case[key] for key in ("activities","profile","first_times")}


def fit_lookups(training,strict):
    tables={representation:defaultdict(lambda:[0,0]) for representation in REPRESENTATIONS}
    labels=Counter()
    for case in training:
        truth=expected_violation(case,strict);labels[int(truth)]+=1
        for representation,table in tables.items():table[signature(case,representation)][int(truth)]+=1
    return tables,labels[1]>labels[0],dict(accepted=labels[0],rejected=labels[1])


def lookup(case,table,representation,mode,fallback):
    counts=table.get(signature(case,representation))
    if mode=="majority":return (counts[1]>counts[0] if counts else fallback),counts is None
    if not counts or min(counts)>0:return None,counts is None
    return bool(counts[1]),False


def summarize(truth,predictions):
    covered=[(y,p) for y,p in zip(truth,predictions) if p is not None]
    fp=sum(not y and p for y,p in covered);fn=sum(y and not p for y,p in covered)
    return dict(cases=len(truth),violations=sum(truth),covered=len(covered),abstained=len(truth)-len(covered),
                coverage=len(covered)/len(truth) if truth else None,disagreements=fp+fn,
                error_on_covered=(fp+fn)/len(covered) if covered else None,false_alarms=fp,missed_violations=fn)


def make_fixtures(test,strict):
    fixtures=[];selection=Counter()
    for profile in RULES:
        compatible=[case for case in test if case["profile"]==profile and not expected_violation(case,strict)]
        chosen=sorted(compatible,key=lambda case:rank(case,"timestamp"))[:500]
        selection["timestamp:"+profile]=len(chosen)
        for i,base in enumerate(chosen):
            trial=deepcopy(base);a,b=RULES[profile][1][i%len(RULES[profile][1])]
            source=base["first_times"][a]
            # Acquired source stamps have millisecond precision and a known Z
            # suffix. A one-second UTC displacement is exact in this domain.
            before=datetime.fromisoformat(source.replace("Z","+00:00"))
            trial["first_times"][b]=(before-timedelta(seconds=1)).isoformat(timespec="milliseconds")
            assert trial["activities"]==base["activities"] and trial["profile"]==base["profile"]
            assert not expected_violation(base,strict) and expected_violation(trial,strict)
            edit=dict(edge=[a,b],activity=b,original_time=base["first_times"][b],new_time=trial["first_times"][b])
            fixtures.extend([("timestamp_source_control",base,base,None),("timestamp_reversal",base,trial,edit)])
    selected=0
    for base in sorted(test,key=lambda case:rank(case,"profile")):
        initial=expected_violation(base,strict)
        alternatives=sorted((name for name in RULES if name!=base["profile"]),
                            key=lambda name:hashlib.sha256(f"{base['case_id']}:{name}".encode()).hexdigest())
        for name in alternatives:
            trial=dict(base,profile=name)
            if expected_violation(trial,strict)==initial:continue
            assert trial["activities"]==base["activities"] and trial["first_times"]==base["first_times"]
            fixtures.extend([("profile_source_control",base,base,None),
                             ("profile_reassignment",base,trial,dict(original_profile=base["profile"],new_profile=name))])
            selection["profile:"+base["profile"]+" -> "+name]+=1
            selected+=1
            break
        if selected==2000:break
    return fixtures,dict(selection)


def main():
    started=time.perf_counter();destination=ROOT/"results/v03";source=destination/"bpi_compact.jsonl.gz"
    cases=[json.loads(line) for line in gzip.open(source,"rt",encoding="utf-8")]
    training=[c for c in cases if part(c["document"],SEED)=="train"]
    testing=[c for c in cases if part(c["document"],SEED)=="test"]
    train_documents={c["document"] for c in training};test_documents={c["document"] for c in testing}
    assert not train_documents&test_documents
    # Verify original labels only as a diagnostic; oracle labels, not archived
    # test labels, drive all counterfactual checks. No test values enter fitting.
    original_disagreement=sum(bool(c["violation"])!=expected_violation(c) for c in cases)
    summaries=[];records=[];variants={};failure_examples=[];lookup_invariance=[]
    for variant,strict in (("default_catalog",False),("strict_consignment",True)):
        tables,fallback,training_labels=fit_lookups(training,strict)
        fixtures,selection=make_fixtures(testing,strict)
        by_scenario=defaultdict(list);profile_transitions=Counter()
        for scenario,base,trial,edit in fixtures:
            truth=expected_violation(trial,strict)
            item=dict(variant=variant,scenario=scenario,case_id=base["case_id"],document=base["document"],
                      source_trace=base["source_trace"],source_locator=f"data/raw/bpi/BPI_Challenge_2019.xes:trace-{base['source_trace']}",
                      source_profile=base["profile"],original_expected_violation=expected_violation(base,strict),
                      features=snapshot(trial),expected_violation=truth,edit=edit,acquisition={},lookups={})
            for policy in POLICIES:
                access=ReadTrace(trial)
                result=acquire(access,policy=policy,forbidden={"Consignment":("invoice","clear")} if strict else None)
                predicted=result["decision"]=="reject" if result["decision"] in ("accept","reject") else None
                trace_ok=access.accessed==["activities",*result["fetched_blocks"]]
                exact=result["status"]=="determined" and predicted==truth
                item["acquisition"][policy]=dict(decision=result["decision"],expected_match=exact,read_trace_matches=trace_ok,
                                                  accessed=access.accessed,fetched_blocks=result["fetched_blocks"],
                                                  profile_queries=result["profile_queries"],time_queries=result["time_queries"])
                if not exact or not trace_ok:
                    failure_examples.append(dict(variant=variant,scenario=scenario,case_id=base["case_id"],policy=policy,
                                                 expected=truth,result=result,actual_access=access.accessed))
            for representation in REPRESENTATIONS:
                for mode in ("majority","pure"):
                    predicted,unseen=lookup(trial,tables[representation],representation,mode,fallback)
                    original_predicted,_=lookup(base,tables[representation],representation,mode,fallback)
                    key=representation+":"+mode
                    item["lookups"][key]=dict(predicted_violation=predicted,unseen=unseen,
                                               source_predicted_violation=original_predicted,
                                               prediction_changed=predicted!=original_predicted)
            if scenario=="profile_reassignment":profile_transitions[(base["profile"],trial["profile"],not truth)]+=1
            by_scenario[scenario].append(item);records.append(item)
        for scenario,items in sorted(by_scenario.items()):
            truth=[x["expected_violation"] for x in items]
            for policy in POLICIES:
                predictions=[x["acquisition"][policy]["decision"]=="reject"
                             if x["acquisition"][policy]["decision"] in ("accept","reject") else None for x in items]
                summaries.append(dict(variant=variant,scenario=scenario,method=policy,**summarize(truth,predictions),
                                      profile_queries=sum(x["acquisition"][policy]["profile_queries"] for x in items),
                                      time_queries=sum(x["acquisition"][policy]["time_queries"] for x in items),
                                      read_trace_mismatches=sum(not x["acquisition"][policy]["read_trace_matches"] for x in items)))
            for representation in REPRESENTATIONS:
                for mode in ("majority","pure"):
                    key=representation+":"+mode
                    summary=dict(variant=variant,scenario=scenario,method=key,
                                 **summarize(truth,[x["lookups"][key]["predicted_violation"] for x in items]),
                                 unseen_cases=sum(x["lookups"][key]["unseen"] for x in items),
                                 predictions_changed_from_source=sum(x["lookups"][key]["prediction_changed"] for x in items))
                    summaries.append(summary)
                    if scenario=="timestamp_reversal":
                        assert summary["predictions_changed_from_source"]==0
                        lookup_invariance.append({key:summary[key] for key in ("variant","scenario","method","cases","predictions_changed_from_source")})
        variants[variant]=dict(selection=selection,training_labels=training_labels,fixtures=len(fixtures),
                               strict_forbidden={"Consignment":["invoice","clear"]} if strict else {},
                               profile_transitions=[dict(original=a,reassigned=b,accepted_after=c,cases=n) for (a,b,c),n in profile_transitions.items()])
        print(f"{variant}: evaluated {len(fixtures):,} paired controls/counterfactuals",flush=True)
    fixtures_path=destination/"acquisition_stress_fixtures.jsonl.gz"
    with fixtures_path.open("wb") as binary,gzip.GzipFile(fileobj=binary,mode="wb",filename="",mtime=0) as compressed:
        with io.TextIOWrapper(compressed,encoding="utf-8") as stream:
            for record in records:stream.write(json.dumps(record,separators=(",",":"))+"\n")
    result=dict(status="passed" if not failure_examples else "failed",seed=SEED,
                split=dict(function="scripts.audit_representations.part",train_cases=len(training),test_cases=len(testing),
                           train_documents=len(train_documents),test_documents=len(test_documents),document_overlap=0,
                           calibration_used=False),
                generation="Up to 500 SHA256-ranked contract-compatible source cases per profile for a one-second required-edge reversal; up to 2000 hash-ranked source cases with one deterministic label-flipping profile reassignment. Both use only seed17 test documents.",
                source_compact_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                code_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in [Path(__file__),ROOT/"src/logistics_validation/acquisition.py",ROOT/"scripts/audit_representations.py"]},
                oracle="Independent full-observation brute-force occurrence-position contract with exact Fraction interpretation of raw timestamps; no acquisition truth functions called.",
                lookup_training="Source training documents only; independently evaluated training labels under each contract variant. Majority falls back to the global training majority, pure lookup abstains on mixed/unseen signatures. No test labels or mutations train these tables.",
                original_contract_label_disagreements=original_disagreement,variants=variants,metrics=summaries,
                acquisition_mismatches=len(failure_examples),failure_examples=failure_examples[:20],
                unchanged_lookup_predictions_after_time_edits=lookup_invariance,
                fixture_file=dict(path=str(fixtures_path.relative_to(ROOT)),sha256=hashlib.sha256(fixtures_path.read_bytes()).hexdigest(),rows=len(records)),
                limitations=["Counterfactuals are engineered stress cases, not observed natural clock/profile shifts.",
                             "Profile reassignment changes declared metadata while source events stay fixed; it does not assert that the source business profile was wrong.",
                             "Full contract truth concerns the declared milestone projection, not financial/lifecycle correctness or natural anomalies.",
                             "Strict consignment adds explicit forbidden invoice/clear activities; it is a separate catalog assumption.",
                             "Certificates remain conditional on a trusted finite catalog and supported hidden metadata domain."],
                elapsed_seconds=round(time.perf_counter()-started,3))
    (destination/"acquisition_stress.json").write_text(json.dumps(result,indent=2))
    print(json.dumps(dict(status=result["status"],fixtures=len(records),acquisition_mismatches=len(failure_examples),original_contract_label_disagreements=original_disagreement),indent=2))
    if failure_examples or original_disagreement:raise SystemExit(1)


if __name__=="__main__":main()
