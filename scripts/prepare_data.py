"""Source-preserving adapters with explicit qualification, not natural labels."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import heapq
import json
from pathlib import Path
import pandas as pd
from lxml import etree
from logistics_validation.model import Case, Event, uri
from logistics_validation.constraints import indexed_issues

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "configs/protocol_v1.json").read_text())

def rank(value: str) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest(),16)

def offer(heap, case, cap):
    key = rank(case.case_id)
    item = (-key, case.case_id, case)
    if len(heap)<cap:
        heapq.heappush(heap,item)
    elif key < -heap[0][0]:
        heapq.heapreplace(heap,item)

def lade(city):
    path = ROOT / f"data/raw/lade/delivery_{city}.csv"
    counts = Counter()
    ids = set()
    sampled = []
    offset = 0
    for chunk in pd.read_csv(path, chunksize=100000, dtype={"order_id":"str"}):
        counts["raw_rows"] += len(chunk)
        # Year and zone absent from source. Surrogate year 2000, +08 convention.
        ta = pd.to_datetime("2000-"+chunk.accept_time.astype(str),format="%Y-%m-%d %H:%M:%S",errors="coerce")
        tb = pd.to_datetime("2000-"+chunk.delivery_time.astype(str),format="%Y-%m-%d %H:%M:%S",errors="coerce")
        for pos,(row,a,b) in enumerate(zip(chunk.to_dict("records"),ta,tb)):
            oid = row["order_id"]
            if oid in ids:
                counts["duplicate_source_order_excluded"] += 1
                continue
            ids.add(oid)
            if pd.isna(a) or pd.isna(b):
                counts["missing_or_unparseable_time_excluded"] += 1
                continue
            if a > b:
                counts["inverted_source_time_excluded"] += 1
                continue
            counts["qualified_all_months"] += 1
            if int(row["ds"]) < 901:
                counts["earlier_period_not_sampled"] += 1
                continue
            counts["qualified_later_period"] += 1
            cid = f"lade:{city}:{oid}"
            # Compare rank first to avoid allocating millions of unused objects.
            if len(sampled)>=CONFIG["qualified_sample_per_city"] and rank(cid)>=-sampled[0][0]:
                continue
            obj = uri("lade/"+city, oid)
            times = [x.to_pydatetime().replace(tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc).isoformat() for x in (a,b)]
            events = [Event(uri("event",cid+":accept"),obj,"accept",times[0]),
                      Event(uri("event",cid+":deliver"),obj,"deliver",times[1],ref=uri("event",cid+":accept"))]
            case = Case(cid,"lade",str(row["city"]),"last_mile_delivery",
                        f"{path.relative_to(ROOT)}:CSV-row-{offset+pos+2}",events,
                        [("accept","deliver")],["accept","deliver"],
                        {"source_order_id":oid,"source_courier_id":str(row["courier_id"]),
                         "source_ds":int(row["ds"]),"object_id":obj,
                         "calendar":"surrogate year 2000; source year unknown; +08 normalization convention"})
            offer(sampled,case,CONFIG["qualified_sample_per_city"])
        offset += len(chunk)
    counts["sampled_cases"] = len(sampled)
    print(f"LaDe {city}: {dict(counts)}",flush=True)
    return [x[2] for x in sampled],dict(counts)

MILESTONES = {"Create Purchase Order Item":"create", "Record Goods Receipt":"receive",
              "Record Invoice Receipt":"invoice", "Clear Invoice":"clear"}
PROFILES = {
    "3-way match, invoice after GR": (["create","receive","invoice","clear"],[("create","receive"),("receive","invoice"),("invoice","clear")]),
    "3-way match, invoice before GR": (["create","receive","invoice","clear"],[("create","receive"),("create","invoice"),("receive","clear"),("invoice","clear")]),
    "2-way match": (["create","invoice","clear"],[("create","invoice"),("invoice","clear")]),
    "Consignment": (["create","receive"],[("create","receive")]),
}

def bpi():
    path = ROOT / "data/raw/bpi/BPI_Challenge_2019.xes"
    if not path.exists():
        raise FileNotFoundError("Run scripts/download_bpi.py first.")
    counts = Counter()
    profiles = {key:Counter() for key in PROFILES}
    sampled = {key:[] for key in PROFILES}
    trace_no = 0
    activities = Counter()
    for _,trace in etree.iterparse(str(path),events=("end",),tag="trace"):
        trace_no += 1
        counts["raw_traces"] += 1
        attrs = {e.get("key"):e.get("value") for e in trace if e.tag!="event"}
        category = attrs.get("Item Category","")
        raw_events = [e for e in trace if e.tag=="event"]
        counts["raw_events"] += len(raw_events)
        # All source activities counted, but only milestones enter the projection.
        event_attrs = [{x.get("key"):x.get("value") for x in e} for e in raw_events]
        activities.update(e.get("concept:name","") for e in event_attrs)
        if category not in PROFILES:
            counts["unknown_profile_excluded"] += 1
        else:
            stat = profiles[category]
            stat["raw_traces"] += 1
            cid = "bpi2019:"+attrs["concept:name"]
            obj = uri("bpi/item",attrs["concept:name"])
            events = []
            first_create = None
            for pos,e in enumerate(event_attrs):
                activity = MILESTONES.get(e.get("concept:name"))
                if not activity:
                    continue
                eid = uri("event",cid+":"+str(pos))
                if activity=="create" and first_create is None:
                    first_create = eid
                ref = first_create if activity!="create" else None
                events.append(Event(eid,obj,activity,e.get("time:timestamp"),ref=ref))
            required,edges = PROFILES[category]
            case = Case(cid,"bpi2019",category,category,
                        f"{path.relative_to(ROOT)}:trace-{trace_no}",events,edges,required,
                        {"source_case_id":attrs["concept:name"],"source_company":attrs.get("Company"),
                         "source_vendor":attrs.get("Vendor"),"object_id":obj,
                         "source_trace_event_count":len(raw_events),"source_profile_fields":
                         {k:attrs.get(k) for k in ["GR-Based Inv. Verif.","Goods Receipt","Item Type","Item Category"]}})
            if not all(e.time for e in events):
                stat["missing_time_excluded"] += 1
            elif indexed_issues(case):
                # Qualification under an explicit contract. This is NOT labelled
                # natural anomaly data and is not independent external ground truth.
                stat["outside_complete_contract_slice"] += 1
            else:
                stat["qualified_complete_contract_slice"] += 1
                if len(events)>len(required):
                    stat["qualified_with_repeats"] += 1
                offer(sampled[category],case,CONFIG["bpi_sample_target"]//len(PROFILES))
        trace.clear()
        while trace.getprevious() is not None:
            del trace.getparent()[0]
    counts["sampled_cases"] = sum(len(x) for x in sampled.values())
    counts["distinct_source_activities"] = len(activities)
    result = dict(totals=dict(counts),profiles={k:dict(v) for k,v in profiles.items()},source_activities=dict(activities))
    print(f"BPI totals: {dict(counts)}",flush=True)
    return [x[2] for heap in sampled.values() for x in heap],result

def main():
    dest = ROOT / "data/processed"
    dest.mkdir(parents=True,exist_ok=True)
    stats = {"protocol_sha256":hashlib.sha256((ROOT/"configs/protocol_v1.json").read_bytes()).hexdigest(),
             "normalization_notes": "LaDe relative calendar only; no assigned GS1 keys. Event IDs/references are deterministic projections, not source observations.","lade":{}}
    cases = []
    for city in ["cq","hz","jl","sh","yt"]:
        subset,report = lade(city)
        cases.extend(subset)
        stats["lade"][city] = report
    subset,report = bpi()
    cases.extend(subset)
    stats["bpi2019"] = report
    cases.sort(key=lambda c:c.case_id)
    if len({c.case_id for c in cases})!=len(cases):
        raise RuntimeError("Duplicate case identity in sample")
    target = dest/"cases.jsonl"
    with target.open("w") as f:
        for c in cases:
            f.write(json.dumps(c.to_dict(),ensure_ascii=False)+"\n")
    stats["sample_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    stats["sample_cases"] = len(cases)
    stats["sample_projected_events"] = sum(len(c.events) for c in cases)
    (ROOT/"results").mkdir(exist_ok=True)
    (ROOT/"results/data_audit.json").write_text(json.dumps(stats,indent=2,ensure_ascii=False))

if __name__=="__main__":
    main()
