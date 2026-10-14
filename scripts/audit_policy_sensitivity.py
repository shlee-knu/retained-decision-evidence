"""Audit alternative observation policies and preserve unfiltered BPI features.

No policy is an independently labelled natural-anomaly oracle. Response imposes
an explicit end-of-observation assumption; AlternatePrecedence is a deliberately
stronger policy which can conflict with legitimate batching/partial invoicing.
Only new results/v03 files are written. Existing audit/validator code is unused.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal, localcontext
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import time
from lxml import etree

ROOT=Path(__file__).resolve().parents[1]
ACTIVITY={"Create Purchase Order Item":"create","Record Goods Receipt":"receive",
          "Record Invoice Receipt":"invoice","Clear Invoice":"clear"}
PROFILE={
    "3-way match, invoice after GR": (("create","receive","invoice","clear"),(("create","receive"),("receive","invoice"),("invoice","clear"))),
    "3-way match, invoice before GR": (("create","receive","invoice","clear"),(("create","receive"),("create","invoice"),("receive","clear"),("invoice","clear"))),
    "2-way match": (("create","invoice","clear"),(("create","invoice"),("invoice","clear"))),
    "Consignment": (("create","receive"),(("create","receive"),)),
}
POLICIES=("presence_only","first_position","first_time_nonstrict","first_position_and_time",
          "standard_precedence","first_plus_response_closure","first_plus_alternate_precedence")
TIMESTAMP=re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")
SPECIAL={"Cancel Goods Receipt":"cancel_goods","Cancel Invoice Receipt":"cancel_invoice",
         "Cancel Subsequent Invoice":"cancel_subsequent_invoice","Delete Purchase Order Item":"delete_item",
         "SRM: Deleted":"delete_srm","Reactivate Purchase Order Item":"reactivate_item"}


def exact_time(value):
    """Standalone exact parser; no candidate parser is imported."""
    match=TIMESTAMP.fullmatch(value or "")
    if match is None:return None
    y,mo,d,h,mi,s=map(int,match.groups()[:6]);fraction,zone=match.groups()[6:]
    if h>23 or mi>59 or s>59 or zone=="-00:00":return None
    try:day=date(y,mo,d).toordinal()-date(1970,1,1).toordinal()
    except ValueError:return None
    offset=0
    if zone.upper()!="Z":
        oh,om=map(int,zone[1:].split(":"))
        if oh>23 or om>59:return None
        offset=(oh*60+om)*60*(1 if zone[0]=="+" else -1)
    with localcontext() as context:
        context.prec=max(40,len(fraction or "")+25)
        return Decimal(day*86400+h*3600+mi*60+s-offset)+Decimal("0."+(fraction or "0"))


def evaluate(milestones,profile):
    required,edges=PROFILE[profile]
    first={}
    for event in milestones:first.setdefault(event["activity"],event)
    present=all(a in first for a in required)
    pos=present and all(first[a]["source_position"]<first[b]["source_position"] for a,b in edges)
    temporal=present and all(first[a]["exact_time"] is not None and first[b]["exact_time"] is not None
                            and first[a]["exact_time"]<=first[b]["exact_time"] for a,b in edges)
    precedence=[];response=[];alternation=[]
    for a,b in edges:
        seen=False;armed=False
        for event in milestones:
            activity=event["activity"]
            if activity==b:
                if not seen:precedence.append((a,b,event["source_position"]))
                if not armed:alternation.append((a,b,event["source_position"]))
                armed=False
            if activity==a:seen=True;armed=True
        future=False
        for event in reversed(milestones):
            activity=event["activity"]
            if activity==a and not future:response.append((a,b,event["source_position"]))
            if activity==b:future=True
    return dict(presence_only=present,first_position=pos,first_time_nonstrict=temporal,
                first_position_and_time=pos and temporal,standard_precedence=present and not precedence,
                first_plus_response_closure=pos and temporal and not response,
                first_plus_alternate_precedence=pos and temporal and not alternation),dict(
                    precedence=precedence,response=response,alternate_precedence=alternation)


def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):h.update(block)
    return h.hexdigest()


def verify_known_answers():
    """Known-answer guards checked before reading the source file."""
    def events(names):return [dict(activity=a,source_position=i,exact_time=Decimal(i)) for i,a in enumerate(names)]
    p="3-way match, invoice after GR"
    policies,issues=evaluate(events(["create","receive","invoice","clear","invoice"]),p)
    assert policies["first_position_and_time"] and policies["standard_precedence"]
    assert not policies["first_plus_response_closure"]
    assert ("invoice","clear",4) in issues["response"]
    policies,_=evaluate(events(["create","receive","invoice","invoice","clear"]),p)
    assert policies["first_plus_response_closure"] and not policies["first_plus_alternate_precedence"]
    assert exact_time("2000-01-01t00:00:00.000000001z")<exact_time("2000-01-01T01:00:00.000000002+01:00")
    assert exact_time("2000-01-01T00:00:00-00:00") is None


def audit_feature_extensions():
    """Additional policy/amount diagnostics; does not rewrite feature bytes."""
    folder=ROOT/"results/v03"
    counts=Counter();groups=defaultdict(Counter);examples=defaultdict(list)
    for line in gzip.open(folder/"bpi_features.jsonl.gz","rt",encoding="utf-8"):
        feature=json.loads(line);profile=feature["profile"];stat=groups[profile]
        counts["cases"]+=1;stat["cases"]+=1
        raw_values=[e["amount"] for e in feature["events"]]
        numeric=[]
        for value in raw_values:
            try:numeric.append(Decimal(value) if value is not None else None)
            except Exception:numeric.append(None)
        available=all(v is not None and v.is_finite() for v in numeric)
        distinct=len(set(numeric)) if available else None
        amount_constant=available and distinct==1
        counts["cases_with_all_finite_amounts"]+=int(available)
        counts["cases_with_constant_event_amount"]+=int(amount_constant)
        counts["cases_with_varying_event_amount"]+=int(available and distinct>1)
        stat["cases_with_constant_event_amount"]+=int(amount_constant)
        stat["cases_with_varying_event_amount"]+=int(available and distinct>1)
        if available and distinct>1 and len(examples["varying_amount"] )<3:
            examples["varying_amount"].append(feature)
        if not feature["policies"]["first_position_and_time"]:continue
        stat["first_pass_cases"]+=1;counts["first_pass_cases"]+=1
        _,edges=PROFILE[profile]
        faults=[]
        for a,b in edges:
            if a=="create":continue
            armed=False
            for event in feature["milestones"]:
                if event["activity"]==b:
                    if not armed:faults.append((a,b,event["source_position"]))
                    armed=False
                if event["activity"]==a:armed=True
        added=bool(faults)
        stat["transaction_edge_alternation_additional_alerts"]+=int(added)
        counts["transaction_edge_alternation_additional_alerts"]+=int(added)
        special=feature["indicators"]["special_pattern"]!="none"
        stat["transaction_edge_alternation_alerts_with_special_activity"]+=int(added and special)
        if added and len(examples[profile+" / transaction_edge_alternation"])<2:
            examples[profile+" / transaction_edge_alternation"].append(dict(feature,alternate_precedence_violations=faults))
    report=dict(
        definition="AlternatePrecedence only on downstream transaction edges, excluding edges whose antecedent is create. Still an unsupported matching assumption: several invoices can correspond to one goods receipt and partial payments may repeat.",
        amount_interpretation="Distinct numeric source Cumulative net worth (EUR) values within each case. A constant value does not prove equal-valued individual transactions; no incremental financial semantics is inferred.",
        totals=dict(counts),by_profile={name:dict(value) for name,value in groups.items()},examples=dict(examples))
    (folder/"policy_sensitivity_extensions.json").write_text(json.dumps(report,indent=2,ensure_ascii=False))
    print("Feature extension:",json.dumps(dict(counts)),flush=True)


def audit_lade_projection():
    """Full-city descriptive two-clock projection audit, without event sorting."""
    import pandas as pd
    resolutions=(1,60,300,3600)
    by_city={};examples=[];totals=Counter();sources=[]
    for city in ("cq","hz","jl","sh","yt"):
        path=ROOT/f"data/raw/lade/delivery_{city}.csv"
        stat=Counter();coarse={str(value):Counter() for value in resolutions};offset=0
        for chunk in pd.read_csv(path,chunksize=100000,dtype={"order_id":"str"},usecols=["order_id","accept_time","delivery_time"]):
            a=pd.to_datetime("2000-"+chunk.accept_time.astype(str),format="%Y-%m-%d %H:%M:%S",errors="coerce")
            b=pd.to_datetime("2000-"+chunk.delivery_time.astype(str),format="%Y-%m-%d %H:%M:%S",errors="coerce")
            valid=a.notna()&b.notna();inverted=(a>b)&valid;equal=(a==b)&valid
            stat["rows"]+=len(chunk);stat["usable_timestamp_pairs"]+=int(valid.sum())
            stat["unusable_timestamp_pairs"]+=int((~valid).sum())
            stat["acceptance_after_delivery"]+=int(inverted.sum())
            stat["equal_timestamps"]+=int(equal.sum())
            stat["acceptance_before_delivery"]+=int(((a<b)&valid).sum())
            stat["acceptance_nonzero_second"]+=int(((a.dt.second!=0)&a.notna()).sum())
            stat["delivery_nonzero_second"]+=int(((b.dt.second!=0)&b.notna()).sum())
            for precision in resolutions:
                after=(a.dt.floor(f"{precision}s")>b.dt.floor(f"{precision}s"))&valid
                same=(a.dt.floor(f"{precision}s")==b.dt.floor(f"{precision}s"))&valid
                coarse[str(precision)]["retained_observed_inversions"]+=int(after.sum())
                coarse[str(precision)]["lost_observed_inversions"]+=int((inverted&~after).sum())
                coarse[str(precision)]["equal_after_flooring"]+=int(same.sum())
                coarse[str(precision)]["new_inversions_created"]+=int((after&~inverted).sum())
            for local in inverted.to_numpy().nonzero()[0]:
                # The source audit found only three inversions. Keep all of their
                # original identifiers and row locations without exporting every row.
                local=int(local)
                row=chunk.iloc[local]
                examples.append(dict(city=city,order_id=row.order_id,csv_row=offset+local+2,
                                     source_locator=f"{path.relative_to(ROOT)}:CSV-row-{offset+local+2}",
                                     accept_time=row.accept_time,delivery_time=row.delivery_time,
                                     delivery_minus_acceptance_seconds=int((b.iloc[local]-a.iloc[local]).total_seconds()),
                                     next_year_delivery_minus_acceptance_seconds=int((b.iloc[local].replace(year=2001)-a.iloc[local]).total_seconds()),
                                     calendar_ambiguity="Source omits years; assigning delivery to the next surrogate year reverses the sign. Neither calendar assignment is independently verified.",
                                     predicate_label="same-surrogate-year acceptance timestamp greater than delivery timestamp; no natural-error truth"))
            offset+=len(chunk)
        totals.update(stat)
        by_city[city]=dict(counts=dict(stat),flooring_seconds={key:dict(value) for key,value in coarse.items()},
                          activity_only_projection=dict(signature="accept,deliver",distinct_signatures=1,
                                                        opposite_temporal_predicates_share_signature=stat["acceptance_after_delivery"]>0 and stat["acceptance_before_delivery"]+stat["equal_timestamps"]>0,
                                                        minority_predicate_cases=stat["acceptance_after_delivery"]))
        sources.append(dict(path=str(path.relative_to(ROOT)),sha256=digest(path),rows=stat["rows"]))
        print(f"LaDe {city} projection audit: {stat['rows']:,} rows",flush=True)
    aggregate={str(p):{name:sum(v["flooring_seconds"][str(p)].get(name,0) for v in by_city.values())
                        for name in ["retained_observed_inversions","lost_observed_inversions","equal_after_flooring","new_inversions_created"]}
               for p in resolutions}
    assert totals["rows"]==4514661
    assert len(examples)==totals["acceptance_after_delivery"]
    assert all(v["new_inversions_created"]==0 for v in aggregate.values())
    result=dict(status="completed full raw-file descriptive projection audit",totals=dict(totals),by_city=by_city,
                aggregate_flooring_seconds=aggregate,observed_inversion_examples=examples,sources=sources,
                representation="Each CSV row is projected into fixed semantic activity order accept then deliver; no chronological event reordering is applied.",
                calendar="Surrogate year 2000 with fixed +08 convention. Within-row differences do not establish an absolute source year or calibrated device clocks.",
                label_scope="The retained predicate compares month/day timestamps after assigning one surrogate year. All three conflicts are October-to-January pairs; a following-year delivery reverses their sign. Neither year assignment nor operational anomaly truth is independently established.",
                activity_only_projection=dict(signature="accept,deliver",distinct_signatures=1,
                                              group_size=totals["usable_timestamp_pairs"],
                                              reversed_time_predicate_cases=totals["acceptance_after_delivery"],
                                              nonreversed_time_predicate_cases=totals["acceptance_before_delivery"]+totals["equal_timestamps"],
                                              interpretation="Removing timestamps maps all usable rows to one activity signature. Mixed predicate values are representational ambiguity, not a performance estimate for a trained detector."),
                flooring="Both timestamps floored independently to common 1, 60, 300 or 3600 second boundaries. Floor is monotone and cannot create a new strict inversion; it can erase one by tying both endpoints.")
    folder=ROOT/"results/v03";folder.mkdir(exist_ok=True)
    (folder/"lade_projection_audit.json").write_text(json.dumps(result,indent=2))
    print(json.dumps(dict(totals),indent=2),flush=True)
    print(json.dumps(aggregate,indent=2),flush=True)


def main():
    started=time.perf_counter();verify_known_answers()
    destination=ROOT/"results/v03";destination.mkdir(parents=True,exist_ok=True)
    raw=ROOT/"data/raw/bpi/BPI_Challenge_2019.xes"
    feature_path=destination/"bpi_features.jsonl.gz"
    totals=Counter();by_profile=defaultdict(Counter);edge_counts=defaultdict(Counter)
    patterns=defaultdict(Counter);examples=defaultdict(list);special_pass_activities=Counter()
    amounts=Counter();activity_counts=Counter();source_patterns=Counter();joint=Counter()
    with feature_path.open("wb") as binary:
        with gzip.GzipFile(fileobj=binary,mode="wb",mtime=0,filename="",compresslevel=6) as compressed:
            with io.TextIOWrapper(compressed,encoding="utf-8") as feature_stream:
                for _,trace in etree.iterparse(str(raw),events=("end",),tag="trace"):
                    totals["cases"]+=1;number=totals["cases"]
                    attrs={a.get("key"):a.get("value") for a in trace if a.tag!="event"}
                    profile=attrs.get("Item Category","UNKNOWN")
                    if profile not in PROFILE:raise ValueError(f"Undeclared profile {profile}")
                    stat=by_profile[profile];stat["cases"]+=1
                    events=[];milestones=[];times=[];special=[];repeat=Counter()
                    for position,node in enumerate(a for a in trace if a.tag=="event"):
                        values={a.get("key"):a.get("value") for a in node}
                        activity=values.get("concept:name")
                        value=values.get("Cumulative net worth (EUR)")
                        timestamp=values.get("time:timestamp");parsed=exact_time(timestamp)
                        events.append(dict(activity=activity,time=timestamp,amount=value))
                        times.append(parsed);activity_counts[activity]+=1
                        totals["events"]+=1
                        if parsed is None:totals["unusable_timestamps"]+=1
                        if value is None:amounts["missing_values"]+=1
                        else:
                            try:
                                amount=Decimal(value)
                                amounts["available_numeric_values"]+=1
                                if amount==0:amounts["zero_values"]+=1
                                if amount<0:amounts["negative_values"]+=1
                            except Exception:amounts["non_numeric_values"]+=1
                        if activity in SPECIAL:special.append(SPECIAL[activity])
                        if activity in ACTIVITY:
                            short=ACTIVITY[activity];repeat[short]+=1
                            milestones.append(dict(source_position=position,activity=short,time=timestamp,amount=value,exact_time=parsed))
                    parsed_all=all(t is not None for t in times)
                    nondecreasing=parsed_all and all(a<=b for a,b in zip(times,times[1:]))
                    tied=parsed_all and any(a==b for a,b in zip(times,times[1:]))
                    totals["source_time_nondecreasing_cases"]+=int(nondecreasing)
                    totals["source_time_has_adjacent_tie_cases"]+=int(tied)
                    stat["source_time_nondecreasing_cases"]+=int(nondecreasing)
                    policies,issues=evaluate(milestones,profile)
                    for key,value in policies.items():stat[key+"_passes"]+=int(value);totals[key+"_passes"]+=int(value)
                    totals["first_position_standard_precedence_disagreements"]+=int(policies["first_position"]!=policies["standard_precedence"])
                    totals["first_position_temporal_disagreements"]+=int(policies["first_position"]!=policies["first_time_nonstrict"])
                    baseline=policies["first_position_and_time"]
                    response_extra=baseline and not policies["first_plus_response_closure"]
                    alternating_extra=baseline and not policies["first_plus_alternate_precedence"]
                    for name,condition in [("response_additional_alerts",response_extra),("alternation_additional_alerts",alternating_extra)]:
                        stat[name]+=int(condition);totals[name]+=int(condition)
                    pattern=" + ".join(sorted(set(special))) if special else "none"
                    patterns[profile][pattern]+=1
                    indicators=dict(has_cancellation=any(x.startswith("cancel") for x in special),
                                    has_deletion=any(x.startswith("delete") for x in special),
                                    has_reactivation="reactivate_item" in special,
                                    has_repeated_milestones=any(count>1 for count in repeat.values()),
                                    special_pattern=pattern,source_time_nondecreasing=nondecreasing,
                                    source_time_has_adjacent_tie=tied)
                    if baseline:
                        source_patterns[pattern]+=1
                        special_pass_activities.update(set(special))
                        if special:stat["first_pass_with_special_activity"]+=1
                        if response_extra:stat["response_additional_with_special_activity"]+=int(bool(special))
                        if alternating_extra:stat["alternation_additional_with_special_activity"]+=int(bool(special))
                        joint[(response_extra,alternating_extra,bool(special))]+=1
                    for kind in ("response","alternate_precedence"):
                        if baseline:
                            for a,b in set((a,b) for a,b,_ in issues[kind]):edge_counts[profile][kind+":"+a+"->"+b]+=1
                    feature=dict(case_id=attrs.get("concept:name"),source_trace=number,
                                 source_locator=f"data/raw/bpi/BPI_Challenge_2019.xes:trace-{number}",
                                 company=attrs.get("Company"),purchasing_document=attrs.get("Purchasing Document"),
                                 profile=profile,flags={key:attrs.get(key) for key in ["Item Type","GR-Based Inv. Verif.","Goods Receipt"]},
                                 events=events,milestones=[{key:value for key,value in m.items() if key!="exact_time"} for m in milestones],
                                 indicators=indicators,policies=policies)
                    feature_stream.write(json.dumps(feature,separators=(",",":"),ensure_ascii=False)+"\n")
                    example_kinds=[]
                    if response_extra:example_kinds.append("first_pass_response_alert")
                    if alternating_extra:example_kinds.append("first_pass_alternation_alert")
                    if baseline and special:example_kinds.append("first_pass_special_pattern:"+pattern)
                    for kind in example_kinds:
                        key=profile+" / "+kind
                        if len(examples[key])<2:
                            examples[key].append(dict(feature,policy_edge_violations=issues))
                    trace.clear()
                    while trace.getprevious() is not None:del trace.getparent()[0]
                    if number%50000==0:print(f"Exported and audited {number:,} raw cases",flush=True)
    totals["distinct_activities"]=len(activity_counts)
    assert totals["cases"]==251734 and totals["events"]==1595923
    assert totals["first_position_standard_precedence_disagreements"]==0
    source_hash=digest(raw);features_hash=digest(feature_path)
    result=dict(
        status="descriptive alternative observation-policy audit",source_sha256=source_hash,
        source_doi="https://doi.org/10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1",
        policy_meanings={
            "presence_only":"Every declared required activity occurs at least once; no closure claim.",
            "first_position":"Presence plus first(A)<first(B) in source XML order for every profile edge.",
            "first_time_nonstrict":"Presence plus time(first(A))<=time(first(B)); no separate storage-order requirement.",
            "first_position_and_time":"Both first-position and non-strict first-time requirements.",
            "standard_precedence":"Presence plus every B has some strictly earlier A, checked by independent sequence scanning. Equivalent to first-position for these distinct activities.",
            "first_plus_response_closure":"First-position-and-time plus every A has some later B before observation ends. Adds an unverified observation-end closure assumption.",
            "first_plus_alternate_precedence":"First-position-and-time plus each B requires a new A since the previous B. This strong matching assumption is not established by source semantics and may reject legitimate split invoices or batching.",
        },
        caveats=["No natural-anomaly truth labels or causal claims.",
                 "Source XML order may already be chronological; positional and time checks cannot be advertised as independent evidence when they coincide.",
                 "Cumulative net worth (EUR) values are preserved as raw strings. No incremental-amount interpretation or reconciliation truth is imposed.",
                 "Cancellations, deletions and reactivations do not alone establish noncompliance; full monetary and lifecycle semantics are not modelled.",
                 "Response is an observation policy, not proof that a case has actually closed."],
        totals=dict(totals),by_profile={name:dict(value) for name,value in sorted(by_profile.items())},
        first_pass_edge_sensitivity={name:dict(value) for name,value in sorted(edge_counts.items())},
        all_case_special_patterns={name:dict(value) for name,value in sorted(patterns.items())},
        first_pass_special_patterns=dict(source_patterns),first_pass_special_activity_presence=dict(special_pass_activities),
        first_pass_joint_sensitivity=[dict(response_extra=key[0],alternation_extra=key[1],special_activity=key[2],cases=value) for key,value in sorted(joint.items())],
        amount_value_availability=dict(amounts),source_activities=dict(activity_counts),
        examples=dict(examples),feature_file=dict(path=str(feature_path.relative_to(ROOT)),sha256=features_hash,bytes=feature_path.stat().st_size),
        execution_seconds=round(time.perf_counter()-started,3))
    (destination/"policy_sensitivity.json").write_text(json.dumps(result,indent=2,ensure_ascii=False))
    (destination/"bpi_features_manifest.json").write_text(json.dumps(dict(
        file=result["feature_file"],cases=totals["cases"],events=totals["events"],source_sha256=source_hash,
        source_doi=result["source_doi"],license="CC BY 4.0, inherited public source; retain source attribution",
        schema="One JSON record per original case; events preserve every source activity, timestamp and original amount string in source order; milestones add original zero-based source_position.",
        field_notes={"amount":"Exact source text of Cumulative net worth (EUR), not asserted to be a transaction increment.",
                     "policies":"Computed observation predicates, never natural-anomaly labels.",
                     "source_trace":"1-based trace ordinal in pinned raw XES.","closure":"Unknown; no closure label is provided."},
        policy_report="results/v03/policy_sensitivity.json",determinism="gzip mtime=0, no filename header; stable raw-source order"),indent=2))
    print(json.dumps(dict(totals),indent=2),flush=True)
    audit_feature_extensions()


if __name__=="__main__":
    if "--lade" in sys.argv:audit_lade_projection()
    elif "--features-only" in sys.argv:audit_feature_extensions()
    else:main()
