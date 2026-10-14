"""Descriptive census of raw BPI 2019 traces without qualification or labels.

This audit imports neither the candidate checkers nor their time parser/adapters.
Observed milestones do not establish case closure. Every alert is conditional on
the stated projection; no observation is assigned a natural-anomaly truth label.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import re
import time

from lxml import etree

ROOT=Path(__file__).resolve().parents[1]
MILESTONES={"Create Purchase Order Item":"create", "Record Goods Receipt":"receive",
            "Record Invoice Receipt":"invoice", "Clear Invoice":"clear"}
# Independent declaration of the limited first-occurrence projection. These are
# hypotheses about the projection, not a model of all source procurement rules.
PROFILES={
    "3-way match, invoice after GR": (("create","receive","invoice","clear"),(("create","receive"),("receive","invoice"),("invoice","clear"))),
    "3-way match, invoice before GR": (("create","receive","invoice","clear"),(("create","receive"),("create","invoice"),("receive","clear"),("invoice","clear"))),
    "2-way match": (("create","invoice","clear"),(("create","invoice"),("invoice","clear"))),
    "Consignment": (("create","receive"),(("create","receive"),)),
}
FIXED_REQUIRED=("create","receive","invoice","clear")
FIXED_EDGES=(("create","receive"),("receive","invoice"),("invoice","clear"))
STAMP=re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")


def exact_time(value):
    """Exact Decimal UTC seconds; reject unknown-offset and leap-second inputs."""
    if not isinstance(value,str):return None
    match=STAMP.fullmatch(value)
    if not match:return None
    year,month,day,hour,minute,second=map(int,match.groups()[:6])
    fraction,zone=match.groups()[6:]
    if hour>23 or minute>59 or second>59 or zone=="-00:00":return None
    try:days=date(year,month,day).toordinal()-date(1970,1,1).toordinal()
    except ValueError:return None
    offset=0
    if zone not in ("Z","z"):
        zh,zm=map(int,zone[1:].split(":"))
        if zh>23 or zm>59:return None
        offset=(zh*60+zm)*60*(1 if zone[0]=="+" else -1)
    with localcontext() as ctx:
        ctx.prec=max(40,len(fraction or "")+25)
        return Decimal(days*86400+hour*3600+minute*60+second-offset)+Decimal("0."+(fraction or "0"))


def summarize_predicates(first,required,edges):
    missing=tuple(a for a in required if a not in first)
    position=[];clock=[];equal_position=[];unavailable_time=[];predecessor=[]
    per_edge={}
    for a,b in edges:
        facts={"target_observed":int(b in first),"both_observed":int(a in first and b in first)}
        if b in first and a not in first:
            predecessor.append((a,b));facts["missing_predecessor"]=1
        if a in first and b in first:
            ia,ta=first[a];ib,tb=first[b]
            if ia>=ib:position.append((a,b));facts["position_violation"]=1
            if ta is None or tb is None:
                unavailable_time.append((a,b));facts["time_not_comparable"]=1
            else:
                facts["time_comparable"]=1
                if ta>tb:clock.append((a,b));facts["time_violation"]=1
                if ta==tb:
                    facts["equal_time"]=1
                    if ia>=ib:equal_position.append((a,b));facts["equal_time_position_violation"]=1
        per_edge[a+"->"+b]=facts
    return dict(missing=missing,position=position,clock=clock,equal_position=equal_position,
                unavailable_time=unavailable_time,predecessor=predecessor,per_edge=per_edge,
                compatible=not(missing or position or clock or unavailable_time))


def sha256(path):
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):digest.update(block)
    return digest.hexdigest()


def main():
    started=time.perf_counter()
    source=ROOT/"data/raw/bpi/BPI_Challenge_2019.xes"
    totals=Counter(cases=0,events=0,events_with_unusable_timestamps=0,duplicate_case_identifiers=0)
    groups=defaultdict(Counter);activities=Counter()
    missing_sets=defaultdict(Counter);presence=defaultdict(Counter);repeats=defaultdict(Counter)
    edges=defaultdict(lambda:defaultdict(Counter));decisions=defaultdict(Counter)
    flags=Counter();company_profile=defaultdict(Counter);documents=defaultdict(set)
    document_profile=defaultdict(set);document_companies=defaultdict(set);ids=set()
    events_special=defaultdict(Counter);cases_special=defaultdict(Counter)
    examples=defaultdict(list);trace_attribute_keys=Counter();company_documents=defaultdict(set)
    timestamp_lexical_forms=Counter()
    for _,trace in etree.iterparse(str(source),events=("end",),tag="trace"):
        totals["cases"]+=1
        number=totals["cases"]
        attrs={item.get("key"):item.get("value") for item in trace if item.tag!="event"}
        trace_attribute_keys.update(attrs.keys())
        cid=attrs.get("concept:name","")
        if cid in ids:totals["duplicate_case_identifiers"]+=1
        ids.add(cid)
        category=attrs.get("Item Category","MISSING")
        stat=groups[category];stat["cases"]+=1
        company=attrs.get("Company","MISSING");document=attrs.get("Purchasing Document","MISSING")
        company_profile[company][category]+=1
        documents[category].add((company,document))
        document_profile[(company,document)].add(category)
        document_companies[document].add(company)
        company_documents[company].add(document)
        flags[(category,attrs.get("GR-Based Inv. Verif.","MISSING"),attrs.get("Goods Receipt","MISSING"),attrs.get("Item Type","MISSING"))]+=1
        first={};milestone_count=Counter();trace_special=Counter();milestone_records=[]
        last_time=None;full_clock_inversion=False
        for pos,node in enumerate(item for item in trace if item.tag=="event"):
            event={item.get("key"):item.get("value") for item in node}
            activity=event.get("concept:name","MISSING")
            raw_time=event.get("time:timestamp")
            stamp=exact_time(raw_time)
            totals["events"]+=1;stat["events"]+=1;activities[activity]+=1
            if stamp is None:
                totals["events_with_unusable_timestamps"]+=1;stat["events_with_unusable_timestamps"]+=1
            else:
                if last_time is not None and stamp<last_time:full_clock_inversion=True
                last_time=stamp
            lexical=STAMP.fullmatch(raw_time) if isinstance(raw_time,str) else None
            if lexical:timestamp_lexical_forms[(len(lexical.group(7) or ""),lexical.group(8))]+=1
            special=[]
            if activity.startswith("Cancel "):special.append("cancellation")
            if activity in ("Delete Purchase Order Item","SRM: Deleted"):special.append("deletion")
            if activity=="Reactivate Purchase Order Item":special.append("reactivation")
            for name in special:trace_special[name]+=1;events_special[category][name]+=1
            short=MILESTONES.get(activity)
            if short:
                totals["retained_milestone_events"]+=1;stat["retained_milestone_events"]+=1
                milestone_count[short]+=1
                first.setdefault(short,(pos,stamp))
                milestone_records.append(dict(source_position=pos,activity=short,time=raw_time))
        if full_clock_inversion:stat["cases_with_adjacent_source_time_inversion"]+=1
        for name in trace_special:cases_special[category][name]+=1
        if trace_special:stat["cases_with_any_cancellation_deletion_or_reactivation"]+=1
        repeated=[name for name,count in milestone_count.items() if count>1]
        presence[category].update(first.keys())
        repeats[category].update(repeated)
        if repeated:stat["cases_with_repeated_milestones"]+=1
        stat["repeated_milestone_events_beyond_first"]+=sum(max(0,count-1) for count in milestone_count.values())
        if category not in PROFILES:
            stat["unsupported_profile"]+=1
        else:
            required,order=PROFILES[category]
            conditional=summarize_predicates(first,required,order)
            fixed=summarize_predicates(first,FIXED_REQUIRED,FIXED_EDGES)
            missing_sets[category][conditional["missing"]]+=1
            for name,found in [("all_required_milestones_observed",not conditional["missing"]),
                               ("cases_with_missing_required_milestone",bool(conditional["missing"])),
                               ("cases_with_missing_predecessor",bool(conditional["predecessor"])),
                               ("cases_with_first_occurrence_position_alert",bool(conditional["position"])),
                               ("cases_with_first_occurrence_time_alert",bool(conditional["clock"])),
                               ("cases_with_both_position_and_time_alert",bool(conditional["position"] and conditional["clock"])),
                               ("cases_with_position_only_alert",bool(conditional["position"] and not conditional["clock"])),
                               ("cases_with_time_only_alert",bool(conditional["clock"] and not conditional["position"])),
                               ("cases_with_equal_time_position_alert",bool(conditional["equal_position"])),
                               ("cases_with_uncomparable_edge_time",bool(conditional["unavailable_time"])),
                               ("all_required_observed_with_contract_alert",not conditional["missing"] and not conditional["compatible"]),
                               ("missing_milestones_with_order_or_time_alert",bool(conditional["missing"] and (conditional["position"] or conditional["clock"]))),
                               ("conditional_projection_compatible",conditional["compatible"]),
                               ("conditional_compatible_with_special_activity",conditional["compatible"] and bool(trace_special)),
                               ("conditional_compatible_with_repeated_milestones",conditional["compatible"] and bool(repeated)),
                               ("missing_required_with_special_activity",bool(conditional["missing"] and trace_special)),
                               ("fixed_projection_compatible",fixed["compatible"]),
                               ("conditional_compatible_fixed_alert",conditional["compatible"] and not fixed["compatible"]),
                               ("fixed_compatible_conditional_alert",fixed["compatible"] and not conditional["compatible"])]:
                stat[name]+=int(found)
            for edge,facts in conditional["per_edge"].items():edges[category][edge].update(facts)
            decision=("compatible" if conditional["compatible"] else "alert", "compatible" if fixed["compatible"] else "alert")
            decisions[category][decision]+=1
            example_kinds=[]
            if conditional["equal_position"]:example_kinds.append("equal_time_position_alert")
            if conditional["clock"]:example_kinds.append("first_occurrence_time_alert")
            if conditional["compatible"] and not fixed["compatible"]:example_kinds.append("conditional_compatible_fixed_alert")
            if conditional["missing"]:example_kinds.append("missing_required_milestone")
            for kind in example_kinds:
                key=category+" / "+kind
                if len(examples[key])<2:
                    examples[key].append(dict(case_id=cid,source_trace=number,company=company,purchasing_document=document,
                                              missing=list(conditional["missing"]),position_alerts=conditional["position"],time_alerts=conditional["clock"],
                                              milestones=milestone_records[:24],milestones_truncated=len(milestone_records)>24))
        trace.clear()
        while trace.getprevious() is not None:del trace.getparent()[0]
        if number%50000==0:print(f"Audited {number:,} unfiltered source cases",flush=True)
    totals["omitted_non_milestone_events"]=totals["events"]-totals["retained_milestone_events"]
    totals["distinct_activities"]=len(activities)
    totals["companies"]=len(company_profile)
    totals["distinct_purchasing_document_identifiers"]=len(document_companies)
    totals["distinct_company_document_pairs"]=len(document_profile)
    totals["documents_spanning_multiple_profiles"]=sum(len(values)>1 for values in document_profile.values())
    totals["document_identifiers_spanning_multiple_companies"]=sum(len(values)>1 for values in document_companies.values())
    totals["companies_spanning_multiple_profiles"]=sum(len(values)>1 for values in company_profile.values())
    numeric_keys=["all_required_milestones_observed","cases_with_missing_required_milestone","cases_with_missing_predecessor",
                  "cases_with_first_occurrence_position_alert","cases_with_first_occurrence_time_alert","cases_with_equal_time_position_alert",
                  "cases_with_both_position_and_time_alert","cases_with_position_only_alert","cases_with_time_only_alert",
                  "all_required_observed_with_contract_alert","missing_milestones_with_order_or_time_alert",
                  "conditional_projection_compatible","fixed_projection_compatible","conditional_compatible_fixed_alert","fixed_compatible_conditional_alert",
                  "conditional_compatible_with_special_activity","conditional_compatible_with_repeated_milestones","missing_required_with_special_activity",
                  "cases_with_repeated_milestones","repeated_milestone_events_beyond_first","cases_with_any_cancellation_deletion_or_reactivation"]
    for key in numeric_keys:totals[key]=sum(group[key] for group in groups.values())
    totals["special_activity_case_counts"]={name:sum(group[name] for group in cases_special.values()) for name in ["cancellation","deletion","reactivation"]}
    result=dict(
        status="completed descriptive census",
        source=dict(path=str(source.relative_to(ROOT)),sha256=sha256(source)),
        interpretation={
            "scope":"All raw traces retained; no candidate checker, candidate time parser, or eligibility filter imported.",
            "closure":"Unknown. Observing the chosen required milestones does not certify business completion, account settlement or absence of later events.",
            "truth":"No natural-anomaly truth labels. Predicate alerts are descriptive consequences of declared projection assumptions.",
            "order":"Source XML positions define first occurrence; equal-time order conflicts are counted separately from strictly inverted clocks.",
            "time":"Independent RFC3339 Decimal parser; arbitrary fractional precision is retained. Leap seconds, malformed timestamps and unknown -00:00 offsets are uncomparable, not automatically natural anomalies.",
            "omissions":"Monetary reconciliation, cancellations' effects on balances, case closure and complete procurement semantics are outside the projection.",
            "inference":"Counts are a census of the acquired file. No confidence intervals, population inference or causal effects are claimed.",
        },
        totals=dict(totals),
        profiles={name:dict(counts=dict(counts),required_milestones=list(PROFILES[name][0]) if name in PROFILES else [],
                            observed_milestone_case_counts=dict(presence[name]),repeated_milestone_case_counts=dict(repeats[name]),
                            missing_required_sets=[dict(missing=list(key),cases=value) for key,value in sorted(missing_sets[name].items())],
                            edge_predicates={key:dict(value) for key,value in edges[name].items()},
                            fixed_vs_conditional=[dict(conditional=key[0],fixed=key[1],cases=value) for key,value in sorted(decisions[name].items())],
                            special_activity_event_counts=dict(events_special[name]),special_activity_case_counts=dict(cases_special[name]),
                            company_count=len({company for company,profile in company_profile.items() if name in profile}),
                            company_document_pair_count=len(documents[name])) for name,counts in sorted(groups.items())},
        company_profile_counts={company:dict(profiles) for company,profiles in sorted(company_profile.items())},
        company_document_counts={company:len(values) for company,values in sorted(company_documents.items())},
        document_profile_membership_counts=[dict(profiles=list(key),documents=value) for key,value in sorted(Counter(tuple(sorted(value)) for value in document_profile.values()).items())],
        source_attribute_cross_tabs=[dict(category=key[0],gr_based_invoice_verification=key[1],goods_receipt=key[2],item_type=key[3],cases=count) for key,count in sorted(flags.items())],
        source_trace_attribute_keys=dict(trace_attribute_keys),
        source_activities=dict(activities),
        timestamp_lexical_forms=[dict(fraction_digits=key[0],zone=key[1],events=count) for key,count in sorted(timestamp_lexical_forms.items())],
        examples=dict(examples),
        execution_seconds=round(time.perf_counter()-started,3),
    )
    assert totals["cases"]==251734 and totals["events"]==1595923
    assert sum(sum(counts.values()) for counts in missing_sets.values())==totals["cases"]
    assert sum(sum(counts.values()) for counts in decisions.values())==totals["cases"]
    destination=ROOT/"results/revision/bpi_unfiltered_audit.json"
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(result,indent=2))
    print(json.dumps(dict(totals),indent=2),flush=True)


if __name__=="__main__":main()
