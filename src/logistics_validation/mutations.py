"""Known contract violations; no inference about naturally occurring anomalies."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta
import uuid
from .model import Case, uri

FAULTS = ["missing_time","malformed_uri","duplicate_id","dangling_reference","missing_predecessor","time_inversion"]

def fault(case: Case, name: str) -> Case:
    mutant = copy.deepcopy(case)
    events = mutant.events
    if name=="missing_time":
        events[-1].time = None
    elif name=="malformed_uri":
        events[-1].object_id = "not a URI with spaces"
    elif name=="duplicate_id":
        events[-1].event_id = events[0].event_id
    elif name=="dangling_reference":
        events[-1].ref = uri("absent-event",case.case_id)
    elif name=="missing_predecessor":
        predecessor = case.edges[0][0]
        mutant.events = [e for e in events if e.activity!=predecessor]
    elif name=="time_inversion":
        a,b = case.edges[0]
        before = next(e for e in events if e.activity==a)
        after = next(e for e in events if e.activity==b)
        after.time = (datetime.fromisoformat(before.time.replace("Z","+00:00"))-timedelta(seconds=1)).isoformat()
    else:
        raise ValueError(name)
    if mutant.digest()==case.digest():
        raise RuntimeError(f"No-op fault: {name} {case.case_id}")
    return mutant

def benign(case: Case, variant: int) -> tuple[Case,str]:
    control = copy.deepcopy(case)
    choices = ["optional_readpoint_omitted","vendor_vocabulary","equal_timestamps","non_gs1_uri","permitted_repeated_activity"]
    if case.profile=="3-way match, invoice before GR":
        choices.append("invoice_before_receipt_when_permitted")
    name = choices[variant%len(choices)]
    if name=="optional_readpoint_omitted":
        for e in control.events:
            e.readpoint = None
    elif name=="vendor_vocabulary":
        for e in control.events:
            e.vendor_step = True
    elif name=="equal_timestamps":
        t = min(e.time for e in control.events)
        for e in control.events:
            e.time = t
    elif name=="non_gs1_uri":
        object_id = "urn:uuid:"+str(uuid.uuid5(uuid.NAMESPACE_URL,case.case_id))
        control.attributes["object_id"] = object_id
        for e in control.events:
            e.object_id = object_id
    elif name=="permitted_repeated_activity":
        event = copy.deepcopy(control.events[0])
        event.event_id = uri("event",case.case_id+":benign-repeat")
        control.events.insert(1,event)
    elif name=="invoice_before_receipt_when_permitted":
        order = {"create":0,"invoice":1,"receive":2,"clear":3}
        times = sorted(e.time for e in control.events)
        control.events.sort(key=lambda e:order.get(e.activity,4))
        for e,t in zip(control.events,times):
            e.time = t
    return control,name
