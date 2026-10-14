"""Independently encoded SQL contracts and an actual PM4Py replay baseline."""
from __future__ import annotations
from collections import defaultdict
import sqlite3
from itertools import combinations
from pm4py.objects.log.obj import EventLog, Trace, Event as PMEvent
from pm4py.objects.petri_net.obj import PetriNet, Marking
from pm4py.objects.petri_net.utils import petri_utils
from pm4py.algo.conformance.tokenreplay import algorithm as token_replay
from .model import Case, timestamp_key

RULE_SQL = """
WITH firsts AS (
  SELECT cid, activity, MIN(pos) pos FROM events GROUP BY cid, activity
), milestones AS (
  SELECT f.cid, f.activity, f.pos, e.ts FROM firsts f
  JOIN events e ON e.cid=f.cid AND e.pos=f.pos
)
SELECT cid, 'duplicate_id' rule FROM events GROUP BY cid,eid HAVING COUNT(*)>1
UNION
SELECT r.cid, 'missing_activity' FROM required r
WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.cid=r.cid AND e.activity=r.activity)
UNION
SELECT d.cid, 'missing_predecessor' FROM edges d
JOIN milestones b ON d.cid=b.cid AND d.b=b.activity
WHERE NOT EXISTS(SELECT 1 FROM milestones a WHERE a.cid=d.cid AND a.activity=d.a)
UNION
SELECT d.cid, 'precedence' FROM edges d
JOIN milestones a ON a.cid=d.cid AND a.activity=d.a
JOIN milestones b ON b.cid=d.cid AND b.activity=d.b
WHERE a.pos >= b.pos
UNION
SELECT d.cid, 'time_precedence' FROM edges d
JOIN milestones a ON a.cid=d.cid AND a.activity=d.a
JOIN milestones b ON b.cid=d.cid AND b.activity=d.b
WHERE a.ts > b.ts
UNION
SELECT e.cid, 'dangling_reference' FROM events e
WHERE e.ref IS NOT NULL AND e.ref<>'' AND NOT EXISTS(SELECT 1 FROM events t WHERE t.cid=e.cid AND t.eid=e.ref)
UNION
SELECT e.cid, 'object_identity' FROM events e JOIN cases c ON e.cid=c.cid
WHERE c.obj IS NOT NULL AND c.obj<>e.obj
"""

def sql_issues(cases: list[Case]) -> dict[str, set[str]]:
    """Includes connection, inserts and indexes in the measured wall time."""
    with sqlite3.connect(":memory:") as db:
        db.executescript("""
        CREATE TABLE cases(cid TEXT PRIMARY KEY, obj TEXT);
        CREATE TABLE events(cid TEXT, pos INTEGER, eid TEXT, obj TEXT, activity TEXT, ts TEXT COLLATE BINARY, ref TEXT);
        CREATE TABLE edges(cid TEXT, a TEXT, b TEXT);
        CREATE TABLE required(cid TEXT, activity TEXT);
        """)
        db.executemany("INSERT INTO cases VALUES (?,?)", [(c.case_id,c.attributes.get("object_id")) for c in cases])
        db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                       [(c.case_id,i,e.event_id,e.object_id,e.activity,timestamp_key(e.time),e.ref)
                        for c in cases for i,e in enumerate(c.events)])
        db.executemany("INSERT INTO edges VALUES (?,?,?)", [(c.case_id,a,b) for c in cases for a,b in c.edges])
        db.executemany("INSERT INTO required VALUES (?,?)", [(c.case_id,a) for c in cases for a in c.required])
        db.executescript("CREATE INDEX eid_idx ON events(cid,eid); CREATE UNIQUE INDEX pos_idx ON events(cid,pos); CREATE INDEX act_idx ON events(cid,activity);")
        issues = {c.case_id:set() for c in cases}
        for cid,rule in db.execute(RULE_SQL):
            issues[cid].add(rule)
        return issues

def profile_net(required: tuple[str,...], edges: tuple[tuple[str,str],...]):
    """Finite-state net for first-occurrence partial order with valid repetitions.

    Known milestones can repeat after their first occurrence. The complete-case
    final marking requires every required milestone. Other source activities are
    not modelled and are explicitly excluded from this control-flow projection.
    """
    n = len(required)
    full = (1 << n) - 1
    bit = {a:1<<i for i,a in enumerate(required)}
    dependencies = {a:0 for a in required}
    for a,b in edges:
        if a in bit and b in bit:
            dependencies[b] |= bit[a]
    net = PetriNet("profile_first_occurrence")
    places = {}
    for mask in range(1<<n):
        # Only down-sets are reachable, but unreachable states cannot add tokens.
        place = PetriNet.Place(str(mask))
        net.places.add(place)
        places[mask] = place
    for mask in range(1<<n):
        for a in required:
            if (mask & dependencies[a]) != dependencies[a]:
                continue
            out = mask | bit[a]
            t = PetriNet.Transition(f"{mask}_{a}", a)
            net.transitions.add(t)
            petri_utils.add_arc_from_to(places[mask], t, net)
            petri_utils.add_arc_from_to(t, places[out], net)
    return net, Marking({places[0]:1}), Marking({places[full]:1})

def pm4py_valid(cases: list[Case]) -> dict[str,bool]:
    groups = defaultdict(list)
    for c in cases:
        groups[(tuple(c.required),tuple(c.edges))].append(c)
    answer = {}
    for (required,edges), group in groups.items():
        net,im,fm = profile_net(required,edges)
        log = EventLog()
        for c in group:
            trace = Trace(attributes={"concept:name":c.case_id})
            for e in c.events:
                if e.activity in required:
                    trace.append(PMEvent({"concept:name":e.activity}))
            log.append(trace)
        replay = token_replay.apply(log,net,im,fm, parameters={
            "show_progress_bar":False,
            "consider_remaining_in_fitness":True,
            "enable_pltr_fitness":False,
        })
        for c,r in zip(group,replay):
            answer[c.case_id] = bool(r["trace_is_fit"])
    return answer
