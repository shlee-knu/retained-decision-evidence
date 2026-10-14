"""Tests target scientific failure modes and independent-engine consistency."""
import itertools
from copy import deepcopy
import pytest
from logistics_validation.model import Case, Event, uri
from logistics_validation.constraints import SchemaChecker, indexed_issues
from logistics_validation.baselines import sql_issues, pm4py_valid
from logistics_validation.mutations import FAULTS, fault, benign

def example(profile="delivery"):
    activities=["accept","deliver"] if profile=="delivery" else ["create","invoice","receive","clear"]
    cid="example";obj=uri("object",cid)
    times=[f"2000-01-01T00:0{i}:00+00:00" for i in range(len(activities))]
    events=[Event(uri("event",f"{cid}:{i}"),obj,a,times[i]) for i,a in enumerate(activities)]
    events[-1].ref=events[0].event_id
    edges=[("accept","deliver")] if profile=="delivery" else [("create","receive"),("create","invoice"),("receive","clear"),("invoice","clear")]
    return Case(cid,"lade" if profile=="delivery" else "bpi2019","test",profile if profile=="delivery" else "3-way match, invoice before GR","fixture",events,edges,activities,{"object_id":obj})

@pytest.mark.parametrize("name",FAULTS)
def test_fault_is_effective_and_input_is_unchanged(name):
    case=example();before=case.digest();mutant=fault(case,name)
    assert mutant.digest()!=before
    assert case.digest()==before
    checker=SchemaChecker()
    assert not checker.valid(mutant) or indexed_issues(mutant)
    assert bool(indexed_issues(mutant))==bool(sql_issues([mutant])[case.case_id])

@pytest.mark.parametrize("variant",range(6))
def test_benign_variants_are_not_false_alarms(variant):
    case=example("invoice_before")
    control,name=benign(case,variant)
    assert SchemaChecker().valid(control), name
    assert not indexed_issues(control), name
    assert not sql_issues([control])[control.case_id], name
    assert pm4py_valid([control])[control.case_id], name

def test_readpoint_is_optional_for_epclist_object_event():
    checker=SchemaChecker();case=example()
    assert all("readPoint" not in e.epcis() for e in case.events)
    assert checker.valid(case)

def test_schema_does_not_claim_cross_event_semantics():
    checker=SchemaChecker();case=fault(example(),"time_inversion")
    assert checker.valid(case)
    assert indexed_issues(case)=={"time_precedence"}
    assert pm4py_valid([case])[case.case_id]

def test_unordered_partial_profile_independent_engines_agree():
    case=example("invoice_before")
    for i,sequence in enumerate(itertools.permutations(case.events)):
        trial=deepcopy(case);trial.case_id=f"perm{i}";trial.events=list(deepcopy(sequence))
        # Equal timestamps isolate control flow from clock constraints.
        for e in trial.events:e.time="2000-01-01T00:00:00Z"
        assert indexed_issues(trial)==sql_issues([trial])[trial.case_id]
        assert (not indexed_issues(trial))==pm4py_valid([trial])[trial.case_id]

def test_equal_times_are_allowed_but_before_position_is_required():
    case=example()
    for e in case.events:e.time="2000-01-01T00:00:00Z"
    assert not indexed_issues(case)
    case.events.reverse()
    assert "precedence" in indexed_issues(case)
