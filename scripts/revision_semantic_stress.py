"""Post-review bounded differential checking with independently assigned truths.

Synthetic specification tests, not natural anomaly detection or a formal proof.
Oracle uses exhaustive position sets and assigned integer times, not core parsers.
"""
from __future__ import annotations
from itertools import product, permutations
from pathlib import Path
from collections import Counter
import copy, hashlib, json, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logistics_validation.model import Case, Event, uri, timestamp_key
from logistics_validation.constraints import indexed_issues, SchemaChecker
from logistics_validation.baselines import sql_issues
from logistics_validation.declarative_baseline import mp_declare_issues

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    'delivery': (['accept','deliver'], [('accept','deliver')]),
    'after': (['create','receive','invoice','clear'], [('create','receive'),('receive','invoice'),('invoice','clear')]),
    'before': (['create','receive','invoice','clear'], [('create','receive'),('create','invoice'),('receive','clear'),('invoice','clear')]),
    'two_way': (['create','invoice','clear'], [('create','invoice'),('invoice','clear')]),
    'consignment': (['create','receive'], [('create','receive')]),
}

def brute_truth(seq, times, required, edges):
    """Quantified specification, using known generator integers as the clock oracle."""
    issues = set()
    if not all(any(x == a for x in seq) for a in required): issues.add('missing_activity')
    for a,b in edges:
        apos = [i for i,x in enumerate(seq) if x == a]
        bpos = [i for i,x in enumerate(seq) if x == b]
        if not bpos: continue
        if not apos: issues.add('missing_predecessor'); continue
        if not all(min(apos) < j for j in bpos): issues.add('precedence')
        if times[min(apos)] > times[min(bpos)]: issues.add('time_precedence')
    return issues

def make_case(cid, seq, times, required, edges):
    obj = uri('object',cid)
    return Case(cid,'synthetic','bounded','bounded','generated',
        [Event(uri('event',cid+':'+str(i)),obj,a,t) for i,(a,t) in enumerate(zip(seq,times))],
        edges,required,{'object_id':obj})

def main():
    out=ROOT/'results/revision';out.mkdir(exist_ok=True)
    cases=[];truth={};families=Counter()
    for profile,(required,edges) in PROFILES.items():
        for n in range(5):
            for seq in product(required,repeat=n):
                for mode in ['increasing','equal','decreasing']:
                    values=list(range(n)) if mode=='increasing' else ([0]*n if mode=='equal' else list(range(n,0,-1)))
                    cid=f'stress:{len(cases)}'
                    c=make_case(cid,seq,[f'2020-01-01T00:00:{v:02d}Z' for v in values],required,edges)
                    cases.append(c);truth[cid]=brute_truth(seq,values,required,edges);families[profile+':'+mode]+=1
    # Complete longer traces with repetitions, including first/later occurrence
    # distinctions and non-monotonic clocks. This is targeted, not exhaustive.
    for profile,(required,edges) in PROFILES.items():
        for base_seq in permutations(required):
            if brute_truth(base_seq, list(range(len(base_seq))), required, edges):
                continue
            sequences=set()
            for activity in required:
                for at in range(len(base_seq)+1):
                    sequences.add(base_seq[:at]+(activity,)+base_seq[at:])
                sequences.add((activity,)+base_seq+(activity,))
                sequences.add(base_seq+(activity,activity))
            for seq in sorted(sequences):
                n=len(seq)
                for mode in ['increasing','equal','last_earlier','first_later']:
                    values=list(range(n))
                    if mode=='equal':values=[0]*n
                    if mode=='last_earlier':values[-1]=-1
                    if mode=='first_later':values[0]=n+1
                    cid=f'repeats:{len(cases)}'
                    c=make_case(cid,seq,[f'2020-01-01T00:00:{10+v:02d}Z' for v in values],required,edges)
                    cases.append(c);truth[cid]=brute_truth(seq,values,required,edges)
                    families['targeted_repeats:'+profile]+=1
    # Manually assigned temporal truths expose cases hidden by float/microsecond parsing.
    boundary=[
        ('lowercase_inversion','2020-01-01t00:00:02z','2020-01-01t00:00:01z',True),
        ('nanosecond_inversion','2020-01-01T00:00:00.000000002Z','2020-01-01T00:00:00.000000001Z',True),
        ('long_fraction_inversion','2020-01-01T00:00:00.000000000000000000000000000002Z','2020-01-01T00:00:00.000000000000000000000000000001Z',True),
        ('offset_equal','2020-01-01T09:00:00+09:00','2020-01-01T00:00:00Z',False),
        ('offset_date_boundary','2020-01-02T01:00:00+02:00','2020-01-01T23:00:00Z',False),
        ('trailing_zero_equal','1969-12-31T23:59:59.100Z','1969-12-31T23:59:59.1Z',False),
        ('fraction_prefix_order','2020-01-01T00:00:00.1Z','2020-01-01T00:00:00.100000001Z',False),
    ]
    for name,a,b,bad in boundary:
        c=make_case('boundary:'+name,['accept','deliver'],[a,b],['accept','deliver'],[('accept','deliver')])
        cases.append(c);truth[c.case_id]={'time_precedence'} if bad else set();families['timestamp_boundaries']+=1
    # Isolated structural errors, and allowed forward/self references.
    base=make_case('structure:base',['accept','deliver'],['2020-01-01T00:00:00Z','2020-01-01T00:00:01Z'],['accept','deliver'],[('accept','deliver')])
    for mode in ['duplicate','dangling','object_drift','self_ref','forward_ref','empty_ref','unknown_activity']:
        c=copy.deepcopy(base);c.case_id='structure:'+mode;expected=set()
        if mode=='duplicate':c.events[1].event_id=c.events[0].event_id;expected={'duplicate_id'}
        if mode=='dangling':c.events[1].ref=uri('event','absent');expected={'dangling_reference'}
        if mode=='object_drift':c.events[1].object_id=uri('object','other');expected={'object_identity'}
        if mode=='self_ref':c.events[0].ref=c.events[0].event_id
        if mode=='forward_ref':c.events[0].ref=c.events[1].event_id
        if mode=='empty_ref':c.events[1].ref=''
        if mode=='unknown_activity':c.events.append(Event(uri('event','unknown'),c.attributes['object_id'],'other','2020-01-01T00:00:00Z'))
        cases.append(c);truth[c.case_id]=expected;families['structural_boundaries']+=1
    sql=sql_issues(cases);dec=mp_declare_issues(cases,'full');schema=SchemaChecker();failures=[]
    for c in cases:
        actual=indexed_issues(c);expected=truth[c.case_id]
        if actual!=expected or sql[c.case_id]!=expected or bool(dec[c.case_id])!=bool(expected) or not schema.valid(c):
            failures.append(dict(case_id=c.case_id,expected=sorted(expected),indexed=sorted(actual),sql=sorted(sql[c.case_id]),declare=sorted(dec[c.case_id]),schema=schema.valid(c)))
    fixture=out/'semantic_stress_fixtures.jsonl'
    with fixture.open('w') as f:
        for c in cases:f.write(json.dumps({'case':c.to_dict(),'expected_rules':sorted(truth[c.case_id])})+'\n')
    # Paired inputs: information loss is demonstrated without calling it a new theorem.
    pairs=[]
    a=copy.deepcopy(base);b=copy.deepcopy(a);b.events[1].time='2019-12-31T23:59:59Z'
    pairs.append(('time omitted',a,b,lambda c:[e.activity for e in c.events]))
    a=copy.deepcopy(base);b=copy.deepcopy(a);b.events[1].ref=uri('event','missing')
    pairs.append(('references omitted',a,b,lambda c:[(e.activity,e.time) for e in c.events]))
    a=copy.deepcopy(base);b=copy.deepcopy(a);b.events[1].event_id=b.events[0].event_id
    pairs.append(('event keys omitted',a,b,lambda c:[(e.activity,e.time) for e in c.events]))
    a=make_case('profilepair',['create','invoice','receive','clear'],[f'2020-01-01T00:00:0{i}Z' for i in range(4)],*PROFILES['before'])
    a.profile='3-way match, invoice before GR'
    b=copy.deepcopy(a);b.required,b.edges=PROFILES['after'];b.profile='3-way match, invoice after GR'
    pairs.append(('profile omitted',a,b,lambda c:[e.__dict__ for e in c.events]))
    paired=[]
    for name,a,b,projection in pairs:
        assert projection(a)==projection(b)
        assert not indexed_issues(a) and indexed_issues(b)
        paired.append({'omitted_information':name,'same_projection':True,'full_contract_violation_flags':[False,True],
                       'schema_accepts_both':schema.valid(a) and schema.valid(b)})
    report={'design':'Post-review synthetic bounded specification checks; no natural-error labels or independent field validation',
      'cases':len(cases),'families':dict(families),'sequence_bound':'all sequences length 0..4 over each of five profile alphabets, three assigned clock orders; targeted complete repetitions up to length 6 with four clock assignments',
      'oracle':'Independent quantified position specification and generator-assigned integer timestamp truth; boundary truth manually specified before checking',
      'matched_engines':['indexed exact text keys','SQLite exact text keys','Declare4Py 2.2.0 independent exact Decimal parser and rank projection'],
      'failures':failures,'failure_count':len(failures),'schema_accepted_boundary_fixtures':len(boundary),
      'projection_pairs':paired,'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest()}
    (out/'semantic_stress.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='families'},indent=2))
    if failures:raise SystemExit('Differential failure; inspect report')

if __name__=='__main__':main()
