"""Contract-relative representation inconsistency and grouped holdout audit.

Classical inconsistency/rough-set statistics applied to a declared milestone
contract. No natural-error labels, no new theorem, no population Bayes bound.
"""
from __future__ import annotations
from collections import Counter,defaultdict
from pathlib import Path
import csv,gzip,hashlib,json,sys,time
from statistics import mean
sys.path.insert(0,str(Path(__file__).resolve().parent))
from audit_policy_sensitivity import exact_time
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/v03'
REPS=['none','activity_set','activity_multiset','first_order','activity_sequence','full_activity_sequence',
      'profile_set','profile_multiset','profile_first_order','profile_sequence','flags_first_order','first_order_time_rank','profile_first_order_time_rank']
HOLDOUT_REPS=['activity_set','first_order','activity_sequence','full_activity_sequence','profile_set','profile_first_order']

def compact(raw):
    seq=tuple(x['activity'] for x in raw['milestones']);first={}
    for e in raw['milestones']:first.setdefault(e['activity'],e['time'])
    return {'case_id':raw['case_id'],'document':raw['company']+'|'+raw['purchasing_document'],
      'company':raw['company'],'profile':raw['profile'],'activities':seq,'first_times':first,
      'full_activities':tuple(x['activity'] for x in raw['events']),
      'flags':tuple(raw['flags'].get(x) for x in ['Item Type','GR-Based Inv. Verif.','Goods Receipt']),
      'violation':not raw['policies']['first_position_and_time'],'source_trace':raw['source_trace']}

def signatures(c):
    seq=c['activities'];first=tuple(dict.fromkeys(seq));bag=tuple(sorted(Counter(seq).items()));aset=tuple(sorted(set(seq)))
    stamps=[exact_time(c['first_times'][a]) for a in first]
    assert all(x is not None for x in stamps)
    levels={v:i for i,v in enumerate(sorted(set(stamps)))};rank=tuple(levels[t] for t in stamps)
    p=c['profile']
    return {'none':(), 'activity_set':aset,'activity_multiset':bag,'first_order':first,'activity_sequence':seq,
      'full_activity_sequence':c['full_activities'],'profile_set':(p,aset),'profile_multiset':(p,bag),
      'profile_first_order':(p,first),'profile_sequence':(p,seq),'flags_first_order':(c['flags'],first),
      'first_order_time_rank':(first,rank),'profile_first_order_time_rank':(p,first,rank)}

def part(document,seed):
    v=int.from_bytes(hashlib.sha256(f'projection-audit-v03:{seed}:{document}'.encode()).digest()[:8],'big')%100
    return 'train' if v<60 else ('calibration' if v<80 else 'test')

def metrics(truth,prediction):
    covered=[(a,b) for a,b in zip(truth,prediction) if b is not None]
    tp=sum(a and b for a,b in covered);tn=sum(not a and not b for a,b in covered)
    fp=sum(not a and b for a,b in covered);fn=sum(a and not b for a,b in covered)
    return {'n':len(truth),'covered':len(covered),'abstained':len(truth)-len(covered),'coverage':len(covered)/len(truth) if truth else None,
      'disagreements':fp+fn,'error_on_covered':(fp+fn)/len(covered) if covered else None,
      'tp':tp,'tn':tn,'fp':fp,'fn':fn}

def main():
    started=time.perf_counter();OUT.mkdir(exist_ok=True)
    source=OUT/'bpi_features.jsonl.gz';groups={k:defaultdict(lambda:[0,0]) for k in REPS};examples={k:defaultdict(dict) for k in REPS}
    cases=[];keys=[];profiles=Counter();payload_sum=Counter()
    pool={} # Intern repeated canonical signatures; do not retain raw42-event dictionaries.
    compact_path=OUT/'bpi_compact.jsonl.gz'
    with gzip.open(source,'rt') as f,gzip.open(compact_path,'wt') as dest:
        for line in f:
            c=compact(json.loads(line));sigs=signatures(c);y=int(c['violation']);profiles[c['profile']]+=1
            for name,key in sigs.items():
                groups[name][key][y]+=1
                if y not in examples[name][key]:examples[name][key][y]={'case_id':c['case_id'],'source_trace':c['source_trace'],'profile':c['profile']}
                payload_sum[name]+=len(json.dumps(key,ensure_ascii=False,separators=(',',':')).encode())
            ckeys={}
            for name in HOLDOUT_REPS:
                key=sigs[name];ckeys[name]=pool.setdefault((name,key),key)
            cases.append(c);keys.append(ckeys)
            dest.write(json.dumps(c,separators=(',',':'))+'\n')
    n=len(cases);summary=[];witness={}
    for name,g in groups.items():
        mixed=[(key,v) for key,v in g.items() if min(v)>0]
        errors=sum(min(v) for v in g.values());ambig=sum(sum(v) for _,v in mixed)
        row={'representation':name,'cases':n,'equivalence_classes':len(g),'mixed_classes':len(mixed),
          'minimum_empirical_disagreements':errors,'empirical_inconsistency':errors/n,
          'cases_in_mixed_classes':ambig,'mixed_case_fraction':ambig/n,
          'singleton_cases':sum(sum(v) for v in g.values() if sum(v)==1),
          'serialized_signature_bytes':payload_sum[name],'mean_signature_bytes':payload_sum[name]/n}
        summary.append(row)
        witness[name]=[{'signature':key,'accepted':v[0],'rejected':v[1],'examples':examples[name][key]} for key,v in sorted(mixed,key=lambda kv:min(kv[1]),reverse=True)[:10]]
    # Refinement checks: extra information cannot increase this in-file minimum.
    byname={r['representation']:r for r in summary}
    refinements=[('activity_set','activity_multiset'),('activity_multiset','activity_sequence'),('first_order','activity_sequence'),
      ('activity_sequence','profile_sequence'),('activity_set','profile_set'),('first_order','profile_first_order'),
      ('profile_set','profile_first_order'),('profile_first_order','profile_sequence'),('profile_first_order','profile_first_order_time_rank')]
    for coarse,fine in refinements:assert byname[fine]['minimum_empirical_disagreements']<=byname[coarse]['minimum_empirical_disagreements']
    holdouts=[];split_reports=[]
    for seed in [17,29,43,71,101]:
        split=[part(c['document'],seed) for c in cases];ix={p:[i for i,v in enumerate(split) if v==p] for p in ['train','calibration','test']}
        docs={p:{cases[i]['document'] for i in ids} for p,ids in ix.items()}
        assert not docs['train']&docs['test'] and not docs['train']&docs['calibration'] and not docs['test']&docs['calibration']
        split_reports.append({'seed':seed,'case_counts':{p:len(v) for p,v in ix.items()},'document_counts':{p:len(v) for p,v in docs.items()},
          'profile_counts':{p:dict(Counter(cases[i]['profile'] for i in ids)) for p,ids in ix.items()},'document_overlap':0})
        for rep in HOLDOUT_REPS:
            train=defaultdict(lambda:[0,0])
            for i in ix['train']:train[keys[i][rep]][int(cases[i]['violation'])]+=1
            global_default=sum(cases[i]['violation'] for i in ix['train'])>len(ix['train'])/2
            def predict(i,mode,k=1):
                counts=train.get(keys[i][rep]);support=sum(counts) if counts else 0
                if mode=='majority':return counts[1]>counts[0] if support else global_default
                if support<k or min(counts)>0:return None
                return bool(counts[1])
            # Calibration chooses only minimum support, never signatures or rules.
            grid=[]
            for k in [1,5,10,20,50,100]:
                mm=metrics([cases[i]['violation'] for i in ix['calibration']],[predict(i,'pure',k) for i in ix['calibration']])
                grid.append((k,mm))
            eligible=[(k,m) for k,m in grid if m['covered'] and m['error_on_covered']<=.005]
            chosen=max(eligible,key=lambda km:(km[1]['coverage'],-km[0]))[0] if eligible else None
            truth=[cases[i]['violation'] for i in ix['test']]
            for mode in ['majority','pure','calibrated_pure']:
                preds=[predict(i,mode,chosen or 1) if chosen or mode!='calibrated_pure' else None for i in ix['test']]
                row={'seed':seed,'representation':rep,'mode':mode,'minimum_support':chosen if mode=='calibrated_pure' else (1 if mode=='pure' else None),
                  'unseen_test_signatures':sum(keys[i][rep] not in train for i in ix['test']),**metrics(truth,preds)}
                holdouts.append(row)
    result={'status':'completed exploratory representation audit','label_semantics':'violation of the declared source-inspired first-milestone observation contract; not natural-error truth',
      'n_cases':n,'n_documents':len({c['document'] for c in cases}),'profiles':dict(profiles),
      'source_feature_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compact_sha256':hashlib.sha256(compact_path.read_bytes()).hexdigest(),
      'classical_measure':'sum over signature classes min(accepted,rejected)/N; empirical inconsistency on this acquired finite file, not a population Bayes risk estimate',
      'representations':summary,'refinement_checks':refinements,'witnesses':witness,'holdout':holdouts,'splits':split_reports,
      'holdout_protocol':'purchase-document hash60/20/20 split within acquired organizations; salts17,29,43,71,101 are sensitivity repeats, not independent datasets; minimumsupport calibrated for observed0.5% selective error, not guaranteedriskcontrol',
      'forbidden_features':'No case IDs, purchase-document IDs, vendor IDs or absolute timestamps enter predictive signatures. Document IDs only define grouping; truth labels only train/calibrate empirical baselines.',
      'elapsed_seconds':time.perf_counter()-started}
    (OUT/'representation_audit.json').write_text(json.dumps(result,indent=2,ensure_ascii=False))
    for name,rows in [('representation_summary.csv',summary),('representation_holdout.csv',holdouts)]:
        with (OUT/name).open('w') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print(json.dumps({'cases':n,'representations':summary,'elapsed_seconds':result['elapsed_seconds']},indent=2))

if __name__=='__main__':main()
