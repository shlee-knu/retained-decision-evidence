"""Replay certified metadata access on the complete public procurement log.

Costs are actual UTF8 bytes of the declared JSON field-block encoding and
logical lookups in replay, not measured network/disk/operational savings.
Learned acquisition order affects cost only; the certificate decides the label.
"""
from collections import Counter,defaultdict
from pathlib import Path
from datetime import datetime,timezone
import csv,gzip,hashlib,json,sys,time
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parent))
from audit_representations import part
from logistics_validation.acquisition import acquire, structural_order
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'results/v03'
VARIANTS={'permissive':{},'strict_consignment':{'Consignment':('invoice','clear')}}
POLICIES=['always_both','profile_first','time_first']
REPORT_POLICIES=POLICIES+['structural_order']

def bytes_for(block,value):return len(json.dumps({block:value},ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8'))
def aggregate(indices,masks,pbytes,tbytes,wrong):
    ids=np.asarray(indices,dtype=int);m=np.asarray(masks,dtype=np.uint8)[ids];pb=np.asarray(pbytes)[ids];tb=np.asarray(tbytes)[ids]
    return {'n':len(ids),'profile_queries':int(np.sum(m&1>0)),'time_queries':int(np.sum(m&2>0)),
      'no_metadata_cases':int(np.sum(m==0)),'one_block_cases':int(np.sum((m==1)|(m==2))),
      'two_block_cases':int(np.sum(m==3)),
      'payload_bytes':int(np.sum(pb*(m&1>0)+tb*(m&2>0))),
      'disagreements':int(np.asarray(wrong)[ids].sum())}

def main():
    started=time.perf_counter();OUT.mkdir(exist_ok=True)
    source=OUT/'bpi_compact.jsonl.gz';cases=[json.loads(s) for s in gzip.open(source,'rt')]
    profile_bytes=[bytes_for('profile',c['profile']) for c in cases]
    time_bytes=[bytes_for('first_times',c['first_times']) for c in cases]
    sig=[tuple(dict.fromkeys(c['activities'])) for c in cases]
    native=[];holdout=[];order_maps={};all_masks={};all_wrong={};failure_examples=[]
    for variant,forbidden in VARIANTS.items():
        masks={p:[] for p in POLICIES};wrong={p:[] for p in POLICIES}
        for i,c in enumerate(cases):
            if variant=='strict_consignment' and c['profile']=='Consignment':
                assert not set(c['activities'])&{'invoice','clear'},'native policylabels would change; report explicitly instead'
            expected='reject' if c['violation'] else 'accept'
            for policy in POLICIES:
                r=acquire(c,policy,forbidden=forbidden)
                mask=int(r['profile_queries'])+2*int(r['time_queries'])
                mismatch=r['decision']!=expected or r['status']!='determined'
                masks[policy].append(mask);wrong[policy].append(mismatch)
                if mismatch and len(failure_examples)<10:failure_examples.append({'case_id':c['case_id'],'variant':variant,'policy':policy,'expected':expected,'actual':r})
            if (i+1)%50000==0:print(f'{variant}: {i+1} cases',flush=True)
        structural_choices=[structural_order(c['activities'],forbidden=forbidden) for c in cases]
        masks['structural_order']=[masks[p][i] for i,p in enumerate(structural_choices)]
        wrong['structural_order']=[wrong[p][i] for i,p in enumerate(structural_choices)]
        for policy in REPORT_POLICIES:
            native.append({'variant':variant,'policy':policy,**aggregate(range(len(cases)),masks[policy],profile_bytes,time_bytes,wrong[policy])})
        all_masks[variant]=masks;all_wrong[variant]=wrong
        cost={p:np.asarray(profile_bytes)*(np.asarray(masks[p])&1>0)+np.asarray(time_bytes)*(np.asarray(masks[p])&2>0) for p in REPORT_POLICIES}
        for seed in [17,29,43,71,101]:
            split=[part(c['document'],seed) for c in cases];train=[i for i,s in enumerate(split) if s=='train'];test=[i for i,s in enumerate(split) if s=='test']
            counts=defaultdict(lambda:[0,0,0])
            for i in train:
                a=counts[sig[i]];a[0]+=1;a[1]+=int(cost['profile_first'][i]);a[2]+=int(cost['time_first'][i])
            global_choice='profile_first' if cost['profile_first'][train].sum()<=cost['time_first'][train].sum() else 'time_first'
            choices={s:'profile_first' if v[1]<=v[2] else 'time_first' for s,v in counts.items()}
            picked=[choices.get(s,global_choice) for s in sig]
            learned=[all_masks[variant][p][i] for i,p in enumerate(picked)]
            learned_wrong=[all_wrong[variant][p][i] for i,p in enumerate(picked)]
            for policy in REPORT_POLICIES+['train_cost_order']:
                ms=learned if policy=='train_cost_order' else masks[policy];ws=learned_wrong if policy=='train_cost_order' else wrong[policy]
                holdout.append({'variant':variant,'seed':seed,'policy':policy,**aggregate(test,ms,profile_bytes,time_bytes,ws)})
            # Unimplementable lower comparator allowed to see both block outcomes.
            clairvoyant=np.minimum(cost['profile_first'],cost['time_first'])
            holdout.append({'variant':variant,'seed':seed,'policy':'clairvoyant_two_order_bound','n':len(test),
              'profile_queries':None,'time_queries':None,'no_metadata_cases':None,'one_block_cases':None,'two_block_cases':None,
              'payload_bytes':int(clairvoyant[test].sum()),'disagreements':None})
            if seed==17:
                order_maps[variant]={'global_fallback':global_choice,'training_documents':len({cases[i]['document'] for i in train}),
                   'test_documents':len({cases[i]['document'] for i in test}),
                   'entries':[{'first_order':s,'train_cases':v[0],'profile_first_total_bytes':v[1],'time_first_total_bytes':v[2],'choice':choices[s]} for s,v in counts.items()],
                   'test_choices':dict(Counter(picked[i] for i in test)),'unseen_test_signatures':sum(sig[i] not in choices for i in test),
                   'structural_vs_learned_test_mask_differences':sum(learned[i]!=masks['structural_order'][i] for i in test),
                   'structural_vs_learned_test_order_differences':sum(picked[i]!=structural_choices[i] for i in test)}
        print('complete',variant,flush=True)
    tracefile=OUT/'acquisition_access_traces.jsonl.gz'
    with gzip.open(tracefile,'wt') as f:
        for i,c in enumerate(cases):
            f.write(json.dumps({'case_id':c['case_id'],'document':c['document'],'violation':c['violation'],
              'profile_bytes':profile_bytes[i],'time_bytes':time_bytes[i],
              'masks':{v:{p:all_masks[v][p][i] for p in REPORT_POLICIES} for v in VARIANTS}},separators=(',',':'))+'\n')
    report={'status':'passed' if not failure_examples else 'failed','created_utc':datetime.now(timezone.utc).isoformat(),
      'n_cases':len(cases),'source_compact_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
      'code_sha256':hashlib.sha256((ROOT/'src/logistics_validation/acquisition.py').read_bytes()).hexdigest(),
      'trace_sha256':hashlib.sha256(tracefile.read_bytes()).hexdigest(),'native':native,'holdout':holdout,'seed17_order_maps':order_maps,
      'cost_definition':'Sum bytes of JSON {profile:value} and {first_times:{activity:original_RFC3339}} encoded UTF8, sortedkeys, compact separators. Counts exclude already-available ordered activity projection, shared validation overhead, transport headers, archive storage and metadata preparation.',
      'guarantee':'Conditional on declaredfinitecatalog/validclock/completeobservedprojection domain. Stop only when all admissible completions share the same contract label. No natural-error truth.',
      'strict_sensitivity':'Forbid invoice andclear underConsignment as an explicitstronger observationpolicy. Verifiedallnative case labels unchanged. This changes counterfactual completions and can change necessarymetadata.',
      'learning':'Each splitusestrain documentsonly toselectlowermeanbyte fixed orderperfirst-order signature;test labels neverchoose order. Allcertificates are independent of learnedfrequencies. Calibrationsplitunused forcostorder.',
      'structural_baseline':'No fitting: query clocks first only when every catalog profile is structurally eligible and the base certificate is ambiguous; otherwise profile first. It observes only the activity sequence and catalog. Matching learned costs mean no demonstrated learning benefit.',
      'failure_examples':failure_examples,'elapsed_seconds':time.perf_counter()-started}
    (OUT/'acquisition_results.json').write_text(json.dumps(report,indent=2))
    for name,rows in [('acquisition_native.csv',native),('acquisition_holdout.csv',holdout)]:
        with (OUT/name).open('w') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(json.dumps({'native':native,'canonical_holdout':[r for r in holdout if r['seed']==17],'status':report['status'],'elapsed_seconds':report['elapsed_seconds']},indent=2))
    if failure_examples:raise SystemExit(1)
if __name__=='__main__':main()
