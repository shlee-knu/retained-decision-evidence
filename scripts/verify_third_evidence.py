"""Independently reconcile saved receipt generation ledgers and paired timings.

This does not run a new benchmark. The finite receipt adapter audit has a
separate verifier. Candidate migration code is not used to predict its ledgers.
"""
from collections import Counter
import gzip
import hashlib
import json
import random
import statistics

from verify_expanded import ROOT, split, table_rows
from stress_acquisition import raw_time
from verify_third_receipt_evidence import verify as verify_receipt_audit

BASE = 'results/third/sqlite_migration/'
ACTIVITIES = ('create', 'receive', 'invoice', 'clear')
PROFILES = ('3-way match, invoice after GR', '3-way match, invoice before GR', '2-way match', 'Consignment')
METHODS = ('generic_receipt', 'ordinary_cache_recompute', 'fresh_guard_joined')
FIELDS = ('cases', 'receipt_queries', 'source_queries', 'total_queries', 'receipt_rows', 'source_rows',
          'receipt_bytes', 'new_source_bytes', 'new_profile_values', 'new_time_values',
          'receipt_decodes', 'source_decodes', 'retained_profile_values', 'retained_time_values',
          'output_profile_values', 'output_time_values', 'output_bytes', 'accepted', 'rejected')
CATALOG_IDS = {'identity':'baseline', 'strict':'strict_consignment', 'equivalent':'edge_p0_a0_b3', 'label_change':'required_p3_a2'}
DISPLAY = {'identity':'Identity', 'strict':'Strict', 'equivalent':'Equivalent', 'label_change':'Label change'}
METHOD_DISPLAY = {'generic_receipt':'Generic receipt', 'ordinary_cache_recompute':'Ordinary cache', 'fresh_guard_joined':'Fresh guarded join'}


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def gz(a, path):
    a.digest(path)
    with gzip.open(ROOT/path, 'rt') as stream:
        return json.load(stream)


def distribution(values):
    q = statistics.quantiles(values, n=4, method='inclusive')
    return dict(n=len(values), min=min(values), q1=q[0], median=statistics.median(values), q3=q[2], max=max(values))


def compare_distribution(a, observed, values, label):
    wanted = distribution(values)
    for key, value in wanted.items():
        a.same(observed[key], value, label+'/'+key, 'third-timing')


def state_key(raw):
    order = tuple(dict.fromkeys(ACTIVITIES.index(x) for x in raw['activities']))
    clocks = [raw_time(raw['first_times'][ACTIVITIES[i]]) for i in order]
    ranks = {v:i for i,v in enumerate(sorted(set(clocks)))}
    return order, tuple(ranks[v] for v in clocks), PROFILES.index(raw['profile'])


def reconstruct(a, config, finite, native):
    # Stored compiled truth is checked independently by the preceding exact
    # audit verifier. Here its observation sufficiency predicts each request
    # without importing or executing the candidate SQLite implementation.
    states = {(tuple(s[0]),tuple(s[1]),s[2]):i for i,s in enumerate(finite['states'])}
    old_records = {}
    a.digest(config['receipt_source'])
    with gzip.open(ROOT/config['receipt_source'], 'rt') as stream:
        for line in stream:
            receipt = json.loads(line)['receipt']
            a.check(receipt['receipt_id'] not in old_records, 'unique saved receipt case', 'third-ledger')
            old_records[receipt['receipt_id']] = receipt
    n = len(old_records)
    a.same(n, 50931, 'migration receipt cohort', 'third-ledger')
    expected = {(t,m):Counter({k:0 for k in FIELDS}) for t in CATALOG_IDS for m in METHODS}
    output_hashes = {key:[] for key in expected}
    statuses = {t:Counter() for t in CATALOG_IDS}
    truths = {t:[] for t in CATALOG_IDS}
    new_hashes = {t:hashlib.sha256(encode(a.load(path))).hexdigest() for t,path in config['targets'].items()}
    receipt_payload = 0
    a.digest(config['compact_source'])
    cases = 0
    with gzip.open(ROOT/config['compact_source'], 'rt') as stream:
        for line in stream:
            raw = json.loads(line)
            if split(raw['document']) != 'test':
                continue
            cases += 1
            original = old_records[raw['case_id']]
            a.same(original['activities'], raw['activities'], 'receipt/base activities', 'third-ledger')
            for name,value in original['observed'].items():
                a.same(value, raw[name], 'retained value/source literal', 'third-ledger')
            old_mask = int('profile' in original['observed']) + 2*int('first_times' in original['observed'])
            index = states[state_key(raw)]
            rbytes = len(encode(original)); receipt_payload += rbytes
            pbytes = len(encode({'profile':raw['profile']}))
            tbytes = len(encode({'first_times':raw['first_times']}))
            for target,catalog_id in CATALOG_IDS.items():
                saved = finite['catalogs'][catalog_id]
                truth = bool(saved['labels'][index]); truths[target].append(truth)
                sufficient = saved['sufficient'][index]
                initial = ('insufficient' if not sufficient & (1<<old_mask)
                           else 'safe' if truth == original['verdict'] else 'stale_verdict')
                statuses[target][initial] += 1
                for method in METHODS:
                    ledger = expected[target,method]
                    uses_receipt = method == 'generic_receipt' or (method == 'ordinary_cache_recompute' and not sufficient & 1)
                    retained = old_mask if uses_receipt else 0
                    mask = retained
                    if method == 'fresh_guard_joined':
                        if not sufficient & 1:
                            mask = 3
                    else:
                        while not sufficient & (1<<mask):
                            mask |= 1 if not mask & 1 else 2
                    added = mask & ~retained
                    pq,tq = int(bool(added&1)),int(bool(added&2))
                    source_q = int(bool(added)) if method == 'fresh_guard_joined' else pq+tq
                    ledger.update(cases=1, receipt_queries=int(uses_receipt), receipt_rows=int(uses_receipt),
                                  receipt_bytes=rbytes*uses_receipt, receipt_decodes=int(uses_receipt),
                                  retained_profile_values=int(bool(retained&1)), retained_time_values=int(bool(retained&2)),
                                  source_queries=source_q, source_rows=source_q, new_profile_values=pq,new_time_values=tq,
                                  new_source_bytes=pbytes*pq+tbytes*tq,source_decodes=pq+tq,
                                  output_profile_values=int(bool(mask&1)),output_time_values=int(bool(mask&2)),
                                  accepted=int(truth),rejected=int(not truth))
                    replacement = dict(schema_version=1, receipt_id=raw['case_id'], snapshot_sha256=config['compact_source_sha256'],
                                       catalog_sha256=new_hashes[target],domain_version='cartesian:v1',activities=raw['activities'],
                                       observed={name:raw[name] for bit,name in ((1,'profile'),(2,'first_times')) if mask&bit},verdict=truth)
                    blob = encode(replacement)
                    ledger['output_bytes'] += len(blob)
                    output_hashes[target,method].append(hashlib.sha256(blob).digest())
    a.same(cases,n,'complete migration source selection','third-ledger')
    a.check(truths==native['truth_vectors'],'all four complete native target vectors','third-ledger')
    a.same(len(native['rows']),12,'complete native migration matrix','third-ledger')
    for row in native['rows']:
        key = row['target'],row['method']; wanted=expected[key]
        wanted['total_queries'] = wanted['receipt_queries']+wanted['source_queries']
        for field in FIELDS:
            a.same(row[field],wanted[field],str(key)+'/'+field,'third-ledger')
        a.same(row['generic_initial_statuses'], dict(statuses[row['target']]) if row['method']=='generic_receipt' else {}, str(key)+' statuses','third-ledger')
        digest = hashlib.sha256(b''.join(sorted(output_hashes[key]))).hexdigest()
        a.same(row['replacement_multiset_sha256'],digest,str(key)+' independent serialized replacements','third-ledger')
        a.same(row['actual_source_selects'],wanted['source_queries'],str(key)+' actual source SQL trace','third-ledger')
        a.same(row['actual_receipt_selects'],wanted['receipt_queries'],str(key)+' actual receipt SQL trace','third-ledger')
        for field in ('oracle_disagreements','insufficient_output_receipts'):
            a.same(row[field],0,str(key)+'/'+field,'third-ledger')
    return expected,statuses,receipt_payload


def migration(a):
    config=a.load('configs/third_migration_protocol.json')
    prep=a.load(BASE+'preparation.json');native=a.load(BASE+'native_verification.json');bench=a.load(BASE+'benchmark.json')
    for result,label in ((prep,'preparation'),(native,'native verification'),(bench,'benchmark')):
        a.same(result['status'],'passed','migration '+label,'third-ledger')
    a.same(prep['config'],config,'frozen migration config','third-ledger')
    a.pin('configs/third_migration_protocol.json',prep['protocol_sha256'])
    a.same(prep['source_and_implementation_sha256'],bench['source_and_implementation_sha256'],'same prepared/measured implementation','third-ledger')
    for name,wanted in prep['source_and_implementation_sha256'].items():a.pin(name,wanted)
    for stem in ('preparation','native_verification','rounds'):
        a.pin(BASE+stem+('.jsonl' if stem=='rounds' else '.json'),bench[stem+'_sha256'])
    for key in ('compact_source','receipt_source'):a.pin(config[key],config[key+'_sha256'])
    a.pin('results/strong/catalog_audit/finite_tables.json.gz',native['finite_truth_source_sha256'])
    presence={}
    for path,expected_hash in ((ROOT/config['source_database'],prep['source_database_sha256']),
                               (ROOT/BASE/'receipts.sqlite3',prep['receipt_database_sha256'])):
        presence[str(path.relative_to(ROOT))]=path.is_file()
        if path.is_file():a.pin(path.relative_to(ROOT),expected_hash)
    finite=gz(a,'results/strong/catalog_audit/finite_tables.json.gz')
    expected,statuses,payload=reconstruct(a,config,finite,native)
    a.same(prep['receipt_json_payload_bytes'],payload,'entire receipt store JSON payload','third-ledger')
    for name,value in (('method_case_comparisons',50931*12),('output_receipt_sufficiency_checks',50931*12),('independent_full_input_labels',50931*4),('oracle_disagreements',0)):
        a.same(native[name],value,'native '+name,'third-ledger')
    rows=[json.loads(line) for line in a.read(BASE+'rounds.jsonl').splitlines()]
    a.same(len(rows),108,'complete scheduled migration runs','third-timing')
    jobs=[(r['target'],r['method']) for r in native['rows']]
    lookup={(r['round'],r['target'],r['method']):r for r in rows}
    a.same(len(lookup),108,'unique migration runs','third-timing')
    rng=random.Random(config['timing']['random_seed']);order=list(range(50931))
    for repetition in range(-2,7):
        rng.shuffle(order);schedule=list(jobs);rng.shuffle(schedule)
        for position,key in enumerate(schedule):
            r=lookup[repetition,*key]
            a.same(r['execution_position'],position,'fixed-seed job schedule','third-timing')
            a.same(r['phase'],'warmup' if repetition<0 else 'measured','warmup/measurement separation','third-timing')
            for field in FIELDS:a.same(r[field],expected[key][field],'timed '+str(key)+'/'+field,'third-timing')
            ref=next(x for x in native['rows'] if (x['target'],x['method'])==key)
            for field in ('generic_initial_statuses','replacement_multiset_sha256'):
                a.same(r[field],ref[field],'timed outputs '+str(key),'third-timing')
            a.same(r['oracle_disagreements'],0,'timed reference disagreement','third-timing')
            for timer in ('cpu','wall'):
                a.same(r['batch_'+timer+'_ns'],r['setup_'+timer+'_ns']+r['migration_'+timer+'_ns'],'setup included in migration batch','third-timing')
                a.check(r['setup_'+timer+'_ns']>=0 and r['migration_'+timer+'_ns']>0,'positive timing intervals','third-timing')
    for summary in bench['results']:
        t,m=summary['target'],summary['method'];selected=[lookup[i,t,m] for i in range(7)]
        for field in FIELDS:a.same(summary[field],expected[t,m][field],'benchmark ledger/'+field,'third-timing')
        for scope in ('setup','migration','batch'):
            for timer in ('cpu','wall'):
                field=scope+'_'+timer+'_ns'
                compare_distribution(a,summary[field],[r[field] for r in selected],str((t,m,field)))
        for other in ('ordinary_cache_recompute','fresh_guard_joined'):
            for timer in ('cpu','wall'):
                field='paired_batch_'+timer+'_ns_vs_'+other
                compare_distribution(a,summary[field],[lookup[i,t,m]['batch_'+timer+'_ns']-lookup[i,t,other]['batch_'+timer+'_ns'] for i in range(7)],str((t,m,field)))
    for field,wanted in (('cases',50931),('warmup_rounds',2),('measured_rounds',7),('full_workload_runs',108),('unchanged_source_and_receipt_databases',True)):
        a.same(bench[field],wanted,'benchmark '+field,'third-timing')
    a.facts['receipt_sqlite_migration']=dict(cases=50931,targets=4,methods=3,measured_runs=84,warmup_runs=24,
        native_method_case_checks=611172,databases_present_and_rehashed=presence,
        generic_initial_statuses={k:dict(v) for k,v in statuses.items()},
        scope='Reconstructed all native ledgers and serialized-output digests from pinned source literals and independently checked finite sufficient sets; recomputed all saved paired timing summaries. No new timing or operational deployment.')
    return bench,native


def manuscript_tables(a, bench, native):
    main=a.read('paper/manuscript_ieee_access_applied.md')
    supp=a.read('paper/supplement_ieee_access_applied.md')
    entries={(r['target'],r['method']):r for r in bench['results']}
    def rendered(row, field, divisor):
        d=row[field]
        return f"{d['median']/divisor:.2f} [{d['q1']/divisor:.2f}, {d['q3']/divisor:.2f}]"
    wanted_main=[]
    for target,label in DISPLAY.items():
        wanted_main.append([label]+[rendered(entries[target,m],'batch_cpu_ns',50931*1000) for m in METHODS])
    a.same(table_rows(main,8),wanted_main,'main Table 8 measured batch CPU','paper-tables')
    for number,fields in (('S17',('receipt_queries','source_queries','total_queries','new_profile_values','new_time_values')),
                          ('S18',('receipt_bytes','new_source_bytes','output_bytes'))):
        wanted=[[DISPLAY[r['target']],METHOD_DISPLAY[r['method']],*[f"{r[k]:,}" for k in fields]] for r in native['rows']]
        a.same(table_rows(supp,number),wanted,'supplement Table '+number,'paper-tables')
    wanted=[]
    for target,label in DISPLAY.items():
        for method in METHODS:
            r=entries[target,method]
            wanted.append([label,METHOD_DISPLAY[method],rendered(r,'setup_cpu_ns',1e6),
                           rendered(r,'batch_cpu_ns',50931*1000),rendered(r,'batch_wall_ns',50931*1000)])
    a.same(table_rows(supp,'S19'),wanted,'supplement Table S19 full timing distributions','paper-tables')
    for method in ('generic_receipt','ordinary_cache_recompute'):
        difference=entries['strict',method]['paired_batch_cpu_ns_vs_fresh_guard_joined']['median']/50931/1000
        for text,label in ((main,'main'),(supp,'supplement')):
            a.check(f'{difference:.2f} µs/case' in text,label+' strict paired CPU difference '+method,'paper-tables')
    for number in ('359,968','104,020','2,557','84,420','75,086','41,597'):
        a.check(number in main,'main verified receipt finding '+number,'paper-tables')
    paper=a.facts.setdefault('paper',{})
    paper.setdefault('main_tables_checked',[]).append(8)
    paper.setdefault('supplementary_tables_checked',[]).extend(['S17','S18','S19'])


def verify(a):
    verify_receipt_audit(a)
    bench,native=migration(a)
    manuscript_tables(a,bench,native)
    return bench,native
