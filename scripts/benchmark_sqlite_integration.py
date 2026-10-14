#!/usr/bin/env python3
"""Fair actual SQLite integration, with joined/full/guard/selective baselines.

Run --stage prepare for database construction and independent correctness first.
Run --stage benchmark only in the agreed quiet timing slot. Existing evidence,
engines and source derivatives are read only. No artificial latency is added.
"""
from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import gc
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import resource
import sqlite3
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import benchmark_acquisition_cost as component
from stress_acquisition import expected_violation

SOURCE = ROOT / "results/v03/bpi_compact.jsonl.gz"
OUT = ROOT / "results/strong/sqlite_integration"
LAYOUTS = ("same_row", "normalized")
VARIANTS = ("permissive", "strict_consignment")
METHODS = ("joined_full", "separate_full", "guard_joined", "hand_selective", "generic_selective")
FROZEN = {
    "results/v03/bpi_compact.jsonl.gz": "3fdfe926a29d35c87a2652447df420bb5c726ab2c996f6317c830d75cc4a1b3b",
    "src/logistics_validation/acquisition.py": "bff6c408496d747523c70029066cd82a600b7e5efa2da27d7534c66684cc4fd7",
    "scripts/benchmark_acquisition_cost.py": "f9832c4bc221401d0629198a7d7b05ac0214057a2a187ef858a6fe54263ed13c",
    "scripts/stress_acquisition.py": "24c02806e711fecfc5d353fd5e9ab180387d3516a3fa30d917e4073d1b7e3e15",
    "results/v03/acquisition_access_traces.jsonl.gz": "0060fe4c8015fa6d7c49da8661acaf073bb28ef6f0dcd1fc9ca4f6b88fa336b6",
}
SQL = {
    "same_row": {
        "profile": "SELECT profile_blob FROM metadata WHERE case_id = ?",
        "first_times": "SELECT time_blob FROM metadata WHERE case_id = ?",
        "both": "SELECT profile_blob, time_blob FROM metadata WHERE case_id = ?",
    },
    "normalized": {
        "profile": "SELECT payload FROM profiles WHERE case_id = ?",
        "first_times": "SELECT payload FROM timestamps WHERE case_id = ?",
        "both": "SELECT p.payload, t.payload FROM profiles AS p JOIN timestamps AS t ON p.case_id = t.case_id WHERE p.case_id = ?",
    },
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def code_hashes():
    names = [*FROZEN, "scripts/benchmark_sqlite_integration.py", "tests/test_sqlite_integration.py", "docs/strong_integration_design.md"]
    return {name: sha(ROOT / name) for name in names}


def check_frozen():
    for name, expected in FROZEN.items():
        if sha(ROOT / name) != expected:
            raise ValueError("Frozen source changed: " + name)


@dataclass(frozen=True, slots=True)
class BaseCase:
    case_id: str
    activities: tuple[str, ...]


def row_digest(case_id, profile_blob, time_blob):
    h = hashlib.sha256()
    for value in (case_id.encode(), profile_blob, time_blob):
        h.update(len(value).to_bytes(8, "big"))
        h.update(value)
    return h.digest()


def aggregate_digest(digests):
    return hashlib.sha256(b"".join(sorted(digests))).hexdigest()


def create_writer(path, layout):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA page_size = 4096")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA cache_size = -131072")
    if layout == "same_row":
        conn.execute("CREATE TABLE metadata (case_id TEXT PRIMARY KEY, profile_blob BLOB NOT NULL, time_blob BLOB NOT NULL) WITHOUT ROWID")
    else:
        conn.execute("CREATE TABLE profiles (case_id TEXT PRIMARY KEY, payload BLOB NOT NULL) WITHOUT ROWID")
        conn.execute("CREATE TABLE timestamps (case_id TEXT PRIMARY KEY, payload BLOB NOT NULL) WITHOUT ROWID")
    conn.commit()
    conn.execute("BEGIN")
    return conn


def insert_batch(conn, layout, rows):
    if layout == "same_row":
        conn.executemany("INSERT INTO metadata VALUES (?, ?, ?)", rows)
    else:
        conn.executemany("INSERT INTO profiles VALUES (?, ?)", [(key, p) for key, p, t in rows])
        conn.executemany("INSERT INTO timestamps VALUES (?, ?)", [(key, t) for key, p, t in rows])


class SQLiteStore:
    def __init__(self, path, layout):
        if layout not in LAYOUTS:
            raise ValueError(layout)
        self.layout = layout
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None, cached_statements=128)
        self.connection.execute("PRAGMA query_only = ON")
        self.connection.execute("PRAGMA cache_size = -131072")
        self.connection.execute("PRAGMA mmap_size = 0")

    def fetch(self, case_id, block):
        row = self.connection.execute(SQL[self.layout][block], (case_id,)).fetchone()
        if row is None:
            raise KeyError(f"Metadata row missing: {case_id}/{block}")
        return row

    def close(self):
        self.connection.close()

    def describe(self):
        settings = {name: self.connection.execute("PRAGMA " + name).fetchone()[0]
                    for name in ("page_size", "page_count", "freelist_count", "cache_size", "mmap_size", "journal_mode", "query_only")}
        plans = {block: [list(row) for row in self.connection.execute("EXPLAIN QUERY PLAN " + query, ("source-case-key",))]
                 for block, query in SQL[self.layout].items()}
        if not all(any("SEARCH" in row[3] and "PRIMARY KEY" in row[3] for row in plan) for plan in plans.values()):
            raise AssertionError("Expected indexed primary-key point lookups")
        tables = ("metadata",) if self.layout == "same_row" else ("profiles", "timestamps")
        return dict(layout=self.layout, file_bytes=self.path.stat().st_size, file_sha256=sha(self.path),
                    settings=settings, cached_statements=128, query_plans=plans, sql=SQL[self.layout],
                    rows={table: self.connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in tables})


class SQLiteAccessor(Mapping):
    """No hidden metadata values or eligibility in the base-input object."""
    __slots__ = ("store", "case_id", "activities", "_cache", "mask", "bytes_read", "decodes", "sql_queries", "rows_returned", "trace")

    def __init__(self, store, base):
        self.store = store
        self.case_id = base.case_id
        self.activities = base.activities
        self._cache = {}
        self.mask = self.bytes_read = self.decodes = self.sql_queries = self.rows_returned = 0
        self.trace = []

    def _remember(self, name, blob):
        if name in self._cache:
            raise AssertionError("Duplicate physical metadata fetch")
        self.mask |= {"profile": 1, "first_times": 2}[name]
        self.bytes_read += len(blob)
        self.decodes += 1
        self.trace.append(name)
        self._cache[name] = json.loads(blob)[name]

    def fetch_both(self):
        if self._cache:
            raise AssertionError("Joined fetch must precede any block fetch")
        row = self.store.fetch(self.case_id, "both")
        self.sql_queries += 1
        self.rows_returned += 1
        self._remember("profile", row[0])
        self._remember("first_times", row[1])

    def __getitem__(self, name):
        if name == "activities":
            return self.activities
        if name not in ("profile", "first_times"):
            raise KeyError(name)
        if name not in self._cache:
            row = self.store.fetch(self.case_id, name)
            self.sql_queries += 1
            self.rows_returned += 1
            self._remember(name, row[0])
        return self._cache[name]

    def __iter__(self):
        raise AssertionError("Bulk hidden-metadata access is forbidden")

    def __len__(self):
        return 3


def decide(access, strict, method):
    if method == "joined_full":
        access.fetch_both()
        return component.direct_full_once(access, strict)
    if method == "separate_full":
        return component.direct_full_once(access, strict)
    if method == "guard_joined":
        first = component.positions(access["activities"])
        possible = [component.eligible(first, i, strict) for i in range(len(component.PROFILES))]
        if not any(possible):
            return False
        access.fetch_both()
        index = component.PROFILES.index(access["profile"])
        return possible[index] and component.clocks_hold(access["first_times"], index, {})
    if method in ("hand_selective", "generic_selective"):
        return component.decide(access, strict, "hand_structural" if method == "hand_selective" else "certificate_structural")
    raise ValueError(method)


def execute(store, cases, order, strict, method):
    outcomes, masks = bytearray(len(order)), bytearray(len(order))
    p = t = payload = decodes = queries = rows = zero = one = two = 0
    for position, index in enumerate(order):
        access = SQLiteAccessor(store, cases[index])
        outcomes[position] = decide(access, strict, method)
        mask = masks[position] = access.mask
        p += bool(mask & 1)
        t += bool(mask & 2)
        payload += access.bytes_read
        decodes += access.decodes
        queries += access.sql_queries
        rows += access.rows_returned
        zero += mask == 0
        one += mask in (1, 2)
        two += mask == 3
    ledger = dict(cases=len(order), profile_values=p, timestamp_values=t, payload_bytes=payload,
                  json_decodes=decodes, sql_queries=queries, sql_rows_returned=rows,
                  no_metadata_cases=zero, one_block_cases=one, two_block_cases=two)
    return outcomes, masks, ledger


def load_workload():
    cases = []
    truths = {variant: bytearray() for variant in VARIANTS}
    for line in gzip.open(SOURCE, "rt"):
        case = json.loads(line)
        if component.test_document(case["document"]):
            cases.append(BaseCase(case["case_id"], tuple(case["activities"])))
            for variant in VARIANTS:
                truths[variant].append(not expected_violation(case, variant == "strict_consignment"))
    if len(cases) != 50931:
        raise AssertionError("Canonical complete held-out workload changed")
    return cases, truths


def expected_access(cases):
    indices = {c.case_id: i for i, c in enumerate(cases)}
    masks = {variant: bytearray(len(cases)) for variant in VARIANTS}
    pbytes, tbytes = [0]*len(cases), [0]*len(cases)
    for line in gzip.open(ROOT / "results/v03/acquisition_access_traces.jsonl.gz", "rt"):
        row = json.loads(line)
        if row["case_id"] not in indices:
            continue
        i = indices[row["case_id"]]
        pbytes[i], tbytes[i] = row["profile_bytes"], row["time_bytes"]
        for variant in VARIANTS:
            masks[variant][i] = row["masks"][variant]["structural_order"]
    if any(size == 0 for size in pbytes) or any(size == 0 for size in tbytes):
        raise AssertionError("Missing stored source-access accounting")
    return masks, pbytes, tbytes


def verify_storage(store, wanted, n):
    check = store.connection.execute("PRAGMA integrity_check").fetchall()
    if check != [("ok",)]:
        raise AssertionError(check)
    query = "SELECT case_id, profile_blob, time_blob FROM metadata" if store.layout == "same_row" else "SELECT p.case_id, p.payload, t.payload FROM profiles AS p JOIN timestamps AS t ON p.case_id=t.case_id"
    digests = [row_digest(*row) for row in store.connection.execute(query)]
    if len(digests) != n or aggregate_digest(digests) != wanted:
        raise AssertionError("Stored full metadata differs from source")
    info = store.describe()
    if any(count != n for count in info["rows"].values()):
        raise AssertionError("Relation cardinality mismatch")
    return info


def verify_native(stores, cases, truths):
    started = time.perf_counter()
    frozen_masks, pb, tb = expected_access(cases)
    order = list(range(len(cases)))
    result = []
    for layout, store in stores.items():
        for variant in VARIANTS:
            for method in METHODS:
                traced_selects = [0]
                def trace(statement):
                    if statement.upper().startswith("SELECT"):
                        traced_selects[0] += 1
                store.connection.set_trace_callback(trace)
                answers, masks, ledger = execute(store, cases, order, variant == "strict_consignment", method)
                store.connection.set_trace_callback(None)
                expected_masks = (bytearray([3]*len(cases)) if method in ("joined_full", "separate_full") else
                                  bytearray(3 if m else 0 for m in frozen_masks[variant]) if method == "guard_joined" else frozen_masks[variant])
                mismatches = sum(a != b for a,b in zip(answers, truths[variant]))
                if mismatches or masks != expected_masks:
                    raise AssertionError((layout, variant, method, mismatches, "verdict/mask disagreement"))
                count_p, count_t = sum(bool(m & 1) for m in masks), sum(bool(m & 2) for m in masks)
                queries = sum(m != 0 for m in masks) if method in ("joined_full", "guard_joined") else count_p+count_t
                expected_bytes = sum(p*bool(m&1) + t*bool(m&2) for p,t,m in zip(pb,tb,masks))
                if not (ledger["sql_queries"] == queries == traced_selects[0] == ledger["sql_rows_returned"] and
                        ledger["profile_values"] == count_p and ledger["timestamp_values"] == count_t and
                        ledger["json_decodes"] == count_p+count_t and ledger["payload_bytes"] == expected_bytes):
                    raise AssertionError((layout, variant, method, "SQL/JSON ledger disagreement"))
                result.append(dict(layout=layout, variant=variant, method=method, **ledger, accepted=sum(answers), rejected=len(cases)-sum(answers),
                                   oracle_disagreements=mismatches, mask_disagreements=0, actual_sql_trace_count=traced_selects[0],
                                   outcome_sha256=hashlib.sha256(answers).hexdigest(), mask_sha256=hashlib.sha256(masks).hexdigest()))
        print(json.dumps({"stage": "native-verification", "layout": layout, "elapsed_seconds": time.perf_counter()-started}), flush=True)
    return dict(status="passed", source_cases=len(cases), policy_case_checks=len(cases)*len(result), oracle_disagreements=0,
                source="Separate Fraction reference on complete source inputs; no business-error truth", rows=result,
                source_access_trace_sha256=sha(ROOT / "results/v03/acquisition_access_traces.jsonl.gz"), elapsed_seconds=time.perf_counter()-started)


def prepare(output):
    started, cpu_started = time.perf_counter(), time.process_time()
    output.mkdir(parents=True, exist_ok=True)
    paths = {layout: output/(layout+".sqlite3") for layout in LAYOUTS}
    if any(path.exists() for path in paths.values()) or (output/"rounds.jsonl").exists():
        raise FileExistsError("Preparation preserves existing DBs/evidence. Choose a fresh --output directory.")
    writers = {layout: create_writer(path, layout) for layout,path in paths.items()}
    insert_seconds = Counter()
    digests, cases = [], []
    truths = {variant: bytearray() for variant in VARIANTS}
    payload = Counter()
    batch = []
    n = 0
    oracle_seconds = 0.0
    def flush():
        for layout, conn in writers.items():
            t0 = time.perf_counter()
            insert_batch(conn, layout, batch)
            insert_seconds[layout] += time.perf_counter()-t0
        batch.clear()
    for line in gzip.open(SOURCE, "rt"):
        source = json.loads(line)
        p = component.encode_block("profile", source["profile"])
        t = component.encode_block("first_times", source["first_times"])
        batch.append((source["case_id"], p, t))
        digests.append(row_digest(source["case_id"], p, t))
        payload.update(profile_bytes=len(p), timestamp_bytes=len(t))
        n += 1
        if component.test_document(source["document"]):
            cases.append(BaseCase(source["case_id"], tuple(source["activities"])))
            t0 = time.perf_counter()
            for variant in VARIANTS:
                truths[variant].append(not expected_violation(source, variant == "strict_consignment"))
            oracle_seconds += time.perf_counter()-t0
        if len(batch) == 2000:
            flush()
    if batch:
        flush()
    for layout, conn in writers.items():
        t0 = time.perf_counter()
        conn.commit()
        conn.execute("ANALYZE")
        conn.commit()
        conn.close()
        insert_seconds[layout] += time.perf_counter()-t0
    build_wall, build_cpu = time.perf_counter()-started, time.process_time()-cpu_started
    if n != 251734 or len(cases) != 50931:
        raise AssertionError("Complete-source/test-case count mismatch")
    expected_digest = aggregate_digest(digests)
    del source, p, t, digests, batch, writers
    gc.collect()
    stores = {layout: SQLiteStore(path, layout) for layout,path in paths.items()}
    verify_started = time.perf_counter()
    databases = {layout: verify_storage(store, expected_digest, n) for layout,store in stores.items()}
    storage_verification_seconds = time.perf_counter()-verify_started
    native = verify_native(stores, cases, truths)
    for store in stores.values():
        store.close()
    report = dict(created_utc=datetime.now(timezone.utc).isoformat(), status="passed", command=sys.argv, source_cases=n, test_cases=len(cases),
                  selected_case_ids_sha256=hashlib.sha256("\n".join(c.case_id for c in cases).encode()).hexdigest(),
                  source_metadata_relation_sha256=expected_digest, source_bytes=SOURCE.stat().st_size, logical_payload=dict(payload),
                  databases=databases, source_and_implementation_sha256=code_hashes(),
                  build_wall_seconds=build_wall, build_cpu_seconds=build_cpu, insertion_commit_analyze_wall_seconds=dict(insert_seconds),
                  oracle_wall_seconds_within_build=oracle_seconds, storage_verification_wall_seconds=storage_verification_seconds,
                  native_verification_wall_seconds=native["elapsed_seconds"], total_preparation_verification_wall_seconds=time.perf_counter()-started,
                  peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  preparation_scope="Compact derivative parsing, serialization, all-source database construction, exact held-out oracle construction, full stored-relation verification and native adapter verification. Original XES download/parsing/projection not included. Insertion timers include batching, commit and ANALYZE; oracle time is separately identified verification work. Other cooperating CPU work may run during this untimed preparation stage.",
                  timing_scope="Warm-cache read-only single-reader SQLite host experiment; no artificial delay/padding, network, concurrency, writer contention, or disk-cold claim.")
    save(output/"preparation.json", report)
    save(output/"native_verification.json", native)
    print(json.dumps({"stage": "prepared", "cases": n, "test_cases": len(cases), "native_checks": native["policy_case_checks"],
                      "build_seconds": build_wall, "verification_seconds": native["elapsed_seconds"],
                      "rough_nine_round_seconds_from_untimed_verification": 9*native["elapsed_seconds"],
                      "database_sizes": {k:v["file_bytes"] for k,v in databases.items()}}), flush=True)


def distribution(values):
    q = statistics.quantiles(values, n=4, method="inclusive")
    return dict(n=len(values), minimum=min(values), q1=q[0], median=statistics.median(values), q3=q[2], maximum=max(values), values=values)


def usage():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return dict(minor_faults=r.ru_minflt, major_faults=r.ru_majflt, block_inputs=r.ru_inblock,
                voluntary_context_switches=r.ru_nvcsw, involuntary_context_switches=r.ru_nivcsw)


def environment():
    return dict(python=sys.version, sqlite_version=sqlite3.sqlite_version, platform=platform.platform(),
                logical_cpus=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)), python_hash_seed=os.environ.get("PYTHONHASHSEED"),
                gc_enabled=gc.isenabled(), sqlite_compile_options=[r[0] for r in sqlite3.connect(":memory:").execute("PRAGMA compile_options")],
                cpu_model=next((line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"))


def benchmark(output, cpu):
    if (output/"rounds.jsonl").exists() or (output/"benchmark.json").exists():
        raise FileExistsError("Preserving existing measured evidence; choose a newly prepared output directory.")
    prep = json.loads((output/"preparation.json").read_text())
    native = json.loads((output/"native_verification.json").read_text())
    if prep["source_and_implementation_sha256"] != code_hashes():
        raise AssertionError("Prepared source/implementation changed before measurement")
    for layout in LAYOUTS:
        if sha(output/(layout+".sqlite3")) != prep["databases"][layout]["file_sha256"]:
            raise AssertionError("Prepared database changed")
    if cpu is not None:
        if cpu not in os.sched_getaffinity(0):
            raise ValueError("Requested CPU is outside allowed affinity")
        os.sched_setaffinity(0, {cpu})
    started = time.perf_counter()
    cases, truths = load_workload()
    stores = {layout: SQLiteStore(output/(layout+".sqlite3"), layout) for layout in LAYOUTS}
    verified = {(r["layout"],r["variant"],r["method"]):r for r in native["rows"]}
    jobs = list(verified)
    rng = random.Random(20261007)
    order = list(range(len(cases)))
    rounds = []
    before = environment()
    for repetition in range(-2, 7):
        rng.shuffle(order)
        expected = {variant: bytearray(values[i] for i in order) for variant,values in truths.items()}
        randomized_jobs = list(jobs)
        rng.shuffle(randomized_jobs)
        for position, (layout, variant, method) in enumerate(randomized_jobs):
            gc.collect()
            ru0 = usage()
            wall0, cpu0 = time.perf_counter_ns(), time.process_time_ns()
            outcomes, masks, ledger = execute(stores[layout], cases, order, variant == "strict_consignment", method)
            cpu_ns, wall_ns = time.process_time_ns()-cpu0, time.perf_counter_ns()-wall0
            ru1 = usage()
            if outcomes != expected[variant]:
                raise AssertionError("Timed output differs from independent reference")
            old = verified[(layout, variant, method)]
            if any(value != old[field] for field,value in ledger.items()):
                raise AssertionError("Timed access ledger differs from verified native run")
            row = dict(phase="warmup" if repetition < 0 else "measured", round=repetition, execution_position=position,
                       layout=layout, variant=variant, method=method, **ledger, cpu_ns=cpu_ns, wall_ns=wall_ns,
                       cpu_ns_per_case=cpu_ns/len(cases), wall_ns_per_case=wall_ns/len(cases),
                       oracle_disagreements=0, process_resource_delta={key:ru1[key]-ru0[key] for key in ru0})
            rounds.append(row)
            with (output/"rounds.jsonl").open("a") as stream:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        print(json.dumps({"stage": "warmup" if repetition < 0 else "measured", "round": repetition, "elapsed_seconds": time.perf_counter()-started}), flush=True)
    summaries = []
    for layout,variant,method in jobs:
        selected = [r for r in rounds if (r["layout"],r["variant"],r["method"]) == (layout,variant,method) and r["phase"] == "measured"]
        row = dict(layout=layout, variant=variant, method=method, **{k:selected[0][k] for k in ("cases", "profile_values", "timestamp_values", "payload_bytes", "json_decodes", "sql_queries", "sql_rows_returned", "no_metadata_cases", "one_block_cases", "two_block_cases")})
        for timer in ("cpu", "wall"):
            row[timer+"_ns_per_case"] = distribution([r[timer+"_ns_per_case"] for r in selected])
            for baseline in ("joined_full", "guard_joined"):
                base = {r["round"]:r for r in rounds if (r["layout"],r["variant"],r["method"]) == (layout,variant,baseline) and r["phase"] == "measured"}
                row["paired_"+timer+"_ns_vs_"+baseline] = distribution([r[timer+"_ns"]-base[r["round"]][timer+"_ns"] for r in selected])
                row["paired_"+timer+"_ratio_vs_"+baseline] = distribution([r[timer+"_ns"]/base[r["round"]][timer+"_ns"] for r in selected])
        row["median_wall_cases_per_second"] = 1e9/row["wall_ns_per_case"]["median"]
        summaries.append(row)
    for store in stores.values():
        store.close()
    unchanged = {layout:sha(output/(layout+".sqlite3")) == prep["databases"][layout]["file_sha256"] for layout in LAYOUTS}
    if not all(unchanged.values()):
        raise AssertionError("Read-only database changed during measurement")
    report = dict(status="passed", created_utc=datetime.now(timezone.utc).isoformat(), command=sys.argv, source_and_implementation_sha256=code_hashes(),
                  preparation_sha256=sha(output/"preparation.json"), native_verification_sha256=sha(output/"native_verification.json"),
                  rounds_sha256=sha(output/"rounds.jsonl"), n=len(cases), warmup_rounds=2, measured_rounds=7, seed=20261007,
                  environment=before, database_hashes_unchanged=unchanged, results=summaries, rounds=len(rounds),
                  timed_boundary="Per-case accessor, real SQL fetch/row conversion, per-fetched-block JSON decoding, rule evaluation, policy/certificate computation, common outcome+mask vectors and ledger accumulation. Correctness comparison, GC collection, resource probes and connection setup outside timer.",
                  excluded="Original XES-to-compact conversion, compact source parsing, base projection construction, database construction, oracle computation, network, concurrency and writes. Preparation costs and storage are separate recorded measurements.",
                  cache_scope="Two complete warmup rounds; shared read-only SQLite connections with suggested 128MiB caches, statement cache128, mmap disabled, OS cache not flushed. No cross-case parsed metadata or decision cache.",
                  statistical_scope="Paired repeat distributions on one host, not enterprise-population confidence intervals or service tail latency.",
                  elapsed_seconds=time.perf_counter()-started)
    save(output/"benchmark.json", report)
    print(json.dumps({"stage":"complete", "status":"passed", "rounds":len(rounds), "elapsed_seconds":report["elapsed_seconds"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("prepare", "benchmark"), required=True)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    check_frozen()
    if args.stage == "prepare":
        prepare(args.output)
    else:
        benchmark(args.output, args.cpu)


if __name__ == "__main__":
    main()
