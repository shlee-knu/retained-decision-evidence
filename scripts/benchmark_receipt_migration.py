"""Real SQLite receipt migration under the frozen third-revision protocol.

Fresh recomputation never reads the receipt store. Ordinary cached recomputation
skips it when the visible base suffices. Generic receipt diagnostics are an
additional service. All methods generate, but do not durably write, a sufficient
replacement receipt. Existing scientific files and databases are read-only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
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
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import revalidate_receipt as receipt_tool
from compare_catalogs import read_catalog
from logistics_validation.acquisition import exact_first_time
from logistics_validation.catalog_audit import ALPHABET, PROFILES, reference_verdict
from stress_acquisition import raw_time
from verify_expanded import split

OUT = ROOT / "results/third/sqlite_migration"
PROTOCOL = ROOT / "configs/third_migration_protocol.json"
METHODS = ("generic_receipt", "ordinary_cache_recompute", "fresh_guard_joined")
DOMAIN = "cartesian:v1"
SOURCE_SQL = {
    "profile": "SELECT payload FROM profiles WHERE case_id = ?",
    "first_times": "SELECT payload FROM timestamps WHERE case_id = ?",
    "both": "SELECT p.payload, t.payload FROM profiles AS p JOIN timestamps AS t ON p.case_id=t.case_id WHERE p.case_id = ?",
}
FIELDS = ("cases", "receipt_queries", "source_queries", "total_queries", "receipt_rows", "source_rows",
          "receipt_bytes", "new_source_bytes", "new_profile_values", "new_time_values",
          "receipt_decodes", "source_decodes", "retained_profile_values", "retained_time_values",
          "output_profile_values", "output_time_values", "output_bytes", "accepted", "rejected")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def fingerprints():
    files = [PROTOCOL, ROOT / "docs/third_migration_design.md", Path(__file__),
             ROOT / "tests/test_receipt_migration.py", ROOT / "scripts/revalidate_receipt.py",
             ROOT / "src/logistics_validation/catalog_audit.py", ROOT / "src/logistics_validation/domain_audit.py",
             ROOT / "src/logistics_validation/acquisition.py", ROOT / "scripts/stress_acquisition.py",
             ROOT / "scripts/compare_catalogs.py", ROOT / "scripts/verify_expanded.py"]
    config = json.loads(PROTOCOL.read_text())
    files.extend(ROOT / p for p in set(config["targets"].values()))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in files}


@dataclass(frozen=True)
class BaseCase:
    case_id: str
    activities: tuple[str, ...]


def connection(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True,
                           isolation_level=None, cached_statements=128)
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA cache_size=-131072")
    conn.execute("PRAGMA mmap_size=0")
    return conn


class Stores:
    def __init__(self, source, receipts):
        self.source = connection(source)
        self.receipts = connection(receipts)

    def close(self):
        self.source.close()
        self.receipts.close()


class Access:
    def __init__(self, stores, base):
        self.stores, self.base = stores, base
        self.observed = {}
        self.counts = Counter()

    def receipt(self, before_hash, snapshot):
        row = self.stores.receipts.execute("SELECT payload FROM receipts WHERE case_id = ?", (self.base.case_id,)).fetchone()
        self.counts["receipt_queries"] += 1
        if row is None:
            raise KeyError("Missing receipt row: " + self.base.case_id)
        self.counts["receipt_rows"] += 1
        self.counts["receipt_bytes"] += len(row[0])
        self.counts["receipt_decodes"] += 1
        value = json.loads(row[0])
        check_envelope(value, self.base, before_hash, snapshot)
        self.observed = value["observed"].copy()
        self.counts["retained_profile_values"] += int("profile" in self.observed)
        self.counts["retained_time_values"] += int("first_times" in self.observed)
        return value

    def read(self, name):
        if name in self.observed:
            raise AssertionError("Attempt to fetch an already retained block")
        row = self.stores.source.execute(SOURCE_SQL[name], (self.base.case_id,)).fetchone()
        self.counts["source_queries"] += 1
        if row is None:
            raise KeyError("Missing source row: " + self.base.case_id + "/" + name)
        self.counts["source_rows"] += 1
        names = ("profile", "first_times") if name == "both" else (name,)
        for field, blob in zip(names, row):
            if field in self.observed:
                raise AssertionError("Joined read would duplicate a retained field")
            self.counts["new_source_bytes"] += len(blob)
            self.counts["new_profile_values" if field == "profile" else "new_time_values"] += 1
            self.counts["source_decodes"] += 1
            self.observed[field] = json.loads(blob)[field]
        return self.observed if name == "both" else self.observed[name]


def check_envelope(value, base, before_hash, snapshot):
    required = {"schema_version", "receipt_id", "snapshot_sha256", "catalog_sha256", "domain_version",
                "activities", "observed", "verdict"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Malformed bound receipt schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or type(value["verdict"]) is not bool:
        raise ValueError("Malformed receipt version/verdict")
    if value["receipt_id"] != base.case_id or value["activities"] != list(base.activities):
        raise ValueError("Receipt case/activity binding mismatch")
    if value["catalog_sha256"] != before_hash or value["snapshot_sha256"] != snapshot or value["domain_version"] != DOMAIN:
        raise ValueError("Receipt catalog/domain/snapshot binding mismatch")
    obs = value["observed"]
    if not isinstance(obs, dict) or set(obs) - {"profile", "first_times"}:
        raise ValueError("Unsupported observed block")
    if "profile" in obs and obs["profile"] not in PROFILES:
        raise ValueError("Unsupported observed profile")
    if "first_times" in obs and (not isinstance(obs["first_times"], dict)
            or set(obs["first_times"]) != set(base.activities)
            or any(not isinstance(t, str) for t in obs["first_times"].values())):
        raise ValueError("Malformed observed first-times block")


class Ordinary:
    """Exact new-predicate guards on the Cartesian conjunction fragment only."""
    def __init__(self, catalog):
        self.catalog = catalog

    def structure(self, activities):
        positions = {}
        for i, name in enumerate(activities):
            positions.setdefault(ALPHABET.index(name), i)
        result = []
        for rule in self.catalog:
            active = tuple((a, b) for a, b in rule.edges if b in positions)
            eligible = (rule.required <= positions.keys() and not rule.forbidden & positions.keys()
                        and all(a in positions and positions[a] < positions[b] for a, b in active))
            result.append((bool(eligible), active))
        return tuple(result)

    def possible(self, structural, observed):
        candidates = (PROFILES.index(observed["profile"]),) if "profile" in observed else range(4)
        outcomes, clocks = set(), {}
        for p in candidates:
            eligible, edges = structural[p]
            if not eligible:
                outcomes.add(False)
            elif "first_times" not in observed:
                outcomes.add(True)
                if edges:
                    outcomes.add(False)
            else:
                def stamp(a):
                    if a not in clocks:
                        clocks[a] = exact_first_time(observed["first_times"][ALPHABET[a]])
                        if clocks[a] is None:
                            raise ValueError("Unsupported clock used by predicate")
                    return clocks[a]
                outcomes.add(all(stamp(a) <= stamp(b) for a, b in edges))
        return outcomes


def clear_semantic_caches():
    receipt_tool.fibers.cache_clear()
    receipt_tool.states.cache_clear()


class Job:
    def __init__(self, before, after, snapshot, method):
        self.before_hash = receipt_tool.catalog_digest(before)
        self.after_hash = receipt_tool.catalog_digest(after)
        self.snapshot, self.method = snapshot, method
        if method == "generic_receipt":
            receipt_tool.states()
            receipt_tool.fibers("cartesian")
            self.engine = receipt_tool.Revalidator(before, after, DOMAIN, DOMAIN, snapshot)
        else:
            self.engine = Ordinary(after)

    def run(self, access):
        status = None
        if self.method == "generic_receipt":
            old = access.receipt(self.before_hash, self.snapshot)
            repaired = self.engine.recover(old, access.read)
            if repaired["verdict"] is None:
                raise ValueError("Cannot migrate invalid or unsupported old receipt: " + repaired["status"])
            decision = repaired["verdict"]
            status = "insufficient" if repaired["requested_blocks"] else repaired["status"]
            access.observed = repaired["retained_observed"]
        else:
            structural = self.engine.structure(access.base.activities)
            outcomes = self.engine.possible(structural, {})
            if len(outcomes) == 1:
                decision = next(iter(outcomes))
            elif self.method == "fresh_guard_joined":
                access.read("both")
                decision = next(iter(self.engine.possible(structural, access.observed)))
            else:
                access.receipt(self.before_hash, self.snapshot)
                while True:
                    outcomes = self.engine.possible(structural, access.observed)
                    if len(outcomes) == 1:
                        decision = next(iter(outcomes))
                        break
                    missing = next(name for name in ("profile", "first_times") if name not in access.observed)
                    access.read(missing)
        replacement = {"schema_version": 1, "receipt_id": access.base.case_id,
                       "snapshot_sha256": self.snapshot, "catalog_sha256": self.after_hash,
                       "domain_version": DOMAIN, "activities": list(access.base.activities),
                       "observed": access.observed, "verdict": bool(decision)}
        return replacement, encode(replacement), status


def execute(job, stores, cases, order, verifier=None):
    ledger = Counter({k: 0 for k in FIELDS})
    statuses, digests = Counter(), []
    outcomes = bytearray(len(order))
    for position, i in enumerate(order):
        access = Access(stores, cases[i])
        replacement, blob, status = job.run(access)
        decision = replacement["verdict"]
        outcomes[position] = decision
        ledger.update(access.counts)
        ledger["cases"] += 1
        ledger["accepted" if decision else "rejected"] += 1
        ledger["output_profile_values"] += int("profile" in replacement["observed"])
        ledger["output_time_values"] += int("first_times" in replacement["observed"])
        ledger["output_bytes"] += len(blob)
        digests.append(hashlib.sha256(blob).digest())
        if status is not None:
            statuses[status] += 1
        if verifier:
            verifier(i, replacement, blob, access)
    ledger["total_queries"] = ledger["receipt_queries"] + ledger["source_queries"]
    # Output includes case ID, so this exact multiset digest is invariant to the
    # round's permutation without removing case binding from verification.
    digest = hashlib.sha256(b"".join(sorted(digests))).hexdigest()
    return outcomes, dict(ledger), dict(statuses), digest


def loaded_inputs(config):
    source = ROOT / config["compact_source"]
    cases, complete = [], []
    with gzip.open(source, "rt") as stream:
        for line in stream:
            raw = json.loads(line)
            if split(raw["document"]) == "test":
                cases.append(BaseCase(raw["case_id"], tuple(raw["activities"])))
                complete.append(raw)
    assert len(cases) == 50931
    return cases, complete


def state_key(value):
    order = tuple(dict.fromkeys(ALPHABET.index(a) for a in value["activities"]))
    clocks = [raw_time(value["first_times"][ALPHABET[a]]) for a in order]
    ranks = {t: i for i, t in enumerate(sorted(set(clocks)))}
    return order, tuple(ranks[t] for t in clocks), PROFILES.index(value["profile"])


def verify_source_relation(path, wanted):
    """Full logical check for explicitly supplied reproduction databases."""
    conn = connection(path)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("Source SQLite integrity failure")
        counts = [conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("profiles", "timestamps")]
        digests = []
        for key, p, t in conn.execute("SELECT p.case_id,p.payload,t.payload FROM profiles p JOIN timestamps t ON p.case_id=t.case_id"):
            h = hashlib.sha256()
            for field in (key.encode(), p, t):
                h.update(len(field).to_bytes(8, "big"))
                h.update(field)
            digests.append(h.digest())
        digest = hashlib.sha256(b"".join(sorted(digests))).hexdigest()
        if counts != [251734, 251734] or len(digests) != 251734 or digest != wanted:
            raise ValueError("Reproduction source differs from the pinned complete logical relation")
        return dict(performed=True, rows=len(digests), relation_sha256=digest)
    finally:
        conn.close()


def prepare(output, source_override=None):
    output.mkdir(parents=True, exist_ok=True)
    if any(p.name not in {"pytest.xml", "pytest.txt"} for p in output.iterdir()):
        raise FileExistsError("Preparation requires a new output directory; existing evidence is preserved")
    config = json.loads(PROTOCOL.read_text())
    for pathkey, hashkey in (("compact_source", "compact_source_sha256"),
                             ("receipt_source", "receipt_source_sha256")):
        assert sha(ROOT / config[pathkey]) == config[hashkey]
    source_path = Path(source_override).resolve() if source_override else ROOT / config["source_database"]
    if source_override:
        source_check = verify_source_relation(source_path, config["source_relation_sha256"])
    else:
        assert sha(source_path) == config["source_database_sha256"]
        source_check = dict(performed=False, reason="Exact canonical source database hash matches the prior fully verified relation",
                            relation_sha256=config["source_relation_sha256"])
    start_wall, start_cpu = time.perf_counter(), time.process_time()
    cases, complete = loaded_inputs(config)
    base_loading_wall = time.perf_counter() - start_wall
    receipt_db = output / "receipts.sqlite3"
    conn = sqlite3.connect(receipt_db)
    conn.execute("PRAGMA page_size=4096")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("CREATE TABLE receipts(case_id TEXT PRIMARY KEY, payload BLOB NOT NULL) WITHOUT ROWID")
    before = read_catalog(ROOT / config["old_catalog"])
    before_hash = receipt_tool.catalog_digest(before)
    receipt_bytes, n = 0, 0
    digests = []
    materialize_wall, materialize_cpu = time.perf_counter(), time.process_time()
    with gzip.open(ROOT / config["receipt_source"], "rt") as stream:
        for line in stream:
            value = json.loads(line)["receipt"]
            assert value["receipt_id"] == cases[n].case_id
            check_envelope(value, cases[n], before_hash, config["compact_source_sha256"])
            payload = encode(value)
            conn.execute("INSERT INTO receipts VALUES (?, ?)", (value["receipt_id"], payload))
            digests.append(hashlib.sha256(value["receipt_id"].encode()+b"\0"+payload).digest())
            receipt_bytes += len(payload)
            n += 1
    assert n == len(cases)
    conn.commit()
    conn.execute("ANALYZE")
    conn.commit()
    materialize_wall = time.perf_counter() - materialize_wall
    materialize_cpu = time.process_time() - materialize_cpu
    assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    relation = hashlib.sha256(b"".join(sorted(digests))).hexdigest()
    stored = [hashlib.sha256(key.encode()+b"\0"+blob).digest() for key, blob in conn.execute("SELECT case_id,payload FROM receipts")]
    assert hashlib.sha256(b"".join(sorted(stored))).hexdigest() == relation
    plan = [list(r) for r in conn.execute("EXPLAIN QUERY PLAN SELECT payload FROM receipts WHERE case_id=?", (cases[0].case_id,))]
    assert any("PRIMARY KEY" in row[3] for row in plan)
    conn.close()
    prep_before_verify_wall = time.perf_counter() - start_wall
    prep_before_verify_cpu = time.process_time() - start_cpu
    with gzip.open(ROOT / "results/strong/catalog_audit/finite_tables.json.gz", "rt") as f:
        finite = json.load(f)
    lookup = {(tuple(s[0]), tuple(s[1]), s[2]): i for i, s in enumerate(finite["states"])}
    indices = [lookup[state_key(c)] for c in complete]
    catalog_ids = {"identity": "baseline", "strict": "strict_consignment", "equivalent": "edge_p0_a0_b3", "label_change": "required_p3_a2"}
    stores = Stores(source_path, receipt_db)
    results, oracle = [], {}
    verify_start = time.perf_counter()
    for target, catalog_path in config["targets"].items():
        after = read_catalog(ROOT / catalog_path)
        truths = [reference_verdict(c, after) for c in complete]
        oracle[target] = truths
        saved = finite["catalogs"][catalog_ids[target]]
        assert truths == [bool(saved["labels"][i]) for i in indices]
        for method in METHODS:
            clear_semantic_caches()
            job = Job(before, after, config["compact_source_sha256"], method)
            statement = Counter()
            stores.source.set_trace_callback(lambda sql: statement.update(source=int(sql.lstrip().upper().startswith("SELECT"))))
            stores.receipts.set_trace_callback(lambda sql: statement.update(receipt=int(sql.lstrip().upper().startswith("SELECT"))))

            def verify_output(i, value, blob, access):
                expected = complete[i]
                assert value["receipt_id"] == expected["case_id"] and value["activities"] == expected["activities"]
                assert value["verdict"] is truths[i]
                assert value["catalog_sha256"] == job.after_hash and value["snapshot_sha256"] == config["compact_source_sha256"]
                assert value["domain_version"] == DOMAIN and json.loads(blob) == value
                mask = 0
                for name, field in value["observed"].items():
                    assert field == expected[name]
                    mask |= {"profile": 1, "first_times": 2}[name]
                assert saved["sufficient"][indices[i]] & (1 << mask)

            outcomes, ledger, statuses, digest = execute(job, stores, cases, range(len(cases)), verify_output)
            assert list(outcomes) == truths
            assert statement["source"] == ledger["source_queries"] and statement["receipt"] == ledger["receipt_queries"]
            results.append(dict(target=target, method=method, **ledger, generic_initial_statuses=statuses,
                                replacement_multiset_sha256=digest, actual_source_selects=statement["source"],
                                actual_receipt_selects=statement["receipt"], oracle_disagreements=0, insufficient_output_receipts=0))
        print(json.dumps({"stage": "verified", "target": target, "cases": len(cases)}), flush=True)
    stores.close()
    strict = next(r for r in results if r["target"] == "strict" and r["method"] == "generic_receipt")
    assert strict["new_profile_values"] == 33489 and strict["new_time_values"] == 0 and strict["new_source_bytes"] == 1471664
    prep = dict(status="passed", created_utc=datetime.now(timezone.utc).isoformat(), protocol_sha256=sha(PROTOCOL),
                source_and_implementation_sha256=fingerprints(), config=config, cases=len(cases),
                source_database_path=str(source_path), source_relation_check=source_check,
                source_database_sha256=sha(source_path), receipt_database_sha256=sha(receipt_db),
                receipt_database_bytes=receipt_db.stat().st_size, receipt_json_payload_bytes=receipt_bytes,
                receipt_relation_sha256=relation, receipt_query_plan=plan,
                base_loading_wall_seconds=base_loading_wall, receipt_materialization_wall_seconds=materialize_wall,
                receipt_materialization_cpu_seconds=materialize_cpu, preparation_before_verification_wall_seconds=prep_before_verify_wall,
                preparation_before_verification_cpu_seconds=prep_before_verify_cpu,
                native_verification_wall_seconds=time.perf_counter()-verify_start,
                max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                preparation_scope="Compact-derived base/full-reference loading and receipt JSON extraction/validation/canonical serialization/materialization. Existing normalized source DB reused. Full raw-XES preparation excluded; oracle/sufficiency verification is separate.")
    write_json(output / "preparation.json", prep)
    write_json(output / "native_verification.json", dict(status="passed", rows=results,
               method_case_comparisons=len(cases)*len(results), independent_full_input_labels=len(cases)*4,
               output_receipt_sufficiency_checks=len(cases)*len(results), oracle_disagreements=0,
               truth_vectors=oracle, finite_truth_source_sha256=sha(ROOT / "results/strong/catalog_audit/finite_tables.json.gz")))
    print(json.dumps({"stage": "prepared", "cases": len(cases), "method_case_comparisons": len(cases)*len(results)}), flush=True)


def distribution(values):
    ordered = sorted(values)
    # Linear interpolation matches the preceding benchmark's empirical IQR.
    def q(f):
        x = (len(ordered)-1)*f
        lo = int(x)
        return ordered[lo] + (ordered[min(lo+1, len(ordered)-1)]-ordered[lo])*(x-lo)
    return dict(n=len(values), min=min(values), q1=q(.25), median=statistics.median(values), q3=q(.75), max=max(values))


def benchmark(output, cpu):
    if (output / "rounds.jsonl").exists() or (output / "benchmark.json").exists():
        raise FileExistsError("Timing refuses to append to previous evidence")
    prep = json.loads((output / "preparation.json").read_text())
    native = json.loads((output / "native_verification.json").read_text())
    config = prep["config"]
    assert prep["source_and_implementation_sha256"] == fingerprints()
    source = Path(prep["source_database_path"])
    receipt_db = output / "receipts.sqlite3"
    assert sha(source) == prep["source_database_sha256"] and sha(receipt_db) == prep["receipt_database_sha256"]
    if cpu is not None:
        if cpu not in os.sched_getaffinity(0):
            raise ValueError("CPU not allowed")
        os.sched_setaffinity(0, {cpu})
    cases, complete = loaded_inputs(config)
    del complete
    before = read_catalog(ROOT / config["old_catalog"])
    targets = {name: read_catalog(ROOT / path) for name, path in config["targets"].items()}
    stores = Stores(source, receipt_db)
    expected = {(r["target"], r["method"]): r for r in native["rows"]}
    rng = random.Random(config["timing"]["random_seed"])
    order, jobs, rows = list(range(len(cases))), list(expected), []
    env = dict(python=sys.version, platform=platform.platform(), sqlite_version=sqlite3.sqlite_version,
               affinity=sorted(os.sched_getaffinity(0)), hash_seed=os.environ.get("PYTHONHASHSEED"),
               cpu_model=next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
               sqlite_cache_kib=131072, mmap_size=0, statement_cache=128)
    start = time.perf_counter()
    job = None
    for repetition in range(-2, 7):
        rng.shuffle(order)
        schedule = list(jobs)
        rng.shuffle(schedule)
        truths = {target: bytearray(values[i] for i in order) for target, values in native["truth_vectors"].items()}
        for position, (target, method) in enumerate(schedule):
            job = None
            clear_semantic_caches()
            gc.collect()
            usage0 = resource.getrusage(resource.RUSAGE_SELF)
            wall0, cpu0 = time.perf_counter_ns(), time.process_time_ns()
            job = Job(before, targets[target], config["compact_source_sha256"], method)
            cpu1, wall1 = time.process_time_ns(), time.perf_counter_ns()
            outcomes, ledger, statuses, digest = execute(job, stores, cases, order)
            cpu2, wall2 = time.process_time_ns(), time.perf_counter_ns()
            usage1 = resource.getrusage(resource.RUSAGE_SELF)
            wanted = expected[(target, method)]
            assert outcomes == truths[target]
            assert all(ledger[k] == wanted[k] for k in FIELDS)
            assert statuses == wanted["generic_initial_statuses"] and digest == wanted["replacement_multiset_sha256"]
            row = dict(round=repetition, phase="warmup" if repetition < 0 else "measured", execution_position=position,
                       target=target, method=method, **ledger, generic_initial_statuses=statuses,
                       replacement_multiset_sha256=digest, oracle_disagreements=0,
                       setup_cpu_ns=cpu1-cpu0, setup_wall_ns=wall1-wall0,
                       migration_cpu_ns=cpu2-cpu1, migration_wall_ns=wall2-wall1,
                       batch_cpu_ns=cpu2-cpu0, batch_wall_ns=wall2-wall0,
                       minor_faults=usage1.ru_minflt-usage0.ru_minflt, major_faults=usage1.ru_majflt-usage0.ru_majflt,
                       block_inputs=usage1.ru_inblock-usage0.ru_inblock,
                       voluntary_context_switches=usage1.ru_nvcsw-usage0.ru_nvcsw,
                       involuntary_context_switches=usage1.ru_nivcsw-usage0.ru_nivcsw)
            rows.append(row)
            with (output / "rounds.jsonl").open("a") as f:
                f.write(json.dumps(row, separators=(",", ":"))+"\n")
        print(json.dumps({"stage": "warmup" if repetition < 0 else "measured", "round": repetition,
                          "elapsed_seconds": time.perf_counter()-start}), flush=True)
    stores.close()
    result = []
    for target, method in jobs:
        subset = [r for r in rows if r["target"] == target and r["method"] == method and r["phase"] == "measured"]
        summary = dict(target=target, method=method, **{k: subset[0][k] for k in FIELDS})
        for scope in ("setup", "migration", "batch"):
            for timer in ("cpu", "wall"):
                summary[scope+"_"+timer+"_ns"] = distribution([r[scope+"_"+timer+"_ns"] for r in subset])
        for comparator in ("ordinary_cache_recompute", "fresh_guard_joined"):
            base = {r["round"]: r for r in rows if r["target"] == target and r["method"] == comparator and r["phase"] == "measured"}
            for timer in ("cpu", "wall"):
                summary["paired_batch_"+timer+"_ns_vs_"+comparator] = distribution([r["batch_"+timer+"_ns"]-base[r["round"]]["batch_"+timer+"_ns"] for r in subset])
        result.append(summary)
    assert sha(source) == prep["source_database_sha256"] and sha(receipt_db) == prep["receipt_database_sha256"]
    report = dict(status="passed", created_utc=datetime.now(timezone.utc).isoformat(), source_and_implementation_sha256=fingerprints(),
                  preparation_sha256=sha(output/"preparation.json"), native_verification_sha256=sha(output/"native_verification.json"),
                  rounds_sha256=sha(output/"rounds.jsonl"), environment=env, cases=len(cases),
                  warmup_rounds=2, measured_rounds=7, full_workload_runs=len(rows), results=result,
                  unchanged_source_and_receipt_databases=True, elapsed_seconds=time.perf_counter()-start,
                  scope="Warm, read-only, one-reader SQLite replacement-receipt generation. Setup plus migration measured; common base loading/materialization, durable writes, network and live freshness excluded. Generic includes extra old-certificate diagnostics. No negative or null outcome excluded.")
    write_json(output / "benchmark.json", report)
    print(json.dumps({"stage": "complete", "runs": len(rows), "elapsed_seconds": report["elapsed_seconds"]}), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=("prepare", "benchmark"), required=True)
    p.add_argument("--output", type=Path, default=OUT)
    p.add_argument("--cpu", type=int)
    p.add_argument("--source-db", type=Path, help="Prepare only: rebuilt normalized source, verified against the full pinned logical relation")
    args = p.parse_args()
    if args.stage == "prepare":
        prepare(args.output.resolve(), args.source_db)
    else:
        if args.source_db:
            p.error("--source-db is a preparation-only binding; benchmark uses the recorded source")
        benchmark(args.output.resolve(), args.cpu)


if __name__ == "__main__":
    main()
