"""Actual SQLite interfaces, strong baselines and bound replacement receipts."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_receipt_migration as b
from compare_catalogs import read_catalog
from logistics_validation.catalog_audit import concrete, reference_verdict, universe

SNAPSHOT = "0" * 64
BASE = read_catalog(ROOT / "examples/baseline_catalog.json")
TARGETS = {name: read_catalog(ROOT / path) for name, path in json.loads(b.PROTOCOL.read_text())["targets"].items()}


def feature():
    return {"case_id": "case-A", "activities": ["create", "receive", "receive", "invoice", "clear"],
            "profile": "3-way match, invoice after GR", "first_times": {
                "create": "2020-01-01t00:00:00.0000000001z", "receive": "2020-01-01T09:00:00.0000000001+09:00",
                "invoice": "2020-01-01T00:00:01.000000001Z", "clear": "2020-01-01T00:00:02Z"}}


def receipt(value, mask=2, catalog=BASE):
    r = b.receipt_tool.make_receipt(value, mask, reference_verdict(value, catalog), catalog, b.DOMAIN, SNAPSHOT)
    r["receipt_id"] = value["case_id"]
    return r


def databases(tmp_path, value, old=None, *, source_missing=False, receipt_missing=False):
    src, rec = tmp_path / "source.sqlite3", tmp_path / "receipts.sqlite3"
    with sqlite3.connect(src) as conn:
        conn.execute("CREATE TABLE profiles(case_id TEXT PRIMARY KEY,payload BLOB) WITHOUT ROWID")
        conn.execute("CREATE TABLE timestamps(case_id TEXT PRIMARY KEY,payload BLOB) WITHOUT ROWID")
        if not source_missing:
            conn.execute("INSERT INTO profiles VALUES (?,?)", (value["case_id"], b.encode({"profile": value["profile"]})))
            conn.execute("INSERT INTO timestamps VALUES (?,?)", (value["case_id"], b.encode({"first_times": value["first_times"]})))
    with sqlite3.connect(rec) as conn:
        conn.execute("CREATE TABLE receipts(case_id TEXT PRIMARY KEY,payload BLOB) WITHOUT ROWID")
        if not receipt_missing:
            conn.execute("INSERT INTO receipts VALUES (?,?)", (value["case_id"], b.encode(old if old is not None else receipt(value))))
    return src, rec


def run(stores, value, method, target="strict", before=BASE):
    base = b.BaseCase(value["case_id"], tuple(value["activities"]))
    access = b.Access(stores, base)
    job = b.Job(before, TARGETS[target], SNAPSHOT, method)
    result, blob, status = job.run(access)
    return result, blob, status, access


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("method", b.METHODS)
def test_actual_methods_correct_bound_outputs_and_query_counts(tmp_path, target, method):
    value = feature()
    src, rec = databases(tmp_path, value)
    stores = b.Stores(src, rec)
    source_sql, receipt_sql = [], []
    stores.source.set_trace_callback(source_sql.append)
    stores.receipts.set_trace_callback(receipt_sql.append)
    try:
        out, blob, status, access = run(stores, value, method, target)
        assert out["verdict"] is reference_verdict(value, TARGETS[target])
        assert out["receipt_id"] == value["case_id"] and out["activities"] == value["activities"]
        assert out["catalog_sha256"] == b.receipt_tool.catalog_digest(TARGETS[target])
        assert out["snapshot_sha256"] == SNAPSHOT and json.loads(blob) == out
        assert all(field == value[name] for name, field in out["observed"].items())
        assert len(source_sql) == access.counts["source_queries"]
        assert len(receipt_sql) == access.counts["receipt_queries"]
        if method == "fresh_guard_joined":
            assert not receipt_sql and len(source_sql) == 1 and "JOIN" in source_sql[0]
        else:
            assert len(receipt_sql) == 1
            if target in {"identity", "equivalent"}:
                assert source_sql == []
            elif target == "strict":
                assert len(source_sql) == 1 and "profiles" in source_sql[0]
                assert access.counts["new_time_values"] == 0
    finally:
        stores.close()


@pytest.mark.parametrize("method", b.METHODS)
def test_base_guard_avoids_unneeded_receipt_and_source(tmp_path, method):
    value = dict(case_id="case-A", activities=[], profile="Consignment", first_times={})
    old = receipt(value, 0)
    src, rec = databases(tmp_path, value, old, source_missing=True, receipt_missing=method != "generic_receipt")
    stores = b.Stores(src, rec)
    try:
        out, _, _, access = run(stores, value, method)
        assert out["verdict"] is False and out["observed"] == {}
        assert access.counts["source_queries"] == 0
        assert access.counts["receipt_queries"] == int(method == "generic_receipt")
    finally:
        stores.close()


@pytest.mark.parametrize("method", ("generic_receipt", "ordinary_cache_recompute"))
@pytest.mark.parametrize("defect", ("case_swap", "activities", "snapshot", "catalog", "domain"))
def test_cached_adapter_rejects_misbound_receipt(tmp_path, method, defect):
    value = feature()
    old = receipt(value)
    field, changed = {"case_swap": ("receipt_id", "case-B"), "activities": ("activities", ["create"]),
                      "snapshot": ("snapshot_sha256", "f" * 64), "catalog": ("catalog_sha256", "f" * 64),
                      "domain": ("domain_version", "chronological:v1")}[defect]
    old[field] = changed
    src, rec = databases(tmp_path, value, old)
    stores = b.Stores(src, rec)
    try:
        with pytest.raises(ValueError):
            run(stores, value, method)
    finally:
        stores.close()


@pytest.mark.parametrize("method", b.METHODS)
def test_missing_required_source_row_fails(tmp_path, method):
    value = feature()
    src, rec = databases(tmp_path, value, source_missing=True)
    stores = b.Stores(src, rec)
    try:
        with pytest.raises(KeyError):
            run(stores, value, method)
    finally:
        stores.close()


@pytest.mark.parametrize("method", ("generic_receipt", "ordinary_cache_recompute"))
def test_missing_needed_receipt_row_fails(tmp_path, method):
    value = feature()
    src, rec = databases(tmp_path, value, receipt_missing=True)
    stores = b.Stores(src, rec)
    try:
        with pytest.raises(KeyError):
            run(stores, value, method)
    finally:
        stores.close()


@pytest.mark.parametrize("method", ("generic_receipt", "ordinary_cache_recompute"))
def test_replacement_receipt_idempotence_needs_no_new_source(tmp_path, method):
    value = feature()
    src, rec = databases(tmp_path, value)
    stores = b.Stores(src, rec)
    try:
        first, _, _, _ = run(stores, value, method)
    finally:
        stores.close()
    with sqlite3.connect(rec) as conn:
        conn.execute("UPDATE receipts SET payload=?", (b.encode(first),))
    with sqlite3.connect(src) as conn:
        conn.execute("DELETE FROM profiles")
        conn.execute("DELETE FROM timestamps")
    stores = b.Stores(src, rec)
    try:
        second, _, _, access = run(stores, value, method, before=TARGETS["strict"])
        assert second == first and access.counts["source_queries"] == 0
    finally:
        stores.close()


def test_ordinary_new_only_service_does_not_require_valid_old_verdict(tmp_path):
    value = feature()
    old = receipt(value)
    old["verdict"] = False
    src, rec = databases(tmp_path, value, old)
    stores = b.Stores(src, rec)
    try:
        ordinary, _, _, _ = run(stores, value, "ordinary_cache_recompute")
        assert ordinary["verdict"] is True
        with pytest.raises(ValueError, match="invalid"):
            run(stores, value, "generic_receipt")
    finally:
        stores.close()


@pytest.mark.parametrize("method", b.METHODS)
def test_subnanosecond_reversal_changes_label_and_preserves_literals(tmp_path, method):
    value = feature()
    value["first_times"]["create"] = "2020-01-01T00:00:00.0000000002Z"
    src, rec = databases(tmp_path, value, receipt(value, 3))
    stores = b.Stores(src, rec)
    try:
        out, _, _, _ = run(stores, value, method)
        assert out["verdict"] is False
        assert out["observed"]["first_times"] == value["first_times"]
    finally:
        stores.close()


def test_hand_guard_matches_all_fixed_fragment_partial_fibers():
    # Independent saved full-domain truth defines every observation's possible
    # outcomes. This does not call the generic receipt implementation.
    import gzip
    with gzip.open(ROOT / "results/strong/catalog_audit/finite_tables.json.gz", "rt") as f:
        saved = json.load(f)
    states = universe()
    names = {"identity": "baseline", "strict": "strict_consignment", "equivalent": "edge_p0_a0_b3", "label_change": "required_p3_a2"}
    from collections import defaultdict
    for target, rules in TARGETS.items():
        truth = saved["catalogs"][names[target]]["labels"]
        fibers, reps = defaultdict(set), {}
        for i, state in enumerate(states):
            raw = concrete(state)
            for mask in range(4):
                key = state.order, state.profile if mask & 1 else None, state.ranks if mask & 2 else None
                fibers[key].add(bool(truth[i]))
                reps.setdefault(key, (raw, mask))
        checker = b.Ordinary(rules)
        for key, expected in fibers.items():
            raw, mask = reps[key]
            obs = {name: raw[name] for bit, name in ((1, "profile"), (2, "first_times")) if mask & bit}
            assert checker.possible(checker.structure(raw["activities"]), obs) == expected


def test_store_is_read_only_and_source_override_rejects_different_relation(tmp_path):
    value = feature()
    src, rec = databases(tmp_path, value)
    stores = b.Stores(src, rec)
    try:
        with pytest.raises(sqlite3.OperationalError):
            stores.source.execute("DELETE FROM profiles")
        with pytest.raises(sqlite3.OperationalError):
            stores.receipts.execute("DELETE FROM receipts")
    finally:
        stores.close()
    with pytest.raises(ValueError, match="logical relation"):
        b.verify_source_relation(src, "0" * 64)


def test_existing_prepare_and_timing_evidence_not_overwritten(tmp_path):
    (tmp_path / "rounds.jsonl").write_text("preserved\n")
    with pytest.raises(FileExistsError):
        b.prepare(tmp_path)
    with pytest.raises(FileExistsError):
        b.benchmark(tmp_path, None)
    assert (tmp_path / "rounds.jsonl").read_text() == "preserved\n"
