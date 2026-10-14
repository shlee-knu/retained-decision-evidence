"""Known-answer semantics and actual-SQL access boundaries for the new adapter."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sqlite_integration_benchmark", ROOT / "scripts/benchmark_sqlite_integration.py")
bench = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bench
spec.loader.exec_module(bench)


def source(case_id="case", activities=("create", "receive", "invoice", "clear"), profile="3-way match, invoice before GR", times=None):
    if times is None:
        times = {a:f"2020-01-01T00:00:0{i}Z" for i,a in enumerate(dict.fromkeys(activities))}
    return dict(case_id=case_id, activities=list(activities), profile=profile, first_times=times)


def build(tmp_path, layout, inputs):
    path = tmp_path/(layout+".sqlite3")
    conn = bench.create_writer(path, layout)
    rows = [(c["case_id"], bench.component.encode_block("profile", c["profile"]), bench.component.encode_block("first_times", c["first_times"])) for c in inputs]
    bench.insert_batch(conn, layout, rows)
    conn.commit()
    conn.close()
    return bench.SQLiteStore(path, layout)


@pytest.mark.parametrize("layout", bench.LAYOUTS)
def test_joined_is_one_actual_sql_and_two_decodes_even_when_base_rejects(tmp_path, layout):
    case = source(activities=("clear",))
    store = build(tmp_path, layout, [case])
    statements = []
    store.connection.set_trace_callback(statements.append)
    access = bench.SQLiteAccessor(store, bench.BaseCase("case", tuple(case["activities"])))
    assert bench.decide(access, False, "joined_full") is False
    assert len(statements) == access.sql_queries == access.rows_returned == 1
    assert statements[0].startswith("SELECT ")
    assert access.mask == 3 and access.decodes == 2
    assert access.trace == ["profile", "first_times"]
    store.close()


@pytest.mark.parametrize("layout", bench.LAYOUTS)
def test_separate_full_really_executes_two_statements(tmp_path, layout):
    case = source()
    store = build(tmp_path, layout, [case])
    statements = []
    store.connection.set_trace_callback(statements.append)
    access = bench.SQLiteAccessor(store, bench.BaseCase("case", tuple(case["activities"])))
    assert bench.decide(access, False, "separate_full") is True
    assert len(statements) == access.sql_queries == access.rows_returned == 2
    assert access.decodes == 2 and access.mask == 3
    store.close()


@pytest.mark.parametrize("layout", bench.LAYOUTS)
@pytest.mark.parametrize("method", ("guard_joined", "hand_selective", "generic_selective"))
def test_base_guard_has_no_hidden_row_access(tmp_path, layout, method):
    # An absent hidden row witnesses non-access only, not supported-domain validity.
    store = build(tmp_path, layout, [])
    statements = []
    store.connection.set_trace_callback(statements.append)
    access = bench.SQLiteAccessor(store, bench.BaseCase("deliberately-absent", ("clear",)))
    assert bench.decide(access, False, method) is False
    assert statements == [] and access.sql_queries == access.decodes == access.mask == 0
    store.close()


FIXTURES = [
    source(case_id="ordinary"),
    source(case_id="missing-required", activities=("create", "invoice")),
    source(case_id="repeated-late-create", activities=("create", "receive", "create", "invoice", "clear")),
    source(case_id="position-reversal", activities=("invoice", "create", "receive", "clear")),
    source(case_id="consignment-extra", profile="Consignment"),
    source(case_id="two-way", activities=("create", "invoice", "clear"), profile="2-way match"),
    source(case_id="equal-utc", times={"create":"2020-01-01T00:00:00Z", "receive":"2020-01-01T01:00:00+01:00", "invoice":"2020-01-01t00:00:00z", "clear":"2019-12-31T19:00:00-05:00"}),
    source(case_id="submicro-reversal", times={"create":"2020-01-01T00:00:00.000000002Z", "receive":"2020-01-01T00:00:00.000000001Z", "invoice":"2020-01-01T00:00:01Z", "clear":"2020-01-01T00:00:02Z"}),
]


@pytest.mark.parametrize("layout", bench.LAYOUTS)
@pytest.mark.parametrize("strict", (False, True))
@pytest.mark.parametrize("case", FIXTURES, ids=lambda c:c["case_id"])
def test_all_database_implementations_match_independent_reference(tmp_path, layout, strict, case):
    store = build(tmp_path, layout, [case])
    expected = not bench.expected_violation(case, strict)
    masks = {}
    for method in bench.METHODS:
        access = bench.SQLiteAccessor(store, bench.BaseCase(case["case_id"], tuple(case["activities"])))
        assert bench.decide(access, strict, method) == expected
        masks[method] = access.mask
        assert access.sql_queries == access.rows_returned
        assert access.decodes == int(bool(access.mask&1))+int(bool(access.mask&2))
    assert masks["hand_selective"] == masks["generic_selective"]
    store.close()


@pytest.mark.parametrize("layout", bench.LAYOUTS)
def test_full_relation_digest_and_primary_key_query_plans(tmp_path, layout):
    store = build(tmp_path, layout, FIXTURES)
    rows = [bench.row_digest(c["case_id"], bench.component.encode_block("profile", c["profile"]), bench.component.encode_block("first_times", c["first_times"])) for c in FIXTURES]
    info = bench.verify_storage(store, bench.aggregate_digest(rows), len(FIXTURES))
    assert all(count == len(FIXTURES) for count in info["rows"].values())
    for plan in info["query_plans"].values():
        assert all("SEARCH" in row[3] and "PRIMARY KEY" in row[3] for row in plan)
    assert info["settings"]["query_only"] == 1
    assert info["settings"]["cache_size"] == -131072
    assert info["settings"]["mmap_size"] == 0
    store.close()


def test_base_descriptor_does_not_contain_profile_clock_label_or_precomputed_positions():
    base = bench.BaseCase("id", ("create", "receive"))
    assert base.__slots__ == ("case_id", "activities")


def test_normalized_and_same_row_return_identical_source_blobs(tmp_path):
    stores = {layout:build(tmp_path, layout, FIXTURES) for layout in bench.LAYOUTS}
    for case in FIXTURES:
        key = case["case_id"]
        assert stores["same_row"].fetch(key, "both") == stores["normalized"].fetch(key, "both")
    for store in stores.values():
        store.close()
