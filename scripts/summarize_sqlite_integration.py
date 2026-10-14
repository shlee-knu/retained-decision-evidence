#!/usr/bin/env python3
"""Recompute SQLite run summaries from recorded rows; no benchmark rerun."""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/strong/sqlite_integration"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()
    out = args.output.resolve()
    report = json.loads((out/"benchmark.json").read_text())
    prep = json.loads((out/"preparation.json").read_text())
    native = json.loads((out/"native_verification.json").read_text())
    rounds = [json.loads(line) for line in (out/"rounds.jsonl").read_text().splitlines()]
    failures = []
    checks = 0
    def check(value, label):
        nonlocal checks
        checks += 1
        if not value:
            failures.append(label)
    def equal(a,b,label):
        check(math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-8),label)
    check(report["status"] == prep["status"] == native["status"] == "passed", "all driver stages passed")
    check(report["n"] == prep["test_cases"] == native["source_cases"] == 50931, "complete heldout cases")
    check(prep["source_cases"] == 251734, "complete source in database")
    check(report["warmup_rounds"] == 2 and report["measured_rounds"] == 7, "fixed repeat protocol")
    check(len(rounds) == report["rounds"] == 180, "180 canonical rows only")
    check(sum(r["phase"] == "warmup" for r in rounds) == 40, "40 warmup rows")
    check(native["policy_case_checks"] == 50931*20 == 1018620 and native["oracle_disagreements"] == 0, "native reference comparisons")
    check(report["source_and_implementation_sha256"] == prep["source_and_implementation_sha256"], "preparation and run code hashes")
    for name, wanted in report["source_and_implementation_sha256"].items():
        check(sha(ROOT/name) == wanted, "current source hash " + name)
    for name,key in (("rounds.jsonl","rounds_sha256"),("preparation.json","preparation_sha256"),("native_verification.json","native_verification_sha256")):
        check(sha(out/name) == report[key], "recorded result hash " + name)
    for layout, info in prep["databases"].items():
        check(all(n == 251734 for n in info["rows"].values()), "all-source relation counts " + layout)
        check(report["database_hashes_unchanged"][layout], "driver read-only database check " + layout)
        path = out/(layout+".sqlite3")
        check(path.is_file() and sha(path) == info["file_sha256"], "current database hash " + layout)
    key = lambda row:(row["layout"],row["variant"],row["method"])
    native_by_key = {key(r):r for r in native["rows"]}
    check(len(native_by_key) == len(report["results"]) == 20, "twenty unique method cells")
    for repetition in range(-2,7):
        selected = [r for r in rounds if r["round"] == repetition]
        check(len(selected) == 20 and len({key(r) for r in selected}) == 20, "complete round " + str(repetition))
        check({r["execution_position"] for r in selected} == set(range(20)), "unique round execution positions")
        check(all(r["phase"] == ("warmup" if repetition < 0 else "measured") for r in selected), "warmup/measurement phase label")
    ledger_fields = ("cases","profile_values","timestamp_values","payload_bytes","json_decodes","sql_queries","sql_rows_returned","no_metadata_cases","one_block_cases","two_block_cases")
    for row in rounds:
        ref = native_by_key[key(row)]
        check(all(row[k] == ref[k] for k in ledger_fields), "timed/native ledger " + str(key(row)))
        check(row["oracle_disagreements"] == 0, "timed oracle disagreement")
        check(row["json_decodes"] == row["profile_values"]+row["timestamp_values"], "one decode per returned value")
        for timer in ("cpu","wall"):
            equal(row[timer+"_ns_per_case"],row[timer+"_ns"]/50931,"per-case timer normalization")
    csv_rows = []
    def verify_distribution(actual, values, label):
        q = statistics.quantiles(values,n=4,method="inclusive")
        expected = dict(n=len(values),minimum=min(values),q1=q[0],median=statistics.median(values),q3=q[2],maximum=max(values))
        for field,value in expected.items():
            equal(actual[field],value,label+"/"+field)
        check(actual["values"] == values,label+"/raw values")
    paired_signs = []
    for result in report["results"]:
        k = key(result)
        selected = sorted([r for r in rounds if key(r) == k and r["phase"] == "measured"],key=lambda r:r["round"])
        check([r["round"] for r in selected] == list(range(7)), "seven unique measured repeats " + str(k))
        flat = {field:result[field] for field in ("layout","variant","method",*ledger_fields)}
        for timer in ("cpu","wall"):
            values = [r[timer+"_ns_per_case"] for r in selected]
            verify_distribution(result[timer+"_ns_per_case"],values,str(k)+timer)
            for q in ("median","q1","q3"):
                flat[timer+"_us_per_case_"+q] = result[timer+"_ns_per_case"][q]/1000
            for baseline in ("joined_full","guard_joined"):
                base = {r["round"]:r for r in rounds if key(r) == (*k[:2],baseline) and r["phase"] == "measured"}
                deltas = [r[timer+"_ns"]-base[r["round"]][timer+"_ns"] for r in selected]
                ratios = [r[timer+"_ns"]/base[r["round"]][timer+"_ns"] for r in selected]
                verify_distribution(result["paired_"+timer+"_ns_vs_"+baseline],deltas,str(k)+timer+baseline+"deltas")
                verify_distribution(result["paired_"+timer+"_ratio_vs_"+baseline],ratios,str(k)+timer+baseline+"ratios")
                flat["paired_"+timer+"_extra_us_per_case_vs_"+baseline] = statistics.median(deltas)/50931/1000
                flat["paired_"+timer+"_ratio_vs_"+baseline] = statistics.median(ratios)
                paired_signs.append(dict(layout=k[0],variant=k[1],method=k[2],baseline=baseline,timer=timer,
                                         positive=sum(v>0 for v in deltas),zero=sum(v==0 for v in deltas),negative=sum(v<0 for v in deltas)))
        equal(result["median_wall_cases_per_second"],1e9/result["wall_ns_per_case"]["median"],"normalized throughput")
        csv_rows.append(flat)
    with (out/"summary.csv").open("w",newline="") as stream:
        writer = csv.DictWriter(stream,fieldnames=list(csv_rows[0]))
        writer.writeheader();writer.writerows(csv_rows)
    tests = ET.parse(out/"pytest.xml").getroot()
    suites = [tests] if tests.tag == "testsuite" else list(tests.findall("testsuite"))
    test_summary = {k:sum(int(s.get(k,0)) for s in suites) for k in ("tests","failures","errors","skipped")}
    check(test_summary == dict(tests=46,failures=0,errors=0,skipped=0), "focused test evidence")
    files = ["preparation.json","native_verification.json","rounds.jsonl","benchmark.json","summary.csv","pytest.xml"]
    result = dict(status="passed" if not failures else "failed",created_utc=datetime.now(timezone.utc).isoformat(),checks=checks,failures=failures,
                  rows=180,warmup_rows=40,measured_rows=140,full_workload_cases_per_row=50931,native_policy_case_checks=1018620,
                  pytest=test_summary,paired_delta_signs=paired_signs,files_sha256={str((out/f).relative_to(ROOT)):sha(out/f) for f in files},
                  summary_script_sha256=sha(Path(__file__)),scope="Independent arithmetic/source-hash reconciliation of recorded SQLite evidence, not another native experiment or a deployment validity claim. Interrupted-attempt records are excluded in their entirety.")
    (out/"verification.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:result[k] for k in ("status","checks","failures","pytest")},indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
