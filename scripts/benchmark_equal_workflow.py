#!/usr/bin/env python3
"""Paired whole-workflow comparison with an independently authored ordinary implementation.

The timing protocol is locked before warmup. Shared imports, parser/schema,
source adapter, writer and independent verifier are documented in the protocol.
"""
from __future__ import annotations
import argparse
from collections import Counter
import cProfile
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pstats
import resource
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
import benchmark_audit_workflow as shared
from ordinary_audit_workflow import OrdinaryWorkflow
PROTOCOL = ROOT / "configs/equal_workflow_protocol.json"
METHODS = ("checked_api", "ordinary_worklist")


def protocol():
    base = shared.read_json(shared.PROTOCOL)
    base.update(shared.read_json(PROTOCOL))
    return base


def select(prepared, settings):
    """Select native IDs without duplicates; inclusion choices do not use timings."""
    if settings == "full":
        return prepared
    if settings == "representatives":
        return shared.group_receipts([row["receipt"] for row in prepared["classes"]], protocol())
    kind, count = settings.split(":")
    count = int(count)
    if kind == "n":
        representatives = {row["receipt"]["receipt_id"] for row in prepared["classes"]}
        chosen = set(representatives)
        for receipt in prepared["receipts"]:
            if len(chosen) >= count:
                break
            chosen.add(receipt["receipt_id"])
    elif kind == "k":
        sizes = Counter(index for _, index in prepared["mapping"])
        wanted = sorted(sizes, key=lambda k: (-sizes[k], k))[:count]
        chosen = {prepared["classes"][k]["receipt"]["receipt_id"] for k in wanted}
        for rid, index in prepared["mapping"]:
            if len(chosen) >= 1000:
                break
            if index in wanted:
                chosen.add(rid)
        shared.check(len(chosen) == 1000, "K scaling population")
    else:
        raise ValueError("unknown selection")
    return shared.group_receipts([r for r in prepared["receipts"] if r["receipt_id"] in chosen], protocol())


def recovery(prepared, source, generated, engine, method, profile=None):
    buffer, counts, statuses = io.BytesIO(), Counter(), Counter()
    replacement_hash = hashlib.sha256()
    split = Counter()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as stream:
        for receipt, (rid, index) in zip(prepared["receipts"], prepared["mapping"]):
            shared.check(receipt["receipt_id"] == rid, "retained order")
            begin = time.perf_counter_ns() if profile is not None else 0
            row = engine.execute(receipt, source)
            if profile is not None:
                split["execution_ns"] += time.perf_counter_ns() - begin
                begin = time.perf_counter_ns()
            shared.check(row["initial_status"] == generated["class_reports"][index]["status"], "class/recovery diagnosis mismatch")
            shared.check(row["action"] == "replaced" and row["replacement_verified"], "workflow unresolved")
            row["class_index"] = index
            encoded = shared.json_bytes(row)
            replacement_hash.update(shared.json_bytes(row["replacement_receipt"]))
            if profile is not None:
                split["encoding_and_checks_ns"] += time.perf_counter_ns() - begin
                begin = time.perf_counter_ns()
            stream.write(encoded)
            if profile is not None:
                split["gzip_write_ns"] += time.perf_counter_ns() - begin
            counts["replacements"] += 1
            counts["profile_reads"] += row["successful_reads"].count("profile")
            counts["first_times_reads"] += row["successful_reads"].count("first_times")
            statuses[row["initial_status"]] += 1
    shared.check(dict(statuses) == generated["status_counts"], "recovery status totals")
    if profile is not None:
        profile.update(split)
    return buffer.getvalue(), dict(counts), replacement_hash.hexdigest()


def host_sample():
    """Read-only contention context; unrelated user processes are not controlled."""
    return {"load_average": list(os.getloadavg()),
            "cpu0_proc_stat": next(line for line in Path("/proc/stat").read_text().splitlines() if line.startswith("cpu0 ")),
            "top_process_names": subprocess.run(["ps", "-eo", "pid,comm,pcpu", "--sort=-pcpu"], capture_output=True, text=True, check=True).stdout.splitlines()[:13]}


def execute_child(method, output, selection, profiling=False):
    setup = time.perf_counter_ns()
    config = protocol()
    shared.check(config["cpu_affinity"] in os.sched_getaffinity(0), "CPU unavailable")
    os.sched_setaffinity(0, {config["cpu_affinity"]})
    from logistics_validation.receipt_repair import PublicSnapshot, ReceiptRepair
    checker = shared.independent_checker(config)
    setup_ms = (time.perf_counter_ns() - setup) / 1e6
    phases = []
    def phase(name, action):
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        result = action()
        phases.append({"stage": name, "wall_ms": (time.perf_counter_ns()-wall)/1e6,
                       "cpu_ms": (time.process_time_ns()-cpu)/1e6,
                       "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
        return result
    host_before = host_sample()
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    prepared = phase("retained_store_read_validate_group", lambda: select(shared.load_receipts(config), selection))
    source = phase("snapshot_hash_read_index", lambda: PublicSnapshot(ROOT/config["snapshot_source"], config["pinned_files"][config["snapshot_source"]], capabilities={"profile":"authorized","first_times":"authorized"}))
    def construct():
        if method == "checked_api":
            generated = shared.construct_reports(prepared, config)
            engine = ReceiptRepair("procurement_workflow_strict", generated["target"])
        else:
            engine = OrdinaryWorkflow(shared.read_json(ROOT/config["old_catalog"]), shared.read_json(ROOT/config["target_catalog"]))
            generated = engine.construct_reports(prepared, config)
        return generated, engine
    generated, engine = phase("class_reports_and_exact_id_list", construct)
    split = {} if profiling else None
    profiler = cProfile.Profile() if profiling else None
    def recover():
        if profiler:
            profiler.enable()
        value = recovery(prepared, source, generated, engine, method, split)
        if profiler:
            profiler.disable()
        return value
    ledger, counts, fingerprint = phase("checked_recovery_and_ledger_encoding", recover)
    manifest_hash, manifest = phase("artifact_serialization_and_fsync", lambda: shared.persist_artifacts(output, generated, ledger, counts, fingerprint))
    verification = phase("persisted_readback_semantic_verification", lambda: shared.verify_persisted(output, manifest_hash, prepared, source, config, checker))
    total = {"wall_ms": (time.perf_counter_ns()-wall)/1e6, "cpu_ms": (time.process_time_ns()-cpu)/1e6,
             "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    if selection == "full":
        shared.check(verification["reports"] == config["expected"]["observation_classes"] and verification["receipts"] == config["expected"]["receipts"] and verification["affected_ids"] == config["expected"]["affected_ids"] and verification["counts"] == config["expected"]["counts"], "full cohort reconciliation")
    result = {"host_before":host_before, "host_after":host_sample(), "method":method, "selection":selection, "profiling":profiling, "setup_ms":setup_ms, "stages":phases,
              "integrated_total":total, "verification":verification, "manifest_sha256":manifest_hash,
              "replacement_stream_sha256":fingerprint, "payload_files":manifest["files"],
              "source_rows_indexed":len(source.rows), "selected_receipt_ids_sha256":hashlib.sha256(shared.json_bytes([r["receipt_id"] for r in prepared["receipts"]])).hexdigest(),
              "class_sizes":dict(Counter(index for _,index in prepared["mapping"])),
              "environment":{"python":sys.version,"platform":platform.platform(),"pid":os.getpid(),"affinity":sorted(os.sched_getaffinity(0)),"hash_seed":os.environ.get("PYTHONHASHSEED"),"cpu_model":next((l.split(":",1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("model name")),platform.processor())}}
    if profiler:
        profiler.dump_stats(str(output/"recovery_profile.pstats"))
        report = io.StringIO()
        pstats.Stats(profiler, stream=report).strip_dirs().sort_stats("cumulative").print_stats(40)
        (output/"recovery_profile.txt").write_text(report.getvalue())
        result["instrumented_recovery_parts_ns"] = split
    return result


def freeze(output):
    config = protocol()
    pins = dict(config["pinned_files"])
    for name in ("scripts/benchmark_audit_workflow.py", "configs/audit_workflow_cost_protocol.json", "scripts/benchmark_equal_workflow.py", "scripts/ordinary_audit_workflow.py", "configs/equal_workflow_protocol.json", "tests/test_equal_workflow.py"):
        pins[name] = shared.sha(ROOT/name)
    shared.check(all(shared.sha(ROOT/name)==wanted for name,wanted in pins.items()), "source pin mismatch")
    shared.check(not output.exists(), "preserve run directory")
    output.mkdir(parents=True)
    (output/"execution_freeze.json").write_bytes(shared.json_bytes({"protocol":config,"files":pins,"created_unix_ns":time.time_ns()}))
    return config,pins


def run_child(output, label, method, selection, pins, profiling=False):
    command = [sys.executable, str(Path(__file__).resolve()), "--child", "--method", method, "--selection", selection, "--output",str(output/label)]
    if profiling:
        command.append("--profile")
    began=time.perf_counter_ns()
    completed=subprocess.run(command,cwd=ROOT,env={**os.environ,"PYTHONHASHSEED":"0"},capture_output=True,text=True)
    if completed.returncode:
        (output/(label+"_failure.txt")).write_text(completed.stdout+completed.stderr)
        raise RuntimeError("Child failed: "+label)
    row=json.loads(completed.stdout)
    row["subprocess_wall_ms"]=(time.perf_counter_ns()-began)/1e6
    row["stderr"]=completed.stderr
    (output/(label+".json")).write_bytes(shared.json_bytes(row))
    shared.check(all(shared.sha(ROOT/name)==wanted for name,wanted in pins.items()),"source changed during measurement")
    print(json.dumps({"completed":label,"wall_s":row["integrated_total"]["wall_ms"]/1000,"N":row["verification"]["receipts"],"K":row["verification"]["reports"]}),flush=True)
    return row


def summarize(rows):
    result={}
    for method in METHODS:
        subset=[r for r in rows if r["method"]==method]
        result[method]={"integrated_total":{m:shared.describe([r["integrated_total"][m] for r in subset]) for m in ("wall_ms","cpu_ms","peak_rss_kib")},
                        "stages":{s["stage"]:{m:shared.describe([next(x[m] for x in r["stages"] if x["stage"]==s["stage"]) for r in subset]) for m in ("wall_ms","cpu_ms")} for s in subset[0]["stages"]},
                        "verification":subset[0]["verification"],"payload_files":subset[0]["payload_files"]}
        shared.check(len({r["manifest_sha256"] for r in subset})==1,"nondeterministic within-method output")
    shared.check(len({r["replacement_stream_sha256"] for r in rows})==1,"replacement outputs differ")
    shared.check(len({json.dumps(r["verification"],sort_keys=True) for r in rows})==1,"verified obligations differ")
    shared.check(len({r["payload_files"]["affected_receipt_ids.jsonl.gz"]["sha256"] for r in rows})==1,"affected IDs differ")
    result["equivalence"]={"all_runs_independent_readback_passed":True,"replacement_stream_sha256":rows[0]["replacement_stream_sha256"],"affected_ids_sha256":rows[0]["payload_files"]["affected_receipt_ids.jsonl.gz"]["sha256"],"witness_contract":"same valid labels/complete minimal robust sets, independently verified; literal witness choices need not be byte identical"}
    return result


def run(output, mode):
    config,pins=freeze(output)
    rows=[]
    if mode=="paired":
        for round_no in range(-1,config["paired_measured_rounds"]):
            order=METHODS if round_no%2==0 else METHODS[::-1]
            pair=[]
            for method in order:
                label=("warmup" if round_no<0 else f"round_{round_no+1}")+"_"+method
                row=run_child(output,label,method,"full",pins)
                row["round"]=round_no
                pair.append(row)
            if round_no>=0:
                rows.extend(pair)
        report={"status":"passed","summary":summarize(rows),"protocol_sha256":shared.sha(PROTOCOL),"measured_rows":len(rows),"environment":rows[0]["environment"]}
        deltas=[]
        for i in range(config["paired_measured_rounds"]):
            pair={r["method"]:r["integrated_total"]["wall_ms"] for r in rows if r["round"]==i}
            deltas.append({"round":i+1,"checked_api_minus_ordinary_ms":pair["checked_api"]-pair["ordinary_worklist"],"checked_api_divided_by_ordinary":pair["checked_api"]/pair["ordinary_worklist"]})
        report["paired_differences"]=deltas
    elif mode=="profile":
        for method in METHODS:
            rows.append(run_child(output,"profile_"+method,method,"full",pins,True))
        report={"status":"passed","scope":"Separate cProfile/instrumentation run, excluded from timing comparison; no overhead-corrected timing inference.","rows":rows}
    elif mode=="scaling":
        for selection in config["scaling_selections"]:
            cell=[]
            for repeat in range(config["scaling_repeats"]):
                for method in (METHODS if repeat%2==0 else METHODS[::-1]):
                    cell.append(run_child(output,selection.replace(":","_")+f"_round_{repeat+1}_"+method,method,selection,pins))
            rows.append({"selection":selection,"summary":summarize(cell)})
        report={"status":"passed","scope":config["scaling_scope"],"cells":rows}
    else:
        raise ValueError("mode")
    (output/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--child",action="store_true")
    parser.add_argument("--method",choices=METHODS,default=METHODS[0])
    parser.add_argument("--selection",default="full")
    parser.add_argument("--profile",action="store_true")
    parser.add_argument("--mode",choices=("paired","profile","scaling"),default="paired")
    args=parser.parse_args()
    if args.child:
        print(json.dumps(execute_child(args.method,args.output.resolve(),args.selection,args.profile)))
    else:
        print(json.dumps(run(args.output.resolve(),args.mode),indent=2))
