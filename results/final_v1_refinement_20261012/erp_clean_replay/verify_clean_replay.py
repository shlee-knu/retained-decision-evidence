"""Cross-check the archived driver replay without rerunning ERPNext.

Use --check-host with the retained external workspace to additionally inspect
the source checkouts, SQL snapshot, and task-owned service cleanup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_trace(path):
    rows = []
    for line in path.read_text().splitlines():
        row = json.loads(line)
        rows.append({
            "event": row["event"], "file": row["file"],
            "function": row["function"], "line": row["line"],
            "document": {k: v for k, v in row["document"].items()
                         if k not in {"name", "return_against"}},
            "linked_order_count": len(row.get("linked_purchase_orders", [])),
            "guard_order": {k: v for k, v in row.get("guard_purchase_order", {}).items()
                            if k != "name"},
            "validation_statuses": sorted(row.get("validation_status_map", {}).values()),
            "exception_type": row.get("exception", {}).get("type"),
        })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--check-host", action="store_true")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--output", type=Path, help="Optional new verification record; otherwise print summary only.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    old = args.original.resolve()
    bindings = {}
    for name in ("reproduce.py", "run_upstream_traced.py", "summarize.py",
                 "python_requirements_lock.txt", "pins.json"):
        assert (root / name).read_bytes() == (old / name).read_bytes(), name
        bindings[name] = sha(root / name)
    commands = json.loads((root / "commands.json").read_text())
    assert all(row["exit_code"] == row["expected_exit_code"] for row in commands)
    assert [row["label"] for row in commands].count("test_before") == 1
    assert [row["label"] for row in commands].count("test_after") == 1
    labels = [row["label"] for row in commands]
    assert labels.index("test_before") < labels.index("reset_test_database")
    assert labels.index("reset_test_database") < labels.index("flush_isolated_cache")
    assert labels.index("flush_isolated_cache") < labels.index("test_after")
    assert labels[-1] == "validate_results"
    source = json.loads((root / "source_manifest.json").read_text())
    old_source = json.loads((old / "source_manifest.json").read_text())
    source_key = lambda row: (row["version"], row["path"])
    assert sorted(source["erpnext_files"], key=source_key) == sorted(old_source["erpnext_files"], key=source_key)
    assert source["upstream_regression_identical_between_versions"]
    test_hashes = {r["sha256"] for r in source["erpnext_files"]
                   if r["path"].endswith("test_purchase_receipt.py")}
    assert len(test_hashes) == 1
    lock = {line for line in (root / "python_requirements_lock.txt").read_text().splitlines()
            if line and not line.startswith("#")}
    freeze = {line for line in (root / "python_freeze.txt").read_text().splitlines()
              if line and not line.startswith(("#", "-e "))}
    assert freeze == lock
    original_summary = json.loads((old / "summary.json").read_text())
    current_summary = json.loads((root / "summary.json").read_text())
    assert current_summary["checks_passed"]
    traces = {}
    for label, guard_count, events in (("before", 3, 197), ("after", 5, 276)):
        before = normalized_trace(old / f"{label}_trace.jsonl")
        replay = normalized_trace(root / f"{label}_trace.jsonl")
        assert replay == before, label
        assert len(replay) == events
        result = json.loads((root / f"{label}_test_result.json").read_text())
        assert result == original_summary["runs"][label]["test_result"]
        assert current_summary["runs"][label]["all_guard_call_count"] == guard_count
        traces[label] = {"events": len(replay), "guard_calls": guard_count,
                         "normalized_trace_matches_original": True,
                         "normalization": "Omit generated document/order identifiers and exception message text; preserve event order, source line, status, docstatus, is_return, linked-order count and exception type."}
    isolation = json.loads((root / "container_isolation.json").read_text())
    assert len(isolation["containers"]) == 3
    assert all(not row["port_bindings"] for row in isolation["containers"])
    runtime = json.loads((root / "runtime_versions.json").read_text())
    pins = json.loads((root / "pins.json").read_text())
    assert runtime["frappe_commit"] == pins["frappe"] and not runtime["frappe_worktree_status"]
    host = {"checked": False}
    if args.check_host:
        assert args.workdir is not None
        host = {"checked": True, "source_checkouts": {}}
        for name, pin in (("frappe", pins["frappe"]), ("erpnext", pins["after"])):
            path = args.workdir / "bench" / "apps" / name
            commit = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
            status = subprocess.check_output(["git", "-C", str(path), "status", "--porcelain"], text=True).strip()
            assert commit == pin and not status
            host["source_checkouts"][name] = {"commit": commit, "clean": True}
        snapshot = json.loads((root / "database_snapshot.json").read_text())
        assert sha(args.workdir / "baseline.sql") == snapshot["sha256"]
        host["initialized_snapshot_sha256"] = snapshot["sha256"]
        names = subprocess.check_output(["docker", "ps", "-a", "--format", "{{.Names}}"], text=True).splitlines()
        provenance = json.loads((root / "observer_provenance.json").read_text())
        prefix = provenance["new_container_prefix"]
        assert not any(name.startswith(prefix) for name in names)
        networks = subprocess.check_output(["docker", "network", "ls", "--format", "{{.Name}}"], text=True).splitlines()
        assert prefix not in networks
        preexisting = []
        for row in provenance["preexisting_containers"]:
            identity, name = row.split()[:2]
            state = json.loads(subprocess.check_output(["docker", "inspect", identity], text=True))[0]
            assert state["Name"].lstrip("/") == name
            assert state["State"]["Running"] == (" Up " in row)
            preexisting.append({"id": identity, "name": name, "running": state["State"]["Running"]})
        host.update({"task_containers_removed": True, "task_network_removed": True,
                     "preexisting_containers_preserved": preexisting})
    result = {"checks_passed": True, "driver_exit_code": 0,
              "original_driver_executed_without_modification": True,
              "bindings": bindings, "erpnext_file_hashes_match_original": len(source["erpnext_files"]),
              "noneditable_dependency_versions_match_lock": len(lock),
              "upstream_test_bytes_identical_across_versions": True,
              "traces": traces, "host": host,
              "scope": "Fresh environment replay of one existing generated regression fixture; no new independent application case or performance measurement."}
    if args.output is not None:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"checks_passed": True, "host_checked": args.check_host,
                      "dependency_versions": len(lock), "erpnext_file_hashes": len(source["erpnext_files"])}))


if __name__ == "__main__":
    main()
