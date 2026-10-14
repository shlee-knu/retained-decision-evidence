#!/usr/bin/env python3
"""Independent stdlib-only readback of the new native P/T functional comparison.

Imports the earlier independent declarative checker, not either executor,
diagnostic implementation, catalog generator, source adapter or report builder.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT = ROOT / "results/repair_revision_20261010/methods/check_repair_methods.py"
spec = importlib.util.spec_from_file_location("final_v1_independent_predicates", INDEPENDENT)
ind = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ind)
BLOCKS = ("profile", "first_times")
METHODS = ("checked_api", "ordinary_worklist")
SCENARIOS = ("all_authorized", "times_unavailable", "times_wrong_request")


def check(value, message):
    if not value:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def rows(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def status(old, new):
    return "insufficient" if len(new) == 2 else "safe" if new == old else "stale_verdict"


def mask_names(masks):
    return [[block for index, block in enumerate(BLOCKS) if mask & (1 << index)] for mask in masks]


def independent_selection(receipts):
    classes, representatives, mapping = {}, [], {}
    selected = []
    for receipt in receipts:
        rid = receipt["receipt_id"]
        check(rid not in mapping, "Duplicate retained ID")
        query = ind.key(receipt)
        key = query + (receipt["verdict"],)
        if key not in classes:
            classes[key] = len(classes)
            representatives.append(receipt)
        mapping[rid] = classes[key]
    for target in ind.TARGETS:
        for receipt in receipts:
            old, new, robust = ind.inspect_query(ind.key(receipt), target)
            check(old == [receipt["verdict"]], "Old admission not certified")
            if robust == [3]:
                check(new == [False, True] and receipt["observed"] == {}, "Selected P/T condition")
                selected.append({"target": target, "receipt_id": receipt["receipt_id"],
                                 "class_index": mapping[receipt["receipt_id"]],
                                 "robust_additional_sets": [["profile", "first_times"]]})
    return representatives, mapping, selected


def verify_reports(bundles, representatives, receipt_pin):
    check(set(bundles) == set(ind.TARGETS), "Report target coverage")
    count = 0
    for target, bundle in bundles.items():
        check(bundle["bundle_sha256"] == digest({k: v for k, v in bundle.items() if k != "bundle_sha256"}), "Bundle content hash")
        check(bundle["provenance"]["receipt_store_sha256"] == receipt_pin, "Report archive binding")
        for key, artifact in bundle["artifacts"].items():
            check(digest(artifact) == key and digest(artifact["content"]) == artifact["content_sha256"], "Artifact content binding")
        for name, pin in bundle["source_hashes"].items():
            check(ind.sha(ROOT / name) == pin, "Bundle source binding")
        check(len(bundle["reports"]) == len(representatives), "Report class cardinality")
        by_request = {r["request_id"]: r for r in bundle["reports"]}
        check(len(by_request) == len(representatives), "Duplicate report class")
        for index, receipt in enumerate(representatives):
            report = by_request["class:" + str(index)]
            check(report["report_sha256"] == digest({k: v for k, v in report.items() if k != "report_sha256"}), "Report content hash")
            check(report["receipt"] == receipt and report["receipt_id"] == receipt["receipt_id"] and report["receipt_sha256"] == digest(receipt), "Literal representative binding")
            check(report["snapshot_sha256"] == receipt["snapshot_sha256"], "Report snapshot binding")
            check(report["problem"] == "procurement_" + target, "Report target name")
            check(bundle["artifacts"][report["bindings"]["old_rule"]]["content"] == ind.CATALOGS["old"], "Old rule binding")
            check(bundle["artifacts"][report["bindings"]["new_rule"]]["content"] == ind.CATALOGS[target], "New rule binding")
            for side in ("old_domain", "new_domain"):
                domain = bundle["artifacts"][report["bindings"][side]]["content"]
                check(domain["id"] == "cartesian:v1" and domain["guarantees"] == [] and tuple(domain["profiles"]) == ind.PROFILES and tuple(domain["alphabet"]) == ind.ACTIVITIES, "Domain binding")
            query = ind.key(receipt)
            old, new, robust = ind.inspect_query(query, target)
            check(report["status"] == status(old, new) and report["old_valid"] is True, "Independent report status")
            check(report["old_verdict_candidates"] == old and report["new_verdict_candidates"] == new, "Independent report candidate labels")
            check(report["robust_additional_sets"] == mask_names(robust), "Independent complete minimal robust sets")
            check(report["old_completion_classes"] == len(ind.completions(*query, "old")) and report["new_completion_classes"] == len(ind.completions(*query, target)), "Independent completion count")
            witnesses = report["labeled_witnesses"]
            check(len(witnesses) == len(new) and {r["new_verdict"] for r in witnesses} == set(new), "Witness label coverage")
            for witness in witnesses:
                raw = witness["raw"]
                check(raw["activities"] == receipt["activities"] and all(raw[k] == v for k, v in receipt["observed"].items()), "Witness literal retention")
                base = tuple(dict.fromkeys(raw["activities"]))
                check(raw["profile"] in ind.PROFILES and set(raw["first_times"]) == set(base), "Witness supported complete fields")
                clock = ind.stamps(raw["first_times"])
                check(witness["old_domain_member"] is True and witness["new_domain_member"] is True, "Witness domain flags")
                check(witness["old_verdict"] == ind.decision(base, raw["profile"], clock, "old") and witness["new_verdict"] == ind.decision(base, raw["profile"], clock, target), "Independent witness labels")
            count += 1
    return count


def expected_row(original, full, target, scenario, class_index):
    """Reconstruct policy obligations from independent labels and source literals."""
    old, new, robust = ind.inspect_query(ind.key(original), target)
    target_digest = digest(ind.CATALOGS[target])
    result = {"schema_version": "executed-receipt-repair/v1", "source_case_id": original["receipt_id"],
              "strategy": "adaptive_p_first", "target": "procurement_" + target,
              "target_catalog_sha256": target_digest, "original_receipt_sha256": digest(original),
              "initial_status": status(old, new), "initial_robust_additional_sets": mask_names(robust),
              "action": "unresolved", "reason": None, "capability_checks": [], "attempted_reads": [],
              "successful_reads": [], "acquisition_completed": False, "accepted_responses": [],
              "replacement_receipt": None, "replacement_verified": False, "scenario": scenario,
              "change_target": target, "class_index": class_index, "source_calls": []}
    current = deepcopy(original)
    for block in BLOCKS:
        candidates = {row[2] for row in ind.completions(*ind.key(current), target)}
        if len(candidates) == 1:
            break
        if block in current["observed"]:
            continue
        capability = "source_unavailable" if scenario == "times_unavailable" and block == "first_times" else "authorized"
        result["capability_checks"].append({"block": block, "state": capability})
        result["source_calls"].append({"operation": "capability", "block": block,
                                       "request_receipt_sha256": digest(current), "returned": capability})
        if capability != "authorized":
            result.update(reason="source_unavailable", blocked_block=block)
            return result
        result["attempted_reads"].append(block)
        response = {"case_id": original["receipt_id"], "snapshot_sha256": original["snapshot_sha256"],
                    "request_receipt_sha256": digest(current), "activities": deepcopy(full["activities"]),
                    "block": block, "complete": True, "value": deepcopy(full[block])}
        if scenario == "times_wrong_request" and block == "first_times":
            response["request_receipt_sha256"] = "0" * 64
        result["source_calls"].append({"operation": "read", "block": block,
                                       "request_receipt_sha256": digest(current), "returned": deepcopy(response)})
        if scenario == "times_wrong_request" and block == "first_times":
            result.update(reason="read_request_mismatch", blocked_block=block)
            return result
        current["observed"][block] = deepcopy(full[block])
        result["successful_reads"].append(block)
        result["accepted_responses"].append(response)
    candidates = {row[2] for row in ind.completions(*ind.key(current), target)}
    check(len(candidates) == 1, "Independent terminal fiber not singleton")
    replacement = deepcopy(current)
    replacement["catalog_sha256"] = target_digest
    replacement["verdict"] = next(iter(candidates))
    actual = ind.decision(tuple(dict.fromkeys(full["activities"])), full["profile"], ind.stamps(full["first_times"]), target)
    check(actual == replacement["verdict"], "Independent full-source verdict")
    result.update(action="replaced", reason="acquired_sufficient_evidence" if result["successful_reads"] else "retained_sufficient_evidence",
                  acquisition_completed=bool(result["successful_reads"]), replacement_receipt=replacement, replacement_verified=True)
    return result


def aggregate(ledger):
    return {"episodes": len(ledger), "actions": dict(Counter(r["action"] for r in ledger)),
            "reasons": dict(Counter(r["reason"] for r in ledger)),
            "attempted_reads": dict(Counter(b for r in ledger for b in r["attempted_reads"])),
            "successful_reads": dict(Counter(b for r in ledger for b in r["successful_reads"])),
            "verified_replacements": sum(r["replacement_verified"] for r in ledger)}


def verify_run(folder):
    frozen = load(folder / "execution_freeze.json")
    for name, pin in frozen["files"].items():
        check(ind.sha(ROOT / name) == pin, "Frozen code/input mismatch: " + name)
    check(tuple(frozen["protocol"]["targets"]) == ind.TARGETS and tuple(frozen["protocol"]["scenarios"]) == SCENARIOS, "Protocol target/scenario coverage")
    receipts = [row["receipt"] for row in rows(ROOT / ind.RECEIPTS)]
    by_id = {r["receipt_id"]: r for r in receipts}
    representatives, mapping, selected = independent_selection(receipts)
    selected_keys = {(r["target"], r["receipt_id"]) for r in selected}
    historical = load(ROOT / "results/repair_revision_20261010/methods/independent_expected_cases.json")
    check(selected_keys == {(r["target"], r["case_id"]) for r in historical}, "Reconstructed selection differs from prior challenge")
    needed = {r["receipt_id"] for r in selected}
    source = {}
    source_count = 0
    with gzip.open(ROOT / ind.SOURCE, "rt") as stream:
        for line in stream:
            row = json.loads(line)
            source_count += 1
            if row["case_id"] in needed:
                check(row["case_id"] not in source, "Duplicate source case")
                source[row["case_id"]] = row
    check(set(source) == needed, "Incomplete source join")
    for rid in needed:
        original, full = by_id[rid], source[rid]
        check(original["catalog_sha256"] == digest(ind.CATALOGS["old"]) and original["domain_version"] == "cartesian:v1", "Old rule/domain binding")
        check(original["snapshot_sha256"] == frozen["files"][ind.SOURCE], "Old snapshot binding")
        check(original["activities"] == full["activities"] and all(full[k] == v for k, v in original["observed"].items()), "Original/source literal mismatch")
    expected = [expected_row(by_id[item["receipt_id"]], source[item["receipt_id"]], item["target"], scenario, item["class_index"])
                for scenario in SCENARIOS for item in selected]
    summary = {"retained_receipts": len(receipts), "classes_per_target": len(representatives),
               "target_class_reports": len(representatives) * len(ind.TARGETS),
               "selected_case_target_pairs": len(selected), "distinct_source_ids": len(needed),
               "selected_per_target": {target: sum(r["target"] == target for r in selected) for target in ind.TARGETS},
               "scenarios": {s: aggregate([r for r in expected if r["scenario"] == s]) for s in SCENARIOS},
               "per_target_scenarios": {t: {s: aggregate([r for r in expected if r["scenario"] == s and r["change_target"] == t]) for s in SCENARIOS} for t in ind.TARGETS}}
    methods = {}
    manifests = {}
    for method in METHODS:
        base = folder / method
        manifest = load(base / "manifest.json")
        check(set(manifest["files"]) == {"class_reports.json", "selected_ids.json", "repair_ledger.jsonl.gz", "summary.json"}, "Method payload set")
        for name, item in manifest["files"].items():
            check(ind.sha(base / name) == item["sha256"] and (base / name).stat().st_size == item["bytes"], "Persisted payload integrity")
        report_count = verify_reports(load(base / "class_reports.json"), representatives, frozen["files"][ind.RECEIPTS])
        check(load(base / "selected_ids.json") == selected, "Independent exact selected IDs")
        ledger = rows(base / "repair_ledger.jsonl.gz")
        check(len(ledger) == len(expected), "Replay row coverage")
        for got, wanted in zip(ledger, expected):
            check(got == wanted, "Independent replay transcript/replacement mismatch: " + str((wanted["scenario"], wanted["change_target"], wanted["source_case_id"])))
        check(load(base / "summary.json") == summary, "Independent aggregate counts")
        methods[method] = {"verified_reports": report_count, "verified_replays": len(ledger), "selected_pairs": len(selected)}
        manifests[method] = manifest
    equality = {name: manifests[METHODS[0]]["files"][name] == manifests[METHODS[1]]["files"][name]
                for name in manifests[METHODS[0]]["files"]}
    check(all(equality.values()), "Observed equivalent payload bytes differ")
    return {"status": "passed", "source_rows_scanned": source_count,
            "retained_receipts_scanned": len(receipts), "target_receipt_pairs_checked": len(receipts) * len(ind.TARGETS),
            "methods": methods, "summary": summary, "payload_byte_equality": equality,
            "total_replay_rows": len(expected) * len(METHODS),
            "files_sha256": {str(p.relative_to(folder)): ind.sha(p) for method in METHODS for p in sorted((folder / method).iterdir())},
            "execution_freeze_sha256": ind.sha(folder / "execution_freeze.json"),
            "checker_sha256": ind.sha(Path(__file__)), "independent_predicate_checker_sha256": ind.sha(INDEPENDENT),
            "scope": "Three declared local conditions, existing selected native cases and finite Cartesian P/T domain. New implementation coverage, not independent field data, all-failure equivalence, latency evidence, authentication or authorization validation."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify_run(args.run)
    with args.output.open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "total_replay_rows": result["total_replay_rows"], "summary": result["summary"]}, indent=2))
