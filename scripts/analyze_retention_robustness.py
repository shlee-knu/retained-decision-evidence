#!/usr/bin/env python3
"""Replay four old retention policies on the fixed public receipt cohort.

The independent oracle uses raw JSON rules, separately generated completions,
and observed fields only. Existing finite tables are comparison evidence, not
the source of its stopping or diagnostic decisions. Access counts are logical.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import io
from itertools import permutations, product, zip_longest
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logistics_validation.catalog_audit import (  # noqa: E402
    ALPHABET, PROFILES, CertificateTable, abstract, generated_catalogs,
    observation, universe, verdict,
)
from logistics_validation.domain_audit import DomainCertificateTable  # noqa: E402

PROTOCOL = "configs/retention_robustness_protocol.json"
SOURCE = "results/v03/bpi_compact.jsonl.gz"
TRACES = "results/v03/acquisition_access_traces.jsonl.gz"
RECEIPTS = "results/second/receipt_revalidation/native_receipts.jsonl.gz"
FIELDS = ((1, "profile"), (2, "first_times"))
POLICIES = ("structural_order", "profile_first", "time_first", "always_both")
DOMAINS = ("cartesian", "consignment_exclusion")


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def timestamp(value):
    """Separate exact ISO timestamp reader; no candidate normalization call."""
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", value)
    if not match or match[3] == "-00:00":
        raise ValueError(value)
    whole = datetime.fromisoformat(match[1] + ("+00:00" if match[3] == "Z" else match[3]))
    delta = whole - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return Fraction(delta.days * 86400 + delta.seconds) + Fraction(int(match[2] or "0"), 10 ** len(match[2] or ""))


def raw_verdict(raw, rules):
    positions = {name: raw["activities"].index(name) for name in set(raw["activities"])}
    clocks = {name: timestamp(raw["first_times"][name]) for name in positions}
    rule = rules[raw["profile"]]
    failures = [name not in positions for name in rule["required"]]
    failures += [name in positions for name in rule["forbidden"]]
    for predecessor, successor in rule["edges"]:
        if successor in positions:
            failures.append(predecessor not in positions or positions[predecessor] >= positions[successor]
                            or clocks[predecessor] > clocks[successor])
    return not any(failures)


def supported(raw, domain):
    if domain not in DOMAINS:
        raise ValueError(domain)
    return domain == "cartesian" or raw["profile"] != "Consignment" or not ({"invoice", "clear"} & set(raw["activities"]))


def raw_key(activities, observed):
    order = tuple(dict.fromkeys(activities))
    ranks = None
    if "first_times" in observed:
        times = tuple(timestamp(observed["first_times"][a]) for a in order)
        unique = sorted(set(times))
        ranks = tuple(unique.index(t) for t in times)
    return order, observed.get("profile"), ranks


class RawOracle:
    def __init__(self, before, after):
        self.rules = (before, after)
        self.fibers = {(d, side): defaultdict(set) for d in DOMAINS for side in (0, 1)}
        self.complete = {}
        # This enumeration does not call State, universe, weak_orders or verdict.
        for length in range(5):
            for names in permutations(tuple(before[PROFILES[0]]["required"]), length):
                rank_vectors = [()] if not length else product(range(length), repeat=length)
                for ranks in rank_vectors:
                    if ranks and set(ranks) != set(range(max(ranks) + 1)):
                        continue
                    for profile in before:
                        raw = {"activities": list(names), "profile": profile,
                               "first_times": {a: f"2000-01-01T00:00:0{rank}Z" for a, rank in zip(names, ranks)}}
                        truth = tuple(raw_verdict(raw, rules) for rules in self.rules)
                        self.complete[(names, profile, tuple(ranks))] = truth
                        for domain in DOMAINS:
                            if not supported(raw, domain):
                                continue
                            for mask in range(4):
                                key = (names, profile if mask & 1 else None, tuple(ranks) if mask & 2 else None)
                                for side in (0, 1):
                                    self.fibers[domain, side][key].add(truth[side])

    def labels(self, activities, observed, domain, side):
        return self.fibers[domain, side].get(raw_key(activities, observed), set())


def acquire_old(activities, read, oracle, domain, policy, first_block):
    """Only this callback exposes each optional block after its choice is made."""
    observed, reads = {}, []
    order = (("profile", "first_times") if policy in ("profile_first", "always_both")
             else ("first_times", "profile") if policy == "time_first"
             else (("profile", "first_times") if first_block == 1 else ("first_times", "profile")))
    for field in order:
        if policy != "always_both" and len(oracle.labels(activities, observed, domain, 0)) == 1:
            break
        observed[field] = read(field)
        reads.append(field)
    labels = oracle.labels(activities, observed, domain, 0)
    assert len(labels) == 1
    return observed, reads, next(iter(labels))


def diagnose_and_repair(activities, observed, old_label, read, oracle, domain):
    old_labels = oracle.labels(activities, observed, domain, 0)
    assert old_labels == {old_label}, "Old observation must certify its recorded label"
    labels = oracle.labels(activities, observed, domain, 1)
    assert labels, "Same supported domain cannot lose all completions"
    action = "acquire" if len(labels) == 2 else "retain" if labels == {old_label} else "update"
    repaired, reads = dict(observed), []
    for field in ("profile", "first_times"):
        if len(labels) == 1:
            break
        if field not in repaired:
            repaired[field] = read(field)
            reads.append(field)
            labels = oracle.labels(activities, repaired, domain, 1)
    assert len(labels) == 1
    return action, repaired, reads, next(iter(labels))


def ledger_stream(stack, path):
    raw = stack.enter_context(path.open("xb"))
    compressed = stack.enter_context(gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0))
    return stack.enter_context(io.TextIOWrapper(compressed, encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/robustness_revision_20261011/retention/run")
    args = parser.parse_args()
    protocol = json.loads((ROOT / PROTOCOL).read_text())
    for name, expected in protocol["inputs"].items():
        assert sha(ROOT / name) == expected, name
    args.output.mkdir(parents=True, exist_ok=False)
    own = [PROTOCOL, "scripts/analyze_retention_robustness.py", "tests/test_retention_robustness.py"]
    freeze = {name: sha(ROOT / name) for name in own}
    write(args.output / "execution_freeze.json", {"prepared_utc": datetime.now(timezone.utc).isoformat(),
          "implementation_and_protocol": freeze, "inputs": protocol["inputs"], "prior_known_targets": protocol["known_reconciliation_targets"]})
    before = json.loads((ROOT / "examples/baseline_catalog.json").read_text())
    after = json.loads((ROOT / "examples/strict_consignment_catalog.json").read_text())
    oracle = RawOracle(before, after)
    states = universe()
    index = {s: i for i, s in enumerate(states)}
    catalogs = {name: value for name, value, _ in generated_catalogs()}
    labels = [tuple(verdict(s, catalogs[name]) for s in states) for name in ("baseline", "strict_consignment")]
    tables = {(domain, side): DomainCertificateTable(states, labels[side], domain) for domain in DOMAINS for side in (0, 1)}
    broad = CertificateTable(states, labels[0])
    truth_checks = fiber_checks = 0
    for i, state in enumerate(states):
        key = tuple(ALPHABET[a] for a in state.order), PROFILES[state.profile], state.ranks
        assert oracle.complete[key] == (labels[0][i], labels[1][i])
        truth_checks += 2
    assert len(oracle.complete) == len(states) == 8612
    for (domain, side), table in tables.items():
        for mask in range(4):
            for obs, ids in table.fibers[mask].items():
                order, profile, ranks = obs
                key = tuple(ALPHABET[a] for a in order), None if profile is None else PROFILES[profile], ranks
                assert oracle.fibers[domain, side][key] == {bool(table.labels[i]) for i in ids}
                fiber_checks += 1
    print(json.dumps({"finite_truth_checks": truth_checks, "finite_fiber_checks": fiber_checks}), flush=True)
    totals = {(d, p): Counter() for d in DOMAINS for p in POLICIES}
    classes = {(d, p): {} for d in DOMAINS for p in POLICIES}
    id_hashes = {(d, p, a): hashlib.sha256() for d in DOMAINS for p in POLICIES for a in ("retain", "update", "acquire", "unsupported")}
    cohort_ids, seen_ids = hashlib.sha256(), set()
    scans = archive_checks = raw_checks = receipt_checks = 0
    with ExitStack() as stack:
        source = stack.enter_context(gzip.open(ROOT / SOURCE, "rt"))
        traces = stack.enter_context(gzip.open(ROOT / TRACES, "rt"))
        receipts = stack.enter_context(gzip.open(ROOT / RECEIPTS, "rt"))
        ledgers = {(d, p): ledger_stream(stack, args.output / f"{d}__{p}.jsonl.gz") for d in DOMAINS for p in POLICIES}
        for source_line, trace_line in zip_longest(source, traces):
            assert source_line is not None and trace_line is not None
            raw, archived = json.loads(source_line), json.loads(trace_line)
            assert raw["case_id"] == archived["case_id"] and raw["document"] == archived["document"]
            scans += 1
            split = int.from_bytes(hashlib.sha256(f"projection-audit-v03:17:{raw['document']}".encode()).digest()[:8], "big") % 100
            if split < 80:
                continue
            case_id = raw["case_id"]
            assert case_id not in seen_ids
            seen_ids.add(case_id)
            cohort_ids.update((case_id + "\n").encode())
            saved = json.loads(next(receipts))
            assert saved["receipt"]["receipt_id"] == case_id
            state = abstract(raw)
            i = index[state]
            raw_labels = tuple(raw_verdict(raw, rules) for rules in (before, after))
            assert raw_labels == (labels[0][i], labels[1][i])
            assert raw_labels[0] is (not raw["violation"])
            raw_checks += 2
            sizes = {field: len(encode({field: raw[field]})) for _, field in FIELDS}
            assert sizes == {"profile": archived["profile_bytes"], "first_times": archived["time_bytes"]}
            for domain in DOMAINS:
                active = supported(raw, domain)
                assert active == tables[domain, 0].active[i]
                for policy in POLICIES:
                    key = domain, policy
                    counts = totals[key]
                    counts["cases"] += 1
                    if not active:
                        action = "unsupported"
                        row = {"case_id": case_id, "action": action, "reason": "complete_source_outside_trusted_domain"}
                    else:
                        counts["admitted"] += 1
                        observed, reads, old_label = acquire_old(raw["activities"], lambda field: raw[field], oracle, domain, policy, broad.structural_first[state.order])
                        mask = sum(bit for bit, field in FIELDS if field in observed)
                        assert tables[domain, 0].sufficient[i] & (1 << mask)
                        if domain == "cartesian":
                            assert mask == broad.policy_mask(i, policy) == archived["masks"]["permissive"][policy]
                            archive_checks += 1
                        action, repaired, additional, new_label = diagnose_and_repair(raw["activities"], observed, old_label, lambda field: raw[field], oracle, domain)
                        assert (old_label, new_label) == raw_labels
                        final_mask = sum(bit for bit, field in FIELDS if field in repaired)
                        assert tables[domain, 1].sufficient[i] & (1 << final_mask)
                        # The exact observer's fiber does not use the old Boolean as a new constraint.
                        class_key = raw_key(raw["activities"], observed)
                        class_id = hashlib.sha256(encode(class_key)).hexdigest()
                        group = classes[key].setdefault(class_id, {"observation": class_key, "old_mask": mask, "action": action, "cases": 0})
                        assert group["action"] == action
                        group["cases"] += 1
                        for field in reads:
                            counts["old_" + field + "_reads"] += 1
                            counts["retained_payload_bytes"] += sizes[field]
                        for field in additional:
                            counts["additional_" + field + "_reads"] += 1
                            counts["additional_payload_bytes"] += sizes[field]
                        row = {"case_id": case_id, "class_id": class_id, "old_mask": mask, "action": action,
                               "old_verdict": old_label, "new_verdict": new_label, "old_reads": reads,
                               "additional_reads": additional, "replacement_mask": final_mask,
                               "retained_payload_bytes": sum(sizes[f] for f in reads),
                               "additional_payload_bytes": sum(sizes[f] for f in additional)}
                        if domain == "cartesian" and policy == "structural_order":
                            assert saved["receipt"]["activities"] == raw["activities"]
                            assert saved["receipt"]["observed"] == observed and saved["receipt"]["verdict"] == old_label
                            assert saved["initial_status"] == {"retain": "safe", "update": "stale_verdict", "acquire": "insufficient"}[action]
                            assert saved["issued_logical_reads"] == additional and saved["recovered_verdict"] == new_label
                            receipt_checks += 1
                    counts[action] += 1
                    id_hashes[domain, policy, action].update((case_id + "\n").encode())
                    ledgers[key].write(encode(row).decode() + "\n")
            if len(seen_ids) % 10000 == 0:
                print(json.dumps({"case_ids_processed": len(seen_ids)}), flush=True)
        assert next(receipts, None) is None
    assert scans == 251734 and len(seen_ids) == receipt_checks == 50931 and archive_checks == 4 * 50931
    rows = []
    for domain in DOMAINS:
        for policy in POLICIES:
            counts = totals[domain, policy]
            class_rows = classes[domain, policy]
            counts["old_reads"] = counts["old_profile_reads"] + counts["old_first_times_reads"]
            counts["additional_reads"] = counts["additional_profile_reads"] + counts["additional_first_times_reads"]
            counts["combined_reads"] = counts["old_reads"] + counts["additional_reads"]
            counts["combined_payload_bytes"] = counts["retained_payload_bytes"] + counts["additional_payload_bytes"]
            fields = ("cases", "admitted", "retain", "update", "acquire", "unsupported", "old_profile_reads", "old_first_times_reads",
                      "old_reads", "additional_profile_reads", "additional_first_times_reads", "additional_reads", "combined_reads",
                      "retained_payload_bytes", "additional_payload_bytes", "combined_payload_bytes")
            row = {"domain": domain, "policy": policy, **{f: counts[f] for f in fields},
                   "old_observation_classes": len(class_rows), "affected_observation_classes": sum(v["action"] != "retain" for v in class_rows.values()),
                   "case_id_order_sha256_by_action": {a: id_hashes[domain, policy, a].hexdigest() for a in ("retain", "update", "acquire", "unsupported")}}
            assert row["cases"] == row["admitted"] + row["unsupported"] == sum(row[a] for a in ("retain", "update", "acquire", "unsupported"))
            rows.append(row)
            write(args.output / f"{domain}__{policy}__classes.json", {"classes": class_rows})
    original = rows[0]
    assert (original["cases"], original["retain"], original["acquire"], original["old_reads"], original["additional_profile_reads"], original["old_observation_classes"]) == (50931, 17442, 33489, 52855, 33489, 20)
    assert all(r["acquire"] == 0 for r in rows if r["policy"] == "always_both")
    assert freeze == {name: sha(ROOT / name) for name in freeze}
    summary = {"schema_version": 1, "status": "passed", "rows": rows,
               "verification": {"finite_raw_truth_checks": truth_checks, "finite_fiber_checks": fiber_checks,
                                "native_raw_truth_checks": raw_checks, "archived_policy_mask_checks": archive_checks,
                                "archived_structural_receipt_checks": receipt_checks, "scanned_source_cases": scans,
                                "case_id_order_sha256": cohort_ids.hexdigest()},
               "limits": protocol["limits"], "payload_encoding": protocol["byte_encoding"],
               "files": {p.name: sha(p) for p in sorted(args.output.iterdir()) if p.is_file()}}
    write(args.output / "summary.json", summary)
    print(json.dumps(summary["rows"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
