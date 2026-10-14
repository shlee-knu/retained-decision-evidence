"""Revalidate a partial-observation receipt across catalogs and versioned domains.

This is conditional semantic revalidation, not authentication of retained values
or validation of an unread source guarantee. Native recovery reports logical
block reads, not SQL/network requests. Existing artifacts are never overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from compare_catalogs import read_catalog
from logistics_validation.catalog_audit import (
    ALPHABET, PROFILES, MASK_NAMES, catalog_json, concrete, observation,
    reference_time, reference_verdict, universe, verdict,
)
from logistics_validation.domain_audit import DOMAINS, domain_contains

DOMAIN_VERSIONS = {name + ":v1": name for name in DOMAINS}
CONDITIONAL_SCOPE = (
    "Conditional on truthful observed values, an unchanged source snapshot, and "
    "the actual input belonging to the declared new completion domain. A "
    "nonempty compatible fiber does not establish hidden-domain membership. "
    "Hash equality is a binding check, not source authentication."
)
SOURCE = ROOT / "results/v03/bpi_compact.jsonl.gz"
TRACES = ROOT / "results/v03/acquisition_access_traces.jsonl.gz"
PINNED_SOURCE = "3fdfe926a29d35c87a2652447df420bb5c726ab2c996f6317c830d75cc4a1b3b"
PINNED_TRACES = "0060fe4c8015fa6d7c49da8661acaf073bb28ef6f0dcd1fc9ca4f6b88fa336b6"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def catalog_digest(catalog):
    return hashlib.sha256(canonical(catalog_json(catalog))).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


@lru_cache(maxsize=1)
def states():
    return universe()


@lru_cache(maxsize=4)
def fibers(domain):
    out = [defaultdict(list) for _ in range(4)]
    for i, state in enumerate(states()):
        if domain_contains(state, domain):
            for mask in range(4):
                out[mask][observation(state, mask)].append(i)
    return tuple({key: tuple(ids) for key, ids in part.items()} for part in out)


def receipt_key(receipt):
    """Validate only values actually present in the receipt; no hidden input."""
    required = {"schema_version", "snapshot_sha256", "catalog_sha256", "domain_version",
                "activities", "observed", "verdict"}
    if not isinstance(receipt, dict) or not required <= receipt.keys() or set(receipt) - required - {"receipt_id"}:
        raise ValueError("Receipt needs the exact declared schema; hidden top-level fields are forbidden")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise ValueError("Unsupported receipt schema version")
    if type(receipt["verdict"]) is not bool:
        raise ValueError("Recorded verdict must be a Boolean")
    for name in ("snapshot_sha256", "catalog_sha256"):
        value = receipt[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Receipt hashes must be lowercase SHA-256 strings")
    if not isinstance(receipt["domain_version"], str) or receipt["domain_version"] not in DOMAIN_VERSIONS:
        raise ValueError("Unsupported receipt domain version")
    if "receipt_id" in receipt and not isinstance(receipt["receipt_id"], str):
        raise ValueError("receipt_id must be a string")
    activity = receipt["activities"]
    if not isinstance(activity, list) or any(not isinstance(a, str) or a not in ALPHABET for a in activity):
        raise ValueError("Activities must be the full repeated projection in the fixed alphabet")
    order = tuple(dict.fromkeys(ALPHABET.index(a) for a in activity))
    observed = receipt["observed"]
    if not isinstance(observed, dict) or set(observed) - {"profile", "first_times"}:
        raise ValueError("Only previously read profile and first_times blocks are permitted")
    mask, profile, ranks = 0, None, None
    if "profile" in observed:
        if observed["profile"] not in PROFILES:
            raise ValueError("Unknown observed profile")
        profile = PROFILES.index(observed["profile"])
        mask |= 1
    if "first_times" in observed:
        times = observed["first_times"]
        if not isinstance(times, dict) or set(times) != set(activity):
            raise ValueError("An observed T block must contain exactly one first timestamp per present activity")
        values = [reference_time(times[ALPHABET[a]]) for a in order]
        levels = {v: i for i, v in enumerate(sorted(set(values)))}
        ranks = tuple(levels[v] for v in values)
        mask |= 2
    return mask, (order, profile, ranks)


def make_receipt(features, mask, label, catalog, domain_version, snapshot_sha256):
    observed = {}
    if mask & 1:
        observed["profile"] = features["profile"]
    if mask & 2:
        observed["first_times"] = deepcopy(features["first_times"])
    return {"schema_version": 1, "snapshot_sha256": snapshot_sha256,
            "catalog_sha256": catalog_digest(catalog), "domain_version": domain_version,
            "activities": list(features["activities"]), "observed": observed, "verdict": bool(label)}


class Revalidator:
    def __init__(self, before, after, before_domain, after_domain, snapshot_sha256):
        if before_domain not in DOMAIN_VERSIONS or after_domain not in DOMAIN_VERSIONS:
            raise ValueError("Explicit supported versioned before/after domains are required")
        if not isinstance(snapshot_sha256, str) or len(snapshot_sha256) != 64 or any(c not in "0123456789abcdef" for c in snapshot_sha256):
            raise ValueError("Expected snapshot must be a lowercase SHA-256 string")
        self.before, self.after = before, after
        self.before_domain, self.after_domain = before_domain, after_domain
        self.snapshot = snapshot_sha256
        self.old_digest, self.new_digest = catalog_digest(before), catalog_digest(after)
        self.labels = (tuple(verdict(s, before) for s in states()), tuple(verdict(s, after) for s in states()))
        self.cache = {}

    def fiber_summary(self, mask, key, which):
        cached = (mask, key, which)
        if cached not in self.cache:
            version = (self.before_domain, self.after_domain)[which]
            ids = fibers(DOMAIN_VERSIONS[version])[mask].get(key, ())
            examples = {}
            for i in ids:
                examples.setdefault(self.labels[which][i], i)
            self.cache[cached] = (len(ids), examples)
        return self.cache[cached]

    def completion(self, index, receipt):
        state = states()[index]
        value = concrete(state)
        value["activities"] = list(receipt["activities"])
        value.update(deepcopy(receipt["observed"]))
        return {"features": value,
                "before_domain_member": domain_contains(state, DOMAIN_VERSIONS[self.before_domain]),
                "after_domain_member": domain_contains(state, DOMAIN_VERSIONS[self.after_domain]),
                "before_verdict": self.labels[0][index], "after_verdict": self.labels[1][index]}

    def revalidate(self, receipt, *, witnesses=True):
        mask, key = receipt_key(receipt)
        if receipt["catalog_sha256"] != self.old_digest or receipt["domain_version"] != self.before_domain:
            raise ValueError("Receipt old catalog/domain binding does not match supplied inputs")
        if receipt["snapshot_sha256"] != self.snapshot:
            raise ValueError("Receipt snapshot binding does not match; reusing retained values is unsupported")
        old_n, old_examples = self.fiber_summary(mask, key, 0)
        new_n, new_examples = self.fiber_summary(mask, key, 1)
        old_labels, new_labels = sorted(old_examples), sorted(new_examples)
        if not old_n:
            status, reason = "invalid_receipt", "empty_before_fiber"
        elif old_labels != [receipt["verdict"]]:
            status, reason = "invalid_receipt", "old_observation_does_not_certify_recorded_verdict"
        elif not new_n:
            status, reason = "unsupported", "empty_after_fiber"
        elif len(new_labels) == 2:
            status, reason = "insufficient", "new_compatible_completions_disagree"
        elif new_labels == [receipt["verdict"]]:
            status, reason = "safe", "recorded_verdict_remains_certified_conditionally"
        else:
            status, reason = "stale_verdict", "observation_sufficient_but_recorded_verdict_changed"
        out = {"status": status, "reason": reason, "observed_mask": MASK_NAMES[mask],
               "before_compatible_classes": old_n, "after_compatible_classes": new_n,
               "before_labels": old_labels, "after_labels": new_labels,
               "conditional_scope": CONDITIONAL_SCOPE,
               "before_domain_version": self.before_domain, "after_domain_version": self.after_domain,
               "before_catalog_sha256": self.old_digest, "after_catalog_sha256": self.new_digest,
               "snapshot_sha256": self.snapshot}
        if witnesses:
            out["compatible_new_completions"] = [self.completion(new_examples[y], receipt) for y in new_labels]
        return out

    def recover(self, receipt, read_block):
        """Read missing P then T only when needed; full input is never passed here."""
        original = self.revalidate(receipt, witnesses=False)
        if original["status"] == "invalid_receipt":
            return {"status": "invalid_receipt", "requested_blocks": [], "verdict": None,
                    "retained_observed": deepcopy(receipt["observed"]), "old_domain_still_compatible": bool(original["before_compatible_classes"])}
        current = deepcopy(receipt)
        requested = []
        while True:
            # After guarantee withdrawal, new observations can reveal a valid
            # NEW-domain input that violates the old guarantee. Do not pretend
            # the enlarged observation is the historical old receipt.
            mask, key = receipt_key(current)
            new_n, examples = self.fiber_summary(mask, key, 1)
            labels = sorted(examples)
            old_n, _ = self.fiber_summary(mask, key, 0)
            status = ("unsupported" if not new_n else "insufficient" if len(labels) == 2
                      else "safe" if labels == [receipt["verdict"]] else "stale_verdict")
            if status != "insufficient":
                return {"status": status, "requested_blocks": requested,
                        "verdict": labels[0] if status in {"safe", "stale_verdict"} else None,
                        "retained_observed": current["observed"], "old_domain_still_compatible": bool(old_n)}
            missing = next((name for name in ("profile", "first_times") if name not in current["observed"]), None)
            if missing is None:
                raise AssertionError("Fully observed supported state cannot be ambiguous")
            current["observed"][missing] = deepcopy(read_block(missing))
            requested.append(missing)


def verify_concrete(result, receipt, before, after):
    """Independent raw-event reference replay of each returned completion."""
    for item in result.get("compatible_new_completions", []):
        value = item["features"]
        assert value["activities"] == receipt["activities"]
        assert all(value[key] == field for key, field in receipt["observed"].items())
        assert reference_verdict(value, before) == item["before_verdict"]
        assert reference_verdict(value, after) == item["after_verdict"]
        from stress_acquisition import raw_time
        raw_clocks = [raw_time(value["first_times"][a]) for a in dict.fromkeys(value["activities"])]
        chronological = all(a <= b for a, b in zip(raw_clocks, raw_clocks[1:]))
        exclusion = value["profile"] != "Consignment" or not set(value["activities"]) & {"invoice", "clear"}
        membership = {"cartesian": True, "chronological": chronological,
                      "consignment_exclusion": exclusion, "both": chronological and exclusion}
        for side in ("before", "after"):
            assert membership[DOMAIN_VERSIONS[result[side + "_domain_version"]]] == item[side + "_domain_member"]


def replay_examples(path, output):
    source = json.loads(Path(path).read_text())
    records = []
    for spec in source["cases"]:
        before, after = (read_catalog(ROOT / spec[k]) for k in ("before_catalog", "after_catalog"))
        receipt = spec["receipt"]
        engine = Revalidator(before, after, spec["before_domain"], spec["after_domain"], receipt["snapshot_sha256"])
        result = engine.revalidate(receipt)
        assert result["status"] == spec["expected_status"], spec["name"]
        verify_concrete(result, receipt, before, after)
        records.append({"name": spec["name"], "expected_status": spec["expected_status"], "result": result})
    write_json(output / "examples.json", {"status": "passed", "cases": len(records),
               "source_sha256": sha(path), "records": records})
    return len(records)


def replay_native(output):
    from itertools import zip_longest
    from audit_representations import part
    from stress_acquisition import expected_violation

    assert sha(SOURCE) == PINNED_SOURCE and sha(TRACES) == PINNED_TRACES
    before = read_catalog(ROOT / "examples/baseline_catalog.json")
    after = read_catalog(ROOT / "examples/strict_consignment_catalog.json")
    engine = Revalidator(before, after, "cartesian:v1", "cartesian:v1", PINNED_SOURCE)
    statuses, requests, original_reads, fresh_reads = Counter(), Counter(), Counter(), Counter()
    prior_bytes = repair_bytes = fresh_bytes = n = scanned = 0
    labels, ids = Counter(), hashlib.sha256()
    no_longer_minimal = 0
    samples = {}
    record_path = output / "native_receipts.jsonl.gz"
    with SOURCE.open("rb") as raw, TRACES.open("rb") as trace_raw, record_path.open("xb") as record_raw:
        with gzip.open(raw, "rt") as cases, gzip.open(trace_raw, "rt") as traces:
            with gzip.GzipFile(fileobj=record_raw, mode="wb", mtime=0, filename="") as zipped:
                with io.TextIOWrapper(zipped, encoding="utf-8") as records:
                    for source_line, trace_line in zip_longest(cases, traces):
                        assert source_line is not None and trace_line is not None
                        case, trace = json.loads(source_line), json.loads(trace_line)
                        assert case["case_id"] == trace["case_id"] and case["document"] == trace["document"]
                        scanned += 1
                        if part(case["document"], 17) != "test":
                            continue
                        n += 1
                        ids.update((case["case_id"] + "\n").encode())
                        mask = trace["masks"]["permissive"]["structural_order"]
                        new_mask = trace["masks"]["strict_consignment"]["structural_order"]
                        old_truth = not expected_violation(case, False)
                        new_truth = not expected_violation(case, True)
                        assert old_truth == (not case["violation"])
                        receipt = make_receipt(case, mask, old_truth, before, "cartesian:v1", PINNED_SOURCE)
                        receipt["receipt_id"] = case["case_id"]
                        result = engine.revalidate(receipt, witnesses=False)
                        statuses[result["status"]] += 1
                        issued = []

                        def read_block(name):
                            assert name not in receipt["observed"] and name not in issued
                            issued.append(name)
                            return case[name]

                        recovered = engine.recover(receipt, read_block)
                        assert recovered["verdict"] is new_truth
                        assert recovered["requested_blocks"] == issued
                        requests.update(issued)
                        labels[str(new_truth)] += 1
                        for bit, name, bytekey in ((1, "profile", "profile_bytes"), (2, "first_times", "time_bytes")):
                            if mask & bit:
                                original_reads[name] += 1
                                prior_bytes += trace[bytekey]
                            if new_mask & bit:
                                fresh_reads[name] += 1
                                fresh_bytes += trace[bytekey]
                            if name in issued:
                                count = len(canonical({name: case[name]}))
                                assert count == trace[bytekey]
                                repair_bytes += count
                        if new_mask & mask == new_mask and new_mask != mask:
                            no_longer_minimal += 1
                            assert result["status"] == "safe"
                        if result["status"] not in samples:
                            detailed = engine.revalidate(receipt)
                            verify_concrete(detailed, receipt, before, after)
                            samples[result["status"]] = {"case_id": case["case_id"], "source_trace": case["source_trace"],
                                                         "receipt": receipt, "result": detailed}
                        records.write(json.dumps({"receipt": receipt, "initial_status": result["status"],
                                                   "issued_logical_reads": issued, "recovered_verdict": recovered["verdict"]},
                                                  ensure_ascii=False, separators=(",", ":")) + "\n")
    assert scanned == 251734 and n == 50931
    # Known reconciliation targets declared before the new replay, not discoveries.
    assert statuses == {"safe": 17442, "insufficient": 33489}
    assert requests == {"profile": 33489} and no_longer_minimal == 5605
    assert fresh_reads["profile"] - original_reads["profile"] == 27884
    report = {"status": "passed", "source_cases_scanned": scanned, "receipt_cases": n,
              "case_id_order_sha256": ids.hexdigest(), "input_sha256": {str(p.relative_to(ROOT)): sha(p) for p in (SOURCE, TRACES)},
              "cohort": "Original salt-17 document-held-out workload; no new independent holdout",
              "receipt_origin": "Reconstructed retained observations from an immutable public derivative and archived masks; not a deployed cache",
              "interface": "Instrumented in-memory block accessor; counts are logical additional block reads, not SQL calls or measured latency",
              "conditional_scope": CONDITIONAL_SCOPE, "initial_status_counts": dict(statuses),
              "additional_logical_reads": {name: requests[name] for name in ("profile", "first_times")},
              "additional_payload_bytes": repair_bytes, "old_observations_logical_reads": dict(original_reads),
              "old_observations_payload_bytes": prior_bytes, "fresh_new_logical_reads": dict(fresh_reads),
              "fresh_new_payload_bytes": fresh_bytes,
              "retained_plus_repair_logical_reads": {k: original_reads[k] + requests[k] for k in ("profile", "first_times")},
              "retained_plus_repair_payload_bytes": prior_bytes + repair_bytes,
              "safe_receipts_with_now_redundant_old_observations": no_longer_minimal,
              "fresh_profile_read_increase": fresh_reads["profile"] - original_reads["profile"],
              "independent_raw_oracle_comparisons": 2 * n, "oracle_disagreements": 0,
              "recovered_verdict_counts": dict(labels), "samples": samples,
              "compressed_receipts_sha256": sha(record_path),
              "known_before_run": "33,489 added P recovery reads and 5,605 redundant old P observations were expected from inspected prior evidence; 27,884 is the fresh-execution net increase."}
    write_json(output / "native_summary.json", report)
    return report


def run_suite(output):
    output.mkdir(parents=True, exist_ok=True)
    if any(p.name not in {"pytest.xml", "pytest.txt"} for p in output.iterdir()):
        raise ValueError("Suite output must be new or contain only focused pytest records")
    examples = ROOT / "examples/second_receipt_cases.json"
    count = replay_examples(examples, output)
    native = replay_native(output)
    inputs = [SOURCE, TRACES, ROOT / "examples/baseline_catalog.json", ROOT / "examples/strict_consignment_catalog.json",
              ROOT / "examples/second_equivalent_catalog.json", ROOT / "examples/second_label_flip_catalog.json", examples,
              Path(__file__), ROOT / "src/logistics_validation/catalog_audit.py", ROOT / "src/logistics_validation/domain_audit.py",
              ROOT / "scripts/compare_catalogs.py", ROOT / "scripts/stress_acquisition.py", ROOT / "scripts/audit_representations.py",
              ROOT / "tests/test_receipt_revalidation.py"]
    report = {"status": "passed", "examples": count, "native_receipts": native["receipt_cases"],
              "input_sha256": {str(p.relative_to(ROOT)): sha(p) for p in inputs},
              "output_sha256": {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()},
              "design_prefix_sha256": hashlib.sha256((ROOT / "docs/second_receipt_evidence.md").read_text().split("## Execution evidence")[0].encode()).hexdigest(),
              "scope": "Conditional receipt classification and logical recovery replay; no new runtime benchmark, SQL experiment, source guarantees or natural-error truth."}
    write_json(output / "manifest.json", report)
    print(json.dumps({"status": "passed", "examples": count, "native_receipts": native["receipt_cases"],
                      "additional_logical_reads": native["additional_logical_reads"]}, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--suite", action="store_true", help="Run constructed examples and complete retained-observation replay")
    p.add_argument("--output", type=Path, required=True, help="New JSON file, or new directory with --suite")
    p.add_argument("--receipt", type=Path)
    p.add_argument("--before", type=Path)
    p.add_argument("--after", type=Path)
    p.add_argument("--before-domain", choices=DOMAIN_VERSIONS)
    p.add_argument("--after-domain", choices=DOMAIN_VERSIONS)
    p.add_argument("--snapshot-sha256")
    args = p.parse_args()
    try:
        if args.suite:
            if any((args.receipt, args.before, args.after, args.before_domain, args.after_domain, args.snapshot_sha256)):
                p.error("--suite uses the fixed example and native inputs; individual receipt arguments are incompatible")
            run_suite(args.output)
        else:
            if not all((args.receipt, args.before, args.after, args.before_domain, args.after_domain, args.snapshot_sha256)):
                p.error("Individual mode requires --receipt, --before, --after, both domains and --snapshot-sha256")
            before, after = read_catalog(args.before), read_catalog(args.after)
            receipt = json.loads(args.receipt.read_text())
            engine = Revalidator(before, after, args.before_domain, args.after_domain, args.snapshot_sha256)
            result = engine.revalidate(receipt)
            verify_concrete(result, receipt, before, after)
            result["input_file_sha256"] = {str(x): sha(x) for x in (args.receipt, args.before, args.after)}
            write_json(args.output, result)
    except (ValueError, KeyError, TypeError, FileExistsError) as error:
        p.error(str(error))


if __name__ == "__main__":
    main()
