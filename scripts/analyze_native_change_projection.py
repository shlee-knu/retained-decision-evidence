"""Project the frozen authored-edit census onto archived retained receipts.

Only new output directories are written. This is a descriptive replay, not a
benchmark or a new cohort. Raw predicates and finite grouping come from the
separately implemented checker, never from a candidate diagnostic engine.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_compact_evidence as oracle
from analyze_census_robustness import stream_object_items

PROTOCOL = "configs/native_change_projection_protocol.json"
STATUSES = ("safe", "stale_verdict", "insufficient")
MASK_NAMES = {1: "P", 2: "T", 3: "PT"}


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load(path):
    path = Path(path)
    with gzip.open(path, "rt") if path.suffix == ".gz" else path.open() as stream:
        return json.load(stream)


def jsonl(path):
    with gzip.open(path, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


@contextmanager
def jsonl_writer(path):
    with Path(path).open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8") as stream:
                yield lambda value: stream.write(encode(value).decode() + "\n")


def id_digest(ids):
    """Match prior evidence: sorted UTF-8 IDs joined by LF, no final LF."""
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()


def timestamp(value):
    # Independent exact normalization; no candidate receipt encoder is called.
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", value)
    if not match or match[3] == "-00:00":
        raise ValueError("Unsupported first timestamp")
    whole = datetime.fromisoformat(match[1] + ("+00:00" if match[3] == "Z" else match[3]))
    delta = whole - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return Fraction(delta.days * 86400 + delta.seconds) + Fraction(int(match[2] or "0"), 10 ** len(match[2] or ""))


def observation_key(activities, observed, profiles):
    if not isinstance(observed, dict) or set(observed) - {"profile", "first_times"}:
        raise ValueError("Unknown observed block")
    order = tuple(dict.fromkeys(activities))
    base = tuple(oracle.ACTIVITIES.index(name) for name in order)
    mask = int("profile" in observed) + 2 * int("first_times" in observed)
    profile = profiles.index(observed["profile"]) if mask & 1 else None
    ranks = None
    if mask & 2:
        if not isinstance(observed["first_times"], dict) or set(observed["first_times"]) != set(order):
            raise ValueError("Incomplete first-times block")
        clocks = tuple(timestamp(observed["first_times"][name]) for name in order)
        unique = sorted(set(clocks))
        ranks = tuple(unique.index(clock) for clock in clocks)
    return base, mask, profile, ranks


def check_source_match(receipt, source, trace, profiles):
    if receipt["receipt_id"] != source["case_id"] or source["case_id"] != trace["case_id"]:
        raise ValueError("Case-ID mismatch")
    if receipt["activities"] != source["activities"]:
        raise ValueError("Activity literal mismatch")
    key = observation_key(receipt["activities"], receipt["observed"], profiles)
    if key[1] != trace["masks"]["permissive"]["structural_order"]:
        raise ValueError("Archived retention-mask mismatch")
    if any(value != source[name] for name, value in receipt["observed"].items()):
        raise ValueError("Retained literal mismatch")
    return key


def classify(key, fiber, positives, old_verdict, states):
    yes = fiber & positives
    if yes in (0, fiber):
        return ("safe" if (yes == fiber) == old_verdict else "stale_verdict"), [0]
    robust = oracle.hit_all_differences(oracle.difference_masks(yes, fiber ^ yes, states), key[1])
    return "insufficient", robust


def adaptive_reads(key, actual_state, partitions, positives):
    base, mask, profile, ranks = key
    actual_base, actual_ranks, actual_profile = actual_state
    assert actual_base == base
    reads = []
    for bit, field in ((1, "P"), (2, "T")):
        fiber = partitions[(base, mask, profile, ranks)]
        yes = fiber & positives
        if yes in (0, fiber):
            return reads, yes == fiber
        if not mask & bit:
            reads.append(field)
            mask |= bit
            if bit == 1:
                profile = actual_profile
            else:
                ranks = actual_ranks
    fiber = partitions[(base, mask, profile, ranks)]
    yes = fiber & positives
    assert yes in (0, fiber)
    return reads, yes == fiber


def descriptive(values):
    return {"minimum": min(values), "median": statistics.median(values), "maximum": max(values)} if values else None


def selection_summary(names, summaries, affected_ids, affected_classes, native_count):
    statuses, requirements, reads = Counter(), Counter(), Counter()
    for name in names:
        statuses.update(summaries[name]["status_counts"])
        requirements.update(summaries[name]["additional_requirements"])
        reads.update(summaries[name]["adaptive_additional_reads"])
    values = [summaries[name]["status_counts"]["insufficient"] for name in names]
    union = set().union(*(affected_ids[name] for name in names))
    classes = set().union(*(affected_classes[name] for name in names))
    assert sum(statuses.values()) == len(names) * native_count
    assert sum(requirements.values()) == statuses["insufficient"]
    return {"targets": len(names), "native_cases_per_target": native_count,
            "target_case_pairs": len(names) * native_count, "status_counts": dict(statuses),
            "additional_requirements": dict(requirements), "adaptive_additional_reads": dict(reads),
            "targets_with_insufficient_records": sum(v > 0 for v in values),
            "distinct_insufficient_case_ids": len(union), "distinct_insufficient_native_classes": len(classes),
            "sorted_insufficient_union_ids_sha256": id_digest(union),
            "insufficient_records_per_target_all": descriptive(values),
            "insufficient_records_per_target_nonzero": descriptive([v for v in values if v]),
            "target_names": names}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    cfg = load(ROOT / PROTOCOL)
    paths = [cfg[k] for k in ("baseline", "strict_anchor", "finite_domain", "observations", "saved_census",
        "saved_selection", "source", "access_traces", "receipts", "prior_two_block_check", "independent_predicates")]
    paths += [PROTOCOL, "scripts/analyze_native_change_projection.py", "scripts/analyze_census_robustness.py",
              "tests/test_native_change_projection.py"]
    pins = {name: sha(ROOT / name) for name in sorted(paths)}
    save(output / "protocol_snapshot.json", {"protocol": cfg, "input_sha256": pins,
        "written_before_outcomes_utc": datetime.now(timezone.utc).isoformat()})
    baseline, strict = load(ROOT / cfg["baseline"]), load(ROOT / cfg["strict_anchor"])
    profiles = list(baseline)
    table = load(ROOT / cfg["finite_domain"])
    states = [(tuple(b), tuple(t), p) for b, t, p in table["states"]]
    state_ids = {state: i for i, state in enumerate(states)}
    assert len(states) == len(state_ids) == 8612
    raw = [(tuple(oracle.ACTIVITIES[a] for a in base),
            {oracle.ACTIVITIES[a]: rank for a, rank in zip(base, ranks)}, profiles[profile])
           for base, ranks, profile in states]
    targets = oracle.declared_targets(baseline)
    assert len(targets) == 80
    catalogs = {"baseline": baseline, **targets, "strict_consignment": strict}
    vectors = {name: bytes(oracle.raw_label(catalog, *record) for record in raw)
               for name, catalog in catalogs.items()}
    for name, vector in vectors.items():
        assert list(vector) == table["catalogs"][name]["labels"], name
    del table
    positive = {name: oracle.state_bits(i for i, label in enumerate(vector) if label)
                for name, vector in vectors.items()}
    # Selection is freshly derived from complete semantics, not native outcomes.
    groups = defaultdict(list)
    for name in sorted(targets):
        groups[vectors[name]].append(name)
    representatives = sorted(names[0] for names in groups.values())
    valid = {name for name in targets if all(any(value for value, state in zip(vectors[name], states) if state[2] == p)
                                            for p in range(len(profiles)))}
    sets = {"all_edits": sorted(targets), "all_profiles_satisfiable": sorted(valid),
            "semantic_representatives": representatives,
            "satisfiable_semantic_representatives": [name for name in representatives if name in valid]}
    prior_selection = load(ROOT / cfg["saved_selection"])
    assert all(names == prior_selection["sets"][name]["target_names"] for name, names in sets.items())
    assert len(sets["satisfiable_semantic_representatives"]) == 39
    assert vectors["strict_consignment"] not in groups
    partitions = oracle.group_states(states)
    queries = load(ROOT / cfg["observations"])
    class_ids = {oracle.query_key(query): i for i, query in enumerate(queries)}
    receipts, strict_old = {}, {}
    for row in jsonl(ROOT / cfg["receipts"]):
        receipt = row["receipt"]
        cid = receipt["receipt_id"]
        assert cid not in receipts
        receipts[cid] = receipt
        strict_old[cid] = row
    assert len(receipts) == 50931
    canonical_catalog = {profile: {"required": sorted(rule["required"], key=oracle.ACTIVITIES.index),
        "forbidden": sorted(rule["forbidden"], key=oracle.ACTIVITIES.index),
        "edges": sorted(rule["edges"], key=lambda pair: tuple(oracle.ACTIVITIES.index(a) for a in pair))}
        for profile, rule in baseline.items()}
    catalog_hash = hashlib.sha256(encode(canonical_catalog)).hexdigest()
    native, members, seen, complete_support = {}, defaultdict(list), set(), Counter()
    for source, trace in zip(jsonl(ROOT / cfg["source"]), jsonl(ROOT / cfg["access_traces"]), strict=True):
        cid = source["case_id"]
        assert cid == trace["case_id"] and cid not in seen
        seen.add(cid)
        if cid not in receipts:
            continue
        receipt = receipts[cid]
        assert receipt["schema_version"] == 1 and type(receipt["verdict"]) is bool
        assert receipt["domain_version"] == "cartesian:v1"
        assert receipt["snapshot_sha256"] == pins[cfg["source"]] and receipt["catalog_sha256"] == catalog_hash
        key = check_source_match(receipt, source, trace, profiles)
        fiber = partitions[key]
        assert fiber & positive["baseline"] in (0, fiber)
        assert receipt["verdict"] == (fiber & positive["baseline"] == fiber)
        assert queries[class_ids[key]]["old_verdict"] == receipt["verdict"]
        full = observation_key(source["activities"], {"profile": source["profile"], "first_times": source["first_times"]}, profiles)
        state = (full[0], full[3], full[2])
        sid = state_ids[state]
        assert bool(vectors["baseline"][sid]) == receipt["verdict"]
        class_id = class_ids[key]
        native[cid] = {"class_id": class_id, "key": key, "state_id": sid}
        members[class_id].append(cid)
        complete_support[sid] += 1
    assert set(native) == set(receipts) and len(seen) == 251734
    assert len(members) == 20 and 0 < len(complete_support) <= len(states)
    keys_by_class = {value["class_id"]: value["key"] for value in native.values()}
    class_rows = [{"census_class_id": cid, "query": queries[cid], "native_records": len(members[cid]),
                   "sorted_case_ids_sha256": id_digest(members[cid])} for cid in sorted(members)]
    save(output / "native_classes.json", class_rows)
    with jsonl_writer(output / "native_case_mapping.jsonl.gz") as write:
        for cid, item in sorted(native.items()):
            write({"case_id": cid, "census_class_id": item["class_id"], "complete_state_id": item["state_id"]})
    diagnostics = {}
    for name in sorted(targets) + ["strict_consignment"]:
        diagnostics[name] = {cid: classify(key, partitions[key], positive[name], queries[cid]["old_verdict"], states)
                             for cid, key in keys_by_class.items()}
    checks = 0
    with gzip.open(ROOT / cfg["saved_census"], "rt") as stream:
        visited = set()
        for name, rows in stream_object_items(stream):
            assert name in targets and name not in visited
            visited.add(name)
            for cid in members:
                status, robust = diagnostics[name][cid]
                assert rows[cid] == [status, robust], (name, cid)
                checks += 1
        assert visited == set(targets)
    summaries, affected_ids, affected_classes, pt_ids = {}, {}, {}, {}
    read_cache = {}
    with jsonl_writer(output / "insufficient_target_case_index.jsonl.gz") as write:
        for name in sorted(diagnostics):
            statuses = Counter({s: 0 for s in STATUSES})
            needs = Counter({n: 0 for n in MASK_NAMES.values()})
            reads_count = Counter({"P": 0, "T": 0, "total": 0})
            changed, preserved_insuff = 0, 0
            ids_by_status = {s: set() for s in STATUSES}
            pt_ids[name], affected_classes[name] = set(), set()
            rows = []
            for cid in sorted(members):
                status, robust = diagnostics[name][cid]
                ids = sorted(members[cid])
                statuses[status] += len(ids)
                ids_by_status[status].update(ids)
                if status == "insufficient":
                    assert len(robust) == 1 and robust[0] in MASK_NAMES
                    needs[MASK_NAMES[robust[0]]] += len(ids)
                    affected_classes[name].add(cid)
                    if robust == [3]:
                        pt_ids[name].update(ids)
                rows.append({"census_class_id": cid, "native_records": len(ids), "status": status, "robust_masks": robust})
                for case_id in ids:
                    item = native[case_id]
                    sid = item["state_id"]
                    cache_key = (name, cid, sid)
                    if cache_key not in read_cache:
                        acquired, label = adaptive_reads(item["key"], states[sid], partitions, positive[name])
                        assert label == bool(vectors[name][sid])
                        read_cache[cache_key] = acquired
                    acquired = read_cache[cache_key]
                    reads_count.update(acquired)
                    reads_count["total"] += len(acquired)
                    changed += vectors[name][sid] != vectors["baseline"][sid]
                    if status == "insufficient":
                        preserved_insuff += vectors[name][sid] == vectors["baseline"][sid]
                        write({"target": name, "case_id": case_id, "census_class_id": cid,
                               "robust_mask": robust[0], "P_first_additional_reads": acquired})
                    else:
                        assert not acquired
                    if name == "strict_consignment":
                        assert status == strict_old[case_id]["initial_status"]
                        assert acquired == ["P" if field == "profile" else "T" for field in strict_old[case_id]["issued_logical_reads"]]
                        assert bool(vectors[name][sid]) == strict_old[case_id]["recovered_verdict"]
            affected_ids[name] = ids_by_status["insufficient"]
            summaries[name] = {"native_cases": len(native), "status_counts": dict(statuses),
                "additional_requirements": dict(needs), "adaptive_additional_reads": dict(reads_count),
                "complete_input_verdict_changes": changed,
                "insufficient_records_with_preserved_complete_verdict": preserved_insuff,
                "status_id_sha256": {s: id_digest(ids_by_status[s]) for s in STATUSES},
                "native_observation_classes": rows,
                "all_profiles_satisfiable": name in valid if name in targets else True,
                "target_truth_vector_sha256": hashlib.sha256(vectors[name]).hexdigest()}
    selected_summaries = {name: selection_summary(names, summaries, affected_ids, affected_classes, len(native))
                          for name, names in sets.items()}
    # Prior four-target result covers PT classes, not every insufficient record
    # of those targets. Verify the exact same subset and each recorded digest.
    previous = load(ROOT / cfg["prior_two_block_check"])["cohorts"]["heldout_receipts"]
    pt_reads = Counter(P_reads=0, T_reads_after_P=0, stop_after_P=0, affected=0)
    for name, expected in previous["targets"].items():
        assert id_digest(pt_ids[name]) == expected["sorted_affected_ids_sha256"]
        assert len(pt_ids[name]) == expected["counts"].get("affected", 0)
        for case_id in pt_ids[name]:
            item = native[case_id]
            acquired = read_cache[name, item["class_id"], item["state_id"]]
            pt_reads.update({"affected": 1, "P_reads": int("P" in acquired),
                "T_reads_after_P": int("T" in acquired), "stop_after_P": int(acquired == ["P"])})
    assert dict(pt_reads) == previous["aggregates"]
    assert summaries["strict_consignment"]["status_counts"] == {"safe": 17442, "stale_verdict": 0, "insufficient": 33489}
    assert summaries["strict_consignment"]["complete_input_verdict_changes"] == 0
    assert all(sha(ROOT / name) == expected for name, expected in pins.items())
    verification = {"status": "passed", "source_cases_scanned": len(seen), "native_cases": len(native),
        "native_observation_classes": len(members), "native_complete_states": len(complete_support),
        "raw_finite_truth_labels_compared": sum(map(len, vectors.values())),
        "saved_native_census_status_and_robust_rows_compared": checks,
        "fresh_selection_matches_all_prior_sets": True, "strict_receipt_replays_compared": len(native),
        "strict_affected_ids": len(affected_ids["strict_consignment"]),
        "four_weakening_two_block_subset": dict(pt_reads),
        "four_weakening_id_digests_match": True, "input_hashes_unchanged": True,
        "shared_inputs": "Declared finite state enumeration, block meaning and archive; raw predicates/grouping/robust masks use the pre-existing separately written checker, not candidate engines.",
        "interpretation": cfg["analysis_type"]}
    save(output / "verification.json", verification)
    save(output / "target_summaries.json", summaries)
    result = {"status": "passed", "cohort": cfg["cohort"], "analysis_type": cfg["analysis_type"],
        "native_observation_classes": len(members), "native_complete_states": len(complete_support),
        "affected_definition": cfg["affected_definition"], "sets": selected_summaries,
        "strict_anchor_separate": summaries["strict_consignment"]}
    save(output / "summary.json", result)
    filtered = selected_summaries["satisfiable_semantic_representatives"]
    all_edits = selected_summaries["all_edits"]
    values = filtered["insufficient_records_per_target_all"]
    nonzero = filtered["insufficient_records_per_target_nonzero"]
    lines = ["Native projection of the authored changes (same archive and archived retention)", "",
        "Selection | targets with any insufficient record / targets | insufficient target/case pairs | distinct affected IDs | P | T | PT | median [min, max] insufficient records per target"]
    for name in ("all_edits", "satisfiable_semantic_representatives"):
        item = selected_summaries[name]
        counts = item["insufficient_records_per_target_all"]
        lines.append(f"{name} | {item['targets_with_insufficient_records']}/{item['targets']} | {item['status_counts']['insufficient']:,} | {item['distinct_insufficient_case_ids']:,} | " +
            " | ".join(f"{item['additional_requirements'][m]:,}" for m in ("P", "T", "PT")) +
            f" | {counts['median']:,} [{counts['minimum']:,}, {counts['maximum']:,}]")
    lines += ["", f"Projecting the same 39 satisfiable, semantically distinct authored changes onto the 50,931 saved receipts yields {filtered['targets_with_insufficient_records']} changes with at least one insufficient record. "
        f"Across all 39 targets, the median workload is {values['median']:,} records (range {values['minimum']:,}–{values['maximum']:,}); among nonzero workloads it is {nonzero['median']:,} "
        f"(range {nonzero['minimum']:,}–{nonzero['maximum']:,}). The {filtered['status_counts']['insufficient']:,} insufficient target/case pairs involve {filtered['distinct_insufficient_case_ids']:,} distinct case IDs. "
        f"Their robust additional requirements are P for {filtered['additional_requirements']['P']:,} pairs, T for {filtered['additional_requirements']['T']:,}, and P/T for {filtered['additional_requirements']['PT']:,}. "
        f"The full 80-edit set has {all_edits['targets_with_insufficient_records']} affected targets and {all_edits['status_counts']['insufficient']:,} insufficient pairs. "
        "These are dependent projections of authored rules onto the existing archive, not frequencies of actual organizational changes or new independent validation. "
        "The strict two-edit anchor remains separate and reproduces 33,489 affected IDs. The four weakening targets' previously reported two-block subset reproduces 114 cases and 199 P-first logical reads.", ""]
    (output / "manuscript_insert.txt").write_text("\n".join(lines))
    save(output / "manifest.json", {"command": [sys.executable, "scripts/analyze_native_change_projection.py", "--output", str(output)],
        "input_sha256": pins, "output_sha256": {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()},
        "elapsed_seconds_not_a_benchmark": time.perf_counter() - started,
        "completed_utc": datetime.now(timezone.utc).isoformat()})
    print("\n".join(lines[:5]), flush=True)
    print(json.dumps(verification, indent=2), flush=True)


if __name__ == "__main__":
    main()
