"""Post hoc sensitivity of the complete 80-edit census, with a streaming replay.

Run from the repository root:
  .venv/bin/python scripts/analyze_census_robustness.py --output NEW_DIRECTORY

The snapshot is written before any result is loaded. Existing evidence is read
only. Classification is recomputed from raw predicates with the separately
written checker, retaining only one target's saved rows at a time. Exact full
truth vectors determine groups; hashes only identify exported groups.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_compact_evidence as independent

PROTOCOL = ROOT / "configs/census_robustness_protocol.json"
STATUS = ("safe", "stale_verdict", "insufficient")
MASKS = {1: "P", 2: "T", 3: "PT"}


def load(path):
    path = Path(path)
    with gzip.open(path, "rt") if path.suffix == ".gz" else path.open() as handle:
        return json.load(handle)


def save(path, value):
    with Path(path).open("x") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stream_object_items(handle, chunk_size=1 << 16):
    """Yield one top-level JSON object entry; do not retain earlier values.

    Reject malformed separators, duplicate keys, truncation and trailing data.
    Each value must fit memory, but the whole object need not do so.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False

    def fill():
        nonlocal buffer, eof
        chunk = handle.read(chunk_size)
        if not chunk:
            eof = True
        buffer += chunk

    def whitespace():
        nonlocal buffer
        while True:
            buffer = buffer.lstrip()
            if buffer or eof:
                return
            fill()

    def token(wanted):
        nonlocal buffer
        whitespace()
        if not buffer.startswith(wanted):
            raise ValueError(f"Expected {wanted!r} in JSON object")
        buffer = buffer[len(wanted):]

    def value():
        nonlocal buffer
        whitespace()
        while True:
            try:
                result, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise
                fill()
                continue
            # A number may end exactly at the chunk boundary; complete its
            # token before accepting. Keys and values here are strings/arrays,
            # but this also makes the parser correct for arbitrary test values.
            if end == len(buffer) and not eof:
                fill()
                continue
            buffer = buffer[end:]
            return result

    token("{")
    whitespace()
    if buffer.startswith("}"):
        token("}")
    else:
        seen = set()
        while True:
            key = value()
            if not isinstance(key, str) or key in seen:
                raise ValueError("JSON object key must be a unique string")
            seen.add(key)
            token(":")
            item = value()
            yield key, item
            del item
            whitespace()
            if buffer.startswith("}"):
                token("}")
                break
            token(",")
    whitespace()
    if buffer or not eof:
        raise ValueError("Trailing data after JSON object")


def tally(rows):
    statuses = Counter({status: 0 for status in STATUS})
    requirements = Counter({name: 0 for name in MASKS.values()})
    for status, robust in rows:
        if status not in statuses:
            raise ValueError(f"Unknown status: {status}")
        if status == "insufficient":
            if len(robust) != 1 or robust[0] not in MASKS:
                raise ValueError("Expected one nonempty robust set on Cartesian two-block domain")
            requirements[MASKS[robust[0]]] += 1
        elif robust != [0]:
            raise ValueError("A decided observation must have empty additional requirement")
        statuses[status] += 1
    assert sum(requirements.values()) == statuses["insufficient"]
    return dict(status_counts=dict(statuses), additional_requirements=dict(requirements),
                rows=sum(statuses.values()))


def exact_groups(truth_vectors):
    groups = defaultdict(list)
    for name in sorted(truth_vectors):
        groups[truth_vectors[name]].append(name)
    return sorted(groups.values(), key=lambda aliases: aliases[0])


def select_targets(spec, groups, valid_names):
    if spec["semantic_deduplication"]:
        selected = [aliases[0] for aliases in groups]
    else:
        selected = [name for aliases in groups for name in aliases]
    if spec["profile_filter"]:
        selected = [name for name in selected if name in valid_names]
    return sorted(selected)


def combine(names, summaries, group_ids, old_classes):
    statuses = Counter({status: 0 for status in STATUS})
    requirements = Counter({name: 0 for name in MASKS.values()})
    for name in names:
        row = summaries[name]
        assert row["rows"] == old_classes
        statuses.update(row["status_counts"])
        requirements.update(row["additional_requirements"])
    denominator = old_classes * len(names)
    assert sum(statuses.values()) == denominator
    return dict(targets=len(names), semantic_families=len({group_ids[n] for n in names}),
                target_class_combinations=denominator, status_counts=dict(statuses),
                additional_requirements=dict(requirements), target_names=names)


def analyze(output):
    output.mkdir(parents=True, exist_ok=False)
    cfg = load(PROTOCOL)
    input_paths = [cfg[key] for key in ("baseline", "finite_domain", "observations", "saved_rows",
        "saved_aggregate", "independent_checker_result", "predicate_implementation")]
    input_paths += [str(PROTOCOL.relative_to(ROOT)), str(Path(__file__).resolve().relative_to(ROOT)),
                    "tests/test_census_robustness.py"]
    pins = {name: sha(ROOT / name) for name in sorted(input_paths)}
    save(output / "protocol_snapshot.json", dict(protocol=cfg, sha256=pins,
        saved_before_result_loading_utc=datetime.now(timezone.utc).isoformat(),
        command=f".venv/bin/python scripts/analyze_census_robustness.py --output {output}",
        replay="Use the same command with a fresh --output directory; compare summary.json and target_summaries.json byte-for-byte."))

    baseline = load(ROOT / cfg["baseline"])
    table = load(ROOT / cfg["finite_domain"])
    states = [(tuple(base), tuple(ranks), profile) for base, ranks, profile in table["states"]]
    profiles = list(baseline)
    assert len(profiles) == 4 and len(states) == len(set(states)) == 8612
    raw = [(tuple(independent.ACTIVITIES[a] for a in base),
            {independent.ACTIVITIES[a]: rank for a, rank in zip(base, ranks)}, profiles[profile])
           for base, ranks, profile in states]
    old = bytes(independent.raw_label(baseline, *record) for record in raw)
    assert list(old) == table["catalogs"]["baseline"]["labels"]
    old_bits = independent.state_bits(i for i, label in enumerate(old) if label)
    classes = {}
    for key, fiber in independent.group_states(states).items():
        positives = fiber & old_bits
        if positives in (0, fiber):
            classes[key] = fiber, positives == fiber
    queries = load(ROOT / cfg["observations"])
    keys = [independent.query_key(query) for query in queries]
    assert len(keys) == len(set(keys)) == len(classes) == 10436
    assert set(keys) == set(classes)
    assert all(query["old_verdict"] == classes[key][1] for query, key in zip(queries, keys))
    targets = independent.declared_targets(baseline)
    assert len(targets) == 80
    truth_vectors, acceptance = {}, {}
    for name, catalog in sorted(targets.items()):
        labels = bytes(independent.raw_label(catalog, *record) for record in raw)
        assert list(labels) == table["catalogs"][name]["labels"], name
        truth_vectors[name] = labels
        acceptance[name] = {profile: sum(label for label, record in zip(labels, raw) if record[2] == profile)
                            for profile in profiles}
    del table
    groups = exact_groups(truth_vectors)
    group_ids = {name: hashlib.sha256(truth_vectors[name]).hexdigest() for name in targets}
    assert len(set(group_ids.values())) == len(groups)
    valid = {name for name in targets if all(acceptance[name].values())}
    aliases = []
    for names in groups:
        assert len({name in valid for name in names}) == 1
        aliases.append(dict(representative=names[0], aliases=names,
            exact_truth_vector_sha256=group_ids[names[0]],
            all_profiles_satisfiable=names[0] in valid,
            accepting_states_by_profile=acceptance[names[0]],
            equivalent_to_baseline=truth_vectors[names[0]] == old))

    # Compact encodings permit exact row comparison without retaining all JSON
    # rows: two bytes per class, one code for status and one robust mask.
    group_rows = {}
    summaries, row_digests, seen = {}, {}, set()
    row_checks = alias_checks = 0
    with gzip.open(ROOT / cfg["saved_rows"], "rt") as handle:
        for name, rows in stream_object_items(handle):
            assert name in targets and name not in seen
            seen.add(name)
            assert len(rows) == len(keys)
            positives = independent.state_bits(i for i, label in enumerate(truth_vectors[name]) if label)
            exact = bytearray()
            row_digest = hashlib.sha256()
            for class_id, (key, saved) in enumerate(zip(keys, rows)):
                fiber, old_verdict = classes[key]
                yes = fiber & positives
                if yes in (0, fiber):
                    status = "safe" if (yes == fiber) == old_verdict else "stale_verdict"
                    derived = [status, [0]]
                else:
                    differences = independent.difference_masks(yes, fiber ^ yes, states)
                    derived = ["insufficient", independent.hit_all_differences(differences, key[1])]
                assert saved == derived, (name, class_id, saved, derived)
                assert len(saved[1]) == 1
                exact.extend((STATUS.index(saved[0]), saved[1][0]))
                row_digest.update(json.dumps([name, class_id, saved], separators=(",", ":")).encode() + b"\n")
                row_checks += 1
            group = group_ids[name]
            if group in group_rows:
                assert exact == group_rows[group], name
                alias_checks += len(rows)
            else:
                group_rows[group] = bytes(exact)
            summaries[name] = dict(tally(rows), truth_vector_sha256=group,
                accepting_states_by_profile=acceptance[name],
                unsatisfiable_profiles=[profile for profile, count in acceptance[name].items() if count == 0],
                equivalent_to_baseline=truth_vectors[name] == old)
            row_digests[name] = row_digest.hexdigest()
    assert seen == set(targets)

    # Reconstruct the independently saved canonical digest in sorted target
    # order, streaming one target again. Per-target hashes do not compose into
    # the same digest, so they cannot substitute for this exact check.
    complete_digest = hashlib.sha256()
    for name in sorted(targets):
        codes = group_rows[group_ids[name]]
        for class_id in range(len(keys)):
            status = STATUS[codes[2 * class_id]]
            robust = [codes[2 * class_id + 1]]
            complete_digest.update(json.dumps([name, class_id, [status, robust]],
                separators=(",", ":")).encode() + b"\n")
    prior = load(ROOT / cfg["independent_checker_result"])
    saved_aggregate = load(ROOT / cfg["saved_aggregate"])
    assert prior["status"] == "passed" and prior["failures"] == 0
    assert prior["target_class_status_and_complete_robust_family_comparisons"] == row_checks
    assert prior["derived_rows_in_saved_class_order_sha256"] == complete_digest.hexdigest()
    independent_targets = {item["target"]: item for item in prior["per_target"]}
    saved_targets = {item["target"]: item for item in saved_aggregate["details"]}
    for name, row in summaries.items():
        assert Counter(row["status_counts"]) == Counter(independent_targets[name]["status_counts"])
        assert Counter(row["status_counts"]) == Counter(saved_targets[name]["status_counts"])
        for reference in (independent_targets[name], saved_targets[name]):
            expected_families = {str(mask): row["additional_requirements"][label] for mask, label in MASKS.items()
                                 if row["additional_requirements"][label]}
            assert reference["insufficient_robust_families"] == expected_families
    sets = {spec["name"]: combine(select_targets(spec, groups, valid), summaries, group_ids, len(keys))
            for spec in cfg["sets"]}
    assert sets["all_edits"]["status_counts"] == prior["status_counts"] == saved_aggregate["status_counts"]
    assert sets["all_edits"]["target_class_combinations"] == saved_aggregate["target_class_rows"] == 834880
    assert all(sha(ROOT / name) == expected for name, expected in pins.items())
    result = dict(status="passed", analysis_type=cfg["analysis_type"],
        states=len(states), old_valid_classes=len(keys),
        directly_recomputed_baseline_truth_labels=len(old),
        directly_recomputed_target_truth_labels=sum(map(len, truth_vectors.values())),
        saved_status_and_robust_family_rows_recomputed=row_checks,
        alias_rows_compared_exactly=alias_checks,
        canonical_rows_sha256=complete_digest.hexdigest(),
        per_target_row_sha256=dict(sorted(row_digests.items())),
        baseline_equivalent_syntactic_edits=sum(vector == old for vector in truth_vectors.values()),
        unsatisfiable_profile_targets=sorted(set(targets) - valid),
        sets=sets, semantic_groups=aliases, source_sha256=pins,
        interpretation=cfg["interpretation"])
    save(output / "summary.json", result)
    save(output / "target_summaries.json", dict(sorted(summaries.items())))
    lines = ["Post hoc sensitivity of the complete authored-edit census", "",
        "Set | targets | semantic families | target/class combinations | safe | stale | insufficient | P | T | PT"]
    for name, row in sets.items():
        values = [name, row["targets"], row["semantic_families"], row["target_class_combinations"],
                  *[row["status_counts"][status] for status in STATUS],
                  *[row["additional_requirements"][label] for label in MASKS.values()]]
        lines.append(" | ".join(str(v) for v in values))
    lines += ["", "Every selected target contributes the same 10,436 old-valid observation classes.",
        "The original 80-edit census is retained. Filtering checks for at least one accepting supported state per profile; it does not establish operational plausibility.",
        "Semantic grouping compares the complete target truth vector over all 8,612 states, including states outside native support. Baseline and the strict two-edit anchor are not counted among the 80 targets.",
        "The 14 edits equivalent to the baseline remain included and contribute one semantic family after deduplication. No group is removed because its result is uninteresting.",
        "All 834,880 saved status/robust-family rows were freshly reconstructed from raw predicates. Exact row equality was checked across all aliases, and the canonical digest matches the prior independent checker.",
        cfg["interpretation"], ""]
    (output / "paper_ready.txt").write_text("\n".join(lines))
    print("\n".join(lines[:7]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    analyze(args.output.resolve())


if __name__ == "__main__":
    main()
