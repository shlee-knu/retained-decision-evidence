"""Reconcile saved exhaustive receipt evidence without calling its candidate.

The independent raw-state artifact is joined to the preceding complete finite
audit by semantic state key. Fibers, vectors, statuses and recovery ledgers are
then rebuilt from saved labels, not from Revalidator or audit_receipt_tool.
"""
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path

from verify_second_evidence import raw_state, normalized, observation, admitted
from verify_expanded import table_rows

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "results/third/receipt_audit/"
DOMAINS = ("cartesian:v1", "chronological:v1", "consignment_exclusion:v1", "both:v1")
ACTIVITIES = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR", "2-way match", "Consignment")
TARGETS = {"identity": "baseline", "strict": "strict_consignment",
           "equivalent": "edge_p0_a0_b3", "label_flip": "required_p3_a2"}
STATUSES = ("safe", "stale_verdict", "insufficient", "unsupported", "invalid_receipt")
PAIRS = (("strict", "cartesian:v1", "cartesian:v1"),
         ("identity", "chronological:v1", "cartesian:v1"),
         ("identity", "consignment_exclusion:v1", "cartesian:v1"),
         ("identity", "both:v1", "cartesian:v1"),
         ("identity", "both:v1", "chronological:v1"),
         ("identity", "both:v1", "consignment_exclusion:v1"))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def gz_load(a, name):
    a.digest(name)
    with gzip.open(ROOT / name, "rt") as stream:
        return json.load(stream)


def decode_key(value):
    order, profile, ranks = value
    return (tuple(ACTIVITIES.index(x) for x in order), None if profile is None else PROFILES.index(profile),
            None if ranks is None else tuple(ranks))


def classify(n, bits, recorded):
    return ("unsupported" if not n else "insufficient" if bits == 3
            else "safe" if bits == (2 if recorded else 1) else "stale_verdict")


def verify(a):
    summary = a.load(PREFIX + "summary.json")
    manifest = a.load(PREFIX + "manifest.json")
    a.same(summary["status"], "passed", "exhaustive receipt audit status", "receipt-exhaustive")
    a.same(manifest["status"], "passed", "exhaustive receipt manifest status", "receipt-exhaustive")
    for part in ("inputs", "outputs"):
        for path, digest in manifest[part].items():
            a.pin(path, digest)
    saved = gz_load(a, PREFIX + "independent_finite_oracle.json.gz")
    vectors = gz_load(a, PREFIX + "expected_vectors.json.gz")
    previous_manifest = a.load("results/second/domain_sensitivity/manifest.json")
    previous_path = "results/second/domain_sensitivity/finite_tables.json.gz"
    a.pin(previous_path, previous_manifest["outputs"][previous_path])
    previous = gz_load(a, previous_path)
    previous_index = {normalized(s): i for i, s in enumerate(previous["states"])}
    states = [raw_state(raw) for raw in saved["raw_states"]]
    a.same(len(states), 8612, "independent receipt universe size", "receipt-exhaustive")
    a.same(set(states), set(previous_index), "independent universe equals prior quotient", "receipt-exhaustive")
    for target, old_name in TARGETS.items():
        expected = [bool(previous["labels"][old_name][previous_index[s]]) for s in states]
        a.same(saved["labels"][target], expected, "saved independent truth vector " + target, "receipt-exhaustive")
    for d in DOMAINS:
        name = d.split(":")[0]
        expected = [previous["domains"][name]["admitted"][previous_index[s]] for s in states]
        a.same(saved["members"][d], expected, "saved independent admission vector " + d, "receipt-exhaustive")
        a.same(expected, [admitted(s, name) for s in states], "admission independently recomputed " + d, "receipt-exhaustive")
    groups = {d: [defaultdict(list) for _ in range(4)] for d in DOMAINS}
    for d in DOMAINS:
        for i, active in enumerate(saved["members"][d]):
            if active:
                for mask in range(4):
                    groups[d][mask][observation(states[i], mask)].append(i)
    outcomes = {}
    for t in TARGETS:
        outcomes[t] = {}
        for d in DOMAINS:
            outcomes[t][d] = []
            for mask in range(4):
                out = {}
                for key, ids in groups[d][mask].items():
                    bits = 0
                    for i in ids:
                        bits |= 1 << int(saved["labels"][t][i])
                    out[key] = (len(ids), bits)
                outcomes[t][d].append(out)

    def fiber(target, domain, mask, key):
        return outcomes[target][domain][mask].get(key, (0, 0))

    old_valid = {d: {(m, k) for m in range(4) for k, (n, bits) in outcomes["identity"][d][m].items()
                     if n and bits in (1, 2)} for d in DOMAINS}
    counts = {d: len(v) for d, v in old_valid.items()}
    a.same(counts, summary["old_valid_classes"], "all old-valid observation classes", "receipt-exhaustive")
    a.same(sum(counts.values()), summary["total_old_valid_classes"], "old-valid class total", "receipt-exhaustive")
    columns = [(t, d) for t in TARGETS for d in DOMAINS]
    a.same(vectors["columns"], [list(v) for v in columns], "classification vector column meaning", "receipt-exhaustive")
    a.same(vectors["status_codes"], {s: i for i, s in enumerate(STATUSES)}, "status-code schema", "receipt-exhaustive")
    matrix = defaultdict(Counter)
    by_old = {d: [] for d in DOMAINS}
    seen = {d: set() for d in DOMAINS}
    stream = hashlib.sha256()
    checks = 0
    for expected_id, row in enumerate(vectors["rows"]):
        cid, old, mask = row["class_id"], row["old_domain"], row["mask"]
        key = decode_key(row["key"])
        a.same(cid, expected_id, "stable receipt class identifier", "receipt-vectors")
        a.check((mask, key) not in seen[old], "no duplicate receipt observation", "receipt-vectors")
        seen[old].add((mask, key))
        old_n, old_bits = fiber("identity", old, mask, key)
        a.check(old_n > 0 and old_bits in (1, 2), "saved class is old-valid", "receipt-vectors")
        a.same(row["recorded_verdict"], old_bits == 2, "recorded verdict justified", "receipt-vectors")
        a.same(row["old_compatible_states"], old_n, "old fiber size", "receipt-vectors")
        expected_vector = []
        for target, new in columns:
            n, bits = fiber(target, new, mask, key)
            status = classify(n, bits, old_bits == 2)
            labels = [bool(v) for v in range(2) if bits & (1 << v)]
            expected_vector.append([STATUSES.index(status), n, bits])
            matrix[target, old, new][status] += 1
            stream.update(canonical([cid, target, new, status, n, labels]) + b"\n")
            checks += 1
        a.same(row["expected"], expected_vector, "every saved expected receipt outcome", "receipt-vectors")
        by_old[old].append((row, key))
    for d in DOMAINS:
        a.same(seen[d], old_valid[d], "complete observation coverage " + d, "receipt-exhaustive")
    a.same(checks, summary["classification_checks"], "classification check total", "receipt-exhaustive")
    for name in ("classification_expected_sha256", "classification_actual_sha256"):
        a.same(stream.hexdigest(), summary[name], "reconstructed classification stream " + name, "receipt-exhaustive")
    indexed = {(r["target"], r["old_domain"], r["new_domain"]): r for r in summary["classification_matrix"]}
    a.same(set(indexed), set(matrix), "full target/domain matrix", "receipt-exhaustive")
    total_status = Counter()
    for combo, values in matrix.items():
        total_status.update(values)
        a.same(indexed[combo]["old_valid_classes"], sum(values.values()), "matrix class count", "receipt-exhaustive")
        for status in STATUSES:
            a.same(indexed[combo][status], values[status], "matrix status " + status, "receipt-exhaustive")
    a.same(dict(total_status), summary["status_totals"], "all classification status totals", "receipt-exhaustive")
    recovery_rows, recovery_stream, recovery_total = [], hashlib.sha256(), 0
    for target, old, new in PAIRS:
        cc = Counter()
        for row, key in by_old[old]:
            mask, recorded = row["mask"], row["recorded_verdict"]
            for i in groups[new][mask].get(key, ()):
                current = mask
                calls = []
                initial_bits = fiber(target, new, mask, key)[1]
                while True:
                    current_key = observation(states[i], current)
                    n, bits = fiber(target, new, current, current_key)
                    if bits in (1, 2):
                        break
                    a.check(n > 0 and bits == 3, "admitted recovery completion has a nonempty fiber", "receipt-recovery")
                    bit, field = (1, "profile") if not current & 1 else (2, "first_times")
                    current |= bit
                    calls.append(field)
                label = bits == 2
                old_compatible = bool(fiber("identity", old, current, current_key)[0])
                status = "safe" if label == recorded else "stale_verdict"
                a.same(label, saved["labels"][target][i], "recovery full-input oracle", "receipt-recovery")
                cc["recoveries"] += 1
                cc["initially_insufficient"] += initial_bits == 3
                cc["P_reads"] += "profile" in calls
                cc["T_reads"] += "first_times" in calls
                cc["old_domain_incompatible_after_reads"] += not old_compatible
                cc[status] += 1
                recovery_total += 1
                recovery_stream.update(canonical([target, old, new, mask, row["key"], i, calls, status, label, old_compatible]) + b"\n")
        recovery_rows.append({"target": target, "old_domain": old, "new_domain": new, **dict(cc)})
    a.same(recovery_rows, summary["recovery_matrix"], "all recovery aggregates", "receipt-recovery")
    a.same(recovery_total, summary["recovery_checks"], "completion recovery coverage", "receipt-recovery")
    a.same(recovery_stream.hexdigest(), summary["recovery_stream_sha256"], "full recovery stream reconstructed", "receipt-recovery")
    witnesses = a.load(PREFIX + "witnesses.json")
    observed_combos = set()
    for row in witnesses:
        target, old, new = row["target"], row["old_domain"], row["new_domain"]
        receipt, result = row["receipt"], row["result"]
        observed = receipt["observed"]
        mask = int("profile" in observed) + 2 * int("first_times" in observed)
        raw = {"activities": receipt["activities"], "profile": observed.get("profile", PROFILES[0]),
               "first_times": observed.get("first_times", {x: "2020-01-01T00:00:00Z" for x in receipt["activities"]})}
        key = observation(raw_state(raw), mask)
        n, bits = fiber(target, new, mask, key)
        status = classify(n, bits, receipt["verdict"])
        a.same(result["status"], status, "representative status", "receipt-witness")
        combo = target, old, new, status
        a.check(combo not in observed_combos, "unique status witness representative", "receipt-witness")
        observed_combos.add(combo)
        for completion in result["compatible_new_completions"]:
            raw = completion["features"]
            state = raw_state(raw)
            idx = previous_index[state]
            a.same(raw["activities"], receipt["activities"], "full repeated activities retained", "receipt-witness")
            for field, value in observed.items():
                a.same(raw[field], value, "literal observed field retained", "receipt-witness")
            for side, cat, domain in (("before", "baseline", old), ("after", TARGETS[target], new)):
                a.same(completion[side + "_verdict"], bool(previous["labels"][cat][idx]), "witness direct truth", "receipt-witness")
                a.same(completion[side + "_domain_member"], admitted(state, domain.split(":")[0]), "witness admission", "receipt-witness")
    wanted = {(t, old, new, s) for (t, old, new), vals in matrix.items() for s, n in vals.items() if n}
    a.same(observed_combos, wanted, "all observed status/transition combinations witnessed", "receipt-witness")
    a.same(len(witnesses), summary["representative_witness_records"], "witness coverage", "receipt-witness")
    controls = {r["name"]: r["status"] for r in summary["negative_controls"]}
    a.same(controls, {"opposite_recorded_label": "invalid_receipt", "ambiguous_old": "invalid_receipt",
                      "empty_old": "invalid_receipt", "wrong_snapshot_sha256": "binding_error",
                      "wrong_catalog_sha256": "binding_error", "malformed_observed_clock": "syntax_error"},
           "negative controls separate from valid census", "receipt-exhaustive")
    check_paper(a, counts, matrix, recovery_rows, summary)
    a.facts["receipt_exhaustive"] = {"old_valid_classes": counts, "classification_checks": checks,
                                     "status_totals": dict(total_status), "classification_stream_sha256": stream.hexdigest(),
                                     "recovery_checks": recovery_total, "recovery_matrix": recovery_rows,
                                     "witness_records": len(witnesses), "negative_controls": len(controls),
                                     "scope": "Independent reconciliation of saved complete abstract-observation vectors, prior truth/domain tables, recovery ledgers and manuscript. No rerun of candidate or SQL benchmark."}
    return summary


def check_paper(a, classes, matrix, recoveries, summary):
    main = a.read("paper/manuscript_ieee_access_applied.md")
    supp = a.read("paper/supplement_ieee_access_applied.md")
    names = {"Cartesian": "cartesian:v1", "Chronological": "chronological:v1",
             "Consignment exclusion": "consignment_exclusion:v1", "Both guarantees": "both:v1"}
    s15 = table_rows(supp, "S15")
    a.same(len(s15), 4, "supplement TableS15 size", "paper-tables")
    for row in s15:
        domain = names[row[0]]
        counts = Counter()
        for (target, old, new), values in matrix.items():
            if old == domain:
                counts.update(values)
        expected = [classes[domain], sum(counts.values()), *[counts[s] for s in STATUSES[:4]]]
        a.same(row[1:], [f"{x:,}" for x in expected], "TableS15 " + domain, "paper-tables")
    s16 = table_rows(supp, "S16")
    a.same(len(s16), 6, "supplement TableS16 size", "paper-tables")
    indexed = {(r["target"], r["old_domain"], r["new_domain"]): r for r in recoveries}
    for row in s16:
        target, domains = row[0].split("; ")
        old, new = domains.split(" → ")
        r = indexed[target.lower(), names[old], names[new]]
        fields = ("recoveries", "initially_insufficient", "P_reads", "T_reads", "old_domain_incompatible_after_reads")
        a.same(row[1:], [f"{r[k]:,}" for k in fields], "TableS16 " + row[0], "paper-tables")
    for field in ("classification_checks", "recovery_checks"):
        a.check(f"{summary[field]:,}" in main, "main receipt coverage " + field, "paper-numbers")
    paper = a.facts.setdefault("paper", {})
    checked = paper.setdefault("supplementary_tables_checked", [])
    for name in ("S15", "S16"):
        if name not in checked:
            checked.append(name)


if __name__ == "__main__":
    from verify_expanded import Audit
    audit = Audit()
    verify(audit)
    print(json.dumps({"status": "failed" if audit.failures else "passed", "checks": sum(audit.counts.values()),
                      "failures": audit.failures, "facts": audit.facts}, indent=2))
    raise SystemExit(bool(audit.failures))
