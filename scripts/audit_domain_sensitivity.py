"""Reproduce a fixed domain-sensitivity audit without altering prior results."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import csv
import gzip
import hashlib
import json
import time

from logistics_validation.catalog_audit import (
    ALPHABET, MASK_NAMES, PROFILES, abstract, concrete, generated_catalogs,
    observation, universe, verdict,
)
from logistics_validation.domain_audit import (
    DOMAINS, DomainCertificateTable, domain_changes, domain_contains, guarantee_mask,
    reference_domain_contains, verified_gate_mask, withdrawal_pairs,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/second/domain_sensitivity"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def family(masks):
    return "|".join(MASK_NAMES[m] for m in masks)


def byte_size(block, value):
    return len(json.dumps({block: value}, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8"))


def cost(mask, weight, pbytes, tbytes):
    return {"lookups": weight * mask.bit_count(), "P": weight * bool(mask & 1),
            "T": weight * bool(mask & 2),
            "bytes": (pbytes if mask & 1 else 0) + (tbytes if mask & 2 else 0)}


def aggregate(table, broad, weights, pbytes, tbytes):
    counts, families, necessity, verification = Counter(), Counter(), Counter(), Counter()
    paid = {p: Counter() for p in ("profile_first", "time_first")}
    for i, w in enumerate(weights):
        if not w:
            continue
        counts["cases"] += w
        supported = table.active[i]
        counts["admitted"] += w * supported
        counts["unsupported"] += w * (not supported)
        counts["accepted_admitted"] += w * (supported and bool(table.labels[i]))
        g = guarantee_mask(table.states[i], table.domain)
        verification.update(cost(g, w, pbytes[i], tbytes[i]))
        for order in paid:
            result = verified_gate_mask(i, table.domain, broad, order)
            paid[order].update(cost(result["mask"], w, pbytes[i], tbytes[i]))
            paid[order]["failed_guarantees"] += w * result["used_fallback"]
            paid[order]["wrong_decisions"] += w * (result["decision"] != bool(broad.labels[i]))
        if not supported:
            continue
        minimal = table.minimal[i]
        families[family(minimal)] += w
        necessity[MASK_NAMES[table.necessary[i]]] += w
        counts["minimum_lookups"] += w * min(m.bit_count() for m in minimal)
        unions = [m | g for m in minimal]
        assert all(broad.sufficient[i] & (1 << m) for m in unions)
        counts["paid_union_pointwise_minimum_lookups"] += w * min(m.bit_count() for m in unions)
    return {**dict(counts), "minimal_families": dict(sorted(families.items())),
            "necessary_masks": dict(sorted(necessity.items())), "verification_reads": dict(verification),
            "paid_gate_and_broad_fallback": {p: dict(v) for p, v in paid.items()}}


def delta(before, after, weights):
    counts = Counter()
    transitions = Counter()
    for i, w in enumerate(weights):
        if not w:
            continue
        d = domain_changes(before, after, i)
        counts["cases"] += w
        counts["unsupported_before"] += w * (not before.active[i])
        counts["unsupported_after"] += w * (not after.active[i])
        counts["common_admitted"] += w * d["supported_both"]
        if not d["supported_both"]:
            continue
        counts["verdict_changes"] += w * (not d["verdict_preserved"])
        counts["minimal_family_changes"] += w * (before.minimal[i] != after.minimal[i])
        if d["verdict_preserved"]:
            transitions[family(before.minimal[i]) + " -> " + family(after.minimal[i])] += w
            counts["certificate_loss_cases"] += w * bool(d["lost"])
            counts["certificate_gain_cases"] += w * bool(d["gained"])
            counts["lost_mask_instances"] += w * len(d["lost"])
            counts["gained_mask_instances"] += w * len(d["gained"])
            counts["newly_necessary_P"] += w * bool(after.necessary[i] & 1 and not before.necessary[i] & 1)
            counts["newly_necessary_T"] += w * bool(after.necessary[i] & 2 and not before.necessary[i] & 2)
    return {**dict(counts), "minimal_transitions_preserved_verdict": dict(sorted(transitions.items()))}


def withdrawal_witness(before, after, representatives=None):
    allowed = None if representatives is None else set(representatives)
    for i, state in enumerate(before.states):
        if allowed is not None and i not in allowed:
            continue
        for mask in domain_changes(before, after, i)["lost"]:
            candidates = after.fibers[mask][observation(state, mask)]
            for j in candidates:
                if after.labels[j] == after.labels[i]:
                    continue
                assert not before.active[j] and after.active[j]
                anchor, other = concrete(state), concrete(before.states[j])
                source = None
                if representatives is not None:
                    rep = representatives[i]
                    anchor = {k: rep[k] for k in ("activities", "profile", "first_times")}
                    other["activities"] = anchor["activities"]
                    if mask & 1:
                        other["profile"] = anchor["profile"]
                    if mask & 2:
                        other["first_times"] = anchor["first_times"]
                    source = {k: rep[k] for k in ("case_id", "source_trace")}
                assert abstract(anchor) == state and abstract(other) == before.states[j]
                assert reference_domain_contains(anchor, before.domain)
                assert not reference_domain_contains(other, before.domain)
                assert reference_domain_contains(other, after.domain)
                return {"anchor_index": i, "completion_index": j, "lost_mask": mask,
                        "mask_name": MASK_NAMES[mask], "anchor": anchor, "completion": other,
                        "anchor_verdict_before_and_after": bool(after.labels[i]),
                        "completion_before": "unsupported", "completion_after": bool(after.labels[j]),
                        "source_anchor": source,
                        "interpretation": "Same catalog, withdrawn domain guarantee. Alternative completion was excluded before, not previously assigned the anchor verdict."}
    return None


def csv_file(path, rows):
    with path.open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    started = time.perf_counter()
    OUT.mkdir(parents=True, exist_ok=True)
    design = OUT / "design.json"
    assert design.exists()
    states = universe()
    index = {s: i for i, s in enumerate(states)}
    catalogs = generated_catalogs()
    assert len(states) == 8612 and len(catalogs) == 82
    tables = {d: {} for d in DOMAINS}
    labels = {}
    for name, catalog, _ in catalogs:
        labels[name] = bytes(verdict(s, catalog) for s in states)
        for d in DOMAINS:
            tables[d][name] = DomainCertificateTable(states, labels[name], d)
    prior_path = ROOT / "results/strong/catalog_audit/finite_tables.json.gz"
    with gzip.open(prior_path, "rt") as f:
        prior = json.load(f)
    assert prior["states"] == [[list(s.order), list(s.ranks), s.profile] for s in states]
    for name, _, _ in catalogs:
        assert list(labels[name]) == prior["catalogs"][name]["labels"]
        assert list(tables["cartesian"][name].sufficient) == prior["catalogs"][name]["sufficient"]
    print("compiled four domains; exact Cartesian identity checked", flush=True)
    nesting_checks = union_checks = 0
    for name, _, _ in catalogs:
        broad = tables["cartesian"][name]
        for d in DOMAINS:
            table = tables[d][name]
            for i, active in enumerate(table.active):
                if active:
                    g = guarantee_mask(states[i], d)
                    for m in table.minimal[i]:
                        assert broad.sufficient[i] & (1 << (g | m))
                        union_checks += 1
        for small, large in withdrawal_pairs():
            a, b = tables[small][name], tables[large][name]
            for i in range(len(states)):
                if a.active[i]:
                    assert b.active[i]
                    assert a.sufficient[i] | b.sufficient[i] == a.sufficient[i]
                    nesting_checks += 1
    weights = {c: [0] * len(states) for c in ("native", "holdout_seed17")}
    pbytes = {c: [0] * len(states) for c in weights}
    tbytes = {c: [0] * len(states) for c in weights}
    representatives = {}
    membership_checks = 0
    source = ROOT / "results/v03/bpi_compact.jsonl.gz"
    with gzip.open(source, "rt") as f:
        for line in f:
            raw = json.loads(line)
            s = abstract(raw)
            i = index[s]
            assert bool(labels["baseline"][i]) == (not raw["violation"])
            for d in DOMAINS:
                assert reference_domain_contains(raw, d) == domain_contains(s, d)
                membership_checks += 1
            split = int.from_bytes(hashlib.sha256(f"projection-audit-v03:17:{raw['document']}".encode()).digest()[:8], "big") % 100
            for cohort in (("native", "holdout_seed17") if split >= 80 else ("native",)):
                weights[cohort][i] += 1
                pbytes[cohort][i] += byte_size("profile", raw["profile"])
                tbytes[cohort][i] += byte_size("first_times", raw["first_times"])
            if i not in representatives:
                representatives[i] = {k: raw[k] for k in ("case_id", "source_trace", "activities", "profile", "first_times")}
    assert sum(weights["native"]) == 251734 and sum(weights["holdout_seed17"]) == 50931
    print("native domain membership independently checked", flush=True)
    reports, variants, main_rows, withdrawal_rows, withdrawals, witnesses = {}, [], [], [], {}, {}
    expected_sizes = dict(zip(DOMAINS, (8612, 1268, 6468, 958)))
    all_weights = [1] * len(states)
    for d in DOMAINS:
        base = tables[d]["baseline"]
        admitted = [i for i, active in enumerate(base.active) if active]
        assert len(admitted) == expected_sizes[d]
        groups = {}
        for name, _, _ in catalogs:
            vector = bytes(labels[name][i] for i in admitted)
            groups.setdefault(hashlib.sha256(vector).hexdigest(), []).append(name)
        domain_report = {"admitted_states": len(admitted), "unsupported_states": len(states) - len(admitted),
                         "semantic_catalog_count": len(groups), "equivalence_groups": groups, "catalogs": {}}
        for name, _, edit in catalogs:
            table = tables[d][name]
            h = hashlib.sha256(bytes(labels[name][i] for i in admitted)).hexdigest()
            entry = {"edit": edit, "truth_sha256_on_admitted_states": h,
                     "equivalent_syntactic_catalogs": groups[h],
                     "finite_delta_from_baseline": delta(base, table, all_weights), "cohorts": {}}
            unsat = [PROFILES[p] for p in range(4) if not any(table.labels[i] for i in admitted if states[i].profile == p)]
            entry["profiles_without_accepting_admitted_state"] = unsat
            for cohort in weights:
                stats = aggregate(table, tables["cartesian"][name], weights[cohort], pbytes[cohort], tbytes[cohort])
                change = delta(base, table, weights[cohort])
                entry["cohorts"][cohort] = {"statistics": stats, "delta_from_baseline": change}
                variants.append({"domain": d, "catalog": name, "cohort": cohort,
                                 "truth_group": h, "syntactic_multiplicity": len(groups[h]),
                                 "unsatisfiable_profile_count": len(unsat),
                                 **{k: v for k, v in stats.items() if not isinstance(v, dict)},
                                 **{"delta_" + k: v for k, v in change.items() if not isinstance(v, dict)}})
            domain_report["catalogs"][name] = entry
            if name in ("baseline", "strict_consignment"):
                row = {"domain": d, "catalog": name, "admitted_symbolic_states": len(admitted)}
                for cohort in weights:
                    s = entry["cohorts"][cohort]["statistics"]
                    row.update({cohort + "_" + k: s[k] for k in ("cases", "admitted", "unsupported", "minimum_lookups", "paid_union_pointwise_minimum_lookups")})
                    row[cohort + "_verification_lookups"] = s["verification_reads"]["lookups"]
                    for order, cost in s["paid_gate_and_broad_fallback"].items():
                        row[cohort + "_paid_" + order + "_lookups"] = cost["lookups"]
                        row[cohort + "_paid_" + order + "_bytes"] = cost["bytes"]
                main_rows.append(row)
        # Equivalence is compared within the same domain only.
        for names in groups.values():
            for name in names[1:]:
                assert tables[d][names[0]].sufficient == tables[d][name].sufficient
        reports[d] = domain_report
    for small, large in withdrawal_pairs():
        pair = small + " -> " + large
        withdrawals[pair] = {}
        witnesses[pair] = {}
        for name, _, _ in catalogs:
            before, after = tables[small][name], tables[large][name]
            entry = {"finite": delta(before, after, all_weights), "cohorts": {}}
            for cohort in weights:
                entry["cohorts"][cohort] = delta(before, after, weights[cohort])
                withdrawal_rows.append({"before_domain": small, "after_domain": large,
                                        "catalog": name, "cohort": cohort,
                                        **{k: v for k, v in entry["cohorts"][cohort].items() if not isinstance(v, dict)}})
            withdrawals[pair][name] = entry
            if name in ("baseline", "strict_consignment"):
                witnesses[pair][name] = {"global": withdrawal_witness(before, after),
                                         "native_anchor": withdrawal_witness(before, after, representatives)}
    report = {"status": "passed", "created_utc": datetime.now(timezone.utc).isoformat(),
              "domain_order": DOMAINS, "catalog_count": len(catalogs), "universal_states": len(states),
              "native_cases": sum(weights["native"]), "holdout_cases": sum(weights["holdout_seed17"]),
              "independent_native_domain_membership_checks": membership_checks,
              "nesting_monotonicity_checks": nesting_checks, "paid_union_sufficiency_checks": union_checks,
              "domains": reports, "withdrawals": withdrawals,
              "assumptions": "Restrictions are hypothetical upstream guarantees. Archive compliance is checked but does not establish guarantees. Local checks are separately charged. Unsupported anchors never receive vacuous certificates.",
              "elapsed_seconds": time.perf_counter() - started}
    dump(OUT / "summary.json", report)
    dump(OUT / "withdrawal_witnesses.json", witnesses)
    dump(OUT / "weights.json", {"weights": weights, "profile_bytes": pbytes, "time_bytes": tbytes})
    saved = {"states": [[s.order, s.ranks, s.profile] for s in states],
             "encoding": "One entry per universal state ID. Sufficiency bit1<<mask; masks0=empty,1=P,2=T,3=PT; null=unsupported.",
             "labels": {n: list(v) for n, v in labels.items()},
             "domains": {d: {"admitted": list(tables[d]["baseline"].active),
                             "sufficient": {n: list(t.sufficient) for n, t in ts.items()}}
                         for d, ts in tables.items()}}
    with (OUT / "finite_tables.json.gz").open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as z:
            z.write(json.dumps(saved, separators=(",", ":")).encode())
    csv_file(OUT / "main_table.csv", main_rows)
    csv_file(OUT / "domain_variants.csv", variants)
    csv_file(OUT / "guarantee_withdrawals.csv", withdrawal_rows)
    inputs = [design, source, prior_path, ROOT / "src/logistics_validation/domain_audit.py",
              ROOT / "src/logistics_validation/catalog_audit.py", ROOT / "src/logistics_validation/acquisition.py",
              ROOT / "scripts/audit_domain_sensitivity.py", ROOT / "tests/test_domain_audit.py"]
    outputs = [OUT / n for n in ("summary.json", "withdrawal_witnesses.json", "weights.json",
                                "finite_tables.json.gz", "main_table.csv", "domain_variants.csv", "guarantee_withdrawals.csv")]
    dump(OUT / "manifest.json", {"status": "passed", "inputs": {str(p.relative_to(ROOT)): sha(p) for p in inputs},
                                 "outputs": {str(p.relative_to(ROOT)): sha(p) for p in outputs}})
    print(json.dumps({"status": "passed", "elapsed_seconds": report["elapsed_seconds"],
                      "native_membership_checks": membership_checks, "main_table": main_rows}, indent=2))


if __name__ == "__main__":
    main()
