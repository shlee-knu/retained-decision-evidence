"""Execute the frozen finite catalog/certificate regression audit.

Run from an editable-installed project: .venv/bin/python scripts/audit_catalog_certificates.py
No new labels are business-error truth. No benchmark or optimal-policy claim.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import csv
import gzip
import hashlib
import json
import time

from logistics_validation.catalog_audit import (
    ALPHABET, PROFILES, MASK_NAMES, CertificateTable, abstract, catalog_json,
    changes, concrete, generated_catalogs, loss_witness, reference_verdict,
    universe, verdict,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/strong/catalog_audit"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def encoded_size(block, value):
    return len(json.dumps({block: value}, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8"))


def family(masks):
    return "|".join(MASK_NAMES[m] for m in masks)


def weighted(table, weights, pbytes, tbytes):
    distribution = Counter()
    necessary = Counter()
    smallest = Counter()
    policies = {}
    for i, w in enumerate(weights):
        if not w:
            continue
        distribution[family(table.minimal[i])] += w
        necessary[MASK_NAMES[table.necessary[i]]] += w
        smallest[str(min(m.bit_count() for m in table.minimal[i]))] += w
    for policy in ("always_both", "profile_first", "time_first", "structural_order"):
        counts = Counter()
        for i, w in enumerate(weights):
            if not w:
                continue
            m = table.policy_mask(i, policy)
            counts["profile_queries"] += w * bool(m & 1)
            counts["time_queries"] += w * bool(m & 2)
            counts["lookups"] += w * m.bit_count()
            counts["payload_bytes"] += (pbytes[i] if m & 1 else 0) + (tbytes[i] if m & 2 else 0)
            minimum = min(x.bit_count() for x in table.minimal[i])
            counts["lookups_above_pointwise_certificate_bound"] += w * (m.bit_count() - minimum)
        policies[policy] = dict(counts)
    return {"cases": sum(weights), "accept": sum(w * bool(table.labels[i]) for i, w in enumerate(weights)),
            "minimal_families": dict(sorted(distribution.items())),
            "necessary_masks": dict(sorted(necessary.items())),
            "minimum_lookup_distribution": dict(sorted(smallest.items())),
            "pointwise_minimum_lookups": sum(int(k) * v for k, v in smallest.items()), "policies": policies}


def delta(old, new, weights):
    result = Counter()
    transitions = Counter()
    sufficient_transitions = Counter()
    for i, w in enumerate(weights):
        if not w:
            continue
        change = changes(old, new, i)
        transitions[family(old.minimal[i]) + " -> " + family(new.minimal[i])] += w
        sufficient_transitions[str(old.sufficient[i]) + " -> " + str(new.sufficient[i])] += w
        result["verdict_changes"] += w * (not change["verdict_preserved"])
        result["minimal_family_changes"] += w * (old.minimal[i] != new.minimal[i])
        if not change["verdict_preserved"]:
            continue
        result["preserved_verdict_cases"] += w
        result["certificate_loss_cases"] += w * bool(change["lost"])
        result["certificate_gain_cases"] += w * bool(change["gained"])
        result["lost_mask_instances"] += w * len(change["lost"])
        result["gained_mask_instances"] += w * len(change["gained"])
        old_required, new_required = old.necessary[i], new.necessary[i]
        result["newly_necessary_P_cases"] += w * bool(new_required & 1 and not old_required & 1)
        result["newly_necessary_T_cases"] += w * bool(new_required & 2 and not old_required & 2)
        result["no_longer_necessary_P_cases"] += w * bool(old_required & 1 and not new_required & 1)
        result["no_longer_necessary_T_cases"] += w * bool(old_required & 2 and not new_required & 2)
        for policy in ("profile_first", "time_first", "structural_order"):
            result[policy + "_path_changes"] += w * (old.policy_mask(i, policy) != new.policy_mask(i, policy))
    return {**dict(result), "minimal_family_transitions": dict(sorted(transitions.items())),
            "sufficient_bitset_transitions": dict(sorted(sufficient_transitions.items()))}


def show_witness(witness, old, new, old_catalog, new_catalog, counts, representatives):
    if witness is None:
        return None
    i, j, mask = (witness[k] for k in ("anchor_index", "completion_index", "lost_mask"))
    anchor = concrete(old.states[i])
    completion = concrete(old.states[j])
    source = None
    if i in representatives:
        rep = representatives[i]
        anchor = {k: rep[k] for k in ("activities", "profile", "first_times")}
        completion["activities"] = anchor["activities"]
        if mask & 1:
            completion["profile"] = anchor["profile"]
        if mask & 2:
            completion["first_times"] = anchor["first_times"]
        source = {k: rep[k] for k in ("case_id", "source_trace", "source_locator")}
    assert abstract(anchor) == old.states[i] and abstract(completion) == old.states[j]
    if mask & 1:
        assert anchor["profile"] == completion["profile"]
    if mask & 2:
        assert anchor["first_times"] == completion["first_times"]
    assert anchor["activities"] == completion["activities"]
    labels = {"old_anchor": reference_verdict(anchor, old_catalog),
              "old_completion": reference_verdict(completion, old_catalog),
              "new_anchor": reference_verdict(anchor, new_catalog),
              "new_completion": reference_verdict(completion, new_catalog)}
    assert labels["old_anchor"] == labels["old_completion"] == labels["new_anchor"]
    assert labels["new_completion"] != labels["new_anchor"]
    return {**witness, "lost_mask_name": MASK_NAMES[mask], "anchor": anchor, "completion": completion,
            "labels": labels, "source_anchor": source, "anchor_native_count": counts[i],
            "completion_native_count": counts[j], "completion_off_native_support": counts[j] == 0,
            "minimization": "anchor first: milestone count, clock levels, permutation, ranks, profile; then mask; then completion in the same state order"}


def main():
    started = time.perf_counter()
    OUT.mkdir(parents=True, exist_ok=True)
    design_path = OUT / "design.json"
    design_sha = sha(design_path)
    design = json.loads(design_path.read_text())
    catalogs = generated_catalogs()
    states = universe()
    assert len(catalogs) == design["syntactic_catalogs_including_anchors"] == 82
    assert len(states) == design["finite_complete_states"] == 8612
    state_index = {s: i for i, s in enumerate(states)}
    tables = {}
    catalog_lookup = {}
    equivalent = {}
    independent_checks = 0
    # Intentionally execute raw reference for every catalog-state pair.
    for n, (name, catalog, edit) in enumerate(catalogs):
        labels = bytes(verdict(s, catalog) for s in states)
        for i, s in enumerate(states):
            assert reference_verdict(concrete(s), catalog) == bool(labels[i]), (name, i)
            independent_checks += 1
        table = CertificateTable(states, labels)
        tables[name] = table
        catalog_lookup[name] = catalog
        vector_hash = hashlib.sha256(labels).hexdigest()
        equivalent.setdefault(vector_hash, []).append(name)
        if n % 10 == 0:
            print(f"finite catalogs {n + 1}/{len(catalogs)}", flush=True)
    old = tables["baseline"]
    for names in equivalent.values():
        first = tables[names[0]]
        for name in names[1:]:
            assert first.sufficient == tables[name].sufficient
            assert first.minimal == tables[name].minimal
            assert first.necessary == tables[name].necessary
    source = ROOT / "results/v03/bpi_compact.jsonl.gz"
    prior_traces = ROOT / "results/v03/acquisition_access_traces.jsonl.gz"
    weights = {name: [0] * len(states) for name in ("native", "holdout_seed17")}
    pbytes = {name: [0] * len(states) for name in weights}
    tbytes = {name: [0] * len(states) for name in weights}
    representatives = {}
    native_reference_checks = prior_path_checks = 0
    with gzip.open(source, "rt") as handle, gzip.open(prior_traces, "rt") as paths:
        for line in handle:
            c = json.loads(line)
            i = state_index[abstract(c)]
            assert bool(old.labels[i]) == (not c["violation"])
            assert reference_verdict(c) == bool(old.labels[i])
            native_reference_checks += 1
            v = int.from_bytes(hashlib.sha256(f"projection-audit-v03:17:{c['document']}".encode()).digest()[:8], "big") % 100
            cohorts = ("native", "holdout_seed17") if v >= 80 else ("native",)
            for cohort in cohorts:
                weights[cohort][i] += 1
                pbytes[cohort][i] += encoded_size("profile", c["profile"])
                tbytes[cohort][i] += encoded_size("first_times", c["first_times"])
            if i not in representatives:
                representatives[i] = {k: c[k] for k in ("case_id", "source_trace", "activities", "profile", "first_times")}
                representatives[i]["source_locator"] = f"data/raw/bpi/BPI_Challenge_2019.xes:trace-{c['source_trace']}"
            recorded = json.loads(next(paths))
            assert c["case_id"] == recorded["case_id"]
            for name, oldname in (("baseline", "permissive"), ("strict_consignment", "strict_consignment")):
                for policy in ("profile_first", "time_first", "structural_order"):
                    assert tables[name].policy_mask(i, policy) == recorded["masks"][oldname][policy]
                    prior_path_checks += 1
        assert paths.readline() == ""
    assert sum(weights["native"]) == 251734
    assert sum(weights["holdout_seed17"]) == 50931
    print("native projection complete", flush=True)
    rows, variants, witnesses = [], {}, {}
    all_finite = [1] * len(states)
    for name, catalog, edit in catalogs:
        table = tables[name]
        h = hashlib.sha256(table.labels).hexdigest()
        profiles_without_accept = [PROFILES[p] for p in range(4)
                                   if not any(table.labels[i] for i, s in enumerate(states) if s.profile == p)]
        entry = {"edit": edit, "catalog": catalog_json(catalog), "truth_vector_sha256": h,
                 "globally_equivalent_syntactic_catalogs": equivalent[h],
                 "unsatisfiable_profiles": profiles_without_accept,
                 "globally_equivalent_to_baseline": table.labels == old.labels,
                 "finite_delta": delta(old, table, all_finite), "cohorts": {}}
        for cohort in weights:
            stats = weighted(table, weights[cohort], pbytes[cohort], tbytes[cohort])
            change = delta(old, table, weights[cohort])
            entry["cohorts"][cohort] = {"statistics": stats, "delta": change}
            rows.append({"catalog": name, "cohort": cohort, "kind": edit["kind"],
                         "global_equivalence_group": h, "syntactic_multiplicity": len(equivalent[h]),
                         "unsatisfiable_profile_count": len(profiles_without_accept),
                         "globally_equivalent_to_baseline": table.labels == old.labels,
                         "cases": stats["cases"], "accept": stats["accept"],
                         **{k: v for k, v in change.items() if not isinstance(v, dict)},
                         "pointwise_minimum_lookups": stats["pointwise_minimum_lookups"],
                         **{policy + "_" + k: v for policy, values in stats["policies"].items() for k, v in values.items()}})
        witnesses[name] = {
            "global_canonical": show_witness(loss_witness(old, table), old, table,
                                              catalog_lookup["baseline"], catalog, weights["native"], {}),
            "native_anchor_canonical": show_witness(loss_witness(old, table, representatives), old, table,
                                                     catalog_lookup["baseline"], catalog, weights["native"], representatives)}
        variants[name] = entry
    equivalence_groups = [{"truth_vector_sha256": h, "catalogs": names, "multiplicity": len(names)}
                          for h, names in equivalent.items()]
    stable = [name for name in variants if variants[name]["cohorts"]["native"]["delta"]["verdict_changes"] == 0]
    result = {"status": "passed", "created_utc": datetime.now(timezone.utc).isoformat(),
              "design_sha256": design_sha, "syntactic_catalog_count": len(catalogs),
              "single_edit_catalog_count": 80, "semantic_catalog_count": len(equivalent),
              "finite_complete_states": len(states), "finite_base_clock_states": 2153,
              "native_populated_states": len(representatives), "native_verdict_stable_catalogs": stable,
              "globally_equivalent_to_baseline": [n for n in variants if variants[n]["globally_equivalent_to_baseline"]],
              "independent_raw_reference_catalog_state_checks": independent_checks,
              "native_raw_reference_checks": native_reference_checks,
              "prior_native_policy_trace_matches": prior_path_checks,
              "equivalence_groups": equivalence_groups, "variants": variants,
              "label_semantics": "Declared first-occurrence observation predicate; not procurement correctness or natural-error truth",
              "domain": "Four known profiles, four milestones, complete observed source projection, arbitrary supported first-clock weak order, repetitions ignored only by the stated predicates",
              "counterfactual_scope": "Generated edits and quotient states are controls; no population probability or claim of business feasibility beyond the declared completion domain",
              "certificate_bound": "Pointwise minimum sufficient subset, not an adaptive-policy optimality result",
              "delta_scope": "Verdict and minimal-family changes include all cohort cases. Certificate loss/gain, newly/no-longer necessary blocks and policy path changes are restricted to anchors whose verdict is preserved.",
              "structural_order": "Clock first iff every catalog profile passes source-position/presence/prohibition checks (equivalently, every profile accepts all-tied clocks); otherwise profile first. Uses only base and catalog. No global policy optimality claim.",
              "elapsed_seconds": time.perf_counter() - started}
    dump(OUT / "summary.json", result)
    dump(OUT / "witnesses.json", witnesses)
    dump(OUT / "native_projections.json", {"states": [
        {"index": i, "order": [ALPHABET[a] for a in states[i].order], "ranks": states[i].ranks,
         "profile": PROFILES[states[i].profile], "native_count": weights["native"][i],
         "holdout_seed17_count": weights["holdout_seed17"][i], "representative": representatives[i],
         "profile_bytes": {c: pbytes[c][i] for c in weights}, "time_bytes": {c: tbytes[c][i] for c in weights}}
        for i in sorted(representatives)]})
    finite = {"states": [[s.order, s.ranks, s.profile] for s in states],
              "mask_encoding": {str(m): MASK_NAMES[m] for m in range(4)},
              "sufficient_encoding": "bit 1<<mask is set iff mask is sufficient",
              "catalogs": {name: {"labels": list(t.labels), "sufficient": t.sufficient}
                           for name, t in tables.items()}}
    with (OUT / "finite_tables.json.gz").open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as z:
            z.write(json.dumps(finite, separators=(",", ":")).encode())
    with (OUT / "variants.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    inputs = [source, prior_traces, design_path, ROOT / "src/logistics_validation/catalog_audit.py",
              ROOT / "scripts/audit_catalog_certificates.py", ROOT / "tests/test_catalog_audit.py",
              ROOT / "src/logistics_validation/acquisition.py"]
    outputs = [OUT / name for name in ("summary.json", "witnesses.json", "native_projections.json",
                                       "finite_tables.json.gz", "variants.csv")]
    dump(OUT / "manifest.json", {"status": "passed", "inputs": {str(p.relative_to(ROOT)): sha(p) for p in inputs},
                                 "outputs": {str(p.relative_to(ROOT)): sha(p) for p in outputs},
                                 "original_bpi2019_sha256": "af63bc687fc4152f2123b05c3af7772b37ef3fce2d3f67f812666c9e356baae7",
                                 "source_doi": "10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1",
                                 "source_license": "CC BY 4.0"})
    print(json.dumps({"status": "passed", "elapsed_seconds": result["elapsed_seconds"],
                      "semantic_catalogs": len(equivalent), "native_states": len(representatives),
                      "native_stable_catalogs": len(stable), "strict_native": variants["strict_consignment"]["cohorts"]["native"]}, indent=2))


if __name__ == "__main__":
    main()
