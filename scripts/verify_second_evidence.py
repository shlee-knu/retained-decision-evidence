"""Independent regrouping and release reconciliation of second-revision evidence.

No domain/receipt candidate classes are called. Complete truth labels come from
the pinned preceding finite audit; observation fibers, domain predicates,
families, paid ledgers and receipt classifications are recomputed here. Native
projection uses the existing independent Fraction parser. This is post hoc
artifact verification, not a new raw-XES experiment or runtime measurement.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
from stress_acquisition import raw_time
from verify_expanded import split, table_rows

DOMAINS = ("cartesian", "chronological", "consignment_exclusion", "both")
ACTIVITIES = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR", "2-way match", "Consignment")
NAMES = ("empty", "P", "T", "PT")
OLD_FINITE = "results/strong/catalog_audit/finite_tables.json.gz"
OLD_SHA = "e369afd80c9b1ebf57ea456dc2297357b5d64365e27a8efc120e50ba23bfd7af"
DP = "results/second/domain_sensitivity/"
RP = "results/second/receipt_revalidation/"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def read_gzip(a, name):
    a.digest(name)
    with gzip.open(ROOT / name, "rt") as stream:
        return json.load(stream)


def normalized(state):
    return tuple(state[0]), tuple(state[1]), state[2]


def raw_state(features):
    order = tuple(dict.fromkeys(ACTIVITIES.index(x) for x in features["activities"]))
    clocks = [raw_time(features["first_times"][ACTIVITIES[i]]) for i in order]
    levels = {v: i for i, v in enumerate(sorted(set(clocks)))}
    return order, tuple(levels[x] for x in clocks), PROFILES.index(features["profile"])


def admitted(state, domain):
    order, ranks, profile = state
    chronological = all(x <= y for x, y in zip(ranks, ranks[1:]))
    exclusion = profile != 3 or not ({2, 3} & set(order))
    return {"cartesian": True, "chronological": chronological,
            "consignment_exclusion": exclusion, "both": chronological and exclusion}[domain]


def observation(state, mask):
    return state[0], state[2] if mask & 1 else None, state[1] if mask & 2 else None


@lru_cache(maxsize=17)
def minima(bits):
    if bits is None:
        return None
    allowed = [m for m in range(4) if bits & (1 << m)]
    return tuple(m for m in allowed if not any(n != m and n | m == m for n in allowed))


def necessary(bits):
    masks = minima(bits)
    return None if masks is None else ((1 if all(m & 1 for m in masks) else 0) +
                                      (2 if all(m & 2 for m in masks) else 0))


def family(bits):
    return "|".join(NAMES[m] for m in minima(bits))


def guard(state, domain):
    p = domain in {"consignment_exclusion", "both"} and bool(set(state[0]) & {2, 3})
    t = domain in {"chronological", "both"} and len(state[0]) >= 2
    return int(p) + 2 * int(t)


def delta(before, after, old_labels, new_labels, weights):
    fields = ("cases", "unsupported_before", "unsupported_after", "common_admitted", "verdict_changes",
              "minimal_family_changes", "certificate_loss_cases", "certificate_gain_cases", "lost_mask_instances",
              "gained_mask_instances", "newly_necessary_P", "newly_necessary_T")
    counts = Counter({k: 0 for k in fields})
    transitions = Counter()
    for i, w in enumerate(weights):
        if not w:
            continue
        b, c = before[i], after[i]
        counts["cases"] += w
        counts["unsupported_before"] += w * (b is None)
        counts["unsupported_after"] += w * (c is None)
        if b is None or c is None:
            continue
        counts["common_admitted"] += w
        counts["verdict_changes"] += w * (old_labels[i] != new_labels[i])
        counts["minimal_family_changes"] += w * (minima(b) != minima(c))
        if old_labels[i] == new_labels[i]:
            lost, gained = b & ~c, c & ~b
            counts["certificate_loss_cases"] += w * bool(lost)
            counts["certificate_gain_cases"] += w * bool(gained)
            counts["lost_mask_instances"] += w * lost.bit_count()
            counts["gained_mask_instances"] += w * gained.bit_count()
            counts["newly_necessary_P"] += w * bool(necessary(c) & 1 and not necessary(b) & 1)
            counts["newly_necessary_T"] += w * bool(necessary(c) & 2 and not necessary(b) & 2)
            transitions[family(b) + " -> " + family(c)] += w
    return {**dict(counts), "minimal_transitions_preserved_verdict": dict(transitions)}


def stats(states, domain, bits, broad, labels, weights, pbytes, tbytes):
    count = Counter({k: 0 for k in ("cases", "admitted", "unsupported", "accepted_admitted",
                                   "minimum_lookups", "paid_union_pointwise_minimum_lookups")})
    families, necessity = Counter(), Counter()
    verification = Counter({k: 0 for k in ("lookups", "P", "T", "bytes")})
    paid = {name: Counter({k: 0 for k in ("lookups", "P", "T", "bytes", "failed_guarantees", "wrong_decisions")})
            for name in ("profile_first", "time_first")}

    def add(target, m, w, pb, tb):
        target["lookups"] += w * m.bit_count()
        target["P"] += w * bool(m & 1)
        target["T"] += w * bool(m & 2)
        target["bytes"] += pb * bool(m & 1) + tb * bool(m & 2)

    for i, w in enumerate(weights):
        if not w:
            continue
        active = bits[i] is not None
        count["cases"] += w
        count["admitted"] += w * active
        count["unsupported"] += w * (not active)
        count["accepted_admitted"] += w * (active and bool(labels[i]))
        gm = guard(states[i], domain)
        add(verification, gm, w, pbytes[i], tbytes[i])
        for name, order in (("profile_first", (1, 2)), ("time_first", (2, 1))):
            mask = gm
            for block in order:
                if broad[i] & (1 << mask):
                    break
                mask |= block
            add(paid[name], mask, w, pbytes[i], tbytes[i])
            paid[name]["failed_guarantees"] += w * (not active)
        if active:
            mm = minima(bits[i])
            families[family(bits[i])] += w
            necessity[NAMES[necessary(bits[i])]] += w
            count["minimum_lookups"] += w * min(m.bit_count() for m in mm)
            count["paid_union_pointwise_minimum_lookups"] += w * min((m | gm).bit_count() for m in mm)
    return {**dict(count), "minimal_families": dict(families), "necessary_masks": dict(necessity),
            "verification_reads": dict(verification), "paid_gate_and_broad_fallback": {k: dict(v) for k, v in paid.items()}}


def classify(old, new, recorded):
    if not old or old != {recorded}:
        return "invalid_receipt"
    if not new:
        return "unsupported"
    if len(new) > 1:
        return "insufficient"
    return "safe" if new == {recorded} else "stale_verdict"


def normalize_catalog(value):
    value = deepcopy(value)
    for row in value.values():
        row["required"] = sorted(row["required"], key=ACTIVITIES.index)
        row["forbidden"] = sorted(row["forbidden"], key=ACTIVITIES.index)
        row["edges"] = sorted(row["edges"], key=lambda edge: tuple(ACTIVITIES.index(x) for x in edge))
    return value


def check_examples(a, states, index, groups, labels):
    specs = a.load("examples/second_receipt_cases.json")["cases"]
    saved = a.load(RP + "examples.json")
    a.same(saved["cases"], len(specs), "receipt example count", "receipt-examples")
    a.pin("examples/second_receipt_cases.json", saved["source_sha256"])
    rows = {r["name"]: r for r in saved["records"]}
    a.same(set(rows), {s["name"] for s in specs}, "receipt example identity", "receipt-examples")
    base = a.load("examples/baseline_catalog.json")
    equiv = deepcopy(base)
    equiv[PROFILES[0]]["edges"].append(["create", "clear"])
    flip = deepcopy(base)
    flip["Consignment"]["required"].append("invoice")
    a.same(normalize_catalog(a.load("examples/second_equivalent_catalog.json")), normalize_catalog(equiv),
           "equivalent fixture is pinned edge_p0_a0_b3 edit", "receipt-examples")
    a.same(normalize_catalog(a.load("examples/second_label_flip_catalog.json")), normalize_catalog(flip),
           "label-flip fixture is pinned required_p3_a2 edit", "receipt-examples")
    names = {"examples/baseline_catalog.json": "baseline", "examples/strict_consignment_catalog.json": "strict_consignment",
             "examples/second_equivalent_catalog.json": "edge_p0_a0_b3", "examples/second_label_flip_catalog.json": "required_p3_a2"}
    for spec in specs:
        receipt, result = spec["receipt"], rows[spec["name"]]["result"]
        order = tuple(dict.fromkeys(ACTIVITIES.index(x) for x in receipt["activities"]))
        observed = receipt["observed"]
        mask = int("profile" in observed) + 2 * int("first_times" in observed)
        profile = PROFILES.index(observed["profile"]) if mask & 1 else None
        ranks = None
        if mask & 2:
            times = [raw_time(observed["first_times"][ACTIVITIES[i]]) for i in order]
            levels = {v: j for j, v in enumerate(sorted(set(times)))}
            ranks = tuple(levels[v] for v in times)
        key = order, profile, ranks
        compatible, outcomes = {}, {}
        for side in ("before", "after"):
            version = spec[side + "_domain"]
            domain = version.removesuffix(":v1")
            cat = names[spec[side + "_catalog"]]
            compatible[side] = groups[domain][mask].get(key, ())
            outcomes[side] = {bool(labels[cat][i]) for i in compatible[side]}
            a.same(result[side + "_compatible_classes"], len(compatible[side]), "example fiber size", "receipt-examples")
            a.same(result[side + "_labels"], sorted(outcomes[side]), "example fiber labels", "receipt-examples")
            a.same(result[side + "_domain_version"], version, "example domain binding", "receipt-examples")
            catalog_hash = hashlib.sha256(canonical(normalize_catalog(a.load(spec[side + "_catalog"])))).hexdigest()
            a.same(result[side + "_catalog_sha256"], catalog_hash, "example catalog binding", "receipt-examples")
        status = classify(outcomes["before"], outcomes["after"], receipt["verdict"])
        a.same(result["status"], status, "independent constructed receipt status", "receipt-examples")
        a.same(spec["expected_status"], status, "expected constructed receipt status", "receipt-examples")
        a.same(result["observed_mask"], NAMES[mask], "example observed fields", "receipt-examples")
        a.same(len(result["compatible_new_completions"]), len(outcomes["after"]), "one concrete representative per new label", "receipt-examples")
        for witness in result["compatible_new_completions"]:
            features = witness["features"]
            state = raw_state(features)
            i = index[state]
            a.same(observation(state, mask), key, "example concrete completion shares observation", "receipt-examples")
            a.same(features["activities"], receipt["activities"], "example repetitions preserved", "receipt-examples")
            for field, value in observed.items():
                a.same(features[field], value, "example literal observed value preserved", "receipt-examples")
            for side in ("before", "after"):
                a.same(witness[side + "_domain_member"], admitted(state, spec[side + "_domain"].removesuffix(":v1")),
                       "example concrete domain membership", "receipt-examples")
                a.same(witness[side + "_verdict"], bool(labels[names[spec[side + "_catalog"]]][i]),
                       "example concrete predicate label", "receipt-examples")
    return len(specs)


def verify(a):
    dm, rm = a.load(DP + "manifest.json"), a.load(RP + "manifest.json")
    a.same(dm["status"], "passed", "domain manifest status")
    a.same(rm["status"], "passed", "receipt manifest status")
    a.hashes_match(dm["inputs"])
    a.hashes_match(dm["outputs"])
    a.hashes_match(rm["input_sha256"])
    a.hashes_match({RP + k: v for k, v in rm["output_sha256"].items()})
    prefix = a.read("docs/second_receipt_evidence.md").split("## Execution evidence")[0]
    a.same(hashlib.sha256(prefix.encode()).hexdigest(), rm["design_prefix_sha256"], "receipt fixed design prefix", "hashes")
    a.pin(OLD_FINITE, OLD_SHA)
    prior = read_gzip(a, OLD_FINITE)
    finite = read_gzip(a, DP + "finite_tables.json.gz")
    summary, weights_file = a.load(DP + "summary.json"), a.load(DP + "weights.json")
    receipt_summary = a.load(RP + "native_summary.json")
    a.same(finite["states"], prior["states"], "identical universal state IDs", "domain")
    states = [normalized(s) for s in prior["states"]]
    index = {s: i for i, s in enumerate(states)}
    labels = {name: row["labels"] for name, row in prior["catalogs"].items()}
    a.same(finite["labels"], labels, "all labels equal pinned prior truth vectors", "domain")
    a.same(len(states), 8612, "universal state count", "domain")
    a.same(len(labels), 82, "complete catalog count", "domain")
    a.same(summary["domain_order"], list(DOMAINS), "domain order", "domain")
    groups, bits = {}, {}
    for domain in DOMAINS:
        active = [admitted(s, domain) for s in states]
        a.same(active, finite["domains"][domain]["admitted"], "domain admission " + domain, "domain")
        fibers = [defaultdict(list) for _ in range(4)]
        for i, state in enumerate(states):
            if active[i]:
                for mask in range(4):
                    fibers[mask][observation(state, mask)].append(i)
        groups[domain] = fibers
        bits[domain] = {}
        for name, truth in labels.items():
            computed = [0 if member else None for member in active]
            for mask, partitions in enumerate(fibers):
                for ids in partitions.values():
                    outcomes = {truth[i] for i in ids}
                    if len(outcomes) == 1:
                        for i in ids:
                            computed[i] |= 1 << mask
            a.check(computed == finite["domains"][domain]["sufficient"][name],
                    "every sufficiency/unsupported entry " + domain + "/" + name, "domain-fibers")
            bits[domain][name] = computed
    example_count = check_examples(a, states, index, groups, labels)

    @lru_cache(maxsize=None)
    def outcomes(domain, name, mask, key):
        return frozenset(bool(labels[name][i]) for i in groups[domain][mask].get(key, ()))

    # Reconstruct complete-source weights and exact literal receipt observations
    # in one pass. No candidate receipt classifier or catalog evaluator is used.
    n = len(states)
    weights = {cohort: [0] * n for cohort in ("native", "holdout_seed17")}
    pbytes = {cohort: [0] * n for cohort in weights}
    tbytes = {cohort: [0] * n for cohort in weights}
    initial, added, old_reads, fresh_reads, recovered = (Counter() for _ in range(5))
    old_bytes = fresh_bytes = repair_bytes = total = test = redundant = 0
    ids_hash = hashlib.sha256()
    source = "results/v03/bpi_compact.jsonl.gz"
    traces = "results/v03/acquisition_access_traces.jsonl.gz"
    receipts = RP + "native_receipts.jsonl.gz"
    for path in (source, traces, receipts):
        a.digest(path)
    # Compute the receipt's old-catalog binding without its implementation.
    catalog_data = normalize_catalog(a.load("examples/baseline_catalog.json"))
    old_catalog_hash = hashlib.sha256(canonical(catalog_data)).hexdigest()
    with gzip.open(ROOT / source, "rt") as src, gzip.open(ROOT / traces, "rt") as tr, gzip.open(ROOT / receipts, "rt") as rec:
        for line, trace_line in zip_longest(src, tr):
            a.check(line is not None and trace_line is not None, "compact/trace synchronized length", "receipt-source")
            if line is None or trace_line is None:
                break
            case, trace = json.loads(line), json.loads(trace_line)
            a.same(case["case_id"], trace["case_id"], "source/access identity", "receipt-source")
            s = raw_state(case)
            i = index[s]
            pb, tb = (len(canonical({name: case[name]})) for name in ("profile", "first_times"))
            total += 1
            held = split(case["document"]) == "test"
            a.same(bool(labels["baseline"][i]), not case["violation"], "source label versus pinned truth", "receipt-source")
            for cohort in (("native", "holdout_seed17") if held else ("native",)):
                weights[cohort][i] += 1
                pbytes[cohort][i] += pb
                tbytes[cohort][i] += tb
            if not held:
                continue
            test += 1
            record_line = next(rec, None)
            a.check(record_line is not None, "receipt exists for held-out source", "receipt-source")
            if record_line is None:
                break
            row = json.loads(record_line)
            receipt = row["receipt"]
            old_mask = trace["masks"]["permissive"]["structural_order"]
            new_mask = trace["masks"]["strict_consignment"]["structural_order"]
            expected_observed = {name: case[name] for bit, name in ((1, "profile"), (2, "first_times")) if old_mask & bit}
            expected_receipt = {"schema_version": 1, "snapshot_sha256": a.hashes[source], "catalog_sha256": old_catalog_hash,
                                "domain_version": "cartesian:v1", "activities": case["activities"], "observed": expected_observed,
                                "verdict": bool(labels["baseline"][i]), "receipt_id": case["case_id"]}
            a.same(receipt, expected_receipt, "receipt exact source literals and bindings " + case["case_id"], "receipt-ledger")
            old = outcomes("cartesian", "baseline", old_mask, observation(s, old_mask))
            new = outcomes("cartesian", "strict_consignment", old_mask, observation(s, old_mask))
            status = classify(old, new, receipt["verdict"])
            a.same(row["initial_status"], status, "independent initial fiber classification", "receipt-ledger")
            a.check(status != "invalid_receipt", "native old receipt valid", "receipt-ledger")
            initial[status] += 1
            reads, repair_mask = [], old_mask
            while len(outcomes("cartesian", "strict_consignment", repair_mask, observation(s, repair_mask))) > 1:
                block, bit = next((name, bit) for bit, name in ((1, "profile"), (2, "first_times")) if not repair_mask & bit)
                reads.append(block)
                repair_mask |= bit
            a.same(row["issued_logical_reads"], reads, "only necessary policy recovery reads", "receipt-ledger")
            a.same(row["recovered_verdict"], bool(labels["strict_consignment"][i]), "recovery label versus pinned truth", "receipt-ledger")
            a.same(outcomes("cartesian", "strict_consignment", repair_mask, observation(s, repair_mask)),
                   {row["recovered_verdict"]}, "recovered observation certifies new verdict", "receipt-ledger")
            recovered[str(row["recovered_verdict"])] += 1
            added.update(reads)
            ids_hash.update((case["case_id"] + "\n").encode())
            for bit, name, nb in ((1, "profile", pb), (2, "first_times", tb)):
                if old_mask & bit:
                    old_reads[name] += 1
                    old_bytes += nb
                if new_mask & bit:
                    fresh_reads[name] += 1
                    fresh_bytes += nb
                if name in reads:
                    repair_bytes += nb
            if new_mask != old_mask and new_mask & old_mask == new_mask:
                redundant += 1
        a.same(next(rec, None), None, "no extra compressed receipts", "receipt-ledger")
    for name, value in (("weights", weights), ("profile_bytes", pbytes), ("time_bytes", tbytes)):
        a.same(value, weights_file[name], "native independent projection " + name, "domain-source")
    a.same(total, 251734, "full source count", "domain-source")
    a.same(test, 50931, "receipt source count", "receipt-ledger")
    facts = {"source_cases_scanned": total, "receipt_cases": test, "case_id_order_sha256": ids_hash.hexdigest(),
             "initial_status_counts": dict(initial), "additional_logical_reads": {k: added[k] for k in ("profile", "first_times")},
             "additional_payload_bytes": repair_bytes, "old_observations_logical_reads": dict(old_reads),
             "old_observations_payload_bytes": old_bytes, "fresh_new_logical_reads": dict(fresh_reads),
             "fresh_new_payload_bytes": fresh_bytes,
             "retained_plus_repair_logical_reads": {k: old_reads[k] + added[k] for k in ("profile", "first_times")},
             "retained_plus_repair_payload_bytes": old_bytes + repair_bytes,
             "safe_receipts_with_now_redundant_old_observations": redundant,
             "fresh_profile_read_increase": fresh_reads["profile"] - old_reads["profile"],
             "independent_raw_oracle_comparisons": test * 2, "oracle_disagreements": 0,
             "recovered_verdict_counts": dict(recovered)}
    for key, value in facts.items():
        a.same(receipt_summary[key], value, "receipt aggregate " + key, "receipt-ledger")
    a.pin(receipts, receipt_summary["compressed_receipts_sha256"])

    all_weights = [1] * n
    census, calculated = {}, {}
    union_checks = nesting_checks = 0
    for domain in DOMAINS:
        active = [i for i, s in enumerate(states) if admitted(s, domain)]
        reported = summary["domains"][domain]
        a.same(len(active), reported["admitted_states"], "admitted domain size " + domain, "domain-summary")
        a.same(n - len(active), reported["unsupported_states"], "unsupported domain size " + domain, "domain-summary")
        equivalence = defaultdict(list)
        for name, truth in labels.items():
            equivalence[hashlib.sha256(bytes(truth[i] for i in active)).hexdigest()].append(name)
        a.same(dict(equivalence), reported["equivalence_groups"], "restricted truth equivalence groups " + domain, "domain-summary")
        a.same(len(equivalence), reported["semantic_catalog_count"], "restricted semantic group count", "domain-summary")
        census[domain] = [0, 0, 0, 0]
        calculated[domain] = {}
        for name, truth in labels.items():
            entry = reported["catalogs"][name]
            computed = bits[domain][name]
            h = hashlib.sha256(bytes(truth[i] for i in active)).hexdigest()
            a.same(entry["truth_sha256_on_admitted_states"], h, "restricted truth digest", "domain-summary")
            a.same(entry["equivalent_syntactic_catalogs"], equivalence[h], "restricted syntax multiplicity", "domain-summary")
            unsat = [PROFILES[p] for p in range(4) if not any(truth[i] for i in active if states[i][2] == p)]
            a.same(unsat, entry["profiles_without_accepting_admitted_state"], "unsupported accepting profile set", "domain-summary")
            d = delta(bits[domain]["baseline"], computed, labels["baseline"], truth, all_weights)
            a.same(d, entry["finite_delta_from_baseline"], "complete finite delta " + domain + "/" + name, "domain-summary")
            calculated[domain][name] = {}
            for cohort in weights:
                ss = stats(states, domain, computed, bits["cartesian"][name], truth,
                           weights[cohort], pbytes[cohort], tbytes[cohort])
                dd = delta(bits[domain]["baseline"], computed, labels["baseline"], truth, weights[cohort])
                a.same(ss, entry["cohorts"][cohort]["statistics"], "weighted statistics " + domain + "/" + name + "/" + cohort, "domain-summary")
                a.same(dd, entry["cohorts"][cohort]["delta_from_baseline"], "weighted changes " + domain + "/" + name + "/" + cohort, "domain-summary")
                calculated[domain][name][cohort] = ss
                if cohort == "native" and entry["edit"]["kind"] != "anchor":
                    equivalent = all(truth[i] == labels["baseline"][i] for i in active)
                    category = 0 if equivalent else 3 if dd["verdict_changes"] else 2 if dd["minimal_family_changes"] else 1
                    census[domain][category] += 1
            for i in active:
                for m in minima(computed[i]):
                    union_checks += 1
                    a.check(bool(bits["cartesian"][name][i] & (1 << (m | guard(states[i], domain)))),
                            "paid narrow certificate sufficient in Cartesian domain", "domain-paid-bound")
    for transition, rows in summary["withdrawals"].items():
        small, large = transition.split(" -> ")
        for name, reported in rows.items():
            a.same(delta(bits[small][name], bits[large][name], labels[name], labels[name], all_weights),
                   reported["finite"], "finite withdrawal " + transition + "/" + name, "domain-withdrawals")
            for cohort in weights:
                a.same(delta(bits[small][name], bits[large][name], labels[name], labels[name], weights[cohort]),
                       reported["cohorts"][cohort], "weighted withdrawal " + transition + "/" + name + "/" + cohort, "domain-withdrawals")
            for i in range(n):
                if bits[small][name][i] is not None:
                    nesting_checks += 1
                    a.check(bits[large][name][i] is not None and bits[large][name][i] | bits[small][name][i] == bits[small][name][i],
                            "nested domain certificate monotonicity", "domain-nesting")
    a.same(union_checks, summary["paid_union_sufficiency_checks"], "paid-union coverage")
    a.same(nesting_checks, summary["nesting_monotonicity_checks"], "domain-nesting coverage")
    a.same(summary["independent_native_domain_membership_checks"], total * 4, "saved native raw domain-check scope")

    # Concrete withdrawal witnesses are checked against the pinned labels and
    # independent literal-clock projection, not the candidate witness builder.
    witness_file = a.load(DP + "withdrawal_witnesses.json")
    witness_count = 0
    for transition, catalog_rows in witness_file.items():
        small, large = transition.split(" -> ")
        for name, versions in catalog_rows.items():
            for row in versions.values():
                if row is None:
                    continue
                witness_count += 1
                b, c = raw_state(row["anchor"]), raw_state(row["completion"])
                i, j, m = index[b], index[c], row["lost_mask"]
                a.same(i, row["anchor_index"], "witness anchor independent projection", "domain-witness")
                a.same(j, row["completion_index"], "witness completion independent projection", "domain-witness")
                a.check(admitted(b, small) and admitted(c, large) and not admitted(c, small), "withdrawal admits opposite completion", "domain-witness")
                a.same(observation(b, m), observation(c, m), "witness same visible input", "domain-witness")
                a.same(row["anchor"]["activities"], row["completion"]["activities"], "witness full repeats preserved", "domain-witness")
                for bit, field in ((1, "profile"), (2, "first_times")):
                    if m & bit:
                        a.same(row["anchor"][field], row["completion"][field], "witness literal field preserved", "domain-witness")
                a.check(labels[name][i] != labels[name][j], "witness opposite new labels", "domain-witness")
                a.check(bool(bits[small][name][i] & (1 << m)) and not bits[large][name][i] & (1 << m), "witness actual lost certificate", "domain-witness")

    check_tables(a, summary, calculated, census, facts)
    a.facts["domain_sensitivity"] = {"domains": 4, "catalogs": 82, "states": n,
        "saved_sufficiency_entries_independently_regrouped": 4 * 82 * n,
        "domain_sizes": {d: summary["domains"][d]["admitted_states"] for d in DOMAINS},
        "single_edit_census": census, "withdrawal_witnesses_replayed": witness_count,
        "paid_union_checks": union_checks, "nesting_checks": nesting_checks,
        "scope": "Independent regrouping of saved pinned truth arrays and exact native projection; no new raw-XES predicate experiment."}
    a.facts["receipt_revalidation"] = {**{k: v for k, v in facts.items() if k not in {"independent_raw_oracle_comparisons", "oracle_disagreements"}},
        "constructed_examples_independently_reconciled": example_count,
        "saved_experiment_raw_oracle_comparisons": facts["independent_raw_oracle_comparisons"],
        "saved_experiment_raw_oracle_disagreements": facts["oracle_disagreements"],
        "scope": "Every compressed receipt, literal observed value, catalog/snapshot binding, new-fiber status and logical recovery read reconciled independently with saved exact truth and source snapshot; no SQL/runtime claim."}
    return summary, receipt_summary


def check_tables(a, summary, calculated, census, receipts):
    main = a.read("paper/manuscript_ieee_access_applied.md")
    supp = a.read("paper/supplement_ieee_access_applied.md")
    names = {"Cartesian": "cartesian", "Chronological": "chronological",
             "Consignment exclusion": "consignment_exclusion", "Both guarantees": "both"}
    t7 = table_rows(main, 7)
    a.same(len(t7), 4, "main Table7 rows", "paper-tables")
    for row in t7:
        d = names[row[0]]
        b, s = (calculated[d][cat]["holdout_seed17"]["minimum_lookups"] for cat in ("baseline", "strict_consignment"))
        a.same(row[1:], [f"{v:,}" for v in (summary["domains"][d]["admitted_states"], b, s, s-b)], "main Table7 " + d, "paper-tables")
    t12 = table_rows(supp, "S12")
    a.same(len(t12), 4, "TableS12 rows", "paper-tables")
    for row in t12:
        d = names[row[0]]
        a.same(row[1:], [str(x) for x in [summary["domains"][d]["semantic_catalog_count"], *census[d]]], "TableS12 " + d, "paper-tables")
    t13 = table_rows(supp, "S13")
    a.same(len(t13), 8, "TableS13 rows", "paper-tables")
    for row in t13:
        d, cat = names[row[0]], {"Permissive": "baseline", "Strict": "strict_consignment"}[row[1]]
        x = calculated[d][cat]["holdout_seed17"]
        vals = [x["verification_reads"]["lookups"], x["paid_union_pointwise_minimum_lookups"],
                *[x["paid_gate_and_broad_fallback"][order]["lookups"] for order in ("profile_first", "time_first")]]
        a.same(row[2:], [f"{v:,}" for v in vals], "TableS13 " + d + "/" + cat, "paper-tables")
    def ledger(reads, payload):
        p, t = (reads.get(k, 0) for k in ("profile", "first_times"))
        return [p, t, p+t, payload]
    old = ledger(receipts["old_observations_logical_reads"], receipts["old_observations_payload_bytes"])
    add = ledger(receipts["additional_logical_reads"], receipts["additional_payload_bytes"])
    combined = [x+y for x, y in zip(old, add)]
    fresh = ledger(receipts["fresh_new_logical_reads"], receipts["fresh_new_payload_bytes"])
    expected = {"Old retained observations": old, "Additional recovery": add, "Retained plus recovery": combined,
                "Fresh strict execution": fresh, "Already paid excess": [x-y for x, y in zip(combined, fresh)]}
    t14 = table_rows(supp, "S14")
    a.same(len(t14), 5, "TableS14 rows", "paper-tables")
    for row in t14:
        a.same(row[1:], [f"{v:,}" for v in expected[row[0]]], "TableS14 " + row[0], "paper-tables")
    if "paper" in a.facts:
        a.facts["paper"].setdefault("main_tables_checked", []).append(7)
        a.facts["paper"].setdefault("supplementary_tables_checked", []).extend(["S12", "S13", "S14"])


if __name__ == "__main__":
    from verify_expanded import Audit
    audit = Audit()
    verify(audit)
    print(json.dumps({"status": "passed" if not audit.failures else "failed", "checks": sum(audit.counts.values()),
                      "failures": audit.failures, "facts": audit.facts}, indent=2))
    raise SystemExit(bool(audit.failures))
