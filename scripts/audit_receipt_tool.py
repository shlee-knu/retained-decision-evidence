"""Independent exhaustive abstract receipt adapter audit; no benchmark claims."""
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from itertools import permutations, product
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import revalidate_receipt as candidate
from compare_catalogs import read_catalog
from stress_acquisition import raw_time

OUT = ROOT / "results/third/receipt_audit"
ACTIVITIES = ("create", "receive", "invoice", "clear")
PROFILES = ("3-way match, invoice after GR", "3-way match, invoice before GR", "2-way match", "Consignment")
DOMAINS = ("cartesian:v1", "chronological:v1", "consignment_exclusion:v1", "both:v1")
TARGETS = {"identity": "examples/baseline_catalog.json", "strict": "examples/strict_consignment_catalog.json",
           "equivalent": "examples/second_equivalent_catalog.json", "label_flip": "examples/second_label_flip_catalog.json"}
STATUS = {"safe": 0, "stale_verdict": 1, "insufficient": 2, "unsupported": 3, "invalid_receipt": 4}
SNAPSHOT = "0" * 64  # Explicit constructed fixture identifier; never a source claim.


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def gz_json(path, value):
    with path.open("xb") as stream:
        with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as zipped:
            zipped.write(canonical(value))


def raw_universe():
    """Independent realization generator; candidate universe is never called."""
    for count in range(5):
        for order in permutations(ACTIVITIES, count):
            for q in product(range(count), repeat=count):
                if q and sorted(set(q)) != list(range(max(q) + 1)):
                    continue
                for profile in PROFILES:
                    yield {"activities": list(order), "profile": profile,
                           "first_times": {a: f"2020-01-01T00:00:0{r}Z" for a, r in zip(order, q)}}


def direct_label(raw, catalog):
    """Raw JSON atoms and independent clocks; no candidate verdict/abstraction."""
    rule = catalog[raw["profile"]]
    activities = raw["activities"]
    if any(a not in activities for a in rule["required"]):
        return False
    if any(a in activities for a in rule["forbidden"]):
        return False
    for before, after in rule["edges"]:
        if after in activities:
            if before not in activities or activities.index(before) >= activities.index(after):
                return False
            if raw_time(raw["first_times"][before]) > raw_time(raw["first_times"][after]):
                return False
    return True


def direct_member(raw, domain):
    clocks = [raw_time(raw["first_times"][a]) for a in dict.fromkeys(raw["activities"])]
    chronology = all(a <= b for a, b in zip(clocks, clocks[1:]))
    exclusion = raw["profile"] != "Consignment" or not any(a in raw["activities"] for a in ("invoice", "clear"))
    return {"cartesian:v1": True, "chronological:v1": chronology,
            "consignment_exclusion:v1": exclusion, "both:v1": chronology and exclusion}[domain]


def visible_key(activities, observed):
    """Normalize only observed values using the independent reference parser."""
    order = tuple(dict.fromkeys(activities))
    ranks = None
    if "first_times" in observed:
        parsed = [raw_time(observed["first_times"][a]) for a in order]
        levels = sorted(set(parsed))
        ranks = tuple(levels.index(t) for t in parsed)
    return (order, observed.get("profile"), ranks)


def feature_key(raw, mask):
    observed = {name: raw[name] for bit, name in ((1, "profile"), (2, "first_times")) if mask & bit}
    return visible_key(raw["activities"], observed)


def expected_status(old_n, old_bits, recorded, new_n, new_bits):
    wanted_old = 2 if recorded else 1
    if not old_n or old_bits != wanted_old:
        return "invalid_receipt"
    if not new_n:
        return "unsupported"
    if new_bits == 3:
        return "insufficient"
    return "safe" if new_bits == wanted_old else "stale_verdict"


class IndependentOracle:
    def __init__(self):
        self.raws = tuple(raw_universe())
        assert len(self.raws) == 8612
        self.catalogs = {name: json.loads((ROOT / path).read_text()) for name, path in TARGETS.items()}
        self.labels = {name: tuple(direct_label(raw, c) for raw in self.raws) for name, c in self.catalogs.items()}
        self.members = {d: tuple(direct_member(raw, d) for raw in self.raws) for d in DOMAINS}
        self.keys = [tuple(feature_key(raw, mask) for raw in self.raws) for mask in range(4)]
        self.groups = {d: [defaultdict(list) for _ in range(4)] for d in DOMAINS}
        for d in DOMAINS:
            for i, member in enumerate(self.members[d]):
                if member:
                    for mask in range(4):
                        self.groups[d][mask][self.keys[mask][i]].append(i)
        self.outcomes = {}
        for target in TARGETS:
            self.outcomes[target] = {}
            for d in DOMAINS:
                self.outcomes[target][d] = []
                for mask in range(4):
                    values = {}
                    for key, ids in self.groups[d][mask].items():
                        bits = 0
                        for i in ids:
                            bits |= 1 << int(self.labels[target][i])
                        values[key] = (len(ids), bits)
                    self.outcomes[target][d].append(values)

    def summary(self, target, domain, mask, key):
        return self.outcomes[target][domain][mask].get(key, (0, 0))

    def valid_classes(self, domain):
        for mask in range(4):
            for key in sorted(self.groups[domain][mask], key=repr):
                n, bits = self.summary("identity", domain, mask, key)
                if bits in (1, 2):
                    yield mask, key, bits == 2, n

    def receipt(self, domain, mask, key, recorded):
        i = self.groups[domain][mask][key][0]
        raw = self.raws[i]
        return {"schema_version": 1, "snapshot_sha256": SNAPSHOT,
                "catalog_sha256": hashlib.sha256(canonical(self.catalogs["identity"])).hexdigest(),
                "domain_version": domain, "activities": list(raw["activities"]),
                "observed": {name: deepcopy(raw[name]) for bit, name in ((1, "profile"), (2, "first_times")) if mask & bit},
                "verdict": recorded}


def verify_witnesses(result, receipt, oracle, target, old_domain, new_domain):
    for item in result["compatible_new_completions"]:
        raw = item["features"]
        assert raw["activities"] == receipt["activities"]
        assert all(raw[name] == value for name, value in receipt["observed"].items())
        assert direct_label(raw, oracle.catalogs["identity"]) == item["before_verdict"]
        assert direct_label(raw, oracle.catalogs[target]) == item["after_verdict"]
        assert direct_member(raw, old_domain) == item["before_domain_member"]
        assert direct_member(raw, new_domain) == item["after_domain_member"]


def make_engine(target, old_domain, new_domain):
    return candidate.Revalidator(read_catalog(ROOT / TARGETS["identity"]), read_catalog(ROOT / TARGETS[target]),
                                 old_domain, new_domain, SNAPSHOT)


def negative_controls(oracle):
    records = []
    checker = make_engine("strict", "cartesian:v1", "cartesian:v1")
    full = next(x for x in oracle.valid_classes("cartesian:v1") if x[0] == 3)
    good = oracle.receipt("cartesian:v1", full[0], full[1], full[2])
    bad = deepcopy(good)
    bad["verdict"] = not bad["verdict"]
    r = checker.revalidate(bad, witnesses=False)
    assert r["status"] == "invalid_receipt"
    records.append({"name": "opposite_recorded_label", "status": r["status"]})
    for domain, cause in (("cartesian:v1", "ambiguous_old"), ("both:v1", "empty_old")):
        for mask in range(4):
            found = False
            for raw in oracle.raws:
                key = feature_key(raw, mask)
                n, bits = oracle.summary("identity", domain, mask, key)
                if (cause == "ambiguous_old" and bits == 3) or (cause == "empty_old" and n == 0):
                    receipt = deepcopy(good)
                    receipt["domain_version"] = domain
                    receipt["activities"] = list(raw["activities"])
                    receipt["observed"] = {name: deepcopy(raw[name]) for bit, name in ((1, "profile"), (2, "first_times")) if mask & bit}
                    r = make_engine("strict", domain, "cartesian:v1").revalidate(receipt, witnesses=False)
                    assert r["status"] == "invalid_receipt"
                    records.append({"name": cause, "status": r["status"]})
                    found = True
                    break
            if found:
                break
    for field in ("snapshot_sha256", "catalog_sha256"):
        bad = deepcopy(good)
        bad[field] = "f" * 64
        try:
            checker.revalidate(bad)
        except ValueError:
            records.append({"name": "wrong_" + field, "status": "binding_error"})
        else:
            raise AssertionError(field)
    observed_clock = next(x for x in oracle.valid_classes("cartesian:v1") if x[0] == 3 and x[1][0])
    bad = oracle.receipt("cartesian:v1", observed_clock[0], observed_clock[1], observed_clock[2])
    bad["observed"]["first_times"][next(iter(bad["observed"]["first_times"]))] = "2020-01-01T00:00:60Z"
    try:
        checker.revalidate(bad)
    except ValueError:
        records.append({"name": "malformed_observed_clock", "status": "syntax_error"})
    else:
        raise AssertionError("leap second accepted")
    return records


def recovery_pairs():
    return (("strict", "cartesian:v1", "cartesian:v1"),
            ("identity", "chronological:v1", "cartesian:v1"),
            ("identity", "consignment_exclusion:v1", "cartesian:v1"),
            ("identity", "both:v1", "cartesian:v1"),
            ("identity", "both:v1", "chronological:v1"),
            ("identity", "both:v1", "consignment_exclusion:v1"))


def prepare_output(path):
    path = Path(path).resolve()
    if path.exists():
        if not path.is_dir():
            raise ValueError("Output must be a directory")
        unexpected = [p.name for p in path.iterdir() if p.name not in {"pytest.xml", "run.log"} or not p.is_file()]
        if unexpected:
            raise ValueError("Output is populated; choose a fresh directory: " + ", ".join(sorted(unexpected)))
    path.mkdir(parents=True, exist_ok=True)
    return path


def manifest_path(path):
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUT,
                        help="Fresh results directory; only pytest.xml and run.log may already exist")
    args = parser.parse_args(argv)
    try:
        out = prepare_output(args.output)
    except ValueError as error:
        parser.error(str(error))
    start = time.perf_counter()
    protocol = ROOT / "configs/third_receipt_audit_protocol.json"
    design = json.loads(protocol.read_text())
    oracle = IndependentOracle()
    classes = {d: list(oracle.valid_classes(d)) for d in DOMAINS}
    assert {d: len(v) for d, v in classes.items()} == design["expected_old_observation_counts"]
    print("independent oracle and22498old-validclasses ready", flush=True)
    engines = {(t, old, new): make_engine(t, old, new) for t in TARGETS for old in DOMAINS for new in DOMAINS}
    columns = [(t, d) for t in TARGETS for d in DOMAINS]
    rows, vectors, witnesses = [], [], []
    matrix_counts = defaultdict(Counter)
    actual_hash, expected_hash = hashlib.sha256(), hashlib.sha256()
    checks = 0
    witness_seen = set()
    for old_domain in DOMAINS:
        for mask, key, recorded, old_n in classes[old_domain]:
            receipt = oracle.receipt(old_domain, mask, key, recorded)
            expected_vector = []
            class_id = len(vectors)
            for target, new_domain in columns:
                new_n, new_bits = oracle.summary(target, new_domain, mask, key)
                status = expected_status(old_n, 2 if recorded else 1, recorded, new_n, new_bits)
                result = engines[target, old_domain, new_domain].revalidate(receipt, witnesses=False)
                labels = [bool(v) for v in range(2) if new_bits & (1 << v)]
                assert result["status"] == status
                assert result["before_compatible_classes"] == old_n
                assert result["after_compatible_classes"] == new_n
                assert result["after_labels"] == labels
                actual_hash.update(canonical([class_id, target, new_domain, result["status"], result["after_compatible_classes"], result["after_labels"]]) + b"\n")
                expected_hash.update(canonical([class_id, target, new_domain, status, new_n, labels]) + b"\n")
                matrix_counts[target, old_domain, new_domain][status] += 1
                expected_vector.append([STATUS[status], new_n, new_bits])
                checks += 1
                wk = target, old_domain, new_domain, status
                if wk not in witness_seen:
                    specimen = deepcopy(receipt)
                    specimen["activities"] = [a for a in specimen["activities"] for _ in range(2)]
                    # Equivalent literal representation, retained exactly in witnesses.
                    if "first_times" in specimen["observed"]:
                        specimen["observed"]["first_times"] = {a: t.replace("T00:", "t01:").replace("Z", "+01:00")
                                                                 for a, t in specimen["observed"]["first_times"].items()}
                    detail = engines[target, old_domain, new_domain].revalidate(specimen)
                    assert detail["status"] == status
                    verify_witnesses(detail, specimen, oracle, target, old_domain, new_domain)
                    witnesses.append({"target": target, "old_domain": old_domain, "new_domain": new_domain,
                                      "class_id": class_id, "receipt": specimen, "result": detail})
                    witness_seen.add(wk)
            vectors.append({"class_id": class_id, "old_domain": old_domain, "mask": mask, "key": key,
                            "recorded_verdict": recorded, "old_compatible_states": old_n, "expected": expected_vector})
        print(f"classifications complete through{old_domain}", flush=True)
    assert checks == design["expected_total_classification_checks"]
    assert actual_hash.hexdigest() == expected_hash.hexdigest()
    for (target, old, new), counts in matrix_counts.items():
        rows.append({"target": target, "old_domain": old, "new_domain": new, "old_valid_classes": sum(counts.values()),
                     **{s: counts[s] for s in STATUS}})
    recovery_rows, recovery_hash = [], hashlib.sha256()
    recovery_checks = 0
    for target, old_domain, new_domain in recovery_pairs():
        engine = engines[target, old_domain, new_domain]
        counts = Counter()
        for mask, key, recorded, old_n in classes[old_domain]:
            receipt = oracle.receipt(old_domain, mask, key, recorded)
            for actual_index in oracle.groups[new_domain][mask].get(key, ()):
                raw = oracle.raws[actual_index]
                seen, calls = deepcopy(receipt["observed"]), []
                initial_n, initial_bits = oracle.summary(target, new_domain, mask, key)
                expected_requests = []
                while True:
                    current_mask = int("profile" in seen) + 2 * int("first_times" in seen)
                    current_key = visible_key(raw["activities"], seen)
                    n, bits = oracle.summary(target, new_domain, current_mask, current_key)
                    if bits in (1, 2):
                        expected_verdict = bits == 2
                        expected_old_compatible = bool(oracle.summary("identity", old_domain, current_mask, current_key)[0])
                        break
                    assert n and bits == 3
                    field = "profile" if "profile" not in seen else "first_times"
                    expected_requests.append(field)
                    seen[field] = deepcopy(raw[field])

                def fetch(name):
                    assert name not in receipt["observed"] and name not in calls
                    assert name in ("profile", "first_times")
                    calls.append(name)
                    return deepcopy(raw[name])

                result = engine.recover(receipt, fetch)
                assert result["requested_blocks"] == calls == expected_requests
                assert result["verdict"] == expected_verdict == oracle.labels[target][actual_index]
                assert result["status"] == ("safe" if expected_verdict == recorded else "stale_verdict")
                assert result["old_domain_still_compatible"] == expected_old_compatible
                assert result["retained_observed"] == seen
                counts["recoveries"] += 1
                counts["initially_insufficient"] += initial_bits == 3
                counts["P_reads"] += "profile" in calls
                counts["T_reads"] += "first_times" in calls
                counts["old_domain_incompatible_after_reads"] += not expected_old_compatible
                counts[result["status"]] += 1
                recovery_checks += 1
                recovery_hash.update(canonical([target, old_domain, new_domain, mask, key, actual_index, calls,
                                                result["status"], result["verdict"], expected_old_compatible]) + b"\n")
        recovery_rows.append({"target": target, "old_domain": old_domain, "new_domain": new_domain, **dict(counts)})
        print(f"recovery complete:{target}/{old_domain}->{new_domain}", flush=True)
    negatives = negative_controls(oracle)
    summary = {"status": "passed", "created_utc": datetime.now(timezone.utc).isoformat(),
               "scope": "Exhaustive finite abstract OLD observation classes for baseline, fourtargetcatalogs, sixteen domaintransitions. Canonicalclock representatives do not exhaust arbitrarytimestampstrings or authenticate receipts.",
               "old_valid_classes": {d: len(v) for d, v in classes.items()}, "total_old_valid_classes": sum(map(len, classes.values())),
               "classification_checks": checks, "classification_actual_sha256": actual_hash.hexdigest(),
               "classification_expected_sha256": expected_hash.hexdigest(), "classification_matrix": rows,
               "status_totals": dict(sum(matrix_counts.values(), Counter())),
               "representative_witness_records": len(witnesses), "recovery_checks": recovery_checks,
               "recovery_stream_sha256": recovery_hash.hexdigest(), "recovery_matrix": recovery_rows,
               "negative_controls": negatives, "disagreements": 0, "elapsed_seconds": time.perf_counter() - start}
    dump(out / "summary.json", summary)
    dump(out / "witnesses.json", witnesses)
    gz_json(out / "expected_vectors.json.gz", {"status_codes": STATUS, "columns": columns,
                                               "expected_cell": ["status_code", "new_compatible_states", "new_label_bitset"],
                                               "rows": vectors})
    gz_json(out / "independent_finite_oracle.json.gz", {"raw_states": oracle.raws,
                                                        "labels": oracle.labels, "members": oracle.members})
    input_paths = [protocol, ROOT / "scripts/audit_receipt_tool.py", ROOT / "tests/test_third_receipt_audit.py",
                   ROOT / "scripts/revalidate_receipt.py", ROOT / "scripts/stress_acquisition.py",
                   ROOT / "src/logistics_validation/catalog_audit.py", ROOT / "src/logistics_validation/domain_audit.py"]
    input_paths += [ROOT / p for p in TARGETS.values()]
    output_paths = [out / p for p in ("summary.json", "witnesses.json", "expected_vectors.json.gz", "independent_finite_oracle.json.gz")]
    dump(out / "manifest.json", {"status": "passed", "inputs": {manifest_path(p): sha(p) for p in input_paths},
                                 "outputs": {manifest_path(p): sha(p) for p in output_paths}})
    print(json.dumps({k: summary[k] for k in ("status", "classification_checks", "status_totals", "recovery_checks", "elapsed_seconds")}, indent=2))


if __name__ == "__main__":
    main()
