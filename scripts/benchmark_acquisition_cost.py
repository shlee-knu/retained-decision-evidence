"""Fair local component costs for procurement metadata acquisition.

The timed boundary is an already-available activity projection plus two raw,
compact JSON byte blocks. Every policy uses the same audited, per-read JSON
deserializer. No per-case structure, parsed clocks, choices, or labels are
prepared for a policy. Full-input direct evaluation fetches BOTH blocks and
evaluates the contract ONCE; certificate-based always_both is only a diagnostic
comparator. All results are conditional on the existing trusted supported-input
domain. Local CPU/wall measurements are not network measurements.
"""
from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import gc
import gzip
import hashlib
from itertools import permutations, product
import json
import os
from pathlib import Path
import platform
import random
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from logistics_validation.acquisition import (
    DEFAULT_CATALOG, acquire, exact_first_time, possible_outcomes, structural_order,
)
from stress_acquisition import expected_violation

OUT = ROOT / "results/expanded/procurement_cost"
SOURCE = ROOT / "results/v03/bpi_compact.jsonl.gz"
VARIANTS = {"permissive": {}, "strict_consignment": {"Consignment": ("invoice", "clear")}}
PROFILES = tuple(DEFAULT_CATALOG)
CATALOG = tuple(DEFAULT_CATALOG.values())
METHODS = (
    "direct_full_once", "certificate_full_once", "certificate_always_both",
    "certificate_profile_first", "certificate_time_first", "certificate_structural",
    "hand_profile_first", "hand_time_first", "hand_structural",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_document(document):
    value = int.from_bytes(hashlib.sha256(f"projection-audit-v03:17:{document}".encode()).digest()[:8], "big") % 100
    return value >= 80


def encode_block(name, value):
    return json.dumps({name: value}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EncodedCase:
    activities: tuple
    profile_bytes: bytes
    time_bytes: bytes


def encode_case(case):
    return EncodedCase(tuple(case["activities"]), encode_block("profile", case["profile"]),
                       encode_block("first_times", case["first_times"]))


class SerializedAccessor(Mapping):
    """Identical raw-byte read/decode boundary for direct and selective methods."""
    __slots__ = ("_case", "mask", "bytes_read", "decodes", "trace")

    def __init__(self, case):
        self._case = case
        self.mask = 0
        self.bytes_read = 0
        self.decodes = 0
        self.trace = []

    def __getitem__(self, name):
        if name == "activities":
            return self._case.activities
        bit = {"profile": 1, "first_times": 2}[name]
        if self.mask & bit:
            raise AssertionError("Duplicate metadata decode")
        blob = self._case.profile_bytes if bit == 1 else self._case.time_bytes
        self.mask |= bit
        self.trace.append(name)
        self.bytes_read += len(blob)
        self.decodes += 1
        return json.loads(blob)[name]

    def __iter__(self):
        raise AssertionError("Bulk metadata access is forbidden")

    def __len__(self):
        return 3


def positions(activities):
    first = {}
    for i, activity in enumerate(activities):
        first.setdefault(activity, i)
    return first


def eligible(first, profile_index, strict):
    required, edges = CATALOG[profile_index]
    if any(a not in first for a in required):
        return False
    if strict and PROFILES[profile_index] == "Consignment" and ("invoice" in first or "clear" in first):
        return False
    return all(first[a] < first[b] for a, b in edges)


def clocks_hold(first_times, profile_index, parsed):
    """Per-call parse reuse AFTER the timestamp block is fetched; never cached."""
    for a, b in CATALOG[profile_index][1]:
        for activity in (a, b):
            if activity not in parsed:
                parsed[activity] = exact_first_time(first_times[activity])
                if parsed[activity] is None:
                    raise ValueError("Hand baseline received an unsupported timestamp")
        if parsed[a] > parsed[b]:
            return False
    return True


def direct_full_once(access, strict):
    """Strong baseline: always deserialize both blocks, one full verdict."""
    profile = access["profile"]
    times = access["first_times"]
    first = positions(access["activities"])
    index = PROFILES.index(profile)
    return eligible(first, index, strict) and clocks_hold(times, index, {})


def hand_acquire(access, strict, order):
    """Hand-coded known short-circuit logic, without rich certificates.

    Its domain is the same valid finite catalog and supported clock domain as
    the current paper. It is not an unrestricted schema validator. It records
    the same final binary decision and actual read ledger as all comparators.
    """
    first = positions(access["activities"])
    possible = [eligible(first, i, strict) for i in range(len(PROFILES))]
    if not any(possible):
        return False
    if order == "structural":
        order = "time_first" if all(possible) else "profile_first"
    if order == "profile_first":
        index = PROFILES.index(access["profile"])
        if not possible[index]:
            return False
        return clocks_hold(access["first_times"], index, {})
    if order != "time_first":
        raise ValueError(order)
    times = access["first_times"]
    parsed = {}
    outcomes = [flag and clocks_hold(times, i, parsed) for i, flag in enumerate(possible)]
    if all(outcomes):
        return True
    if not any(outcomes):
        return False
    return outcomes[PROFILES.index(access["profile"])]


def decide(access, strict, method):
    forbidden = VARIANTS["strict_consignment" if strict else "permissive"]
    if method == "direct_full_once":
        return direct_full_once(access, strict)
    if method == "certificate_full_once":
        profile = access["profile"]
        stamps = access["first_times"]
        result = possible_outcomes(access["activities"], profile=profile, first_times=stamps, forbidden=forbidden)
        if result["status"] != "determined":
            raise AssertionError(result)
        return result["decision"] == "accept"
    if method.startswith("hand_"):
        return hand_acquire(access, strict, method.removeprefix("hand_"))
    policy = method.removeprefix("certificate_")
    if policy == "structural":
        # The public implementation really runs both calls; no free precomputed
        # structural choices or reuse of saved fixed-policy outcomes.
        policy = structural_order(access["activities"], forbidden=forbidden)
    result = acquire(access, policy=policy, forbidden=forbidden)
    if result["status"] != "determined":
        raise AssertionError(result)
    if result["fetched_blocks"] != access.trace:
        raise AssertionError("Candidate trace disagrees with actual JSON reads")
    return result["decision"] == "accept"


def execute(encoded, truth, order, strict, method):
    """One equal timed boundary, including audit ledger and correctness check."""
    nq_p = nq_t = nbytes = decodes = accepted = mismatches = zero = one = two = 0
    for index in order:
        access = SerializedAccessor(encoded[index])
        answer = decide(access, strict, method)
        accepted += answer
        mismatches += answer != truth[index]
        nq_p += bool(access.mask & 1)
        nq_t += bool(access.mask & 2)
        nbytes += access.bytes_read
        decodes += access.decodes
        zero += access.mask == 0
        one += access.mask in (1, 2)
        two += access.mask == 3
    return dict(n=len(order), profile_queries=nq_p, time_queries=nq_t, payload_bytes=nbytes,
                json_decodes=decodes, accepted=accepted, mismatches=mismatches,
                no_metadata_cases=zero, one_block_cases=one, two_block_cases=two)


def verify_bounded():
    """Independent Fraction oracle over all permutations and weak clock orders."""
    alphabet = ("create", "receive", "invoice", "clear")
    ranks = [values for values in product(range(4), repeat=4) if set(values) == set(range(max(values) + 1))]
    assert len(ranks) == 75
    calls = 0
    for sequence in permutations(alphabet):
        for values in ranks:
            stamps = {a: f"2020-01-01T00:00:0{rank}.000Z" for a, rank in zip(alphabet, values)}
            for profile in PROFILES:
                case = dict(activities=list(sequence), profile=profile, first_times=stamps)
                encoded = encode_case(case)
                for strict in (False, True):
                    truth = not expected_violation(case, strict)
                    masks = {}
                    for method in METHODS:
                        access = SerializedAccessor(encoded)
                        assert decide(access, strict, method) == truth, (case, strict, method)
                        masks[method] = access.mask
                        calls += 1
                    for suffix in ("profile_first", "time_first", "structural"):
                        assert masks["hand_" + suffix] == masks["certificate_" + suffix]
    return dict(weak_clock_orders=75, activity_permutations=24, profiles=4,
                catalogs=2, methods=len(METHODS), evaluations=calls, mismatches=0,
                scope="All four distinct milestones only; native and paired source fixtures cover additional missing/repeated activity patterns.")


def verify_stress():
    path = ROOT / "results/v03/acquisition_stress_fixtures.jsonl.gz"
    calls = rows = 0
    with gzip.open(path, "rt") as stream:
        for line in stream:
            fixture = json.loads(line)
            # Field names are taken from the frozen source fixture schema.
            case = fixture["features"]
            strict = fixture["variant"] == "strict_consignment"
            truth = not expected_violation(case, strict)
            encoded = encode_case(case)
            masks = {}
            for method in METHODS:
                access = SerializedAccessor(encoded)
                assert decide(access, strict, method) == truth, (fixture, method)
                masks[method] = access.mask
                calls += 1
            for suffix in ("profile_first", "time_first", "structural"):
                assert masks["hand_" + suffix] == masks["certificate_" + suffix]
            rows += 1
    return dict(rows=rows, evaluations=calls, mismatches=0, source_sha256=sha(path))


def environment():
    cpu_model = None
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    info = dict(python=sys.version, executable=sys.executable, platform=platform.platform(),
                cpu_model=cpu_model, logical_cpu_count=os.cpu_count(),
                affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
                python_hash_seed=os.environ.get("PYTHONHASHSEED"), garbage_collection_enabled=gc.isenabled(),
                cpu_clock=time.get_clock_info("process_time")._asdict() if hasattr(time.get_clock_info("process_time"), "_asdict") else str(time.get_clock_info("process_time")),
                wall_clock=str(time.get_clock_info("perf_counter")))
    for name in ("cpu.max", "cpu.stat", "memory.max"):
        path = Path("/sys/fs/cgroup") / name
        if path.exists():
            info["cgroup_" + name.replace(".", "_")] = path.read_text().strip()
    return info


def distribution(values):
    ordered = sorted(values)
    quartiles = statistics.quantiles(ordered, n=4, method="inclusive")
    return dict(n=len(values), minimum=min(values), q1=quartiles[0], median=statistics.median(values),
                q3=quartiles[2], maximum=max(values), mean=statistics.mean(values),
                standard_deviation=statistics.stdev(values) if len(values) > 1 else 0.0,
                values=values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=9)
    parser.add_argument("--limit", type=int, default=None, help="Calibration only; cannot write canonical output with a limit")
    parser.add_argument("--cpu", type=int, default=None, help="Optionally pin this process to an allowed CPU")
    parser.add_argument("--verification-only", action="store_true")
    parser.add_argument("--skip-bounded", action="store_true", help="Calibration only; canonical run requires bounded and stress checks")
    args = parser.parse_args()
    if args.repeats < 2 or args.warmups < 1 or (args.limit is not None and args.limit < 1):
        raise SystemExit("Require >=2 measured rounds, >=1 warmup, and positive calibration size")
    if args.output.resolve() == OUT.resolve() and (args.limit or args.skip_bounded or args.repeats < 7 or args.warmups < 1):
        raise SystemExit("Canonical output requires complete test workload, bounded checks, >=7 measured rounds and warmup")
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.verification_only and (args.output / "rounds.jsonl").exists():
        raise SystemExit("Use a fresh output directory; prior timing records are never silently appended or replaced")
    started = time.perf_counter()
    environment_before = environment()
    selected = []
    for line in gzip.open(SOURCE, "rt"):
        case = json.loads(line)
        if test_document(case["document"]):
            selected.append(case)
    assert len(selected) == 50931
    if args.limit:
        # Deterministic evenly distributed indices, NOT the first easy cases.
        size = min(args.limit, len(selected))
        selected = [selected[i * len(selected) // size] for i in range(size)]
    truth = {strict: [not expected_violation(c, strict) for c in selected] for strict in (False, True)}
    assert truth[False] == truth[True]
    for c, value in zip(selected, truth[False]):
        assert value == (not c["violation"])
    # Serialization and original archive parsing are common setup, not timed.
    encoded = [encode_case(c) for c in selected]
    ids_sha = hashlib.sha256("\n".join(c["case_id"] for c in selected).encode()).hexdigest()
    del selected
    bounded = None if args.skip_bounded else verify_bounded()
    stress = None if args.skip_bounded else verify_stress()
    print(json.dumps({"stage": "correctness_ready", "n": len(encoded), "bounded": bounded, "stress": stress}), flush=True)
    jobs = [(variant, method) for variant in VARIANTS for method in METHODS]
    native = {}
    order = list(range(len(encoded)))
    for variant, method in jobs:
        result = execute(encoded, truth[variant == "strict_consignment"], order, variant == "strict_consignment", method)
        assert result["mismatches"] == 0
        native[(variant, method)] = result
    # Existing saved counts independently constrain the selected policy masks.
    historical = json.loads((ROOT / "results/v03/acquisition_results.json").read_text())
    if not args.limit:
        method_to_old = {"certificate_profile_first": "profile_first", "certificate_time_first": "time_first",
                         "certificate_structural": "structural_order", "hand_profile_first": "profile_first",
                         "hand_time_first": "time_first", "hand_structural": "structural_order",
                         "direct_full_once": "always_both", "certificate_full_once": "always_both",
                         "certificate_always_both": "always_both"}
        for (variant, method), actual in native.items():
            old = next(r for r in historical["holdout"] if r["seed"] == 17 and r["variant"] == variant and r["policy"] == method_to_old[method])
            for field in ("n", "profile_queries", "time_queries", "payload_bytes", "no_metadata_cases", "one_block_cases", "two_block_cases"):
                assert actual[field] == old[field], (variant, method, field)
    verification = dict(bounded=bounded, controlled_stress=stress, native_mismatches=0,
                        native_policy_evaluations=len(encoded) * len(jobs),
                        historical_count_reconciliation=not bool(args.limit))
    (args.output / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    if args.verification_only:
        return
    rng = random.Random(20261007)
    rounds = []
    for round_number in range(-args.warmups, args.repeats):
        phase = "warmup" if round_number < 0 else "measured"
        rng.shuffle(order)
        shuffled_jobs = list(jobs)
        rng.shuffle(shuffled_jobs)
        for position, (variant, method) in enumerate(shuffled_jobs):
            gc.collect()
            wall0 = time.perf_counter_ns()
            cpu0 = time.process_time_ns()
            result = execute(encoded, truth[variant == "strict_consignment"], order,
                             variant == "strict_consignment", method)
            cpu_ns = time.process_time_ns() - cpu0
            wall_ns = time.perf_counter_ns() - wall0
            assert result == native[(variant, method)]
            record = dict(phase=phase, round=round_number, execution_position=position,
                          variant=variant, method=method, cpu_ns=cpu_ns, wall_ns=wall_ns,
                          cpu_ns_per_case=cpu_ns / len(encoded), wall_ns_per_case=wall_ns / len(encoded),
                          **result)
            rounds.append(record)
            with (args.output / "rounds.jsonl").open("a") as stream:
                stream.write(json.dumps(record, separators=(",", ":")) + "\n")
        print(json.dumps({"stage": phase, "round": round_number, "elapsed_seconds": time.perf_counter() - started}), flush=True)
    rows = []
    for variant, method in jobs:
        observations = [r for r in rounds if r["phase"] == "measured" and r["variant"] == variant and r["method"] == method]
        baseline = {r["round"]: r for r in rounds if r["phase"] == "measured" and r["variant"] == variant and r["method"] == "direct_full_once"}
        deltas = [r["cpu_ns"] - baseline[r["round"]]["cpu_ns"] for r in observations]
        metrics = native[(variant, method)]
        qp, qt = len(encoded) - metrics["profile_queries"], len(encoded) - metrics["time_queries"]
        avoided = qp + qt
        overhead = statistics.median(deltas)
        rows.append(dict(variant=variant, method=method, **metrics,
                         cpu_ns_per_case=distribution([r["cpu_ns_per_case"] for r in observations]),
                         wall_ns_per_case=distribution([r["wall_ns_per_case"] for r in observations]),
                         paired_cpu_delta_ns=distribution(deltas),
                         avoided_profile_reads=qp, avoided_time_reads=qt,
                         model_equal_separable_query_break_even_ns=max(0.0, overhead) / avoided if avoided else None,
                         model_joint_full_vs_separate_policy_extra_rpcs=metrics["profile_queries"] + metrics["time_queries"] - len(encoded),
                         model_joint_full_vs_separate_policy_cpu_delta_ns=overhead))
    report = dict(status="passed", created_utc=datetime.now(timezone.utc).isoformat(),
                  workload="Complete canonical salt-17 document-held-out BPI2019 workload" if not args.limit else "Calibration subset, not final evidence",
                  n=len(encoded), source_sha256=sha(SOURCE), selected_case_ids_sha256=ids_sha,
                  engine_sha256=sha(ROOT / "src/logistics_validation/acquisition.py"),
                  benchmark_sha256=sha(Path(__file__)), independent_oracle_sha256=sha(ROOT / "scripts/stress_acquisition.py"),
                  warmup_rounds=args.warmups, measured_rounds=args.repeats, random_seed=20261007,
                  environment_before=environment_before, environment_after=environment(),
                  verification=verification, results=rows,
                  timed_boundary="Per case: create audited accessor; read/decode requested compact JSON byte blocks; compute positions, contract logic and exact clock comparisons; materialize existing certificate diagnostics where applicable; record identical decision/read/byte ledger and compare independent truth. No network/disk, sleeping, pre-parsed clocks, precomputed eligibility or across-case policy caches.",
                  common_setup_excluded="Read compact gzip, choose fixed test documents, independently verify truth and encode raw JSON field blocks once. All policies receive identical bytes and already available activity tuples. Configurations are static, no per-case preprocessing is free.",
                  output_and_domain_scope="All methods return the same binary verdict and actual block-read ledger on supported inputs. Existing certificate methods additionally construct rich profile diagnostics and validate visible input. Fast hand/direct methods assume the declared trusted domain and do not offer the same malformed-input diagnostics. Runtime difference includes this implementation/service-output difference.",
                  model_scope="Derived only: relative to two separately priced fetch-both reads, selective total additive cost difference = measured local CPU delta - avoided_P*cP - avoided_T*cT. Equal-cost threshold clips negative CPU overhead to zero. This is neither measured transport latency nor an SLA; CPU and network waiting may overlap. A joint full-fetch one-RPC baseline changes the RPC difference to QP+QT-N; report that counterexample rather than equating field reads with RPCs.",
                  elapsed_seconds=time.perf_counter() - started)
    (args.output / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"stage": "complete", "output": str(args.output), "elapsed_seconds": report["elapsed_seconds"]}), flush=True)


if __name__ == "__main__":
    main()
