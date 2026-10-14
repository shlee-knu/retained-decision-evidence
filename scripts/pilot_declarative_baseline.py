"""Reproduce the actual MP-Declare comparator on the frozen public-data suite.

Examples:
  .venv/bin/python scripts/pilot_declarative_baseline.py --max-per-group 30
  .venv/bin/python scripts/pilot_declarative_baseline.py --max-per-group 0 --all-conditions

The experiment is an added, post-v1 comparison. It is not preregistered.
Dependencies: declare4py==2.2.0 and the repository's existing dependencies.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
import time

from logistics_validation.constraints import SchemaChecker, indexed_issues
from logistics_validation.declarative_baseline import (
    SUPPORTED_RULES, clear_model_cache, model_text, mp_declare_issues,
)
from logistics_validation.model import Case
from run_experiments import metrics, suite

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-per-group", type=int, default=30, help="0 means all original selected cases")
    parser.add_argument("--all-conditions", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "results/declarative_pilot.json")
    args = parser.parse_args()
    source = ROOT / "data/processed/cases.jsonl"
    all_cases = [Case.from_dict(json.loads(x)) for x in source.read_text().splitlines()]
    grouped = defaultdict(list)
    for case in all_cases:
        grouped[(case.dataset, case.group)].append(case)
    cases = []
    for key, group in sorted(grouped.items()):
        # Hash-ranked subset is reproducible and avoids taking a prefix of the
        # BPI input order. It remains conditional on the original cohort.
        group = sorted(group, key=lambda c: sha256(c.case_id.encode()).hexdigest())
        cases.extend(group[:args.max_per_group] if args.max_per_group else group)
    if not args.max_per_group:
        # Preserve the exact v1 case order, hence its random-mutation assignment.
        cases = all_cases
    config = json.loads((ROOT / "configs/protocol_v1.json").read_text())
    conditions = [(seed, rate) for seed in config["seeds"] for rate in config["fault_prevalence"]]
    if not args.all_conditions:
        conditions = [(config["seeds"][0], 0.2)]
    checker = SchemaChecker()
    records = []
    for seed, rate in conditions:
        mutants, labels, kinds, _ = suite(cases, seed, rate)
        schema = [not checker.valid(c) for c in mutants]
        indexed = [bool(indexed_issues(c)) for c in mutants]
        out = {"seed": seed, "prevalence": rate, "cases": len(mutants), "methods": {}}
        for scope in ("process", "full"):
            clear_model_cache()
            t0 = time.perf_counter()
            result = mp_declare_issues(mutants, scope)
            elapsed = time.perf_counter() - t0
            semantic = [bool(result[c.case_id]) for c in mutants]
            predicted = [a or b for a, b in zip(semantic, schema)]
            mismatches = [c.case_id for c, a, b in zip(mutants, semantic, indexed) if a != b]
            by_kind = {}
            for kind in sorted(set(kinds)):
                indexes = [i for i, k in enumerate(kinds) if k == kind]
                by_kind[kind] = {
                    "n": len(indexes), "semantic_rejections": sum(semantic[i] for i in indexes),
                    "combined_rejections": sum(predicted[i] for i in indexes),
                }
            out["methods"][scope] = {
                "schema_combined_metrics": metrics(labels, predicted),
                "semantic_decision_disagreements_with_indexed": len(mismatches),
                "disagreement_examples": mismatches[:10], "by_kind": by_kind,
                "wall_seconds_including_projection_and_cold_model_compilation": elapsed,
            }
        records.append(out)
        full = out["methods"]["full"]
        print(json.dumps({"seed": seed, "prevalence": rate,
                          "full_metrics": full["schema_combined_metrics"],
                          "full_disagreements": full["semantic_decision_disagreements_with_indexed"],
                          "full_seconds": full["wall_seconds_including_projection_and_cold_model_compilation"]},
                         ensure_ascii=False), flush=True)
    profiles = {}
    for case in cases:
        profiles.setdefault(case.profile, {
            scope: model_text(case, scope) for scope in ("process", "full")
        })
    report = {
        "status": "post-v1 supplementary comparator; not preregistered",
        "engine": "Declare4Py MPDeclareAnalyzer", "version": version("declare4py"),
        "case_file_sha256": sha256(source.read_bytes()).hexdigest(),
        "cohort_size": len(cases), "original_cohort_size": len(all_cases),
        "groups": dict(Counter(c.dataset + ":" + c.group for c in cases)),
        "supported_rules": SUPPORTED_RULES, "conditions": records, "models": profiles,
        "interpretation": (
            "The matched full scope uses existing MP-Declare templates with data correlations. "
            "Accuracy equivalence demonstrates executable semantic portability, not novelty or "
            "superiority. Process-only omissions are an explicit feature-scope ablation. "
            "Runtime is exploratory, single execution per condition, not a timing comparison. "
            "First occurrence is an adapter attribute; repetitions remain in original order. "
            "Timestamp normalization is independently implemented with exact Decimal values, "
            "then converted to per-case ordinal ranks preserving signed order and equality. "
            "No duration constraint is claimed. "
            "No natural anomaly labels or unseen-domain performance are inferred."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
