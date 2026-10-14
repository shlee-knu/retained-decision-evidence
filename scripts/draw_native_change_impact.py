#!/usr/bin/env python3
"""Summarize existing native projections; this is not a new experiment.

Every count in panel (a) is a number of authored targets, not records. The two
properties are existential at target level and need not concern the same record.
Panel (b) includes zero workloads and uses an explicitly categorical x axis.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

ROOT = Path(__file__).resolve().parents[1]
SELECTION = "satisfiable_semantic_representatives"
INPUTS = {
    "target_summaries": "results/beta_improvement_20261012/native_projection/run/target_summaries.json",
    "native_projection": "results/beta_improvement_20261012/native_projection/run/summary.json",
    "original_selection": "results/robustness_revision_20261011/census/run/summary.json",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(targets: dict, names: list[str]) -> dict:
    """Derive target membership and workload frequencies without saved counts."""
    if len(names) != len(set(names)):
        raise ValueError("Each selected target must occur exactly once")
    cross = Counter({(changed, insufficient): 0
                     for changed in (False, True) for insufficient in (False, True)})
    rows = []
    workloads = Counter()
    native_counts = set()
    for name in names:
        item = targets[name]
        native = item["native_cases"]
        native_counts.add(native)
        # Rebuild the status totals from class multiplicities rather than trust
        # the target's precomputed aggregates, including zero status counts.
        statuses = Counter({"safe": 0, "stale_verdict": 0, "insufficient": 0})
        class_ids = []
        for row in item["native_observation_classes"]:
            if row["status"] not in statuses or row["native_records"] <= 0:
                raise ValueError(f"Invalid class status or multiplicity: {name}")
            statuses[row["status"]] += row["native_records"]
            class_ids.append(row["census_class_id"])
        if len(class_ids) != len(set(class_ids)):
            raise ValueError(f"Duplicate native observation class: {name}")
        if sum(statuses.values()) != native or dict(statuses) != item["status_counts"]:
            raise ValueError(f"Class multiplicities disagree with target totals: {name}")
        changed = item["complete_input_verdict_changes"]
        insufficient = statuses["insufficient"]
        # Stale determinate observations change the complete-input verdict;
        # safe determinate observations cannot. All other changes must occur
        # among insufficient observations. This provides an independent
        # partition check using the saved within-insufficient count.
        preserved = item["insufficient_records_with_preserved_complete_verdict"]
        if not (0 <= changed <= native and 0 <= preserved <= insufficient):
            raise ValueError(f"Invalid complete-input partition: {name}")
        if changed != statuses["stale_verdict"] + insufficient - preserved:
            raise ValueError(f"Complete-input verdict partition disagrees: {name}")
        cross[changed > 0, insufficient > 0] += 1
        workloads[insufficient] += 1
        rows.append({"target": name, "complete_input_verdict_changes": changed,
                     "insufficient_records": insufficient,
                     "any_complete_input_verdict_change": changed > 0,
                     "any_insufficient_record": insufficient > 0})
    if len(native_counts) != 1:
        raise ValueError("All selected targets must use the same native cohort size")
    return {
        "target_count": len(names),
        "native_records_per_target": native_counts.pop(),
        "cross_tab": [
            {"any_complete_input_verdict_change": changed,
             "any_insufficient_record": insufficient,
             "targets": cross[changed, insufficient]}
            for changed in (False, True) for insufficient in (False, True)
        ],
        "workload_frequencies": [
            {"insufficient_records_per_target": count, "targets": frequency}
            for count, frequency in sorted(workloads.items())
        ],
        "insufficient_target_record_pairs": sum(count * frequency for count, frequency in workloads.items()),
        "targets": rows,
        "interpretation": [
            "Post hoc descriptive summary of 39 authored changes under reconstructed retention on the same public archive.",
            "Cross-tab cells count targets, not cases; the two target-level properties need not hold for the same case.",
            "The selected targets are dependent and are not a sample of observed organizational changes.",
            "Workload frequencies include zero and use exact categorical values, not continuous bins.",
            "The strict two-edit anchor is excluded from this single-edit selection.",
        ],
    }


def load_evidence() -> tuple[dict, dict]:
    loaded = {key: json.loads((ROOT / path).read_text()) for key, path in INPUTS.items()}
    selected = loaded["original_selection"]["sets"][SELECTION]
    projection = loaded["native_projection"]["sets"][SELECTION]
    names = selected["target_names"]
    if names != projection["target_names"]:
        raise ValueError("Original target selection differs from the native projection")
    result = summarize(loaded["target_summaries"], names)
    assert result["target_count"] == selected["targets"] == projection["targets"] == 39
    assert result["native_records_per_target"] == projection["native_cases_per_target"] == 50931
    assert result["insufficient_target_record_pairs"] == projection["status_counts"]["insufficient"] == 411321
    assert [row["targets"] for row in result["cross_tab"]] == [13, 7, 6, 13]
    assert sum(row["targets"] for row in result["workload_frequencies"] if row["insufficient_records_per_target"]) == projection["targets_with_insufficient_records"] == 20
    expected = {0: 19, 1: 2, 2: 1, 5: 1, 113: 1, 297: 1, 3729: 1, 5305: 1, 33489: 12}
    assert {row["insufficient_records_per_target"]: row["targets"] for row in result["workload_frequencies"]} == expected
    provenance = {"status": "passed", "analysis": "Reaggregation of existing saved native projections; no new observations or interventions",
                  "input_sha256": {path: sha(ROOT / path) for path in INPUTS.values()},
                  "script_sha256": sha(Path(__file__)),
                  "checks": ["Original 39-target selection matches projection selection",
                             "No duplicate targets or observation classes",
                             "Per-target status totals independently reconstructed from class multiplicities",
                             "Complete-input changes partition into stale plus changed insufficient records",
                             "All 39 workloads including zero reconcile to 411321 target/record pairs",
                             "Strict two-edit anchor absent from selected names"],
                  "selection": SELECTION}
    assert "strict_consignment" not in names
    return result, provenance


def draw(result: dict, figures: Path) -> list[Path]:
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8,
                         "svg.fonttype": "none", "svg.hashsalt": "native-change-impact-20261012",
                         "pdf.fonttype": 42, "ps.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig = plt.figure(figsize=(7.0, 2.38))
    ink, blue, pale, orange = "#263541", "#245b76", "#f1f4f6", "#fff0d5"
    fig.text(.015, .95, "(a) Change-level cross-tabulation", fontsize=9, weight="bold", color=ink)
    fig.text(.555, .95, "(b) Workload distribution", fontsize=9, weight="bold", color=ink)

    ax = fig.add_axes([.015, .22, .47, .66])
    ax.set(xlim=(0, 3.2), ylim=(0, 2.15))
    ax.axis("off")
    ax.text(2.075, 1.98, "Any insufficient record?", ha="center", va="center", color=ink)
    ax.text(1.57, 1.67, "No", ha="center", va="center", color=ink)
    ax.text(2.57, 1.67, "Yes", ha="center", va="center", color=ink)
    ax.text(.26, .79, "Any verdict change\nwith complete input?", ha="center", va="center", rotation=90, color=ink)
    for r, changed in enumerate((False, True)):
        y = 1.17 - r * .72
        ax.text(.87, y, "Yes" if changed else "No", ha="right", va="center", color=ink)
        for c, insufficient in enumerate((False, True)):
            row = next(row for row in result["cross_tab"]
                       if row["any_complete_input_verdict_change"] == changed
                       and row["any_insufficient_record"] == insufficient)
            fill = orange if insufficient and not changed else "#e3eef3" if changed and not insufficient else pale
            ax.add_patch(Rectangle((1.08 + c, y - .34), .98, .68,
                                   facecolor=fill, edgecolor="#bbc6cd", linewidth=.65))
            ax.text(1.57 + c, y, str(row["targets"]), ha="center", va="center",
                    fontsize=17, weight="bold", color=ink)
    ax.text(2.07, -.01, "Cell values count targets", ha="center", va="top", fontsize=7.5, color=ink)

    bx = fig.add_axes([.59, .305, .395, .55])
    workloads = result["workload_frequencies"]
    x = list(range(len(workloads)))
    heights = [row["targets"] for row in workloads]
    bx.bar(x, heights, width=.64, color=["#8596a0"] + [blue] * (len(x) - 1), zorder=3)
    for index, height in enumerate(heights):
        bx.text(index, height + .55, str(height), ha="center", va="bottom", fontsize=8, color=ink)
    bx.set_xticks(x, [f"{row['insufficient_records_per_target']:,}" for row in workloads], rotation=45, ha="right", fontsize=7.2)
    bx.set_yticks([0, 5, 10, 15, 20])
    bx.set_ylim(0, 22)
    bx.set_xlim(-.7, len(x) - .3)
    bx.tick_params(axis="both", length=2.5, colors=ink, pad=2)
    bx.set_ylabel("Targets", labelpad=3, color=ink)
    bx.set_xlabel("Insufficient records per target (categorical)", fontsize=7.6, labelpad=2, color=ink)
    bx.set_axisbelow(True)
    bx.yaxis.grid(True, linewidth=.5, color="#dce2e6")
    for spine in bx.spines.values():
        spine.set_linewidth(.55)
        spine.set_color("#8596a0")
    fig.text(.5, .027, "39 authored changes; 50,931 retained records per change", ha="center", fontsize=7.6, color=ink)
    figures.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext in ("svg", "pdf", "png"):
        path = figures / f"native_change_impact.{ext}"
        metadata = ({"Date": None} if ext == "svg" else
                    {"CreationDate": None, "ModDate": None} if ext == "pdf" else
                    {"Software": "draw_native_change_impact.py"})
        fig.savefig(path, dpi=300, facecolor="white", metadata=metadata)
        paths.append(path)
    plt.close(fig)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/access_practical_revision_20261012/impact")
    parser.add_argument("--figures", type=Path, default=ROOT / "paper/figures")
    args = parser.parse_args()
    result, provenance = load_evidence()
    paths = draw(result, args.figures)
    args.output.mkdir(parents=True, exist_ok=True)
    summary = args.output / "impact_summary.json"
    summary.write_text(json.dumps(result, indent=2) + "\n")
    provenance["output_sha256"] = {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path): sha(path)
                                  for path in paths + [summary]}
    provenance["figure_size_inches"] = [7, 2.38]
    provenance["png_dpi"] = 300
    (args.output / "figure_manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps({"status": "passed", "target_counts": [row["targets"] for row in result["cross_tab"]],
                      "insufficient_target_record_pairs": result["insufficient_target_record_pairs"],
                      "outputs": [str(path) for path in paths]}, indent=2))


if __name__ == "__main__":
    main()
