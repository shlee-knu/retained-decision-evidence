#!/usr/bin/env python3
"""Draw the procurement rule-change explanation from saved study evidence.

This script asserts existing witness and cohort records; it runs no new study.
The sequence multiplicity is literal. The displayed timestamp inequality is a
summary of the literal first_times retained unchanged by both completions.
"""
from __future__ import annotations

from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "results/selected_revision_reference_public_20261015/figure"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_evidence() -> tuple[dict, dict]:
    paths = {
        "witness": ROOT / "results/strong/catalog_audit/witnesses.json",
        "counts": ROOT / "results/perspective_revision/audit_reports/change_review.json",
        "affected_ids": ROOT / "results/perspective_revision/audit_reports/affected_receipt_ids.jsonl.gz",
        "retention": ROOT / "results/robustness_revision_20261011/retention/run_final/summary.json",
        "ledger": ROOT / "results/robustness_revision_20261011/retention/run_final/cartesian__structural_order.jsonl.gz",
    }
    witness = json.loads(paths["witness"].read_text())["strict_consignment"]["native_anchor_canonical"]
    counts = json.loads(paths["counts"].read_text())
    retention = json.loads(paths["retention"].read_text())
    anchor, alternative = witness["anchor"], witness["completion"]

    # Keep the existing figure's literal source assertions and strengthen the
    # clock check: an inequality alone would allow an accidental date rewrite.
    assert anchor["activities"] == alternative["activities"]
    assert anchor["first_times"] == alternative["first_times"]
    assert anchor["activities"] == ["create"] + ["receive"] * 33 + ["invoice", "clear"]
    clock = anchor["first_times"]
    assert clock == {
        "create": "2018-01-02T21:36:00.000Z",
        "receive": "2018-01-02T21:36:00.000Z",
        "invoice": "2018-04-11T10:40:00.000Z",
        "clear": "2018-04-13T08:37:00.000Z",
    }
    assert clock["create"] == clock["receive"] < clock["invoice"] < clock["clear"]
    assert anchor["profile"] == "3-way match, invoice after GR"
    assert alternative["profile"] == "Consignment"
    assert witness["source_anchor"]["case_id"] == "4507000469_00001"
    assert witness["lost_mask_name"] == "T"
    assert witness["labels"] == {
        "old_anchor": True, "old_completion": True,
        "new_anchor": True, "new_completion": False,
    }
    assert witness["completion_native_count"] == 0
    assert witness["completion_off_native_support"] is True
    assert counts["native_receipts"] == 50931
    assert counts["strict_status_counts"] == {"safe": 17442, "insufficient": 33489}
    assert [row["count"] for row in counts["affected_classes"]] == [33218, 269, 2]
    assert all(row["required_additional_blocks"] == ["profile"] for row in counts["affected_classes"])

    assert sha(paths["affected_ids"]) == counts["affected_id_index"]["sha256"]
    with gzip.open(paths["affected_ids"], "rt") as stream:
        indexed = [json.loads(line) for line in stream]
    indexed_ids = {row["receipt_id"] for row in indexed}
    assert len(indexed) == len(indexed_ids) == 33489
    assert all(row["obligation"] == "acquire profile" for row in indexed)
    assert Counter(row["class_index"] for row in indexed) == {0: 33218, 6: 269, 14: 2}

    assert retention["status"] == "passed"
    rows = {(row["domain"], row["policy"]): row for row in retention["rows"]}
    assert all(row["cases"] == 50931 for row in rows.values())
    assert rows["cartesian", "structural_order"]["acquire"] == 33489
    assert rows["cartesian", "profile_first"]["acquire"] == 0
    assert rows["cartesian", "always_both"]["acquire"] == 0
    assert all(row["acquire"] == 0 for (domain, _), row in rows.items()
               if domain == "consignment_exclusion")
    assert sha(paths["ledger"]) == retention["files"][paths["ledger"].name]
    with gzip.open(paths["ledger"], "rt") as stream:
        ledger = [json.loads(line) for line in stream]
    assert len(ledger) == len({row["case_id"] for row in ledger}) == 50931
    assert witness["source_anchor"]["case_id"] not in {row["case_id"] for row in ledger}
    assert witness["source_anchor"]["case_id"] not in indexed_ids
    assert all(row["old_verdict"] == row["new_verdict"] for row in ledger)
    assert {row["case_id"] for row in ledger if row["action"] == "acquire"} == indexed_ids
    assert all(row["old_mask"] == 2 and row["additional_reads"] == ["profile"]
               for row in ledger if row["action"] == "acquire")

    provenance = {
        "scope": "Explanatory manufacturing-procurement Figure 1 revision; saved evidence only; no new experiment.",
        "input_sha256": {str(path.relative_to(ROOT)): sha(path) for path in paths.values()},
        "source_case": witness["source_anchor"],
        "literal_activities": anchor["activities"],
        "literal_first_times": clock,
        "actual_profile": anchor["profile"],
        "alternative_profile": alternative["profile"],
        "rule_labels": witness["labels"],
        "alternative_is_off_native_support": witness["completion_off_native_support"],
        "display_abbreviations": {
            "C": "create", "R": "receive", "I": "invoice", "X": "clear",
            "P": "profile", "T": "first_times", "GR": "goods receipt",
        },
        "display_transform": "R × 33 is the literal repeated activity sequence. T is displayed as an ordering summary; all four literal timestamps above are equal across the two completions. The abbreviated actual profile is 3-way, after GR.",
        "cohort_checks": {
            "illustrated_opa_control_outside_native_analysis_cohort": True,
            "native_cases": len(ledger),
            "complete_input_verdict_changes": sum(row["old_verdict"] != row["new_verdict"] for row in ledger),
            "structural_insufficient": len(indexed_ids),
            "affected_index_unique_and_matches_ledger": True,
            "affected_class_counts": {str(key): value for key, value in sorted(Counter(row["class_index"] for row in indexed).items())},
            "profile_first_insufficient": rows["cartesian", "profile_first"]["acquire"],
            "full_retention_insufficient": rows["cartesian", "always_both"]["acquire"],
            "trusted_exclusion_insufficient_all_policies": 0,
        },
        "boundaries": [
            "The strict rule is authored for this study, not recovered from an enterprise deployment.",
            "The Consignment completion is hypothetical and not an observed procurement error.",
            "Retention policies are reconstructed on the same archive.",
            "The repair flow requires truthful complete values from the same pinned source snapshot.",
            "Trusted exclusion means an applicable Consignment-exclusion guarantee, not archive correlation.",
        ],
    }
    return witness, provenance


def main() -> None:
    _, provenance = load_evidence()
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9,
        "svg.fonttype": "none", "svg.hashsalt": "manufacturing-rule-change-20261011",
        "pdf.fonttype": 42, "ps.fonttype": 42,
    })
    fig = plt.figure(figsize=(7.0, 3.45))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set(xlim=(0, 7.0), ylim=(0, 3.45))
    ax.axis("off")
    ink, line, accent = "#263541", "#65737d", "#245b76"
    pale, green, amber = "#f4f6f8", "#edf4f0", "#fff4e5"
    labels: list = []
    contained: list = []

    def text(x, y, content, size=9, weight="normal", align="center", color=ink, bounds=None):
        label = ax.text(x, y, content, fontsize=size, fontweight=weight,
                        ha=align, va="center", color=color, linespacing=1.22)
        labels.append(label)
        if bounds is not None:
            contained.append((label, bounds))
        return label

    def panel(x, y, width, height, fill=pale, dashed=False):
        ax.add_patch(Rectangle((x, y), width, height, facecolor=fill, edgecolor=line,
                               lw=.75, linestyle=(0, (4, 2.8)) if dashed else "solid"))
        return x, y, width, height

    def box(x, y, width, height, content, fill=pale, weight="normal"):
        bounds = panel(x, y, width, height, fill)
        text(x + width / 2, y + height / 2, content, weight=weight, bounds=bounds)
        return bounds

    def arrow(start, end):
        ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=9,
                                    linewidth=.9, color=line, shrinkA=1, shrinkB=1))

    text(.10, 3.27, "1  Retained record", 10, "bold", "left", accent)
    text(2.15, 3.27, "2  Changed rule", 10, "bold", "left", accent)
    text(4.86, 3.27, "3  Repair evidence", 10, "bold", "left", accent)

    retained = panel(.10, .89, 1.83, 2.17)
    text(1.015, 2.86, "Case 4507000469_00001", bounds=retained)
    text(1.015, 2.58, "Activity sequence retained", bounds=retained)
    text(1.015, 2.39, "C → R × 33 → I → X", weight="bold", bounds=retained)
    text(1.015, 2.11, "First timestamps T retained", bounds=retained)
    text(1.015, 1.92, r"$t_C = t_R < t_I < t_X$", bounds=retained)
    text(1.015, 1.62, "Profile P: not retained", weight="bold", bounds=retained)
    text(1.015, 1.31, "Old verdict: PASS", weight="bold", bounds=retained)
    text(1.015, 1.08, "Old evidence sufficient", bounds=retained)

    box(2.15, 2.61, 2.46, .45,
        "Authored strict change:\nConsignment forbids I and X")
    text(3.38, 2.42, "Same observations, two profiles", bounds=(2.15, 2.30, 2.46, .24))
    actual = panel(2.15, 1.81, 2.46, .45, green)
    text(3.38, 2.11, "Actual: 3-way, after GR", bounds=actual)
    text(3.38, 1.94, "New verdict: PASS", weight="bold", bounds=actual)
    hypothetical = panel(2.15, 1.13, 2.46, .50, amber, dashed=True)
    text(3.38, 1.46, "Hypothetical: Consignment", bounds=hypothetical)
    text(3.38, 1.27, "New verdict: FAIL", weight="bold", bounds=hypothetical)
    text(3.38, .96, "Alternative absent from archive", bounds=(2.15, .83, 2.46, .26))
    arrow((1.94, 2.42), (2.14, 2.42))
    arrow((4.62, 2.42), (4.84, 2.42))

    box(4.86, 2.30, 2.04, .76,
        "Missing field: P\nSeparate OPA control\noutside analysis cohort", amber, "bold")
    box(4.86, 1.56, 2.04, .49,
        "Recover P at the\nsame source snapshot")
    box(4.86, .89, 2.04, .49,
        "Check replacement:\nnew verdict + evidence", green)
    arrow((5.88, 2.29), (5.88, 2.06))
    arrow((5.88, 1.55), (5.88, 1.39))

    ax.plot([.10, 6.90], [.73, .73], color="#a6b3bc", linewidth=.7)
    text(3.5, .58, "Analysis cohort: 50,931  •  Complete-input verdict changes: 0", weight="bold")
    text(3.5, .37, "Insufficient evidence: 33,489 with structural retention;")
    text(3.5, .16, "0 with P-first, full retention or trusted Consignment exclusion.")

    # Verify labels at the actual printed size, including labels outside boxes.
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    for label, (x, y, width, height) in contained:
        bounds = label.get_window_extent(renderer)
        left, bottom = ax.transData.transform((x, y))
        right, top = ax.transData.transform((x + width, y + height))
        assert left + 2 <= bounds.x0 < bounds.x1 <= right - 2, label.get_text()
        assert bottom + 2 <= bounds.y0 < bounds.y1 <= top - 2, label.get_text()
    extents = [label.get_window_extent(renderer) for label in labels]
    for index, extent in enumerate(extents):
        assert fig.bbox.contains(extent.x0, extent.y0) and fig.bbox.contains(extent.x1, extent.y1), labels[index].get_text()
        for other in extents[index + 1:]:
            assert not extent.overlaps(other), labels[index].get_text()
    assert min(label.get_fontsize() for label in labels) >= 9

    outputs = []
    for suffix in ("svg", "png", "pdf"):
        path = ROOT / "paper/figures" / f"manufacturing_rule_change.{suffix}"
        metadata = ({"CreationDate": None, "ModDate": None} if suffix == "pdf" else
                    {"Date": None} if suffix == "svg" else {})
        fig.savefig(path, dpi=400, facecolor="white", metadata=metadata)
        outputs.append({"path": str(path.relative_to(ROOT)), "sha256": sha(path)})
    plt.close(fig)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    manifest = {
        **provenance,
        "script": str(Path(__file__).relative_to(ROOT)),
        "script_sha256": sha(Path(__file__)),
        "layout_checks": {
            "size_inches": [7.0, 3.45], "smallest_font_points": 9,
            "all_labels_inside_canvas": len(labels),
            "contained_labels_within_bounds": len(contained),
            "pairwise_label_overlap_count": 0, "png_dpi": 400,
            "pdf_embedded_font_type": 42, "svg_text_preserved": True,
        },
        "outputs": outputs,
    }
    (EVIDENCE / "figure_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": "passed", "outputs": outputs, "layout": manifest["layout_checks"]}, indent=2))


if __name__ == "__main__":
    main()
