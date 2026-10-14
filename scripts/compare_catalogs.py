"""Explain information changes between two JSON catalogs in the fixed fragment.

Counts describe exhaustive symbolic equivalence classes, not case frequencies.
Only the declared four profiles, four milestones and first-occurrence predicates
are supported. No native log is used or required by this standalone command.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logistics_validation.catalog_audit import (
    ALPHABET, PROFILES, MASK_NAMES, Rule, universe, verdict,
    CertificateTable, changes, loss_witness, concrete,
)


def read_catalog(path):
    body = json.loads(Path(path).read_text())
    if not isinstance(body, dict) or set(body) != set(PROFILES):
        raise ValueError("Catalog must define exactly the four declared profiles")
    rules = []
    for profile in PROFILES:
        r = body[profile]
        if not isinstance(r, dict) or set(r) != {"required", "forbidden", "edges"}:
            raise ValueError("Each profile needs required, forbidden and edges only")
        memberships = []
        for name in ("required", "forbidden"):
            values = r[name]
            if not isinstance(values, list) or any(not isinstance(v, str) or v not in ALPHABET for v in values):
                raise ValueError("Activity lists must use the declared milestone alphabet")
            if len(set(values)) != len(values):
                raise ValueError("Duplicate activity entry")
            memberships.append(frozenset(ALPHABET.index(v) for v in values))
        if not isinstance(r["edges"], list):
            raise ValueError("Edges must be a list of two-activity lists")
        edges = []
        for edge in r["edges"]:
            if (not isinstance(edge, list) or len(edge) != 2
                    or any(not isinstance(a, str) or a not in ALPHABET for a in edge)
                    or edge[0] == edge[1]):
                raise ValueError("Edges require two distinct declared activities")
            edges.append(tuple(ALPHABET.index(a) for a in edge))
        if len(set(edges)) != len(edges):
            raise ValueError("Duplicate edge")
        # Contradictory rules remain meaningful audit inputs, not syntax errors.
        rules.append(Rule(*memberships, frozenset(edges)))
    return tuple(rules)


def compare(before, after):
    states = universe()
    old = CertificateTable(states, [verdict(s, before) for s in states])
    new = CertificateTable(states, [verdict(s, after) for s in states])
    transitions = Counter()
    counts = Counter({name: 0 for name in (
        "preserved_verdict_states", "changed_verdict_states",
        "states_with_invalidated_certificate", "states_with_newly_sufficient_subset")})
    for i in range(len(states)):
        d = changes(old, new, i)
        counts["preserved_verdict_states" if d["verdict_preserved"] else "changed_verdict_states"] += 1
        if d["verdict_preserved"]:
            counts["states_with_invalidated_certificate"] += bool(d["lost"])
            counts["states_with_newly_sufficient_subset"] += bool(d["gained"])
            transitions[(old.minimal[i], new.minimal[i])] += 1
    w = loss_witness(old, new)
    if w is not None:
        i, j, mask = w["anchor_index"], w["completion_index"], w["lost_mask"]
        witness = {"type": "canonical synthetic pair, not a native case",
                   "observed_blocks": [MASK_NAMES[m] for m in (1, 2) if mask & m],
                   "anchor": concrete(states[i]), "completion": concrete(states[j]),
                   "old_labels": [bool(old.labels[i]), bool(old.labels[j])],
                   "new_labels": [bool(new.labels[i]), bool(new.labels[j])],
                   "ordering": "milestone count, clock levels, activity order, clock ranks, profile, mask; not business edit distance"}
    else:
        witness = None
    unsatisfiable = {}
    for name, table in (("before", old), ("after", new)):
        unsatisfiable[name] = [PROFILES[p] for p in range(4)
                              if not any(table.labels[i] for i, s in enumerate(states) if s.profile == p)]
    return {"scope": "Exact symbolic comparison under the fixed Cartesian completion domain; state counts are not empirical probabilities",
            "complete_symbolic_states": len(states),
            "globally_equivalent": old.labels == new.labels,
            "counts": dict(counts), "unsatisfiable_profiles": unsatisfiable,
            "minimal_certificate_transitions_on_preserved_states": [
                {"before": [MASK_NAMES[m] for m in a], "after": [MASK_NAMES[m] for m in b], "states": n}
                for (a, b), n in sorted(transitions.items())],
            "lost_certificate_witness": witness}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="New output path; existing files are not overwritten")
    args = parser.parse_args()
    try:
        result = compare(read_catalog(args.before), read_catalog(args.after))
    except (ValueError, TypeError, KeyError) as error:
        parser.error(str(error))
    result["input_sha256"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.before, args.after)}
    body = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            stream.write(body)
    else:
        print(body, end="")


if __name__ == "__main__":
    main()
