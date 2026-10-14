"""Indexed application-contract validation. No learned thresholds or fault labels."""
from __future__ import annotations
from collections import defaultdict
import json
from pathlib import Path
from jsonschema import Draft7Validator, FormatChecker
from .model import Case, timestamp_key

ROOT = Path(__file__).resolve().parents[2]

class SchemaChecker:
    def __init__(self, path: Path | None = None):
        # src/pkg/file -> repository root is parents[2]
        schema = json.loads((path or ROOT / "data/standards/epcis-json-schema.json").read_text())
        Draft7Validator.check_schema(schema)
        self.validator = Draft7Validator(schema, format_checker=FormatChecker())

    def valid(self, case: Case) -> bool:
        return all(self.validator.is_valid(e.epcis()) for e in case.events)

    def issues(self, case: Case) -> list[str]:
        return [f"{i}:{err.json_path}:{err.message}" for i,e in enumerate(case.events)
                for err in self.validator.iter_errors(e.epcis())]

def indexed_issues(case: Case) -> set[str]:
    """First-occurrence precedence, local references, event-key uniqueness.

    Precedence uses source event order plus non-strict time. We do not globally
    require all events to have monotone clocks, nor forbid legitimate repeats.
    Scope: complete cases; streaming partial traces require a separate policy.
    """
    issues = set()
    by_id = {}
    first = {}
    for i,e in enumerate(case.events):
        if e.event_id in by_id:
            issues.add("duplicate_id")
        by_id[e.event_id] = e
        first.setdefault(e.activity, (i, timestamp_key(e.time)))
    if any(name not in first for name in case.required):
        issues.add("missing_activity")
    for a,b in case.edges:
        if b not in first:
            continue
        if a not in first:
            issues.add("missing_predecessor")
            continue
        ia,ta = first[a]
        ib,tb = first[b]
        if ia >= ib:
            issues.add("precedence")
        if ta is not None and tb is not None and ta > tb:
            issues.add("time_precedence")
    for e in case.events:
        if e.ref and e.ref not in by_id:
            issues.add("dangling_reference")
        # Adapter assigns object identity from a source case. Identity drift is
        # application-contract failure, not an automatic GS1 violation.
        if e.object_id != case.attributes.get("object_id", e.object_id):
            issues.add("object_identity")
    return issues

def fixed_profile(case: Case) -> Case:
    """Illustrative unconditional baseline; not a state-of-the-art competitor."""
    if case.dataset != "bpi2019":
        return case
    from dataclasses import replace
    return replace(case, edges=[("create", "receive"), ("receive", "invoice"), ("invoice", "clear")],
                   required=["create", "receive", "invoice", "clear"])
