"""Conditional import of one fixed procurement payload from native OPA logs.

The caller supplies a trusted sidecar. Its hashes bind supplied content; this
module does not authenticate OPA, prove a source read, or recover redacted data.
Only complete raw P/T blocks and their declared normalized aliases are supported.
"""
from __future__ import annotations

from copy import deepcopy

from logistics_validation.audit_report import digest, raw_summary, receipt_query
from logistics_validation.catalog_audit import BASELINE, PROFILES, catalog_json, generated_catalogs
from logistics_validation.focused_diagnostics import Problem


BINDING_SCHEMA = "opa-procurement-log-binding/v1"
IMPORT_SCHEMA = "opa-procurement-log-import/v1"
DOMAIN = "cartesian:v1"
BLOCKS = ("profile", "first_times")
STRICT = next(catalog for name, catalog, _ in generated_catalogs() if name == "strict_consignment")
SCOPE = (
    "Conditional on the supplied trusted sidecar, truthful complete original raw "
    "blocks, correctly derived normalized aliases, a fixed source snapshot and "
    "membership in the declared Cartesian domain. Digest and revision checks "
    "do not authenticate an issuer, establish hidden-domain membership or grant "
    "permission to recover masked values. This output is not a portable audit bundle."
)


class LogImportError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _check(condition, code):
    if not condition:
        raise LogImportError(code)


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _text(value):
    return isinstance(value, str) and bool(value)


def _path(value):
    _check(_text(value), "decision_path")
    # The OPA API permits a leading slash. Do not normalize arbitrary paths.
    return value[1:] if value.startswith("/") else value


def _mask_paths(event):
    allowed = {"/input/profile", "/input/first_times", "/input/record/profile", "/input/record/ranks"}
    paths = {}
    for operation in ("erased", "masked"):
        values = event.get(operation, [])
        _check(isinstance(values, list) and all(isinstance(v, str) for v in values), "mask_provenance_shape")
        _check(len(set(values)) == len(values), "duplicate_mask_path")
        for value in values:
            _check(value in allowed, "unsupported_mask_path")
            _check(value not in paths, "conflicting_mask_operations")
            paths[value] = operation
    return paths


def _retained(container, name, pointer, paths):
    operation = paths.get(pointer)
    if operation == "erased":
        _check(name not in container, "erased_field_present")
        return False
    if operation == "masked":
        _check(name in container, "masked_field_absent")
        return False
    _check(name in container, "missing_field_without_provenance")
    return True


def _binding(event, binding):
    fields = {"schema_version", "event_sha256", "decision_id", "source_case_id", "decision_path",
              "bundle", "snapshot_sha256", "domain_version", "source_assertions"}
    _check(isinstance(binding, dict) and set(binding) == fields, "binding_schema")
    _check(binding["schema_version"] == BINDING_SCHEMA, "binding_schema")
    _check(isinstance(event, dict), "event_shape")
    _check(_hash(binding["event_sha256"]), "event_digest_shape")
    try:
        actual_digest = digest(event)
    except (TypeError, ValueError):
        raise LogImportError("event_json_shape") from None
    _check(actual_digest == binding["event_sha256"], "event_digest_mismatch")
    _check(_text(binding["decision_id"]) and event.get("decision_id") == binding["decision_id"], "decision_id_mismatch")
    _check(_text(binding["source_case_id"]), "source_case_id")
    _check(_path(event.get("path")) == _path(binding["decision_path"]), "decision_path_mismatch")
    _check("query" not in event and "error" not in event, "unsupported_query_or_error")
    _check(_hash(binding["snapshot_sha256"]), "snapshot_digest_shape")
    _check(binding["domain_version"] == DOMAIN, "unsupported_domain")
    bundle = binding["bundle"]
    _check(isinstance(bundle, dict) and set(bundle) == {"name", "revision", "archive_sha256", "catalog_sha256"}, "bundle_binding_shape")
    _check(_text(bundle["name"]) and _text(bundle["revision"]) and _hash(bundle["archive_sha256"]), "bundle_binding_shape")
    _check(bundle["catalog_sha256"] == digest(catalog_json(BASELINE)), "catalog_binding_mismatch")
    events = event.get("bundles")
    _check(isinstance(events, dict) and set(events) == {bundle["name"]}, "bundle_name_mismatch")
    _check(events[bundle["name"]] == {"revision": bundle["revision"]}, "bundle_revision_mismatch")
    assertion = binding["source_assertions"]
    _check(isinstance(assertion, dict) and set(assertion) == {
        "source_case_id", "snapshot_sha256", "complete_fields", "normalized_aliases"}, "source_assertion_shape")
    _check(assertion["source_case_id"] == binding["source_case_id"], "source_assertion_case_mismatch")
    _check(assertion["snapshot_sha256"] == binding["snapshot_sha256"], "snapshot_binding_mismatch")
    complete = assertion["complete_fields"]
    _check(isinstance(complete, dict) and set(complete) == {"activities", *BLOCKS}
           and all(v is True for v in complete.values()), "incomplete_original_blocks")
    _check(type(assertion["normalized_aliases"]) is bool, "alias_assertion_shape")
    return bundle, assertion


def import_decision_log(event, binding, *, target_catalog=STRICT):
    """Import retained values only, then run the existing raw semantic audit.

    No request file or source callback is accepted. An invalid old observation
    remains an explicit diagnostic result, not a malformed-envelope exception.
    """
    bundle, assertion = _binding(event, binding)
    paths = _mask_paths(event)
    _check(type(event.get("result")) is bool, "recorded_result_not_boolean")
    payload = event.get("input")
    allowed = {"case_id", "activities", *BLOCKS, "model", "record", "mask_profile", "mask_times"}
    _check(isinstance(payload, dict) and not set(payload) - allowed, "input_schema")
    _check(payload.get("case_id") == binding["source_case_id"], "source_case_id_mismatch")
    _check(payload.get("model") == "procurement", "unsupported_input_model")
    _check("activities" in payload, "missing_activity_base")
    for flag in ("mask_profile", "mask_times"):
        _check(flag not in payload or type(payload[flag]) is bool, "mask_flag_shape")
    observed = {}
    retained = {}
    for name in BLOCKS:
        retained[name] = _retained(payload, name, "/input/" + name, paths)
        if retained[name]:
            observed[name] = deepcopy(payload[name])
    receipt = {
        "schema_version": 1, "receipt_id": binding["source_case_id"],
        "snapshot_sha256": binding["snapshot_sha256"], "catalog_sha256": bundle["catalog_sha256"],
        "domain_version": DOMAIN, "activities": deepcopy(payload["activities"]),
        "observed": observed, "verdict": event["result"],
    }
    try:
        query = receipt_query(receipt)
    except (ValueError, TypeError, KeyError, IndexError):
        raise LogImportError("unsupported_retained_values") from None
    _check(("record" in payload) == assertion["normalized_aliases"], "alias_presence_mismatch")
    if assertion["normalized_aliases"]:
        aliases = payload["record"]
        _check(isinstance(aliases, dict) and not set(aliases) - {"base", "profile", "ranks"}, "alias_schema")
        _check("base" in aliases and digest(aliases["base"]) == digest(list(query["base"])), "base_alias_mismatch")
        for raw_name, alias_name in (("profile", "profile"), ("first_times", "ranks")):
            known = _retained(aliases, alias_name, "/input/record/" + alias_name, paths)
            _check(not known or retained[raw_name], "leaked_normalized_alias")
            if known:
                expected = PROFILES.index(observed["profile"]) if raw_name == "profile" else list(query["observed"][-1])
                _check(digest(aliases[alias_name]) == digest(expected), "normalized_alias_mismatch")
    else:
        _check(not any(p.startswith("/input/record/") for p in paths), "alias_mask_without_record")
    problem = Problem("procurement_log_target", target_catalog)
    summary = raw_summary(problem, query, receipt, DOMAIN, DOMAIN)
    return {
        "schema_version": IMPORT_SCHEMA, "decision_id": binding["decision_id"],
        "source_case_id": binding["source_case_id"], "event_sha256": binding["event_sha256"],
        "binding_sha256": digest(binding), "bundle": deepcopy(bundle),
        "target_catalog_sha256": digest(catalog_json(target_catalog)), "receipt": receipt,
        "query": query, "mask_provenance": {key: sorted(p for p, op in paths.items() if op == key)
                                               for key in ("erased", "masked")},
        "summary": summary, "conditional_scope": SCOPE,
    }


def plan_followup(imported, *, authorized_and_available=(), unavailable=(), unauthorized=(), read_failures=()):
    """Plan only; this function performs no reads and certifies no repair.

    Capability declarations concern the same pinned snapshot. A failure or
    denial overrides a nominal availability declaration. Missing declarations
    never imply permission. Partial acquisition may help adaptively, but this
    bounded planner selects only a fully accessible robust additional set.
    """
    sets = []
    for values in (authorized_and_available, unavailable, unauthorized, read_failures):
        _check(isinstance(values, (list, tuple, set, frozenset)) and all(v in BLOCKS for v in values), "followup_block_names")
        sets.append(set(values))
    available, absent, denied, failed = sets
    available -= absent | denied | failed
    summary = imported["summary"]
    status = summary["status"]
    result = {"semantic_status": status, "action": None, "planned_blocks": [], "reads_performed": [],
              "acquisition_completed": False, "source_case_id": imported["source_case_id"],
              "snapshot_sha256": imported["receipt"]["snapshot_sha256"]}
    if status in {"safe", "stale_verdict"}:
        result.update(action="retain" if status == "safe" else "update", verdict=summary["new_verdict_candidates"][0])
    elif status in {"invalid_receipt", "unsupported"}:
        result.update(action=status, verdict=None)
    elif status == "insufficient":
        robust = summary["robust_additional_sets"]
        candidates = [s for s in robust if set(s) <= available]
        if candidates:
            result.update(action="acquire", planned_blocks=min(candidates, key=lambda s: (len(s), s)), verdict=None)
        else:
            missing = sorted(set().union(*(set(s) for s in robust)) - available)
            reasons = {name: ("read_failed" if name in failed else "authorization_not_granted" if name in denied
                             else "source_unavailable" if name in absent else "access_not_established") for name in missing}
            result.update(action="unresolved", verdict=None, missing_blocks=missing, reasons=reasons)
    else:
        raise LogImportError("unsupported_diagnostic_status")
    return result
