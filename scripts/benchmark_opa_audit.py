"""Real OPA predicate evaluation plus an explicitly authored finite audit adapter.

The primary comparison is functional, not a performance ranking. OPA evaluates
the declared predicate; Python enumerates the supported states, groups retained
observations, proves robust field sets, lifts witnesses and links occurrences.
Neither saved truth labels nor saved diagnoses enter OPA or adapter generation.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import resource
import re
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from compare_catalogs import read_catalog
from logistics_validation.audit_report import canonical, digest, receipt_query
from logistics_validation.catalog_audit import (
    ALPHABET, BASELINE, PROFILES, catalog_json, generated_catalogs, reference_verdict,
)
from logistics_validation.focused_diagnostics import Problem, RawVerifier, freeze, projection
from logistics_validation.revision_diagnostics import (
    DirectResidualDiagnostics, QueryValidationError, validate_query,
)

POLICY = ROOT / "policies/opa_audit/predicates.rego"
MASK_POLICY = ROOT / "policies/opa_audit/log_mask.rego"
DEFAULT_OPA = ROOT / "results/platform_revision_20261010/opa/dependency/opa_linux_amd64_static"
NATIVE = ("identity", "strict", "equivalent", "label_change")
HARD = ("edge_p0_a0_b1", "required_p2_a3", "edge_p2_a0_b2", "edge_p2_a2_b3")
REVISION = "retained-evidence-baseline-v1-local-replay-20261010"
LOG_CASE_ID = "4507000469_00001"  # Published repeated-event/literal-clock example.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def jsonlines(path, rows):
    with Path(path).open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
            for row in rows:
                stream.write(canonical(row) + b"\n")


def catalog_wire(catalog):
    return [{"required": sorted(r.required), "forbidden": sorted(r.forbidden),
             "edges": sorted(map(list, r.edges))} for r in catalog]


def record_wire(base, state):
    return {"base": list(base), "profile": state[0], "ranks": list(state[1])}


def opa_eval(binary, payload, query, *, extra=()):
    command = [str(binary), "eval", "--strict", "--format=json", "--metrics",
               "--data", str(POLICY), "--stdin-input", *extra, query]
    before_child = resource.getrusage(resource.RUSAGE_CHILDREN)
    before = time.perf_counter_ns()
    run = subprocess.run(command, input=canonical(payload), capture_output=True, check=False)
    wall = time.perf_counter_ns() - before
    after_child = resource.getrusage(resource.RUSAGE_CHILDREN)
    if run.returncode:
        raise RuntimeError(f"OPA exited {run.returncode}: {run.stdout.decode()} {run.stderr.decode()}")
    document = json.loads(run.stdout)
    value = document.get("result", [{}])[0].get("expressions", [{}])[0].get("value")
    return value, document, {"subprocess_wall_ns": wall,
            "subprocess_cpu_ns": int(1e9 * (after_child.ru_utime + after_child.ru_stime
                                           - before_child.ru_utime - before_child.ru_stime)),
            "metrics": document.get("metrics", {})}


class OpaAuditAdapter:
    """Finite audit assembly over labels actually returned by real OPA.

    Shared input validation and raw report lifting are interface utilities.
    Policy verdicts never call Problem.label, raw_label or a saved truth table.
    """
    def __init__(self, problem, binary=DEFAULT_OPA, *, bases=None):
        if not problem.procurement:
            raise ValueError("This experiment supports only the procurement grammar")
        self.problem = problem
        self.states = [(b, s) for b, s in problem.all_states() if bases is None or b in bases]
        self.payload = {"model": "procurement", "old_catalog": catalog_wire(BASELINE),
                        "new_catalog": catalog_wire(problem.catalog),
                        "records": [record_wire(b, s) for b, s in self.states]}
        self.labels, self.native_output, self.cost = opa_eval(
            binary, self.payload, "data.audit.predicates.labels")
        if (not isinstance(self.labels, list) or len(self.labels) != len(self.states)
                or any(not isinstance(pair, list) or len(pair) != 2
                       or any(type(v) is not bool for v in pair) for pair in self.labels)):
            raise ValueError("OPA did not return one Boolean old/new pair per complete state")
        self.groups = defaultdict(list)
        for (base, state), labels in zip(self.states, self.labels):
            self.groups[base].append((state, labels[0], labels[1]))

    def diagnose(self, query, *, new_domain="cartesian:v1"):
        try:
            query = validate_query(self.problem, query)
        except QueryValidationError:
            return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}
        rows = [r for r in self.groups[query["base"]]
                if projection(r[0], query["mask"]) == query["observed"]]
        if not rows or {r[1] for r in rows} != {query["old_verdict"]}:
            return {"status": "invalid_receipt", "witnesses": None, "robust_masks": []}
        if new_domain == "consignment_exclusion:v1":
            # Declared restriction only, not evidence that an unread actual
            # profile belongs to it. Old sufficiency was tested before filtering.
            rows = [r for r in rows if r[0][0] != 3 or not {2, 3}.intersection(query["base"])]
        elif new_domain != "cartesian:v1":
            raise ValueError("Unsupported domain control")
        if not rows:
            return {"status": "unsupported", "witnesses": None, "robust_masks": []}
        outcomes = {r[2] for r in rows}
        if len(outcomes) == 1:
            return {"status": "safe" if outcomes == {query["old_verdict"]} else "stale_verdict",
                    "witnesses": None, "robust_masks": [0]}
        succeeds = []
        for mask in range(1 << self.problem.count):
            if mask & query["mask"]:
                continue
            groups = defaultdict(set)
            for state, _, label in rows:
                groups[projection(state, mask)].add(label)
            if all(len(labels) == 1 for labels in groups.values()):
                succeeds.append(mask)
        minimal = [a for a in succeeds if not any(b != a and b & a == b for b in succeeds)]
        return {"status": "insufficient", "robust_masks": minimal,
                "witnesses": [next(r[0] for r in rows if r[2] == label) for label in (False, True)]}


def load_workloads():
    out = []
    for target in NATIVE:
        path = ROOT / f"results/focused_revision/diagnostic_inputs/procurement_{target}.json"
        data = json.loads(path.read_text())
        out.append((path, data, Problem(data["name"], read_catalog(ROOT / data["target"]))))
    catalogs = {name: catalog for name, catalog, _ in generated_catalogs()}
    for target in HARD:
        path = ROOT / f"results/perspective_revision/inputs/procurement_{target}.json"
        data = json.loads(path.read_text())
        out.append((path, data, Problem(data["name"], catalogs[target])))
    return out


def source_fingerprints(workloads):
    paths = [POLICY, MASK_POLICY, Path(__file__), ROOT / "tests/test_opa_audit_integration.py",
             ROOT / "src/logistics_validation/focused_diagnostics.py",
             ROOT / "src/logistics_validation/revision_diagnostics.py",
             ROOT / "src/logistics_validation/catalog_audit.py",
             ROOT / "src/logistics_validation/audit_report.py",
             ROOT / "results/v03/bpi_compact.jsonl.gz",
             ROOT / "results/second/receipt_revalidation/native_receipts.jsonl.gz"]
    for path, data, _ in workloads:
        paths.append(path)
        if data.get("target"):
            paths.append(ROOT / data["target"])
    config = ROOT / "configs/platform_audit_protocol.json"
    if config.exists():
        paths.append(config)
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(set(paths))}


def freeze_protocol(output, workloads, binary):
    protocol = {"schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_before_execution": True, "primary_queries": 941,
        "selection": "All four existing native 20-class workloads and all 861 previously frozen harder rows; no new outcome-based selection.",
        "workloads": [{"name": data["name"], "queries": len(data["queries"]),
                       "input": str(path.relative_to(ROOT))} for path, data, _ in workloads],
        "output_contract": "Compact semantic old-valid/status/opposed witnesses/all minimal robust fields and occurrence links; not full portable-bundle equivalence.",
        "responsibilities": {"OPA": "Independently authored Rego complete-state predicate evaluation; representative native partial evaluation and real local masked console logs.",
          "adapter": "Supported-state enumeration, old-sufficiency checking, fiber grouping, robust-set enumeration, witness lifting, occurrence mapping and serialization."},
        "cost_boundary": "Standalone batched integration costs only, no speed ranking against in-process Python. One OPA eval process per model handles every complete supported state; startup, JSON pipes, compilation and evaluation are included. No per-row CLI startup. Research oracle cost separate; durable writes excluded from generation interval.",
        "controls": ["identity", "equivalent", "stale_verdict", "strict profile requirement",
                     "Consignment exclusion", "full retention", "authentic old decision with insufficient masked observations",
                     "malformed query", "literal repeated events/timestamps"],
        "local_log_source_case_id": LOG_CASE_ID,
        "local_log_source_scope": "Published repeated-event example from the complete public archive, outside the 50,931 held-out receipt cohort; separate integration control, not an additional primary diagnosis.",
        "source_hashes": source_fingerprints(workloads), "opa_binary_sha256": sha(binary),
        "official_sources": ["https://www.openpolicyagent.org/docs/cli",
                             "https://www.openpolicyagent.org/docs/rest-api",
                             "https://www.openpolicyagent.org/docs/management-decision-logs",
                             "https://github.com/open-policy-agent/opa/releases/tag/v1.21.1"],
        "limits": "Authored finite procurement grammar and reconstructed public-archive receipts; local OPA replay does not establish organizational adoption or full policy-engine superiority."}
    write(output / "protocol.json", protocol)
    return protocol


def verify_labels(adapter):
    checks = 0
    for (base, state), labels in zip(adapter.states, adapter.labels):
        for new in (False, True):
            if adapter.problem.raw_label(base, state, new) != labels[int(new)]:
                raise AssertionError((adapter.problem.name, base, state, new, labels))
            checks += 1
    return checks


def native_request(receipt_id):
    with gzip.open(ROOT / "results/v03/bpi_compact.jsonl.gz", "rt") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("case_id") == receipt_id:
                return row
    raise ValueError(f"Native case {receipt_id} absent from pinned snapshot")


def log_payload(raw, case_id, *, mask_profile, mask_times):
    base = tuple(dict.fromkeys(ALPHABET.index(a) for a in raw["activities"]))
    from logistics_validation.catalog_audit import reference_time
    clocks = [reference_time(raw["first_times"][ALPHABET[a]]) for a in base]
    levels = {v: i for i, v in enumerate(sorted(set(clocks)))}
    return {"case_id": case_id, "activities": raw["activities"], "profile": raw["profile"],
            "first_times": raw["first_times"], "model": "procurement",
            "record": record_wire(base, (PROFILES.index(raw["profile"]), tuple(levels[v] for v in clocks))),
            "mask_profile": mask_profile, "mask_times": mask_times}


def save_native_logs(output, binary, strict_data):
    """Generate genuine local OPA logs, with a fixed catalog in a revisioned bundle."""
    output.mkdir()
    baseline = {"catalogs": {"baseline": catalog_wire(BASELINE)}}
    bundle = output / "baseline_bundle.tar.gz"
    # Deterministic archive contents, including policy, mask, data and revision.
    files = {"predicates.rego": POLICY.read_bytes(), "log_mask.rego": MASK_POLICY.read_bytes(),
             "data.json": canonical(baseline), ".manifest": canonical({"revision": REVISION, "roots": [""]})}
    with bundle.open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as archive:
                for name, body in files.items():
                    info = tarfile.TarInfo(name); info.size = len(body); info.mtime = 0
                    archive.addfile(info, io.BytesIO(body))
    actual = native_request(LOG_CASE_ID)
    raw = {key: actual[key] for key in ("activities", "profile", "first_times")}
    requests = {
        "native_strict_profile_masked": log_payload(raw, LOG_CASE_ID, mask_profile=True, mask_times=False),
        "native_full_retention": log_payload(raw, LOG_CASE_ID, mask_profile=False, mask_times=False),
        "insufficient_old_both_masked": log_payload(raw, LOG_CASE_ID, mask_profile=True, mask_times=True),
    }
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    address = f"http://127.0.0.1:{port}"
    logfile = output / "console.jsonl"
    command = [str(binary), "run", "--server", "--addr", f"127.0.0.1:{port}",
               "--set", "decision_logs.console=true", "--bundle", str(bundle)]
    responses = {}
    with logfile.open("xb") as console:
        process = subprocess.Popen(command, stdout=console, stderr=console)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    with urllib.request.urlopen(address + "/health", timeout=.2):
                        break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline or process.poll() is not None:
                        raise RuntimeError("OPA local server did not become ready")
                    time.sleep(.02)
            for name, payload in requests.items():
                request = urllib.request.Request(address + "/v1/data/audit/predicates/logged_old_decision",
                    data=canonical({"input": payload}), headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=10) as response:
                    responses[name] = json.load(response)
                write(output / f"{name}.request.json", payload)
                write(output / f"{name}.response.json", responses[name])
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if sum('"decision_id"' in line and '"erased"' in line for line in logfile.read_text().splitlines()) >= 2:
                    break
                time.sleep(.02)
        finally:
            process.terminate()
            process.wait(timeout=10)
    events = []
    for line in logfile.read_text().splitlines():
        event = json.loads(line)
        if "decision_id" in event and "input" in event and "result" in event:
            events.append(event)
    for name, response in responses.items():
        event = next(e for e in events if e["decision_id"] == response["decision_id"])
        assert type(event["result"]) is bool and event["result"] is True
        assert event["bundles"] and REVISION in {v["revision"] for v in event["bundles"].values()}
        write(output / f"{name}.decision.json", event)
    manifest = {"kind": "Actual local OPA console logs replaying one public native case; not historical OPA deployment evidence",
        "source_case_id": LOG_CASE_ID, "source_activity_count": len(raw["activities"]),
        "source_in_heldout_receipt_cohort": LOG_CASE_ID in {case for case, _ in strict_data["weighted_requests"]},
        "source_scope": "Complete public archive repeated-event example; separate local integration control outside the primary 941 diagnoses.",
        "bundle_revision": REVISION, "bundle_sha256": sha(bundle),
        "bundle_names": sorted({name for event in events for name in event["bundles"]}),
        "bundled_catalog_wire_sha256": digest(baseline["catalogs"]["baseline"]),
        "baseline_catalog_path": "examples/baseline_catalog.json", "baseline_catalog_sha256": sha(ROOT / "examples/baseline_catalog.json"),
        "baseline_catalog_canonical_sha256": digest(catalog_json(BASELINE)),
        "snapshot_path": "results/v03/bpi_compact.jsonl.gz", "snapshot_sha256": sha(ROOT / "results/v03/bpi_compact.jsonl.gz"),
        "domain_version": "cartesian:v1", "opa_binary_sha256": sha(binary),
        "normalization": "Complete raw activity first-occurrence order and RFC3339 clock weak ranks; raw literal fields retained independently. Masked fields remove both raw field and derived coordinate.",
        "normalization_source": "scripts/benchmark_opa_audit.py", "normalization_source_sha256": sha(Path(__file__)),
        "files": {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}}
    write(output / "manifest.json", manifest)
    return manifest


def save_partial(output, binary, data, problem):
    """Save real OPA residuals with every unread coordinate explicitly unknown."""
    output.mkdir(parents=True, exist_ok=True)
    query = data["queries"][0]
    record = {"base": query["base"]}
    observed = iter(query["observed"])
    unknowns = []
    for bit, field in ((1, "profile"), (2, "ranks")):
        if query["mask"] & bit:
            record[field] = next(observed)
        else:
            unknowns.append("input.record." + field)
    payload = {"record": record, "old_catalog": catalog_wire(BASELINE), "new_catalog": catalog_wire(problem.catalog)}
    flags = ["--partial"]
    for unknown in unknowns:
        flags += ["--unknowns", unknown]
    _, document, cost = opa_eval(binary, payload, "data.audit.predicates.new_allowed", extra=flags)
    stem = problem.name
    write(output / f"{stem}.input.json", payload)
    write(output / f"{stem}.partial.json", document)
    command = [str(binary), "eval", "--strict", "--format=source", "--data", str(POLICY),
               "--stdin-input", *flags, "data.audit.predicates.new_allowed"]
    source = subprocess.check_output(command, input=canonical(payload)).decode()
    source_path = output / f"{stem}.partial.rego.txt"
    source_path.write_text(source)
    # OPA's source renderer emits numbered residual query blocks. Keep their
    # bodies verbatim, wrap their disjunction as a testable Boolean entrypoint,
    # and load any OPA-generated support modules unchanged.
    sections = re.split(r"(?m)^# (Query|Module) (\d+)\n", source)
    bodies, support = [], []
    for index in range(1, len(sections), 3):
        (bodies if sections[index] == "Query" else support).append(sections[index + 2].strip())
    residual = "package audit.residual\nimport rego.v1\ndefault allowed := false\n"
    residual += "\n".join("allowed if {\n" + body + "\n}" for body in bodies)
    residual += "\nchecks := [result | some request in input.requests; result := data.audit.residual.allowed with input as request]\n"
    residual_path = output / f"{stem}.replay.rego"
    residual_path.write_text(residual)
    extra = ["--data", str(residual_path)]
    for index, body in enumerate(support):
        support_path = output / f"{stem}.support{index}.rego"
        support_path.write_text(body + "\n")
        extra += ["--data", str(support_path)]
    completions = [(base, state) for base, state in problem.all_states()
                   if list(base) == query["base"] and projection(state, query["mask"]) == freeze(query["observed"])]
    requests = [{**payload, "record": record_wire(base, state)} for base, state in completions]
    replay, replay_document, _ = opa_eval(binary, {"requests": requests}, "data.audit.residual.checks", extra=extra)
    expected = [problem.raw_label(base, state, True) for base, state in completions]
    assert replay == expected, (stem, replay, expected)
    write(output / f"{stem}.replay.json", {"native_result": replay_document,
          "compatible_completion_count": len(completions), "independent_raw_verdict_parity": True})
    write(output / f"{stem}.manifest.json", {"query": "data.audit.predicates.new_allowed", "unknowns": unknowns,
          "class_index": 0, "cost": cost, "residual_completion_replay_checks": len(completions),
          "meaning": "OPA-native residual query/support policies, executed over every compatible completion. This artifact is not itself the adapter audit report."})


def verify_occurrences(strict, strict_rows, occurrence, adapter):
    """Reconstruct EVERY original receipt/class link, including literal witnesses."""
    lookup = {digest(query): index for index, query in enumerate(strict["queries"])}
    expected_ids, independent_affected, oracle_cache = [], set(), {}
    literal_count = 0
    direct = DirectResidualDiagnostics(adapter.problem)
    snapshot = sha(ROOT / "results/v03/bpi_compact.jsonl.gz")
    old_catalog = digest(catalog_json(BASELINE))
    source = ROOT / "results/second/receipt_revalidation/native_receipts.jsonl.gz"
    with gzip.open(source, "rt") as stream:
        for line in stream:
            receipt = json.loads(line)["receipt"]
            query = receipt_query(receipt)
            key = digest(query)
            index = lookup[key]
            assert receipt["snapshot_sha256"] == snapshot
            assert receipt["catalog_sha256"] == old_catalog
            assert receipt["domain_version"] == "cartesian:v1"
            expected_ids.append([receipt["receipt_id"], index])
            if key not in oracle_cache:
                oracle_cache[key] = direct.diagnose(query)
            independent = oracle_cache[key]
            result = strict_rows[index]["diagnostic"]
            assert (result["status"], result["robust_masks"]) == (independent["status"], independent["robust_masks"])
            if independent["status"] == "insufficient":
                independent_affected.add(receipt["receipt_id"])
                report = adapter.problem.report(query, result, receipt)
                for label, witness in zip((False, True), report["witnesses"]):
                    assert witness["activities"] == receipt["activities"]
                    assert all(witness[k] == v for k, v in receipt["observed"].items())
                    assert reference_verdict(witness, adapter.problem.catalog) == label
                    literal_count += 1
    assert expected_ids == strict["weighted_requests"], "Source receipt/order/class mapping differs"
    actual_affected = {r["receipt_id"] for r in occurrence if r["status"] == "insufficient"}
    assert actual_affected == independent_affected
    return {"source_receipts": len(expected_ids), "source_sha256": sha(source),
            "exact_source_order_id_class_reconciliation": True,
            "independent_affected_id_set_equality": True,
            "independent_affected_ids": len(independent_affected),
            "literal_witness_checks": literal_count,
            "method": "Strictly parse every original receipt, reconstruct normalized query and class, bind snapshot/catalog/domain, independently diagnose each class using direct predicates, and compare the exact affected ID set. Lift and raw-check both witnesses on every affected literal receipt."}


def run(output, binary):
    output.mkdir(parents=True, exist_ok=False)
    workloads = load_workloads()
    assert sum(len(d["queries"]) for _, d, _ in workloads) == 941
    protocol = freeze_protocol(output, workloads, binary)
    version = subprocess.check_output([str(binary), "version"], text=True)
    write(output / "opa_version.json", {"text": version, "sha256": sha(binary)})
    rows, costs, summaries, adapters = [], [], [], {}
    label_checks = diagnosis_checks = literal_checks = 0
    for path, data, problem in workloads:
        start = time.perf_counter_ns()
        adapter = OpaAuditAdapter(problem, binary)
        setup_ns = time.perf_counter_ns() - start
        adapters[problem.name] = adapter
        generation_start = time.perf_counter_ns()
        results = []
        for index, query in enumerate(data["queries"]):
            result = adapter.diagnose(query)
            receipt = data.get("exemplars", [None] * len(data["queries"]))[index]
            report = problem.report(query, result, receipt)
            row = {"model": problem.name, "class_index": index, "query": query,
                   "diagnostic": result, "report": report}
            canonical(row)
            rows.append(row); results.append(result)
        assembly_ns = time.perf_counter_ns() - generation_start
        oracle_start = time.perf_counter_ns()
        label_checks += verify_labels(adapter)
        verifier = RawVerifier(problem)
        direct = DirectResidualDiagnostics(problem)
        for index, (query, result) in enumerate(zip(data["queries"], results)):
            verifier.verify(query, result)
            compared = direct.diagnose(query)
            assert result["status"] == compared["status"] and result["robust_masks"] == compared["robust_masks"]
            diagnosis_checks += 1
            if data.get("exemplars") and result["witnesses"] is not None:
                receipt = data["exemplars"][index]
                report = problem.report(query, result, receipt)
                for label, witness in zip((False, True), report["witnesses"]):
                    assert witness["activities"] == receipt["activities"]
                    assert all(witness[k] == v for k, v in receipt["observed"].items())
                    assert reference_verdict(witness, problem.catalog) == label
                    literal_checks += 1
        oracle_ns = time.perf_counter_ns() - oracle_start
        counts = dict(Counter(r["status"] for r in results))
        summaries.append({"model": problem.name, "queries": len(results), "status_counts": counts,
                          "complete_states": len(adapter.states), "parity": "passed"})
        costs.append({"model": problem.name, "setup_wall_ns": setup_ns,
                      "assembly_and_encoding_wall_ns": assembly_ns, "generation_wall_ns": setup_ns + assembly_ns,
                      "research_oracle_wall_ns": oracle_ns, **adapter.cost})
        print(json.dumps(summaries[-1]), flush=True)
    jsonlines(output / "class_reports.jsonl.gz", rows)
    strict = next(d for _, d, p in workloads if p.name == "procurement_strict")
    strict_rows = {r["class_index"]: r for r in rows if r["model"] == "procurement_strict"}
    occurrence = [{"receipt_id": case, "class_index": index,
                   "status": strict_rows[index]["report"]["status"],
                   "robust_additional_sets": strict_rows[index]["report"]["robust_additional_sets"],
                   "report_sha256": digest(strict_rows[index]["report"])} for case, index in strict["weighted_requests"]]
    assert len(occurrence) == len({r["receipt_id"] for r in occurrence}) == 50931
    affected = [r for r in occurrence if r["status"] == "insufficient"]
    assert len(affected) == 33489 and all(r["robust_additional_sets"] == [["profile"]] for r in affected)
    occurrence_verification = verify_occurrences(strict, strict_rows, occurrence, adapters["procurement_strict"])
    write(output / "occurrence_verification.json", occurrence_verification)
    jsonlines(output / "occurrence_index.jsonl.gz", occurrence)
    jsonlines(output / "repair_index.jsonl.gz", affected)
    controls = []
    for index, query in enumerate(strict["queries"]):
        original = adapters["procurement_strict"].diagnose(query)
        if original["status"] == "insufficient":
            restricted = adapters["procurement_strict"].diagnose(query, new_domain="consignment_exclusion:v1")
            assert restricted["status"] == "safe" and restricted["robust_masks"] == [0]
            controls.append({"id": "consignment_exclusion", "class_index": index, "result": restricted})
    invalid = dict(base=[0, 1, 2, 3], mask=0, observed=[], old_verdict=True)
    rejected = adapters["procurement_strict"].diagnose(invalid)
    assert rejected["status"] == "invalid_receipt"
    controls.append({"id": "correct_complete_old_decision_with_insufficient_mask", "query": invalid, "result": rejected})
    write(output / "controls.json", controls)
    for _, data, problem in workloads:
        save_partial(output / "native_partial", binary, data, problem)
    log_manifest = save_native_logs(output / "native_logs", binary, strict)
    write(output / "standalone_costs.json", {"cost_claim": "Descriptive single-run integration accounting; no cross-engine speed claim", "rows": costs})
    summary = {"status": "passed", "primary_diagnoses": diagnosis_checks,
               "complete_predicate_checks": label_checks, "lifted_witness_checks": literal_checks,
               "workloads": summaries, "strict_occurrences": len(occurrence), "strict_repair_ids": len(affected),
               "strict_occurrence_status_counts": dict(Counter(r["status"] for r in occurrence)),
               "occurrence_verification": occurrence_verification,
               "native_logs": 3, "native_partial_artifacts": len(workloads),
               "claims": ["Compact semantic and strict occurrence-repair parity on the frozen finite interface",
                          "Real OPA Rego predicates plus custom finite maintenance assembly",
                          "No full portable-bundle equivalence, production throughput, or policy-engine superiority claim"]}
    write(output / "summary.json", summary)
    assert protocol["source_hashes"] == source_fingerprints(workloads), "Frozen sources changed during run"
    write(output / "manifest.json", {"protocol_sha256": sha(output / "protocol.json"),
          "source_hashes": protocol["source_hashes"], "opa_binary_sha256": sha(binary),
          "artifacts": {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}})
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--opa", type=Path, default=DEFAULT_OPA)
    args = parser.parse_args()
    run(args.output, args.opa.resolve())
