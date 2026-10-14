"""Check complete FHIR resources against independent standard implementations.

No masked JSON is passed to a validator. Full-profile validation is a separately
reported context check; only explicit selected invariant results are comparable
to the finite adapter's verdict.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import time

from logistics_validation.standards_fhir import (
    DATA, ROOT, abstract_resource, all_states, complete_resource,
    constraints_for, raw_constraint_results, state_constraint_results,
)

OUT = ROOT / "results/standards_extension/fhir"


def dump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


NODE_RUNNER = r'''const fs = require('fs');
const fhirpath = require('./node_modules/fhirpath');
const model = require('./node_modules/fhirpath/fhir-context/r4');
const jobs = JSON.parse(fs.readFileSync(0, 'utf8'));
const compiled = new Map();
const output = jobs.map(job => {
  const results = {}, errors = {};
  for (const rule of job.constraints) {
    let expression = rule.expression;
    if (rule.path === 'Observation.value[x]') expression = 'value.all(' + expression + ')';
    else if (rule.path === 'Observation.referenceRange') expression = 'referenceRange.all(' + expression + ')';
    else if (rule.path !== 'Observation') throw Error('Unsupported constraint context ' + rule.path);
    try {
      if (!compiled.has(expression)) compiled.set(expression, fhirpath.compile(expression, model));
      const value = compiled.get(expression)(job.resource, {resource: job.resource});
      if (value.length !== 1 || typeof value[0] !== 'boolean') throw Error('Non-Boolean result: '+JSON.stringify(value));
      results[rule.key] = value[0];
    } catch (error) { errors[rule.key] = String(error); }
  }
  return {id: job.id, results, errors};
});
process.stdout.write(JSON.stringify(output));
'''


def fixture_jobs():
    jobs, native_rows, unsupported = [], [], []
    states = all_states()
    for index, state in enumerate(states):
        resource = complete_resource(state, f"synthetic-{index:04d}")
        dump(DATA / f"generated/finite/observation-{index:04d}.json", resource)
        for profile in ("observation-lab", "observation-clinical-result", "simple-observation"):
            for version in ("6.1.0", "7.0.0"):
                rules = constraints_for(profile, version)
                jobs.append({"id": f"synthetic/{profile}/{version}/{index}", "resource": resource,
                             "constraints": rules, "state": state, "source": "exhaustive_synthetic"})
    # Public fixture membership was fixed by explicit meta.profile, not outcome.
    for entry in json.loads((DATA / "examples_manifest.json").read_text()):
        resource = json.loads((ROOT / entry["path"]).read_text())
        try:
            state = abstract_resource(resource)
        except (ValueError, TypeError, KeyError) as error:
            unsupported.append({**entry, "reason": str(error)})
            continue
        for profile in entry["profiles"]:
            for version in ("6.1.0", "7.0.0"):
                job = {"id": f"official/{profile}/{version}/{entry['path']}", "resource": resource,
                       "constraints": constraints_for(profile, version), "state": state,
                       "source": "official_specification_example"}
                jobs.append(job)
                native_rows.append({"id": job["id"], "source_path": entry["path"], "source_version": entry["version"],
                                    "profile": profile, "evaluated_version": version, "state": state})
    # Unbounded-array property controls place the decisive member after long prefixes.
    for size in (3, 17, 257):
        for changed_root in ("component", "referenceRange"):
            state = ("quantity_ucum", "absent", "different_code", "absent", "valid_ucum")
            resource = complete_resource(state, f"long-{changed_root}-{size}")
            if changed_root == "component":
                resource["component"] = resource["component"] * size
                resource["component"].append({"code": deepcopy(resource["code"]), "valueString": "late matching component"})
            else:
                resource["referenceRange"] = [deepcopy(resource["referenceRange"][0]) for _ in range(size)]
                resource["referenceRange"].append({"high": {"value": 10, "system": "https://example.org/local-units", "code": "g/dL"}})
            dump(DATA / f"generated/long/{resource['id']}.json", resource)
            for version in ("6.1.0", "7.0.0"):
                jobs.append({"id": f"long/{version}/{resource['id']}", "resource": resource,
                             "constraints": constraints_for("observation-lab", version),
                             "state": abstract_resource(resource), "source": "synthetic_long_array_control"})
    return jobs, native_rows, unsupported


def fhirpath_check(jobs):
    runner = DATA / "tools/fragment_oracle.js"
    runner.write_text(NODE_RUNNER)
    before = time.perf_counter()
    process = subprocess.run(["node", str(runner)], input=json.dumps(jobs), text=True,
                             capture_output=True, timeout=120)
    (OUT / "fhirpath_stderr.txt").write_text(process.stderr)
    if process.returncode:
        raise RuntimeError(process.stderr[-4000:])
    oracle = json.loads(process.stdout)
    discrepancies, errors, counts, rows = [], [], Counter(), []
    for job, result in zip(jobs, oracle, strict=True):
        raw = raw_constraint_results(job["resource"], job["constraints"])
        finite = state_constraint_results(tuple(job["state"]), job["constraints"])
        counts[job["source"]] += 1
        counts["individual_invariant_evaluations"] += len(raw)
        if result["errors"]:
            errors.append(result)
        if result["results"] != raw or raw != finite:
            discrepancies.append({"id": job["id"], "oracle": result, "raw": raw, "finite": finite})
        rows.append({"id": job["id"], "source": job["source"], "state": job["state"],
                     "oracle_results": result["results"], "fragment_verdict": all(raw.values())})
    dump(OUT / "fhirpath_oracle_rows.json", rows)
    summary = {"engine": "HL7/fhirpath.js", "version": "4.6.0", "model": "FHIR R4",
               "complete_resources_only": True, "profiles": 3, "profile_versions": 6,
               "finite_states_per_profile": len(all_states()), "counts": dict(counts),
               "discrepancies": discrepancies, "engine_errors": errors,
               "elapsed_seconds": time.perf_counter() - before,
               "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
               "package_lock_sha256": hashlib.sha256((DATA / "tools/package-lock.json").read_bytes()).hexdigest(),
               "scope": "Exact selected computable constraints evaluated in the declared element context; not full profile validation."}
    dump(OUT / "fhirpath_summary.json", summary)
    return summary


def classify_issues(resource):
    issues = []
    if resource.get("resourceType") == "OperationOutcome":
        issues = resource.get("issue", [])
    else:
        for entry in resource.get("entry", []):
            issues.extend(classify_issues(entry.get("resource", {}))["raw_issues"])
    categories = Counter()
    for issue in issues:
        message = (issue.get("diagnostics", "") + " " + issue.get("details", {}).get("text", "")).lower()
        if any(word in message for word in ("unable to resolve", "could not resolve", "not found", "unknown code system", "terminology server", "not checked", "not supported", "unable to find", "cannot be resolved", "no terminology service", "without terminology service", "cannot be validated", "could not be found", "could not confirm")):
            categories["unresolved_or_unchecked"] += 1
        elif issue.get("severity") in ("fatal", "error"):
            categories["error"] += 1
        else:
            categories[issue.get("severity", "unknown")] += 1
    return {"categories": dict(categories), "raw_issues": issues}


def full_validator_check(limit, timeout):
    """Separate full-profile context; unresolved external validation stays visible."""
    jar = DATA / "tools/validator_cli.jar"
    if not jar.exists():
        return {"status": "not_run", "reason": "Pinned validator JAR not acquired"}
    synthetic_paths = sorted((DATA / "generated/finite").glob("*.json"))
    # Deterministic index-stratified subset, fixed before validator outcomes.
    indexes = sorted(set(round(i * (len(synthetic_paths) - 1) / max(1, limit - 1)) for i in range(min(limit, len(synthetic_paths)))))
    selected = [synthetic_paths[i] for i in indexes]
    jobs = []
    for profile in ("observation-lab", "observation-clinical-result", "simple-observation"):
        for version in ("6.1.0", "7.0.0"):
            destination = OUT / f"validator/{profile}/{version}"
            destination.mkdir(parents=True, exist_ok=True)
            fixtures = DATA / f"generated/validator/{profile}/{version}"
            fixtures.mkdir(parents=True, exist_ok=True)
            for path in selected:
                (fixtures / path.name).write_bytes(path.read_bytes())
            # Include each official source fixture of the matching profile/version.
            for entry in json.loads((DATA / "examples_manifest.json").read_text()):
                if entry["version"] == version and profile in entry["profiles"]:
                    (fixtures / ("official-" + Path(entry["path"]).name)).write_bytes((ROOT / entry["path"]).read_bytes())
            command = ["java", "-Xmx2g", "-Duser.home=" + str(DATA / "tools/java-home"), "-jar", str(jar),
                       str(fixtures / "*.json"), "-version", "4.0.1", "-ig", str(DATA / f"packages/us-core-{version}.tgz"),
                       "-profile", f"http://hl7.org/fhir/us/core/StructureDefinition/us-core-{profile}",
                       "-tx", "n/a", "-output", str(destination / "operation_outcomes.json")]
            started = time.perf_counter()
            try:
                process = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
                (destination / "stdout.log").write_text(process.stdout)
                (destination / "stderr.log").write_text(process.stderr)
                result = {"status": "completed" if (destination / "operation_outcomes.json").exists() else "failed_without_outcomes", "exit_code": process.returncode}
            except subprocess.TimeoutExpired as error:
                (destination / "stdout.log").write_bytes(error.stdout or b"")
                (destination / "stderr.log").write_bytes(error.stderr or b"")
                result = {"status": "timeout", "timeout_seconds": timeout}
            result.update(profile=profile, version=version, command=command,
                          fixture_count=len(list(fixtures.glob("*.json"))),
                          fixture_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(fixtures.glob("*.json"))},
                          synthetic_indices=indexes, elapsed_seconds=time.perf_counter() - started)
            if (destination / "operation_outcomes.json").exists():
                counts = classify_issues(json.loads((destination / "operation_outcomes.json").read_text()))
                result["issue_categories"] = counts["categories"]
                result["raw_issue_count"] = len(counts["raw_issues"])
            dump(destination / "execution.json", result)
            jobs.append(result)
            print(json.dumps({"full_validator": profile, "version": version, **{k: result[k] for k in ("status", "elapsed_seconds")}}), flush=True)
    summary = {"engine": "Official HL7 Java Validator", "version": "6.7.0", "jobs": jobs,
               "terminology_mode": "n/a: external terminology disabled; these are not whole-profile certification claims",
               "scope": "Complete resources, explicit same target profile. Never compared masked-resource errors to partial semantic certificates.",
               "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest()}
    dump(OUT / "full_validator_summary.json", summary)
    return summary


def summarize_existing_validator():
    """Inspect emitted diagnostics; no missing diagnostic is advertised as rule coverage."""
    executions, comparisons, discrepancies = [], [], []
    for path in sorted((OUT / "validator").glob("*/*/execution.json")):
        execution = json.loads(path.read_text())
        output = path.parent / "operation_outcomes.json"
        if not output.exists():
            executions.append(execution)
            continue
        results = json.loads(output.read_text())
        classified = classify_issues(results)
        execution["issue_categories"] = classified["categories"]
        executions.append(execution)
        rules = constraints_for(execution["profile"], execution["version"])
        keys = {r["key"] for r in rules}
        for entry in results.get("entry", []):
            outcome = entry["resource"]
            source = next((e["valueString"] for e in outcome.get("extension", [])
                           if e.get("url", "").endswith("operationoutcome-file")), None)
            if not source or not Path(source).name.startswith("observation-"):
                continue
            filename = Path(source).name
            # Portable summary: fixture_jobs regenerated these deterministic files
            # under this checkout, irrespective of the original absolute log path.
            current_fixture = DATA / "generated/finite" / filename
            actual_hash = hashlib.sha256(current_fixture.read_bytes()).hexdigest()
            pinned_hash = execution.get("fixture_sha256", {}).get(filename)
            if pinned_hash is None:
                # Backfill only from the original on-disk validator input, never
                # from a newly generated fixture when the original is unavailable.
                original = Path(source)
                if not original.exists():
                    raise ValueError(f"No original fixture hash available for {source}; rerun full validator")
                pinned_hash = hashlib.sha256(original.read_bytes()).hexdigest()
                execution.setdefault("fixture_sha256", {})[filename] = pinned_hash
            if actual_hash != pinned_hash:
                raise ValueError(f"Saved validator fixture differs from regenerated {filename}; rerun full validator")
            resource = json.loads(current_fixture.read_text())
            expected = {key for key, ok in raw_constraint_results(resource, rules).items() if not ok}
            observed = set()
            for issue in outcome.get("issue", []):
                text = issue.get("details", {}).get("text", "") + " " + issue.get("diagnostics", "")
                observed.update(key for key in re.findall(r"Constraint failed: ([a-z0-9-]+):", text) if key in keys)
            row = {"profile": execution["profile"], "version": execution["version"],
                   "file": Path(source).name, "expected_fragment_failure_keys": sorted(expected),
                   "emitted_fragment_failure_keys": sorted(observed), "agreement": expected == observed}
            comparisons.append(row)
            if expected != observed:
                discrepancies.append(row)
        dump(path, execution)
    package_cache = DATA / "tools/java-home/.fhir/packages"
    package_manifest = []
    for metadata in sorted(package_cache.glob("*/package/package.json")):
        item = json.loads(metadata.read_text())
        package_manifest.append({"name": item.get("name"), "version": item.get("version"),
                                 "package_json_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
                                 "license": item.get("license")})
    summary = {"engine": "Official HL7 Java Validator", "version": "6.7.0", "jobs": executions,
               "terminology_mode": "n/a: external terminology disabled; unresolved/unchecked issues separated",
               "full_profile_pass_claim": False,
               "complete_synthetic_diagnostic_comparisons": len(comparisons),
               "selected_invariant_diagnostic_discrepancies": discrepancies,
               "diagnostic_comparisons": comparisons,
               "coverage_limit": "Emitted selected-invariant failure sets compared on a deterministic subset. Absence of a diagnostic does not independently prove execution of every rule; exhaustive selected-rule coverage is supplied separately by HL7 fhirpath.js.",
               "cached_package_metadata": package_manifest,
               "jar_sha256": hashlib.sha256((DATA / "tools/validator_cli.jar").read_bytes()).hexdigest()}
    dump(OUT / "full_validator_summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-validator", action="store_true")
    parser.add_argument("--validator-limit", type=int, default=12)
    parser.add_argument("--validator-timeout", type=int, default=180)
    parser.add_argument("--summarize-validator", action="store_true", help="Reclassify saved full-validator diagnostics without rerunning Java")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    jobs, native_rows, unsupported = fixture_jobs()
    dump(OUT / "official_example_mapping.json", {"supported_rows": native_rows, "unsupported_source_examples": unsupported})
    summary = fhirpath_check(jobs)
    if args.full_validator:
        full_validator_check(args.validator_limit, args.validator_timeout)
    if args.full_validator or args.summarize_validator:
        summarize_existing_validator()
    summary["all_setup_elapsed_seconds"] = time.perf_counter() - started
    summary["completed_utc"] = datetime.now(timezone.utc).isoformat()
    dump(OUT / "verification.json", {"fhirpath": summary, "official_examples_unsupported": len(unsupported),
         "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
             ROOT / "src/logistics_validation/standards_fhir.py", ROOT / "scripts/validate_fhir_standards.py",
             ROOT / "configs/fhir_standards_protocol.json")},
         "passed": not summary["discrepancies"] and not summary["engine_errors"]})
    print(json.dumps({"counts": summary["counts"], "discrepancies": len(summary["discrepancies"]),
                      "engine_errors": len(summary["engine_errors"]), "unsupported_examples": len(unsupported)}))
    if summary["discrepancies"] or summary["engine_errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
