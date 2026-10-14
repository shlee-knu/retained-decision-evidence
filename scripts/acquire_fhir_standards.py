"""Acquire pinned official FHIR artifacts and inventory every selected profile delta."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import io
import json
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data/external/fhir_standards"
OUT = ROOT / "results/standards_extension/fhir"


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def acquire(url, relative, expected_sha256=None):
    path = DEST / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "FHIR-standards-research/1.0"})
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read()
        if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError(f"Pinned SHA-256 mismatch for {url}; acquired bytes were not installed")
        temporary = path.with_suffix(path.suffix + ".partial")
        temporary.write_bytes(raw)
        temporary.replace(path)
    raw = path.read_bytes()
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"Pinned SHA-256 mismatch for existing {relative}")
    return {"url": url, "path": str(path.relative_to(ROOT)), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def recursive_diff(old, new, path=""):
    """Lossless JSON property inventory; list indices are retained, not normalized away."""
    if type(old) is not type(new):
        return [{"path": path, "old": old, "new": new}]
    if isinstance(old, dict):
        result = []
        for key in sorted(old.keys() | new.keys()):
            where = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in old:
                result.append({"path": where, "added": new[key]})
            elif key not in new:
                result.append({"path": where, "removed": old[key]})
            else:
                result.extend(recursive_diff(old[key], new[key], where))
        return result
    if isinstance(old, list):
        result = []
        for i in range(max(len(old), len(new))):
            where = f"{path}/{i}"
            if i >= len(old):
                result.append({"path": where, "added": new[i]})
            elif i >= len(new):
                result.append({"path": where, "removed": old[i]})
            else:
                result.extend(recursive_diff(old[i], new[i], where))
        return result
    return [] if old == new else [{"path": path, "old": old, "new": new}]


def invariant_inventory(profile, supported):
    result = []
    for element in profile["snapshot"]["element"]:
        for constraint in element.get("constraint", []):
            result.append({"element_id": element["id"], "path": element["path"],
                           **constraint,
                           "support": "implemented_fragment" if constraint["key"] in supported else "outside_fragment",
                           "exclusion_reason": None if constraint["key"] in supported else
                           ("warning excluded from Boolean error verdict" if constraint["severity"] != "error"
                            else "outside declared typed five-root invariant fragment")})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--validator", action="store_true", help="Also download pinned official validator JAR")
    args = parser.parse_args()
    started = time.perf_counter()
    protocol = json.loads((ROOT / "configs/fhir_standards_protocol.json").read_text())
    jobs = []
    for version, publication in protocol["versions"].items():
        for profile in protocol["profiles"]:
            filename = f"StructureDefinition-us-core-{profile}.json"
            jobs.append((f"https://hl7.org/fhir/us/core/{publication}/{filename}", f"profiles/{version}/{filename}"))
        jobs.append((f"https://hl7.org/fhir/us/core/{publication}/package.tgz", f"packages/us-core-{version}.tgz"))
        jobs.append((f"https://hl7.org/fhir/us/core/{publication}/examples.json.zip", f"packages/examples-{version}.json.zip"))
    jobs.append(("https://registry.npmjs.org/fhirpath/" + protocol["fhirpath_js_version"], "tools/fhirpath-npm-metadata.json"))
    if args.validator:
        v = protocol["validator_version"]
        jobs.append((f"https://github.com/hapifhir/org.hl7.fhir.core/releases/download/{v}/validator_cli.jar", "tools/validator_cli.jar"))
    records, failures = [], []
    previous = DEST / "manifest.json"
    pinned = {row["path"]: row["sha256"] for row in json.loads(previous.read_text())["records"]} if previous.exists() else {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [(job, pool.submit(acquire, *job, pinned.get(str((DEST / job[1]).relative_to(ROOT))))) for job in jobs]
        for job, future in futures:
            try:
                records.append(future.result())
            except Exception as error:
                failures.append({"url": job[0], "error": str(error)})
    if failures:
        dump(OUT / "acquisition_failures.json", failures)
        raise SystemExit("Acquisition failed; original pinned manifest was preserved: " + json.dumps(failures))
    examples = []
    # Published package examples are selected by resourceType and explicit profile.
    for version in protocol["versions"]:
        package = DEST / f"packages/us-core-{version}.tgz"
        if not package.exists():
            continue
        with tarfile.open(fileobj=io.BytesIO(package.read_bytes()), mode="r:gz") as archive:
            for entry in archive.getmembers():
                if not entry.isfile() or not entry.name.endswith(".json"):
                    continue
                raw = archive.extractfile(entry).read()
                try:
                    resource = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                if resource.get("resourceType") != "Observation":
                    continue
                targets = [p for p in protocol["profiles"] if any(
                    f"/us-core-{p}" in canonical for canonical in resource.get("meta", {}).get("profile", []))]
                if not targets:
                    continue
                name = entry.name.rsplit("/", 1)[-1]
                target = DEST / f"examples/{version}/{name}"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                examples.append({"path": str(target.relative_to(ROOT)), "package_member": entry.name,
                                 "version": version, "profiles": targets,
                                 "sha256": hashlib.sha256(raw).hexdigest()})
    # Some published NPM packages omit examples; official examples ZIP is a fallback.
    import zipfile
    for version in protocol["versions"]:
        zip_path = DEST / f"packages/examples-{version}.json.zip"
        if not zip_path.exists():
            continue
        with zipfile.ZipFile(zip_path) as archive:
            for entry in archive.namelist():
                if not entry.endswith(".json"):
                    continue
                raw = archive.read(entry)
                try:
                    resource = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                if resource.get("resourceType") != "Observation":
                    continue
                targets = [p for p in protocol["profiles"] if any(
                    f"/us-core-{p}" in c for c in resource.get("meta", {}).get("profile", []))]
                if not targets:
                    continue
                name = entry.rsplit("/", 1)[-1]
                target = DEST / f"examples/{version}/{name}"
                if target.exists():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                examples.append({"path": str(target.relative_to(ROOT)), "zip_member": entry,
                                 "version": version, "profiles": targets,
                                 "sha256": hashlib.sha256(raw).hexdigest()})
    inventory = {}
    for profile in protocol["profiles"]:
        versions = {v: json.loads((DEST / f"profiles/{v}/StructureDefinition-us-core-{profile}.json").read_text())
                    for v in protocol["versions"]}
        old, new = versions["6.1.0"], versions["7.0.0"]
        # Original full-document and element-id-aligned snapshot differences both retained.
        inventory[profile] = {
            "all_document_changes": recursive_diff(old, new),
            "snapshot_by_element_id_changes": recursive_diff(
                {e["id"]: e for e in old["snapshot"]["element"]},
                {e["id"]: e for e in new["snapshot"]["element"]}),
            "invariants": {v: invariant_inventory(d, protocol["supported_invariant_keys"]) for v, d in versions.items()},
            "invariant_changes_by_element_and_key": recursive_diff(
                {e["id"] + "/" + c["key"]: c for e in old["snapshot"]["element"] for c in e.get("constraint", [])},
                {e["id"] + "/" + c["key"]: c for e in new["snapshot"]["element"] for c in e.get("constraint", [])}),
            "non_invariant_changes": "All retained above; cardinality, slicing, type, binding, mustSupport and narrative deltas are outside the implemented fragment and not silently treated as unchanged."
        }
    dump(OUT / "profile_delta_inventory.json", inventory)
    dump(DEST / "examples_manifest.json", examples)
    dump(DEST / "manifest.json", {"acquired_utc": datetime.now(timezone.utc).isoformat(),
         "source_scope": "Official HL7 published artifacts and HL7 FHIRPath npm distribution",
         "license": {"profiles_examples": "CC0-1.0, verified in both official US Core package/package.json files; embedded terminology notices retained", "validator": "Apache-2.0 (HL7 FHIR Java reference implementation)", "fhirpath_js": "Apache-2.0"},
         "records": records, "failures": failures, "examples": len(examples),
         "setup_elapsed_seconds": time.perf_counter() - started})
    print(json.dumps({"sources": len(records), "failures": failures, "examples": len(examples)}))


if __name__ == "__main__":
    main()
