#!/usr/bin/env python3
"""Acquire or verify the exact Linux x86_64 OPA executable used in this study.

Existing files are never replaced. The pinned release digest, saved published
checksum and downloaded checksum must agree before an executable is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY = ROOT / "results/platform_revision_20261010/opa/dependency"
VERSION = "v1.21.1"
EXPECTED_SHA256 = "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"
ASSET = "opa_linux_amd64_static"
URL = "https://github.com/open-policy-agent/opa/releases/download/" + VERSION + "/" + ASSET


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEPENDENCY / ASSET)
    parser.add_argument("--verify-only", action="store_true", help="Never download or modify any file")
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
            "The recorded executable is Linux x86_64; use that platform for this pinned replay")
    published = (DEPENDENCY / (ASSET + ".sha256")).read_text().split()[0]
    provenance = json.loads((DEPENDENCY / "provenance.json").read_text())
    require(published == provenance["published_sha256"] == provenance["binary_sha256"] == EXPECTED_SHA256,
            "Saved published checksum/provenance does not match the independently pinned release digest")
    require(provenance["version"] == VERSION, "Saved version mismatch")
    output = args.output.resolve()
    obtained = False
    if not output.exists():
        require(not args.verify_only, "OPA executable is missing; rerun without --verify-only to download it")
        with urllib.request.urlopen(URL + ".sha256", timeout=60) as response:
            fetched_checksum = response.read().decode().split()[0]
        require(fetched_checksum == EXPECTED_SHA256, "Upstream checksum differs from the recorded digest")
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".opa-download-", dir=output.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as target, urllib.request.urlopen(URL, timeout=60) as source:
                while block := source.read(1024 * 1024):
                    target.write(block)
            require(sha(temporary) == EXPECTED_SHA256, "Downloaded executable checksum mismatch")
            temporary.chmod(0o755)
            # Exclusive creation also protects against a concurrent installer.
            os.link(temporary, output)
            obtained = True
        finally:
            temporary.unlink(missing_ok=True)
    actual = sha(output)
    require(actual == EXPECTED_SHA256, "Existing executable checksum mismatch; file was not replaced")
    require(os.access(output, os.X_OK), "Verified file is not executable; set its executable permission explicitly")
    version_output = subprocess.check_output([str(output), "version"], text=True)
    version_record = dict(line.split(":", 1) for line in version_output.splitlines() if ":" in line)
    version_record = {key.strip(): value.strip() for key, value in version_record.items()}
    require(version_record["Version"] == VERSION.removeprefix("v"), "Executable version output mismatch")
    print(json.dumps({"status": "passed", "downloaded": obtained, "path": str(output),
                      "sha256": actual, "version": version_record, "official_asset": URL}, indent=2))


if __name__ == "__main__":
    main()
