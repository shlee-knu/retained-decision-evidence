"""Download byte-pinned GS1 sources without redistributing their original files."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]


def acquire(resource, originals, offline=False):
    target = originals / resource["file"]
    fetched = False
    if not target.exists():
        if offline:
            raise FileNotFoundError(f"Missing pinned resource: {target}")
        response = requests.get(resource["url"], timeout=(15, 90))
        response.raise_for_status()
        data = response.content
        # Verify bytes before replacing a local source; never keep a bad response.
        if len(data) != resource["bytes"] or hashlib.sha256(data).hexdigest() != resource["sha256"]:
            raise ValueError(f"Downloaded resource differs from pinned bytes: {resource['url']}")
        temp = target.with_suffix(target.suffix + ".part")
        temp.write_bytes(data)
        temp.replace(target)
        fetched = True
    data = target.read_bytes()
    if len(data) != resource["bytes"] or hashlib.sha256(data).hexdigest() != resource["sha256"]:
        raise ValueError(f"Existing resource differs from pinned bytes: {target}")
    return dict(resource, path=str(target.relative_to(ROOT)), downloaded_this_run=fetched,
                verified_utc=datetime.now(timezone.utc).isoformat(),
                source_terms="GS1 terms; original source excluded from redistribution")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Verify existing resources only")
    args = parser.parse_args()
    protocol = json.loads((ROOT / "configs/epcis_standards_protocol.json").read_text())
    destination = ROOT / "data/external/epcis_extension"
    originals = destination / "originals"
    originals.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(lambda item: acquire(item, originals, args.offline), protocol["resources"]))
    manifest = {"scope": protocol["licensing"], "resources": records}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Verified {len(records)} pinned GS1 resources; originals are locally retained and git-ignored.")


if __name__ == "__main__":
    main()
