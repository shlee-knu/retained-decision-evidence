"""Small pinned resources for offline tests and the normative baseline."""
import json
from download_sources import ROOT, download

FILES = {
    "epcis-json-schema.json":"cfabd8620cc4dd67a53e6aa397bc26379f8b05bb9147c8a37a60bbec69a62572",
    "epcis-shacl.ttl":"7db2547a7a55e7d6e6f19c0ad472d1f0987ef19f3d04a43b195bca55c0cc7f42",
    "epcis-context.jsonld":"e532647e8eb371379b8b0e8602d8981c8566bc60f7351f22c76a5bc865962008",
}

if __name__=="__main__":
    records=[]
    for name,hash_value in FILES.items():
        records.append(download(f"https://ref.gs1.org/standards/epcis/2.0.0/{name}",f"data/standards/{name}",
                                expected_hash=hash_value,license_name="GS1 source terms; resources excluded from repository release"))
    (ROOT/"data/provenance/standards_manifest.json").write_text(json.dumps(records,indent=2))
