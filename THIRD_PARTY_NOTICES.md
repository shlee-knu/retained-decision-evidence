# Third-party notices

The root AGPL-3.0-only license applies to project-authored code. It does not override the following source licenses.

| Material | Source and license | Included scope |
| --- | --- | --- |
| BPI Challenge 2019 | Boudewijn van Dongen (2019), [4TU deposit](https://doi.org/10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) | Projected case data and derived receipts, indexes, ledgers and results. See README for the transformations. Raw XES is excluded. |
| ERPNext | [frappe/erpnext](https://github.com/frappe/erpnext), GPLv3 | Selected source, tests and metadata at commits `c2d378a8fd7c8e4b1f5f05cf8cf0cd1c505557be` and `ff78778b7cde837bcd3128582280f34582522e5f`; upstream copyright headers and both complete `license.txt` files are preserved under `results/beta_improvement_20261012/public_change/sources/`. |
| Frappe | [frappe/frappe at ab2ea34e2ca327b2a2c647abe0ac284be088a54f](https://github.com/frappe/frappe/tree/ab2ea34e2ca327b2a2c647abe0ac284be088a54f), MIT | Selected upstream workflow files used as provenance for the ERP setup. The exact upstream [LICENSE](third_party/frappe/LICENSE) is included. |
| Open Policy Agent | [OPA 1.21.1](https://github.com/open-policy-agent/opa/releases/tag/v1.21.1), Apache-2.0 | Version/checksum provenance and the upstream license under `results/platform_revision_20261010/opa/dependency/`. The executable is excluded and can be fetched with its pinned hash. |
| US Core / FHIR | Official HL7 artifacts, with recorded CC0 profile/example metadata and separate terminology notices | Acquisition manifests and derived scientific validation results. Original standards/packages and the Java/Node validators are excluded. Their own license terms apply when fetched. |
| GS1 EPCIS / CBV | Official GS1 artifacts and source terms | Acquisition metadata and research-generated finite models/results. Original PDFs, schemas, SHACL files and examples are excluded. |
| Road Traffic Fine Management Process | [4TU deposit](https://doi.org/10.4121/uuid:270fd440-1057-4fb9-89a9-b699b47990f5), General Terms of Use with noncommercial restrictions | Source metadata and aggregate research results only. Raw and record-level derivatives are excluded. |
| BPI Challenge 2020 Permit Log | [4TU deposit](https://doi.org/10.4121/uuid:ea03d361-a7cd-4f5e-83d8-5fbdf0362550), CC BY-NC 4.0 | Source metadata and aggregate research results only. Raw and record-level derivatives are excluded. |

Public upstream author names and contact addresses can occur in original package or commit metadata. Their attribution is preserved; no research author account or authentication material is supplied. Local ERP replay constants `access-local-test` and `access-local-admin` and the upstream CI database default `root` are synthetic test setup values, not a deployed service configuration.
