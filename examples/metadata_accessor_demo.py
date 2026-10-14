"""Synthetic, no-network example of the separately accessible metadata boundary.

Run from the project root: .venv/bin/python examples/metadata_accessor_demo.py
Replace the callbacks with real block readers only after establishing the
engine's supported-profile, valid-clock and complete-projection assumptions.
"""
from collections.abc import Mapping
import json

from logistics_validation.acquisition import acquire, structural_order


class CallbackMetadata(Mapping):
    def __init__(self, activities, readers):
        self.activities = activities
        self.readers = readers
        self.reads = []

    def __getitem__(self, key):
        if key == "activities":
            return self.activities
        if key not in self.readers:
            raise KeyError(key)
        self.reads.append(key)
        return self.readers[key]()

    def __iter__(self):
        return iter(("activities", *self.readers))

    def __len__(self):
        return 1 + len(self.readers)


def main():
    activities = ["create", "receive", "invoice", "clear"]
    clocks = dict(zip(activities, [f"2020-01-0{day}T00:00:00Z" for day in range(1, 5)]))
    result = {"input_kind": "synthetic demonstration; not an additional data source", "catalogs": []}
    for name, forbidden in (("permissive", {}), ("strict_consignment", {"Consignment": ("invoice", "clear")})):
        source = CallbackMetadata(activities, {
            "profile": lambda: "3-way match, invoice after GR",
            "first_times": lambda: clocks.copy(),
        })
        order = structural_order(activities, forbidden=forbidden)
        decision = acquire(source, order, forbidden=forbidden)
        assert source.reads == decision["fetched_blocks"]
        assert decision["decision"] == "accept"
        result["catalogs"].append({"name": name, "decision": decision["decision"],
                                   "observed_blocks": source.reads, "policy": order})
    assert len(result["catalogs"][0]["observed_blocks"]) == 1
    assert len(result["catalogs"][1]["observed_blocks"]) == 2
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
