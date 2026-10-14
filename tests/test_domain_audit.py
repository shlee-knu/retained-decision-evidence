from collections import defaultdict
import pytest

from logistics_validation.catalog_audit import (
    BASELINE, CertificateTable, State, concrete, generated_catalogs, universe, verdict,
)
from logistics_validation.domain_audit import (
    DOMAINS, DomainCertificateTable, domain_changes, domain_contains,
    guarantee_mask, reference_domain_contains, verified_gate_mask, withdrawal_pairs,
)


@pytest.fixture(scope="module")
def states():
    return universe()


def test_domain_counts_and_independent_raw_filter(states):
    expected = dict(zip(DOMAINS, (8612, 1268, 6468, 958)))
    for domain in DOMAINS:
        assert sum(domain_contains(s, domain) for s in states) == expected[domain]
        for s in states:
            raw = concrete(s)
            raw["activities"] = [a for a in raw["activities"] for _ in range(2)]
            assert reference_domain_contains(raw, domain) == domain_contains(s, domain)


def test_cartesian_identity_and_no_vacuous_certificates(states):
    labels = [verdict(s) for s in states]
    old = CertificateTable(states, labels)
    full = DomainCertificateTable(states, labels, "cartesian")
    assert list(full.sufficient) == old.sufficient
    for d in DOMAINS[1:]:
        restricted = DomainCertificateTable(states, labels, d)
        for i in range(len(states)):
            if not restricted.active[i]:
                assert restricted.sufficient[i] is None
                assert restricted.minimal[i] is None
                assert restricted.necessary[i] is None
                assert domain_changes(restricted, full, i)["supported_both"] is False


def test_independent_brute_domain_fibers(states):
    # Directly filter every raw completion in each <=2-milestone base fiber.
    small = tuple(s for s in states if len(s.order) <= 2)
    for _, catalog, _ in generated_catalogs():
        labels = [verdict(s, catalog) for s in small]
        for domain in DOMAINS:
            table = DomainCertificateTable(small, labels, domain)
            admissible = [reference_domain_contains(concrete(s), domain) for s in small]
            for i, x in enumerate(small):
                if not admissible[i]:
                    continue
                for mask in range(4):
                    possibilities = {labels[j] for j, y in enumerate(small)
                                     if admissible[j] and x.order == y.order
                                     and (not mask & 1 or x.profile == y.profile)
                                     and (not mask & 2 or x.ranks == y.ranks)}
                    assert bool(table.sufficient[i] & (1 << mask)) == (len(possibilities) == 1)


def test_all_catalog_domain_nesting_and_equivalence(states):
    for _, catalog, _ in generated_catalogs():
        labels = [verdict(s, catalog) for s in states]
        tables = {d: DomainCertificateTable(states, labels, d) for d in DOMAINS}
        for small, large in withdrawal_pairs():
            for i in range(len(states)):
                if tables[small].active[i]:
                    assert tables[large].active[i]
                    assert tables[small].sufficient[i] | tables[large].sufficient[i] == tables[small].sufficient[i]
                    assert not domain_changes(tables[small], tables[large], i)["gained"]
    strict = generated_catalogs()[1][1]
    for domain in ("consignment_exclusion", "both"):
        a = DomainCertificateTable(states, [verdict(s) for s in states], domain)
        b = DomainCertificateTable(states, [verdict(s, strict) for s in states], domain)
        assert all(a.labels[i] == b.labels[i] for i in range(len(states)) if a.active[i])
        assert a.sufficient == b.sufficient


def test_chronological_guarantee_eliminates_time_requirement(states):
    for _, catalog, _ in generated_catalogs():
        table = DomainCertificateTable(states, [verdict(s, catalog) for s in states], "chronological")
        for minimal in table.minimal:
            if minimal is not None:
                assert all(not m & 2 for m in minimal)


def test_membership_can_be_verified_only_from_declared_reads(states):
    for domain in DOMAINS:
        fibers = defaultdict(set)
        for s in states:
            m = guarantee_mask(s, domain)
            # This key is exactly what the verifier has read.
            key = (s.order, s.profile if m & 1 else None, s.ranks if m & 2 else None)
            fibers[key].add(domain_contains(s, domain))
        assert all(len(v) == 1 for v in fibers.values())


def test_paid_union_and_failed_guarantee_fallback(states):
    for _, catalog, _ in generated_catalogs()[:2]:
        broad = DomainCertificateTable(states, [verdict(s, catalog) for s in states], "cartesian")
        for domain in DOMAINS:
            restricted = DomainCertificateTable(states, broad.labels, domain)
            failed = 0
            for i, s in enumerate(states):
                g = guarantee_mask(s, domain)
                if restricted.active[i]:
                    for m in restricted.minimal[i]:
                        assert broad.sufficient[i] & (1 << (m | g))
                for order in ("profile_first", "time_first"):
                    result = verified_gate_mask(i, domain, broad, order)
                    assert result["decision"] == bool(broad.labels[i])
                    assert broad.sufficient[i] & (1 << result["mask"])
                    assert sum(result["read_order"]) == result["mask"]
                    assert result["used_fallback"] == (not restricted.active[i])
                    failed += result["used_fallback"]
            assert bool(failed) == (domain != "cartesian")


def test_exact_clock_and_invalid_domain_edges():
    raw = {"activities": ["create", "receive", "create"], "profile": "Consignment",
           "first_times": {"create": "2020-01-01t01:00:00.00000000000000000000000000001z",
                           "receive": "2020-01-01T02:00:00+01:00"}}
    assert not reference_domain_contains(raw, "chronological")
    raw["first_times"]["receive"] = "2020-01-01T02:00:00.00000000000000000000000000001+01:00"
    assert reference_domain_contains(raw, "chronological")
    with pytest.raises(ValueError):
        domain_contains(State((), (), 0), "empirical_support")
    with pytest.raises(ValueError):
        DomainCertificateTable((State((), (), 0),), [2], "cartesian")
