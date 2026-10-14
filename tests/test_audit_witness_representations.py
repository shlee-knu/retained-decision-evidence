"""Portable witnesses must allow concrete unread clocks while preserving evidence."""
from copy import deepcopy

import pytest

from logistics_validation.audit_report import digest, make_bundle, verify_bundle
from logistics_validation.catalog_audit import BASELINE, PROFILES, catalog_json, generated_catalogs
from logistics_validation.focused_diagnostics import Problem


def bundle_for(domain='cartesian:v1', observed=None):
    target = next(catalog for name, catalog, _ in generated_catalogs() if name == 'required_p2_a3')
    observed = observed or {}
    receipt = {
        'schema_version': 1, 'receipt_id': 'authored-witness-boundary',
        'snapshot_sha256': 'a' * 64, 'catalog_sha256': digest(catalog_json(BASELINE)),
        'domain_version': domain, 'activities': ['create', 'invoice', 'create'],
        'observed': observed, 'verdict': False,
    }
    from logistics_validation.audit_report import receipt_query
    return make_bundle([{'problem': Problem('procurement_required_p2_a3', target),
                         'receipt': receipt, 'query': receipt_query(receipt),
                         'old_domain': domain, 'new_domain': domain,
                         'request_id': 'alpha:witness-boundary'}])


def reseal(bundle):
    report = bundle['reports'][0]
    report['report_sha256'] = digest({k: v for k, v in report.items() if k != 'report_sha256'})
    bundle['bundle_sha256'] = digest({k: v for k, v in bundle.items() if k != 'bundle_sha256'})


@pytest.mark.parametrize('domain', ['cartesian:v1', 'chronological:v1', 'consignment_exclusion:v1', 'both:v1'])
@pytest.mark.parametrize('form', ['different_year', 'equivalent_zone', 'different_gaps'])
def test_supported_unread_clock_representations_are_admitted(domain, form):
    bundle = bundle_for(domain)
    original = deepcopy(bundle)
    for witness in bundle['reports'][0]['labeled_witnesses']:
        for name, stamp in witness['raw']['first_times'].items():
            rank = int(stamp[-3:-1])
            if form == 'different_year':
                replacement = stamp.replace('2020-', '2021-', 1)
            elif form == 'equivalent_zone':
                replacement = f'2020-01-01T09:00:{rank:02d}+09:00'
            else:
                replacement = f'2031-08-10T13:24:{rank * 7:02d}.12300000000001Z'
            witness['raw']['first_times'][name] = replacement
    reseal(bundle)
    assert bundle != original
    assert verify_bundle(bundle)['status'] == 'passed'
    # An independently retained old digest still rejects a changed bundle.
    with pytest.raises(ValueError, match='external bundle digest mismatch'):
        verify_bundle(bundle, expected_sha256=original['bundle_sha256'])


def test_literal_retained_clock_cannot_be_reformatted_even_at_the_same_instant():
    observed = {'first_times': {'create': '2020-01-01T00:00:00Z', 'invoice': '2020-01-01T00:00:01Z'}}
    bundle = bundle_for(observed=observed)
    bundle['reports'][0]['labeled_witnesses'][0]['raw']['first_times']['create'] = '2020-01-01T09:00:00+09:00'
    reseal(bundle)
    with pytest.raises(ValueError, match='witness does not preserve observations/domain'):
        verify_bundle(bundle)


@pytest.mark.parametrize('mutate', [
    lambda raw: raw['activities'].pop(),  # same first-occurrence abstraction, different visible source sequence
    lambda raw: raw['activities'].append('invoice'),
    lambda raw: raw['activities'].__setitem__(slice(0, 2), ['invoice', 'create']),
])
def test_complete_repeated_activity_sequence_is_literal(mutate):
    bundle = bundle_for()
    mutate(bundle['reports'][0]['labeled_witnesses'][0]['raw'])
    reseal(bundle)
    with pytest.raises(ValueError, match='witness does not preserve observations/domain'):
        verify_bundle(bundle)


@pytest.mark.parametrize('mutate', [
    lambda raw: raw['first_times'].pop('invoice'),
    lambda raw: raw['first_times'].update(clear='2020-01-01T00:00:03Z'),
    lambda raw: raw['first_times'].update(create='not-a-clock'),
    lambda raw: raw['first_times'].update(create='2020-01-01T00:00:60Z'),
    lambda raw: raw['first_times'].update(create='2020-01-01T00:00:00-00:00'),
    lambda raw: raw.update(profile='unsupported-profile'),
    lambda raw: raw.update(undeclared_field='hidden'),
])
def test_unsupported_raw_witness_values_remain_rejected(mutate):
    bundle = bundle_for()
    mutate(bundle['reports'][0]['labeled_witnesses'][0]['raw'])
    reseal(bundle)
    with pytest.raises(ValueError):
        verify_bundle(bundle)


def test_unread_change_that_invalidates_claimed_label_is_rejected():
    bundle = bundle_for()
    witness = next(w for w in bundle['reports'][0]['labeled_witnesses'] if w['new_verdict'])
    witness['raw']['first_times'] = {'create': '2024-01-01T00:00:01Z', 'invoice': '2024-01-01T00:00:00Z'}
    reseal(bundle)
    with pytest.raises(ValueError, match='raw witness label mismatch'):
        verify_bundle(bundle)


def test_new_domain_membership_is_required_even_when_labels_still_match():
    bundle = bundle_for('chronological:v1')
    witness = next(w for w in bundle['reports'][0]['labeled_witnesses'] if not w['new_verdict'])
    witness['raw']['first_times'] = {'create': '2024-01-01T00:00:01Z', 'invoice': '2024-01-01T00:00:00Z'}
    reseal(bundle)
    with pytest.raises(ValueError, match='witness does not preserve observations/domain'):
        verify_bundle(bundle)


def test_retained_profile_is_not_replaceable_by_a_same_label_profile():
    bundle = bundle_for(observed={'profile': PROFILES[0]})
    assert bundle['reports'][0]['status'] == 'safe'
    bundle['reports'][0]['labeled_witnesses'][0]['raw']['profile'] = PROFILES[1]
    reseal(bundle)
    with pytest.raises(ValueError, match='witness does not preserve observations/domain'):
        verify_bundle(bundle)
