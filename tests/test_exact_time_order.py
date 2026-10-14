"""Regressions for shared-parser errors missed by v1 differential tests."""
import pytest
from logistics_validation.model import Case, Event, uri, timestamp_key
from logistics_validation.constraints import indexed_issues, SchemaChecker
from logistics_validation.baselines import sql_issues

@pytest.mark.parametrize('a,b,inverted', [
 ('2020-01-01t00:00:02z','2020-01-01t00:00:01z',True),
 ('2020-01-01T00:00:00.000000002Z','2020-01-01T00:00:00.000000001Z',True),
 ('2020-01-01T00:00:00.000000000000000000000000000002Z','2020-01-01T00:00:00.000000000000000000000000000001Z',True),
 ('2020-01-01T09:00:00+09:00','2020-01-01T00:00:00Z',False),
 ('2020-01-02T01:00:00+02:00','2020-01-01T23:00:00Z',False),
 ('1969-12-31T23:59:59.100Z','1969-12-31T23:59:59.1Z',False),
 ('2020-01-01T00:00:00.1Z','2020-01-01T00:00:00.100000001Z',False),
])
def test_valid_timestamp_forms_preserve_exact_order(a,b,inverted):
    obj=uri('object','case')
    c=Case('time','synthetic','test','test','test',
           [Event(uri('event','a'),obj,'a',a),Event(uri('event','b'),obj,'b',b)],
           [('a','b')],['a','b'],{'object_id':obj})
    assert SchemaChecker().valid(c)
    assert ('time_precedence' in indexed_issues(c)) is inverted
    assert ('time_precedence' in sql_issues([c])[c.case_id]) is inverted

def test_normalization_same_instants_are_identical():
    assert timestamp_key('1969-12-31T23:59:59.1Z')==timestamp_key('1970-01-01T08:59:59.100000+09:00')
    assert timestamp_key('2020-01-01T00:00:00Z')==timestamp_key('2020-01-01t00:00:00.000z')

def test_empty_reference_is_absent_under_nonempty_reference_contract():
    from logistics_validation.declarative_baseline import mp_declare_issues
    obj=uri('object','emptyref')
    c=Case('emptyref','synthetic','test','test','test',
           [Event(uri('event','e1'),obj,'a','2020-01-01T00:00:00Z'),
            Event(uri('event','e2'),obj,'b','2020-01-01T00:00:01Z',ref='')],
           [('a','b')],['a','b'],{'object_id':obj})
    assert SchemaChecker().valid(c)
    assert indexed_issues(c)==sql_issues([c])[c.case_id]==set()
    assert mp_declare_issues([c],'full')[c.case_id]==set()
