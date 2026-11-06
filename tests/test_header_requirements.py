from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from websecscope.policy import ScanPolicy, load_policy
from websecscope.rules.web.header_requirements import matching_rules
from websecscope.scanner.web import _scan_security_headers

URL = 'https://service.example/'
CSP = 'Content-Security-Policy'
REF = 'Referrer-Policy'
PP = 'Permissions-Policy'


def policy(rules=None, **extra):
    data = dict(policy_version=1, target_origin=URL, **extra)
    if rules is not None:
        data['header_requirements'] = rules
    return ScanPolicy(data, URL)


def rule(name=CSP, path='/', **extra):
    return dict(path=path, required_headers=[name], **extra)


def finding(name=CSP, headers=None, rules=None, **kwargs):
    values = {k.lower(): v for k, v in (headers or {}).items()}
    return next(f for f in _scan_security_headers(values, policy=policy(rules),
                initial_url=URL, **kwargs) if f.title.startswith(name))


@pytest.mark.parametrize('name', [CSP, REF, PP])
def test_required_missing_header_is_requirement_failure(name):
    f = finding(name, rules=[rule(name)])
    assert f.status == 'FAIL'
    assert f.metadata['baseline_status'] == 'WARNING'
    assert f.metadata['header_requirement_decisions'][0]['requirement_status'] == 'FAIL'
    assert 'not demonstrated exploitation' in f.evidence


@pytest.mark.parametrize('rules', [None, []])
def test_absent_optional_extension_preserves_p2_exactly(rules):
    a = _scan_security_headers({})
    b = _scan_security_headers({}, policy=policy(rules), initial_url=URL)
    assert [asdict(f) for f in a] == [asdict(f) for f in b]


@pytest.mark.parametrize('name,value', [(CSP, "default-src 'none'"), (REF, 'no-referrer'), (PP, 'camera=()')])
def test_presence_requirement_satisfied(name, value):
    f = finding(name, {name: value}, [rule(name)])
    assert f.status == 'PASS'
    d = f.metadata['header_requirement_decisions'][0]
    assert d['observed_header_values'] == [value]
    assert d['policy'][0]['policy_sha256']


@pytest.mark.parametrize('value,status', [("default-src 'none'", 'PASS'),
    ("default-src * 'unsafe-inline' 'unsafe-eval'", 'FAIL'), ("script-src 'self'", 'WARNING')])
def test_explicit_csp_strength_reuses_p2(value, status):
    f = finding(CSP, {CSP: value}, [dict(path='/', strength={CSP: 'p2-restricted-script-object'})])
    assert f.status == status


def test_presence_does_not_waive_independent_weakness():
    f = finding(PP, {PP: 'camera=*'}, [rule(PP)])
    assert f.status == 'WARNING'
    assert f.metadata['header_requirement_decisions'][0]['requirement_status'] == 'PASS'


@pytest.mark.parametrize('value,status', [('unsafe-url', 'FAIL'), ('no-referrer-when-downgrade', 'FAIL'),
    ('origin', 'PASS'), ('strict-origin', 'PASS'), ('unknown', 'FAIL'), ('', 'FAIL')])
def test_referrer_requirement_and_context_resolution(value, status):
    f = finding(REF, {REF: value}, [dict(path='/', strength={REF: 'no-cross-origin-full-url'})])
    assert f.status == status
    if value == 'origin':
        assert f.metadata['baseline_status'] == 'WARNING'


@pytest.mark.parametrize('value,status', [('camera=()', 'PASS'), ('camera=*', 'FAIL'),
    ('camera=(self)', 'FAIL'), ('microphone=()', 'WARNING'),
    ('camera=(), camera=*', 'WARNING'), ('camera=denied', 'FAIL')])
def test_explicit_camera_denial(value, status):
    f = finding(PP, {PP: value}, [dict(path='/', strength={PP: dict(deny_features=['camera'])})])
    assert f.status == status


def test_origin_scope_and_path_scope_accumulate_without_waivers():
    p = policy([dict(scope='origin', required_headers=[CSP]), rule(REF, '/account')])
    assert len(matching_rules(p, URL + 'account?unrecorded-query=1')) == 2
    assert len(matching_rules(p, URL + 'account/child')) == 1
    assert len(matching_rules(p, URL)) == 1
    assert not matching_rules(p, 'https://other.example/account')
    f = _scan_security_headers({}, policy=p, initial_url=URL + 'account')
    assert {x.title.split(' header')[0] for x in f if x.metadata.get('header_requirement_decisions')} == {CSP, REF}


@pytest.mark.parametrize('path', ['account', '//other.example/', '/a/../b', '/a%2fb', '/a?x=1', '/a#x', '/*'])
def test_invalid_paths_rejected(path):
    with pytest.raises(ValueError):
        policy([rule(path=path)])


@pytest.mark.parametrize('rules', [
    [rule('Server')], [rule('Content-Security-Policy-Report-Only')],
    [dict(path='/', required_headers=[CSP, CSP.lower()])], [rule(), rule()],
    [dict(path='/', scope='origin', required_headers=[CSP])],
    [dict(scope='all', required_headers=[CSP])], [dict(path='/')],
    [dict(path='/', strength={CSP: 'optional'})],
    [dict(path='/', strength={REF: 'unsafe-url'})],
    [dict(path='/', strength={PP: dict(deny_features=['camera'], allow_features=['camera'])})],
    [dict(path='/', strength={PP: dict(deny_features=['unknown-feature'])})],
    [dict(path='/', strength={PP: dict(deny_features=['camera', 'camera'])})],
    [dict(path='/', required_headers=False)], [dict(path='/', required_headers=[])],
    [dict(scope='origin', required_headers=[CSP]), dict(scope='origin', required_headers=[REF])],
    [dict(path='/', required_headers=[CSP], required=False)],
])
def test_bad_duplicate_or_conflicting_declarations_error(rules):
    with pytest.raises(ValueError):
        policy(rules)


def test_other_origin_policy_is_error():
    with pytest.raises(ValueError):
        ScanPolicy(dict(policy_version=1, target_origin='https://other.example/', header_requirements=[rule()]), URL)


def test_request_error_does_not_confirm_header_absence():
    f = finding(rules=[rule()], headers={CSP: "default-src 'none'"},
                get_headers={}, get_url=URL, comparison_error='timeout')
    assert f.status == 'WARNING'
    assert f.metadata['header_requirement_decisions'][1]['requirement_status'] == 'WARNING'


def test_final_response_path_cannot_satisfy_original_path_requirement():
    p = policy([rule(path='/account')])
    f = _scan_security_headers({}, policy=p, initial_url=URL + 'login', get_headers={}, get_url=URL + 'login')
    assert not any(x.metadata.get('header_requirement_decisions') for x in f)


def test_head_get_mismatch_still_requires_review():
    f = finding(REF, {REF: 'origin'}, [dict(path='/', strength={REF: 'no-cross-origin-full-url'})],
                get_headers={'referrer-policy': 'strict-origin'}, get_url=URL)
    assert f.status == 'WARNING'


def test_initial_get_and_document_get_have_distinct_decisions():
    f = finding(rules=[rule()], headers={CSP: "default-src 'none'"}, initial_method='GET',
                get_headers={}, get_url=URL)
    assert f.status == 'FAIL'
    assert [d['phase'] for d in f.metadata['header_requirement_decisions']] == ['initial', 'document']


def test_p1_cookie_and_resource_declarations_unchanged():
    data = dict(resources=[dict(path='/api-docs', visibility='public')],
                cookies=[dict(name='palette', purpose='preference', javascript_access_required=True)])
    old = policy(**data)
    new = policy([rule()], **data)
    assert old.resources == new.resources and old.cookies == new.cookies
    assert old.data == data | dict(policy_version=1, target_origin=URL)


def test_input_is_copied_and_malformed_json_rejected(tmp_path):
    rules = [rule()]
    p = policy(rules)
    rules[0]['required_headers'].clear()
    assert p.header_requirements[0]['required'] == [CSP.lower()]
    path = tmp_path / 'bad.json'
    path.write_text('{bad')
    with pytest.raises(ValueError, match='Invalid policy file'):
        load_policy(path, URL)


def test_json_html_localization_preserve_policy_interpretation():
    from websecscope.reporter.html_reporter import _finding_row
    f = finding(rules=[rule()])
    for language in ('ko', 'en'):
        payload = f.to_dict(language)
        assert payload['metadata']['finding_kind'] == 'service_requirement_assessment'
        assert 'exploitation' in payload['interpretation']
        assert 'not demonstrated exploitation' in payload['evidence']
        assert 'not demonstrated exploitation' in _finding_row(payload)
