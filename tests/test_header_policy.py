"""Semantic unit boundaries; no new evaluation corpus or fixture truth."""
from email.message import Message

import pytest

from websecscope.rules.web.header_policy import assess_header
from websecscope.scanner.web import _policy_fields, _scan_security_headers


@pytest.mark.parametrize('value,status', [
    ("default-src 'self'", 'PASS'),
    ("default-src * data: 'unsafe-inline' 'unsafe-eval'", 'FAIL'),
    ("default-src 'none'; script-src 'self' 'unsafe-inline'", 'WARNING'),
    ("default-src 'none'; script-src 'self' 'unsafe-eval'", 'WARNING'),
    ("default-src 'none'; script-src 'nonce-YWJjZA==' 'unsafe-inline'", 'PASS'),
    ("default-src 'none'; script-src 'sha256-YWJjZA==' 'unsafe-inline'", 'PASS'),
    ("default-src 'none'; script-src 'nonce-YWJjZA==' 'strict-dynamic' https:", 'PASS'),
    ("object-src 'none'", 'WARNING'),
    ("script-src-elem 'none'; object-src 'none'", 'WARNING'),
    ("default-src *; script-src-elem 'none'", 'WARNING'),
    ("default-src 'none'; script-src-elem 'self'", 'PASS'),
    ("default-src 'none'; base-uri *", 'WARNING'),
    ("default-src 'none'; script-src *; script-src 'none'", 'WARNING'),
    ("default-src * 'unsafe-inline' 'unsafe-eval'; sandbox", 'WARNING'),
    ("default-src 'bogus'", 'WARNING'),
    ("default-src 'self", 'FAIL'),
    ("default-src 'none'; unknown-future on", 'WARNING'),
    ('', 'WARNING'),
])
def test_csp_effective_meaning(value, status):
    assert assess_header('content-security-policy', [value])['status'] == status


def test_csp_multiple_fields_are_conjunctive_not_last_wins():
    weak = "default-src * 'unsafe-inline' 'unsafe-eval'"
    strong = "default-src 'none'"
    for values in ([weak, strong], [strong, weak], [weak + ', ' + strong]):
        result = assess_header('content-security-policy', values)
        assert result['status'] == 'PASS'
        assert not any(result['joint'].values())


def test_report_only_does_not_restrict_enforcing_policy():
    result = assess_header('content-security-policy',
                           ["default-src * 'unsafe-inline' 'unsafe-eval'"], ["default-src 'none'"])
    assert result['status'] == 'FAIL'
    assert result['report_only_enforced'] is False
    assert assess_header('content-security-policy', [], ["default-src 'none'"])['status'] == 'WARNING'


def test_script_element_does_not_control_eval():
    result = assess_header('content-security-policy', ["script-src 'unsafe-eval'; script-src-elem 'none'; object-src 'none'"])
    assert result['effective'][0]['eval_allowed']
    assert result['effective'][0]['script_element']['directive'] == 'script-src-elem'
    assert result['status'] == 'WARNING'


@pytest.mark.parametrize('value,status', [
    ('no-referrer', 'PASS'), ('same-origin', 'PASS'), ('strict-origin', 'PASS'),
    ('strict-origin-when-cross-origin', 'PASS'), ('origin', 'WARNING'),
    ('origin-when-cross-origin', 'WARNING'), ('no-referrer-when-downgrade', 'WARNING'),
    ('unsafe-url', 'WARNING'), ('unknown', 'FAIL'), ('', 'WARNING'),
    ('unsafe-url, future, No-Referrer', 'PASS'), ('no-referrer, unsafe-url', 'WARNING'),
])
def test_referrer_selection_and_exposure(value, status):
    result = assess_header('referrer-policy', [value])
    assert result['status'] == status
    assert not result['browser_enforcement_verified']


@pytest.mark.parametrize('value,status', [
    ('camera=(), microphone=(), geolocation=()', 'PASS'),
    ('camera=(self)', 'PASS'), ('camera=("https://video.example")', 'PASS'),
    ('camera=*', 'WARNING'), ('microphone=*', 'WARNING'), ('geolocation=*', 'WARNING'),
    ('fullscreen=*', 'PASS'), ('future-feature=()', 'WARNING'),
    ('camera=denied', 'FAIL'), ('camera=(', 'FAIL'), ('', 'WARNING'),
    ('camera=(), camera=*', 'WARNING'), ('camera=("https://video.example/path")', 'WARNING'),
])
def test_feature_specific_permissions(value, status):
    result = assess_header('permissions-policy', [value])
    assert result['status'] == status
    assert not result.get('permission_grant_verified', False)


def test_repeated_http_fields_survive_scanner_connection():
    message = Message()
    message['Content-Security-Policy'] = "default-src 'none'"
    message['Content-Security-Policy'] = "default-src * 'unsafe-inline' 'unsafe-eval'"
    message['Content-Security-Policy-Report-Only'] = "default-src 'none'"
    fields = _policy_fields(message)
    findings = _scan_security_headers(dict((k.lower(), v) for k, v in message.items()),
                                      header_fields=fields)
    finding = next(f for f in findings if f.check_id == 'WEB_HEADER_CONTENT_SECURITY_POLICY')
    assert finding.status == 'PASS'
    assert len(finding.metadata['header_values']) == 2
    assert finding.metadata['policy_analysis']['report_only_count'] == 1


def test_analysis_limits_defer_without_certifying_safety():
    assert assess_header('content-security-policy', ['x' * 16385])['status'] == 'WARNING'

