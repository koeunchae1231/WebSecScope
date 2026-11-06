"""Independent content and failure regression cases, separate from v1 fixtures."""
from email.message import Message
from io import BytesIO
from unittest.mock import patch

import pytest

from websecscope.models import FAIL, PASS, WARNING
from websecscope.scanner import web


def response(status=200, body="", error=None, location=None):
    return dict(status=status, body_sample=body, error=error, location=location, headers={})


def scan(monkeypatch, path, head, get, controls=None):
    monkeypatch.setattr(web, 'SENSITIVE_PATHS', [path])
    controls = controls or [response(body='<html>home</html>'), response(404, 'missing')]
    calls = []
    def request(url, method='HEAD', follow_redirects=True):
        calls.append((url, method, follow_redirects))
        # Route by request identity, so legitimate conditional ordering is testable.
        if url == 'http://127.0.0.1/':
            return controls[0]
        if '.websecscope-not-found-' in url:
            return controls[1]
        return head if method == 'HEAD' else get
    monkeypatch.setattr(web, '_request', request)
    return web._scan_sensitive_paths('http://127.0.0.1/')[0], calls


@pytest.mark.parametrize('path,body', [
    ('.env', 'export DATABASE_URL=postgresql://readonly:example@db/app\n'),
    ('.git/HEAD', 'ref: refs/heads/release/2027\n'),
    ('.git/HEAD', 'ab'*20+'\n'),
    ('backup.zip', 'PK\x03\x04\x14\x00archive'),
    ('phpinfo.php', '<html><h1>PHP Version 8.4</h1>phpinfo()</html>'),
])
def test_get_resource_signatures_confirm_exposure_even_after_head_404(monkeypatch, path, body):
    finding, calls = scan(monkeypatch, path, response(404), response(body=body))
    assert finding.status == FAIL
    assert finding.metadata['paths'][0]['head_get_differ']
    assert finding.metadata['paths'][0]['head']['status'] == 404
    assert finding.metadata['paths'][0]['get']['status'] == 200
    assert all(not follow for _, _, follow in calls)
    assert 'readonly:example' not in finding.evidence


@pytest.mark.parametrize('path,body', [
    ('admin', '<html><form>Administrator sign in</form></html>'),
    ('.env', 'Welcome to our public download area'),
    ('.git/HEAD', '<html>ref: refs/heads/main</html>'),
    ('backup.zip', 'This is a public archive description'),
    ('phpinfo.php', '<html>PHP Version information is unavailable</html>'),
])
def test_success_without_resource_evidence_is_review(monkeypatch, path, body):
    finding, _ = scan(monkeypatch, path, response(), response(body=body))
    assert finding.status == WARNING
    assert finding.metadata['paths'][0]['outcome'] == 'unconfirmed'


def test_catch_all_html_requires_two_matching_controls(monkeypatch):
    shell = '<!doctype html><html><body><script src="/app.js"></script></body></html>'
    finding, _ = scan(monkeypatch, 'admin', response(), response(body=shell), [response(body=shell), response(body=shell)])
    assert finding.status == PASS
    assert finding.metadata['paths'][0]['outcome'] == 'spa'
    finding, _ = scan(monkeypatch, 'admin', response(), response(body=shell), [response(body=shell), response(404)])
    assert finding.status == WARNING


def test_public_key_value_catch_all_is_not_confirmed_env(monkeypatch):
    value = 'PUBLIC_VERSION=2027.1'
    finding, _ = scan(monkeypatch, '.env', response(), response(body=value), [response(body=value), response(body=value)])
    assert finding.status == WARNING


@pytest.mark.parametrize('head_code,get_code,expected', [(200,404,PASS),(405,410,PASS),(404,401,WARNING),(200,503,WARNING),(200,307,WARNING),(200,206,WARNING)])
def test_get_status_controls_classification(monkeypatch, head_code, get_code, expected):
    finding, _ = scan(monkeypatch, '.env', response(head_code), response(get_code, location='/sign-in' if get_code==307 else None))
    assert finding.status == expected
    if get_code == 307:
        assert finding.metadata['paths'][0]['get']['location'] == '/sign-in'


@pytest.mark.parametrize('head_error,get_error', [(None,'TimeoutError: read failed'),('URLError: connection reset',None),('OSError: refused','OSError: refused')])
def test_request_errors_never_become_a_clean_pass(monkeypatch, head_error, get_error):
    finding, _ = scan(monkeypatch, '.env', response(None if head_error else 404,error=head_error), response(None if get_error else 404,error=get_error))
    assert finding.status == WARNING
    assert finding.metadata['complete'] is False
    assert 'error=' in finding.evidence


def test_control_failure_retains_incomplete_observation(monkeypatch):
    finding, _ = scan(monkeypatch, '.env', response(404), response(404), [response(error='TimeoutError'),response(404)])
    assert finding.status == WARNING
    assert finding.metadata['controls'][0]['error'] == 'TimeoutError'


def test_get_body_read_is_bounded_and_head_reads_no_body():
    from websecscope.response_body import BODY_LIMIT
    class Reply(BytesIO):
        status = 200
        headers = Message()
        reads = []
        def read(self, size=-1):
            self.reads.append(size)
            return super().read(size)
        read1 = read
    get_reply, head_reply = Reply(b'A'*(BODY_LIMIT+100)), Reply(b'B'*5000)
    get_reply.reads, head_reply.reads = [], []
    with patch.object(web, 'build_opener') as opener:
        opener.return_value.open.return_value = get_reply
        observed = web._request('http://127.0.0.1/', method='GET', follow_redirects=False)
        assert len(observed['body_sample']) == BODY_LIMIT
        assert sum(get_reply.reads) == BODY_LIMIT+1
        assert all(0<n<=4096 for n in get_reply.reads)
        assert observed['body_truncated']
        opener.return_value.open.return_value = head_reply
        web._request('http://127.0.0.1/', method='HEAD')
        assert head_reply.reads == []


def test_http_response_survives_body_timeout():
    class Slow(BytesIO):
        status = 200
        headers = Message()
        def read(self, size=-1):
            raise TimeoutError('slow body')
        read1 = read
    with patch.object(web, 'build_opener') as opener:
        opener.return_value.open.return_value = Slow()
        observed = web._request('http://127.0.0.1/', method='GET')
    assert observed['status'] == 200
    assert 'TimeoutError' in observed['error']
