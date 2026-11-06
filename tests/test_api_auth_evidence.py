"""Independent API/Auth boundaries, including real HTTP observations."""
import json
import threading
from contextlib import contextmanager
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from websecscope.analyzer.api_auth_analyzer import (
    _analyze_cookie_security, _analyze_cors, _analyze_endpoint_exposure, analyze_api_auth,
)
from websecscope.rules.api_evidence import response_kind
from websecscope.rules.web.cookie_values import cookie_attributes
from websecscope.scanner.api_scanner import _build_observation, request_observation, scan_api_endpoints
from websecscope.scanner.auth_scanner import scan_auth_controls
from websecscope.response_body import BODY_LIMIT


def endpoint(body='{}', status=200, path='/api/admin', headers=None, cookies=()):
    h = Message()
    for k, v in (headers or {}).items():
        h[k] = v
    for cookie in cookies:
        h['Set-Cookie'] = cookie
    return dict(_build_observation(status, h, body.encode(), None), path=path)


@pytest.mark.parametrize('status,body,expected', [
    (200, '{"secret":"example"}', 'FAIL'),
    (200, '{}', 'WARNING'), (200, '<html>Dashboard</html>', 'WARNING'),
    (401, '', 'PASS'), (403, '', 'PASS'), (404, '', 'PASS'),
    (500, '', 'WARNING'), (302, '', 'WARNING'),
])
def test_admin_content_and_status(status, body, expected):
    findings = _analyze_endpoint_exposure([endpoint(body, status)])
    assert findings[0].status == expected


def test_html_requires_both_public_controls():
    e = endpoint('<html><body>Welcome</body></html>')
    controls = [dict(e), dict(e)]
    assert response_kind(e, controls) == 'public_shell'
    assert response_kind(e, controls[:1]) == 'unconfirmed'
    controls[1]['body_sample'] = '<html>Missing</html>'
    assert response_kind(e, controls) == 'unconfirmed'


def test_redirect_and_failure_do_not_disclose_admin():
    for extra in ({'redirected': True}, {'error': 'TimeoutError'}, {'status_code': None}):
        e = endpoint('{"secret":"value"}')
        e.update(extra)
        assert _analyze_endpoint_exposure([e])[0].status == 'WARNING'


def test_truncated_html_cannot_establish_public_shell():
    e = endpoint('<html>' + 'x' * (BODY_LIMIT+100))
    assert e['body_truncated'] and len(e['body_sample']) == BODY_LIMIT
    assert response_kind(e, [dict(e), dict(e)]) == 'unconfirmed'


@pytest.mark.parametrize('cookies,expected', [
    (['s=x; Secure; HttpOnly; SameSite=Strict'], 'PASS'),
    (['s=secure_httponly_samesite'], 'FAIL'),
    (['s=x; secure; HTTPONLY; samesite=lax'], 'PASS'),
    (['s=x; Secure; HttpOnly; SameSite=invalid'], 'FAIL'),
    (['s=x; HttpOnly; SameSite=None'], 'FAIL'),
    (['s=x; Secure; HttpOnly; SameSite=None'], 'PASS'),
    (['s=x; Secure; HttpOnly; SameSite=Lax; SameSite=Strict'], 'WARNING'),
    (['s=x; Secure; Secure; HttpOnly; SameSite=Lax'], 'WARNING'),
    (['s=x; Secure=false; HttpOnly; SameSite=Lax'], 'WARNING'),
    (['s=x; Secure; HttpOnly; SameSite=Lax', 'other=y'], 'FAIL'),
    ([], 'PASS'),
])
def test_cookie_shared_parser(cookies, expected):
    finding = _analyze_cookie_security([endpoint(cookies=cookies)])[0]
    assert finding.status == expected
    assert [{k: v for k, v in c.items() if k != 'path'} for c in finding.metadata['cookies']] == [
        cookie_attributes(c) for c in cookies]


def test_auth_only_cookie_and_request_failure():
    auth = endpoint(path='/signin', cookies=['session=x'])
    findings = analyze_api_auth({'endpoints': []}, {'auth_paths': [auth]})
    assert next(f for f in findings if f.check_id == 'AUTH_COOKIE_ATTRIBUTES').status == 'FAIL'
    auth.update(set_cookie=[], error='TimeoutError')
    assert _analyze_cookie_security([auth])[0].status == 'WARNING'


def cors_endpoint(origin='https://trusted.example', credentials='true', private=True):
    e = endpoint('{"records":[1]}', path='/api/users', headers={
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': credentials,
        'Cache-Control': 'private' if private else 'no-cache',
    })
    return e


def reflection(private=True):
    e = cors_endpoint(private=private)
    e['cors']['origin_reflection_observed'] = True
    e['cors']['probes'] = [{'origin': origin, 'response': cors_endpoint(origin, private=private)}
                          for origin in ['https://one.example', 'https://two.example']]
    return e


def test_reflection_requires_all_conditions():
    e = reflection()
    finding = _analyze_cors([e])[0]
    assert finding.status == 'FAIL'
    assert finding.metadata['browser_exploitation_verified'] is False
    assert _analyze_cors([reflection(private=False)])[0].status == 'WARNING'
    e['cors']['probes'].pop()
    assert _analyze_cors([e])[0].status == 'WARNING'


@pytest.mark.parametrize('change', ['error', 'credentials', 'redirect', 'status', 'origin'])
def test_failed_or_nonqualifying_reflection(change):
    e = reflection()
    p = e['cors']['probes'][1]['response']
    if change == 'error':
        p['error'] = 'TimeoutError'
    elif change == 'credentials':
        p['cors']['access_control_allow_credentials'] = 'True'
    elif change == 'redirect':
        p['redirected'] = True
    elif change == 'status':
        p['status_code'] = 403
    else:
        p['cors']['access_control_allow_origin'] = 'https://trusted.example'
    assert _analyze_cors([e])[0].status == 'WARNING'


def test_wildcard_defect_and_public_policy():
    f = _analyze_cors([cors_endpoint('*')])[0]
    assert f.status == 'FAIL'
    assert 'block credentialed' in f.metadata['description']
    e = cors_endpoint('*', '', False)
    assert _analyze_cors([e])[0].status == 'WARNING'
    e['headers']['Cache-Control'] = 'public, max-age=60'
    assert _analyze_cors([e])[0].status == 'PASS'
    e['error'] = 'TimeoutError'
    assert _analyze_cors([e])[0].status == 'WARNING'


@contextmanager
def server(mode):
    events = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            events.append((self.path, self.headers.get('Origin')))
            status, body, headers = 404, 'missing', {}
            if mode == 'spa':
                status, body = 200, '<html><body>Public application</body></html>'
            elif self.path in {'/admin', '/api/admin'}:
                if mode == 'private':
                    status, body = 200, json.dumps({'confidential': ['record']})
                elif mode == 'unknown':
                    status, body = 200, '<html>Console</html>'
                elif mode == 'redirect':
                    status, headers = 302, {'Location': '/login'}
                elif mode in {'401', '403'}:
                    status = int(mode)
            elif self.path == '/api/users' and mode.startswith('reflect'):
                status, body = 200, '{"records":[1]}'
                headers = {'Access-Control-Allow-Origin': self.headers.get('Origin', 'https://trusted.example'),
                           'Access-Control-Allow-Credentials': 'true'}
                if mode == 'reflect-private':
                    headers['Cache-Control'] = 'private'
            elif self.path == '/signin' and mode == 'cookie':
                status, headers = 200, {'Set-Cookie': 'sid=value; Secure; HttpOnly; SameSite=wrong'}
            elif self.path == '/login':
                status, body = 200, '<html>Sign in</html>'
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=http.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{http.server_port}/', events
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


@pytest.mark.parametrize('mode,expected', [('spa','PASS'), ('private','FAIL'), ('unknown','WARNING'),
                                         ('redirect','WARNING'), ('401','PASS'), ('403','PASS')])
def test_local_admin(mode, expected):
    with server(mode) as (url, events):
        api = scan_api_endpoints(url)
    admin = [e for e in api['endpoints'] if 'admin' in e['path']]
    assert _analyze_endpoint_exposure(admin)[0].status == expected
    assert len(api['controls']) == (2 if mode in {'spa', 'unknown'} else 0)


@pytest.mark.parametrize('mode,expected', [('reflect-private','FAIL'), ('reflect-generic','WARNING')])
def test_local_cors(mode, expected):
    with server(mode) as (url, events):
        api = scan_api_endpoints(url)
    assert _analyze_cors(api['endpoints'])[0].status == expected
    assert len({origin for path, origin in events if path == '/api/users' and origin}) == 2


def test_local_auth_cookie():
    with server('cookie') as (url, events):
        api = scan_api_endpoints(url)
        auth = scan_auth_controls(url, api)
    findings = analyze_api_auth(api, auth)
    assert next(f for f in findings if f.check_id == 'AUTH_COOKIE_ATTRIBUTES').status == 'FAIL'


def test_request_deadline_and_failed_cors(monkeypatch):
    import websecscope.scanner.api_scanner as scanner
    def timeout(*args, **kwargs):
        raise TimeoutError('test deadline')
    monkeypatch.setattr(scanner, 'urlopen', timeout)
    e = request_observation('http://127.0.0.1:1/')
    assert e['status_code'] is None and 'TimeoutError' in e['error']
    assert _analyze_cors([dict(e, path='/api')])[0].status == 'WARNING'
