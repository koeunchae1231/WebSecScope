"""P0 branches preserve uncertainty and existing HTTP request budgets."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from websecscope.analyzer.api_auth_analyzer import _analyze_auth_access, _analyze_cors
from websecscope.scanner.api_scanner import scan_api_endpoints


def endpoint(status=200, origin=None, credentials=None, **extra):
    return dict(path='/api/users', status_code=status, body_sample='{"rows":[]}', headers={}, error=None,
                cors={'access_control_allow_origin':origin,'access_control_allow_credentials':credentials}, **extra)


@pytest.mark.parametrize('status,expected', [(404,'WARNING'),(401,'PASS'),(403,'PASS'),(200,'WARNING')])
def test_auth_candidate_status(status, expected):
    result=_analyze_auth_access([endpoint(status)])[0]
    assert result.status==expected
    assert f'HTTP {status}' in result.evidence
    if status==404:
        assert result.check_id=='AUTH_MAY_BE_MISSING_API_USERS'
        assert result.metadata['authentication_assessed'] is False
        assert result.metadata['http_status']==404
        assert result.metadata['reason_code']=='NOT_FOUND_AUTH_UNASSESSED'
        assert 'does not establish' in result.metadata['description']


@pytest.mark.parametrize('path', ['/api','/api/admin','/admin'])
def test_all_existing_auth_candidates_emit_404_observation(path):
    e=endpoint(404)
    e['path']=path
    result=_analyze_auth_access([e])
    assert len(result)==1 and result[0].status=='WARNING'
    assert result[0].metadata['path']==path


def test_non_candidate_still_excluded():
    e=endpoint(404)
    e['path']='/assets/icon.svg'
    assert _analyze_auth_access([e])==[]


@pytest.mark.parametrize('credentials', [None,'true','false'])
def test_literal_null_requires_review_without_disclosure_claim(credentials):
    finding=_analyze_cors([endpoint(origin='null',credentials=credentials)])[0]
    assert finding.check_id=='CORS_NULL_ORIGIN_API_USERS'
    assert finding.status=='WARNING'
    assert finding.metadata['allow_origin']=='null'
    assert finding.metadata['null_origin_request_observed'] is False
    assert finding.metadata['browser_exploitation_verified'] is False
    assert 'does not establish private-data disclosure' in finding.metadata['description']


def test_absent_allow_origin_is_not_literal_null():
    finding=_analyze_cors([endpoint()])[0]
    assert finding.check_id=='CORS_BASELINE' and finding.status=='PASS'


def test_recorded_null_probe_is_not_browser_verification():
    e=endpoint(origin='null',credentials='true')
    e['cors']['probes']=[{'origin':'null','response':endpoint(origin='null')}]
    f=_analyze_cors([e])[0]
    assert f.status=='WARNING'
    assert f.metadata['tested_request_origins']==['null']
    assert f.metadata['null_origin_request_observed'] is True
    assert f.metadata['browser_exploitation_verified'] is False


def test_literal_null_branch_cannot_be_hidden_by_reflection_flag():
    e=endpoint(origin='null',credentials='true')
    e['cors']['origin_reflection_observed']=True
    assert _analyze_cors([e])[0].check_id=='CORS_NULL_ORIGIN_API_USERS'


def test_null_review_coexists_with_other_cors_findings():
    null=endpoint(origin='null')
    null['path']='/api'
    findings=_analyze_cors([null,endpoint(origin='*',credentials='true')])
    assert [(f.check_id,f.status) for f in findings]==[
        ('CORS_NULL_ORIGIN_API','WARNING'),('CORS_WILDCARD_WITH_CREDENTIALS_API_USERS','FAIL')]


@contextmanager
def service(mode):
    events=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            events.append((self.path,self.headers.get('Origin')))
            active=self.path=='/api/users'
            self.send_response(200 if active else 404)
            if active:
                if mode=='null':
                    self.send_header('Access-Control-Allow-Origin','null')
                    self.send_header('Access-Control-Allow-Credentials','true')
                elif mode=='public':
                    self.send_header('Access-Control-Allow-Origin','*')
                    self.send_header('Cache-Control','public, max-age=15')
                elif mode=='reflect':
                    self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin','https://partner.example'))
                    self.send_header('Access-Control-Allow-Credentials','true')
            body=b'{"rows":[1]}'
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    t=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
    t.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/',events
    finally:
        server.shutdown()
        server.server_close()
        t.join()


@pytest.mark.parametrize('mode,status,requests', [('null','WARNING',2),('absent','PASS',1),
                                               ('public','PASS',2),('reflect','WARNING',3)])
def test_local_origin_absence_null_reflection_and_public_policy(mode,status,requests):
    with service(mode) as (target,events):
        data=scan_api_endpoints(target)
    response=next(e for e in data['endpoints'] if e['path']=='/api/users')
    calls=[origin for path,origin in events if path=='/api/users']
    assert calls[0] is None  # No Origin request header, regardless of response ACAO.
    assert len(calls)==requests
    finding=_analyze_cors(data['endpoints'])[0]
    assert finding.status==status
    if mode=='null':
        assert response['cors']['access_control_allow_origin']=='null'
        assert 'null' not in calls  # No new literal-null request was added by P0.
        assert finding.metadata['null_origin_request_observed'] is False


def test_frozen_selector_recognizes_reused_auth_and_new_cors_category():
    import importlib.util
    from pathlib import Path
    path=Path(__file__).resolve().parents[1]/'tools/validation/independent_evaluation.py'
    spec=importlib.util.spec_from_file_location('p0_frozen_selector',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    auth=_analyze_auth_access([endpoint(404)])
    cors=_analyze_cors([endpoint(origin='null')])
    assert module.selected({'selector':'auth_access'},auth)==auth
    assert module.selected({'selector':'cors'},cors)==cors
