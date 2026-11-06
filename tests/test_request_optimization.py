"""Transport identity and lazy-control regressions beyond the fixed baseline."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from websecscope.scanner import web
from websecscope.scanner.api_scanner import request_observation


def reply(status=200, body='', error=None):
    return dict(status=status, body_sample=body, headers={}, location=None, error=error)


def test_absent_resources_keep_both_methods_without_missing_control(monkeypatch):
    calls=[]
    def request(url,method='HEAD',follow_redirects=True):
        calls.append((url,method,follow_redirects))
        return reply(body='<html>landing</html>') if url.endswith('/') else reply(404)
    monkeypatch.setattr(web,'_request',request)
    finding=web._scan_sensitive_paths('http://127.0.0.1/')[0]
    assert finding.status=='PASS'
    assert len(calls)==11  # root GET + five independent HEAD/GET observations
    assert not finding.metadata['missing_control_requested']
    assert all(not follow for _,_,follow in calls)
    assert all(p['head']['status']==p['get']['status']==404 for p in finding.metadata['paths'])


def test_spa_fetches_second_control_once_and_never_uses_head_as_get(monkeypatch):
    calls=[]
    shell='<html><body>dynamic application shell</body></html>'
    def request(url,method='HEAD',follow_redirects=True):
        calls.append((url,method))
        return reply(body=shell if method=='GET' else '')
    monkeypatch.setattr(web,'_request',request)
    finding=web._scan_sensitive_paths('http://127.0.0.1/')[0]
    assert finding.status=='PASS'
    assert len(calls)==12
    assert sum('.websecscope-not-found-' in url for url,_ in calls)==1
    assert all(p['outcome']=='spa' for p in finding.metadata['paths'])
    assert len(finding.metadata['controls'])==2


def test_missing_control_failure_is_retained_when_comparison_is_relevant(monkeypatch):
    shell='<html>same shell</html>'
    def request(url,method='HEAD',follow_redirects=True):
        return reply(error='TimeoutError: stalled') if '.websecscope-not-found-' in url else reply(body=shell if method=='GET' else '')
    monkeypatch.setattr(web,'_request',request)
    finding=web._scan_sensitive_paths('http://127.0.0.1/')[0]
    assert finding.status=='WARNING'
    assert not finding.metadata['complete']
    assert finding.metadata['controls'][1]['error']=='TimeoutError: stalled'


def test_responses_are_not_cached_across_scans_or_candidate_methods(monkeypatch):
    monkeypatch.setattr(web,'SENSITIVE_PATHS',['.env'])
    generation=[0]
    calls=[]
    def request(url,method='HEAD',follow_redirects=True):
        calls.append((url,method))
        if url.endswith('/'):
            generation[0]+=1
            return reply(body='<html>home</html>')
        return reply(200 if method=='HEAD' else 404) if generation[0]==1 else reply(404 if method=='HEAD' else 200, 'DB_PASSWORD=another_demo_value' if method=='GET' else '')
    monkeypatch.setattr(web,'_request',request)
    one=web._scan_sensitive_paths('http://127.0.0.1/')[0]
    two=web._scan_sensitive_paths('http://127.0.0.1/')[0]
    assert one.status=='PASS' and two.status=='FAIL'
    assert one.metadata['paths'][0]['head_get_differ'] and two.metadata['paths'][0]['head_get_differ']
    assert len(calls)==6


def test_real_http_origin_authorization_and_changing_responses_are_independent():
    events=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass
        def do_GET(self):
            origin=self.headers.get('Origin','none')
            auth=self.headers.get('Authorization','anonymous')
            events.append((origin,auth))
            body=f'{origin}|{auth}|{len(events)}'.encode()
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin',origin)
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        target=f'http://127.0.0.1:{server.server_port}/api/users'
        a=request_observation(target,headers={'Origin':'https://first.example'})
        b=request_observation(target,headers={'Origin':'https://second.example','Authorization':'Bearer fixture-only'})
        c=request_observation(target,headers={'Origin':'https://first.example'})
        assert a['cors']['access_control_allow_origin']=='https://first.example'
        assert b['cors']['access_control_allow_origin']=='https://second.example'
        assert 'Bearer fixture-only' in b['body_sample'] and 'anonymous' in a['body_sample']
        assert a['body_sample']!=c['body_sample']
        assert len(events)==3
    finally:
        server.shutdown()
        server.server_close()
