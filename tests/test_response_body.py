from contextlib import contextmanager
from email.message import Message
import gzip
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from io import BytesIO
import json
import threading
import time

import pytest

from websecscope.response_body import BODY_LIMIT,inspect_body,read_body
from websecscope.scanner.api_scanner import _build_observation,request_observation
from websecscope.scanner.web import _classify_sensitive_response,_request
from websecscope.rules.api_evidence import response_kind,public_response


@pytest.mark.parametrize('raw,headers,detected,parse_error,mismatch',[
    (b'{"ok":true}',{'Content-Type':'application/json; charset=UTF-8'},'json',False,False),
    (b'{bad',{'Content-Type':'application/json'},'json',True,False),
    (b'<html><body>OK</body></html>',{'Content-Type':'text/html'},'html',False,False),
    (b'plain text',{'Content-Type':'text/plain'},'text',False,False),
    (b'{"ok":true}',{},'json',False,False),
    (b'{"ok":true}',{'Content-Type':'text/plain'},'json',False,True),
    (b'<html>OK</html>',{'Content-Type':'application/json'},'html',False,True),
    (b'\x89PNG\x00',{'Content-Type':'image/png'},'unsupported',False,False),
    (b'\xef\xbb\xbf{"ok":true}',{},'json',False,False),
])
def test_formats_are_recorded_not_silently_assumed(raw,headers,detected,parse_error,mismatch):
    e=inspect_body(raw,headers)['body_evidence']
    assert e['detected_format']==detected
    assert bool(e['parse_error'])==parse_error
    assert e['content_type_mismatch']==mismatch


def test_declared_charset_decode_errors_and_unknown_encodings():
    r=inspect_body('café'.encode('latin-1'),{'Content-Type':'text/plain; charset=iso-8859-1'})
    assert r['body_sample']=='café' and not r['body_evidence']['decode_error']
    for raw,ct in [(b'\xffbad','text/plain; charset=utf-8'),(b'text','text/plain; charset=not-a-codec')]:
        r=inspect_body(raw,{'Content-Type':ct})
        assert r['body_evidence']['decode_error']
        assert not r['body_evidence']['supported_for_text_analysis']


class Reply(BytesIO):
    def __init__(self,raw,headers=None):super().__init__(raw);self.headers=headers or Message();self.sizes=[]
    def read1(self,n):self.sizes.append(n);return super().read(n)


@pytest.mark.parametrize('size',[0,BODY_LIMIT-1,BODY_LIMIT,BODY_LIMIT+1,BODY_LIMIT*4])
def test_body_limits_exact_eof_and_lookahead(size):
    reply=Reply(b'x'*size)
    result=read_body(reply)
    assert len(result['body_sample'])==min(size,BODY_LIMIT)
    assert result['body_truncated']==(size>BODY_LIMIT)
    assert result['body_evidence']['complete']==(size<=BODY_LIMIT)
    assert result['body_evidence']['bytes_read']<=BODY_LIMIT+1
    assert all(0<n<=4096 for n in reply.sizes)
    head=Reply(b'x'*100)
    assert not read_body(head,'HEAD')['body_evidence']['collected'] and not head.sizes


def test_partial_read_failure_retains_body_and_marks_incomplete():
    class Partial(Reply):
        def read1(self,n):
            if self.tell():raise TimeoutError('stall')
            return super().read1(n)
    r=read_body(Partial(b'known prefix'))
    assert r['body_sample']=='known prefix'
    assert r['error'] and not r['body_evidence']['complete']


def test_streaming_deadline_is_not_reset_per_chunk(monkeypatch):
    clock=[0]
    monkeypatch.setattr('websecscope.response_body.time.monotonic',lambda:clock[0])
    class Streaming(Reply):
        def read1(self,n):clock[0]+=.4;return b'x'
    r=read_body(Streaming(b''))
    assert r['error'] and clock[0]<1.7
    assert r['body_evidence']['bytes_read']<10


def test_compression_is_explicitly_unsupported_and_bounded():
    h=Message();h['Content-Type']='application/json';h['Content-Encoding']='gzip'
    r=read_body(Reply(gzip.compress(b'{"secret":"value"}'),h))
    assert r['body_evidence']['unsupported_content_encoding']
    assert not r['body_evidence']['supported_for_text_analysis']
    assert not public_response(dict(r,headers={'Cache-Control':'public'}))


@pytest.mark.parametrize('path,body,expected',[
    ('.env','{"database":{"username":"billing","password":"concrete-credential"}}','exposed'),
    ('.env','{"smtp":{"user":"sender","token":"active-credential"}}','exposed'),
    ('.env','{"examples":[{"database":{"username":"billing","password":"example"}}]}','unconfirmed'),
    ('.env','{"database":{"username":"billing","password":"REDACTED"}}','unconfirmed'),
    ('.env','{"secret":"mention-only"}','unconfirmed'),
    ('phpinfo.php','<html><title>PHP runtime diagnostics</title><table><tr><td>DB_PASSWORD</td><td>concrete-credential</td></tr></table></html>','exposed'),
    ('phpinfo.php','<html><title>PHP diagnostics reference</title><table><tr><td>DB_PASSWORD</td><td>concrete-credential</td></tr></table></html>','unconfirmed'),
    ('phpinfo.php','<html><title>PHP diagnostics</title><table><tr><td>DB_PASSWORD</td><td>REDACTED</td></tr></table></html>','unconfirmed'),
    ('phpinfo.php','<html><title>PHP diagnostics</title><pre><table><tr><td>DB_PASSWORD</td><td>value</td></tr></table></pre></html>','unconfirmed'),
    ('admin','<html>Customer invoice</html>','unconfirmed'),
])
def test_specific_structures_not_keywords(path,body,expected):
    r=dict(status=200,**inspect_body(body.encode(),{}))
    assert _classify_sensitive_response(path,r,[])[0]==expected


def test_truncated_json_and_equal_html_never_establish_safety():
    raw=b'{"database":{"username":"billing","password":"'+b'x'*BODY_LIMIT
    r=dict(status=200,**inspect_body(raw,{}))
    assert _classify_sensitive_response('.env',r,[])[0]=='unconfirmed'
    raw=b'<html>'+b'x'*BODY_LIMIT
    r=dict(status=200,status_code=200,**inspect_body(raw,{}))
    assert _classify_sensitive_response('admin',r,[dict(r),dict(r)])[0]=='unconfirmed'
    assert response_kind(r,[dict(r),dict(r)])=='unconfirmed'


def test_positive_prefix_is_distinct_from_absence_in_partial_body():
    raw=b'<html><title>PHP diagnostics</title><table><tr><td>AUTH_SECRET</td><td>concrete-value</td></tr></table>'+b'x'*BODY_LIMIT
    r=dict(status=200,**inspect_body(raw,{}))
    assert r['body_truncated']
    assert _classify_sensitive_response('phpinfo.php',r,[])[0]=='exposed'
    r=dict(status=200,**inspect_body(b'PK\x03\x04'+b'x'*BODY_LIMIT,{'Content-Type':'application/zip'}))
    assert _classify_sensitive_response('backup.zip',r,[])[0]=='exposed'


def test_duplicate_headers_and_status_evidence_preserved():
    h=Message();h['Set-Cookie']='a=1; Secure';h['Set-Cookie']='b=2; HttpOnly'
    h['Content-Type']='application/json';h['Content-Type']='text/plain'
    r=_build_observation(403,h,b'{"problem":"denied"}',None)
    assert r['status_code']==403 and len(r['set_cookie'])==2
    assert len([p for p in r['headers_list'] if p[0]=='Content-Type'])==2
    assert len(r['body_evidence']['content_type_values'])==2
    assert r['body_evidence']['content_type_conflict']


@contextmanager
def service():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_GET(self):
            if self.path=='/redirect':
                self.send_response(302);self.send_header('Location','/final');self.end_headers();return
            status=int(self.path.lstrip('/')) if self.path.lstrip('/').isdigit() else 200
            body=json.dumps({'route':self.path}).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{server.server_port}'
    finally:server.shutdown();server.server_close();thread.join()


def test_real_http_status_redirect_and_request_isolation():
    with service() as base:
        observations=[request_observation(base+'/'+str(s)) for s in (200,401,403,404,500)]
        assert [r['status_code'] for r in observations]==[200,401,403,404,500]
        assert len({r['body_sample'] for r in observations})==5
        r=request_observation(base+'/redirect')
        assert r['redirected'] and r['final_url']==base+'/final'
        assert r['redirect_observation']['initial_status'] is None
        r=_request(base+'/redirect',method='GET',follow_redirects=False)
        assert r['status']==302 and r['initial_status']==302 and r['location']=='/final'


def test_completed_large_response_still_needs_private_context():
    from websecscope.analyzer.api_auth_analyzer import _analyze_endpoint_exposure
    body='<html>'+('<!-- padding -->'*400)+'<p>Private employee salary: 74000</p></html>'
    r=_build_observation(200,{},body.encode(),None)
    assert not r['body_truncated'] and len(r['body_sample'])>4096
    r.update(path='/admin')
    assert _analyze_endpoint_exposure([r])[0].status=='WARNING'
