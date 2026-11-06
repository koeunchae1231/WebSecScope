"""Boundary configurations independent of the fixed 38-case accuracy cohort."""
from email.message import Message
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading

import pytest

from websecscope.scanner import web
from websecscope.rules.web.header_values import validate_header
from websecscope.rules.web.cookie_values import cookie_attributes


@pytest.mark.parametrize('name,value,status',[
    ('x-content-type-options',' nosNIFF ','PASS'),
    ('x-content-type-options','off','FAIL'),
    ('x-frame-options','sameorigin','PASS'),
    ('x-frame-options','ALLOW-FROM https://trusted.example','FAIL'),
    ('x-frame-options','DENY, SAMEORIGIN','FAIL'),
    ('strict-transport-security','max-age="86400"; includeSubDomains','PASS'),
    ('strict-transport-security','max-age=0','FAIL'),
    ('strict-transport-security','max-age=-1','FAIL'),
    ('strict-transport-security','max-age=not-a-number','FAIL'),
    ('strict-transport-security','includeSubDomains','FAIL'),
    ('strict-transport-security','max-age=86400; max-age=42','WARNING'),
    ('strict-transport-security','max-age=42; includeSubDomains=true','FAIL'),
    ('content-security-policy',"script-src 'self'; object-src 'none'",'PASS'),
    ('content-security-policy','default-src','PASS'),
    ('content-security-policy',"script-src 'self",'FAIL'),
    ('content-security-policy','unrecognized-policy value','WARNING'),
    ('content-security-policy','report-uri /reports','WARNING'),
    ('content-security-policy',"default-src 'self'; custom-feature on",'WARNING'),
    ('content-security-policy',"script-src 'self'; script-src *",'WARNING'),
    ('content-security-policy','upgrade-insecure-requests on','FAIL'),
    ('referrer-policy','unknown-future, strict-origin','PASS'),
    ('referrer-policy','not-a-referrer-policy','FAIL'),
    ('permissions-policy','camera=(), geolocation=(self "https://maps.example")','PASS'),
    ('permissions-policy','camera=*','WARNING'),
    ('permissions-policy','camera=denied','FAIL'),
    ('permissions-policy','camera=(), camera=*','WARNING'),
])
def test_header_configuration_values(name,value,status):
    assert validate_header(name,value)[0]==status


@pytest.mark.parametrize('name',list(web.SECURITY_HEADERS))
@pytest.mark.parametrize('value',['',' \t '])
def test_all_original_headers_reject_empty_values(name,value):
    assert validate_header(name,value)[0]==('WARNING' if name in {'content-security-policy','referrer-policy','permissions-policy'} else 'FAIL')


@pytest.mark.parametrize('cookie,status',[
    ('id=opaque; Secure; HttpOnly; SameSite=Lax','PASS'),
    ('id=opaque; sECURe; HTTPONLY; samesite=nOnE','PASS'),
    ('id=opaque; Secure; HttpOnly; SameSite=Strict','PASS'),
    ('id=opaque; HttpOnly; SameSite=None','FAIL'),
    ('secure_httponly_samesite=opaque','FAIL'),
    ('id=secure_httponly_samesite','FAIL'),
    ('id=opaque; Secure; HttpOnly; SameSite=bogus','FAIL'),
    ('id=opaque; Secure; HttpOnly; SameSite','FAIL'),
    ('id=opaque; Secure; HttpOnly; SameSite=','FAIL'),
    ('id=opaque; Secure; HttpOnly; SameSite=Lax; SameSite=Strict','WARNING'),
    ('id=opaque; Secure; Secure; HttpOnly; SameSite=Lax','WARNING'),
    ('id=opaque; Secure=false; HttpOnly; SameSite=Strict','WARNING'),
    ('id=opaque; Secure; HttpOnly; SameSite=bogus; SameSite=Lax','FAIL'),
    ('id=; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax','PASS'),
    ('id="secure; httponly; samesite"','WARNING'),
    ('invalid-cookie','WARNING'),
    ('id="unfinished','WARNING'),
])
def test_cookie_attributes_preserve_structure(cookie,status):
    assert cookie_attributes(cookie)['status']==status


def test_multiple_cookie_fields_are_checked_independently_and_values_redacted():
    finding=web._scan_cookie_flags(['session=confidential-A; Secure; HttpOnly; SameSite=Lax',
                                   'session=confidential-B; Path=/admin'])[0]
    assert finding.status=='FAIL'
    assert len(finding.metadata['cookies'])==2
    assert 'confidential-' not in finding.evidence
    assert finding.metadata['cookies'][1]['status']=='FAIL'


def test_hsts_http_is_configuration_pass_without_protection_claim():
    finding=next(f for f in web._scan_security_headers({'strict-transport-security':'max-age=42'},scheme='http') if 'STRICT_TRANSPORT' in f.check_id)
    assert finding.status=='PASS'
    assert finding.metadata['hsts_https_context'] is False
    assert finding.metadata['browser_enforcement_verified'] is False


def test_valid_but_different_head_get_policies_require_review():
    finding=next(f for f in web._scan_security_headers({'x-frame-options':'DENY'},{'x-frame-options':'SAMEORIGIN'}) if f.check_id.endswith('X_FRAME_OPTIONS'))
    assert finding.status=='WARNING'
    assert finding.metadata['head_get_differ']


@pytest.mark.parametrize('variant,check,expected',[
    ('document','WEB_HEADER_CONTENT_SECURITY_POLICY','WARNING'),
    ('frame','WEB_HEADER_X_FRAME_OPTIONS','FAIL'),
    ('cookies','WEB_COOKIE_FLAGS','FAIL'),
    ('secure','WEB_COOKIE_FLAGS','PASS'),
    ('redirect','WEB_HEADER_CONTENT_SECURITY_POLICY','PASS'),
])
def test_local_http_document_and_cookie_observations(variant,check,expected):
    events=[]
    headers={'Strict-Transport-Security':'max-age=86400','Content-Security-Policy':"default-src 'self'",
             'X-Content-Type-Options':'nosniff','X-Frame-Options':'SAMEORIGIN',
             'Referrer-Policy':'same-origin','Permissions-Policy':'microphone=()'}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass
        def do_HEAD(self):
            self.respond()
        def do_GET(self):
            self.respond()
        def respond(self):
            events.append((self.command,self.path))
            if variant=='redirect' and self.path=='/':
                self.send_response(302)
                self.send_header('Location','/document')
                self.end_headers()
                return
            self.send_response(200 if self.path in {'/','/document'} else 404)
            for name,value in headers.items():
                if self.command=='GET' and variant=='document' and name=='Content-Security-Policy':
                    continue
                self.send_header(name,'unsupported' if self.command=='GET' and variant=='frame' and name=='X-Frame-Options' else value)
            if self.command=='GET' and self.path in {'/','/document'}:
                self.send_header('Set-Cookie','opaque=private-token-A; Secure; HttpOnly; SameSite=Lax')
                self.send_header('Set-Cookie','other=private-token-B' if variant=='cookies' else 'other=private-token-B; Secure; HttpOnly; SameSite=Strict')
            body=b'<html>independent landing</html>'
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            if self.command=='GET':
                self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        findings=web.scan_web_target(f'http://127.0.0.1:{server.server_port}/')
        finding=next(f for f in findings if f.check_id==check)
        assert finding.status==expected
        assert 'private-token' not in finding.evidence
        if variant!='redirect':
            assert events.count(('GET','/'))==1  # Reused as the sensitive-path root control.
        else:
            assert ('GET','/document') in events
    finally:
        server.shutdown()
        server.server_close()


def test_failed_get_comparison_never_claims_complete_configuration(monkeypatch):
    def request(url,method='HEAD',follow_redirects=True):
        headers=Message()
        for key,value in [('Strict-Transport-Security','max-age=42'),('Content-Security-Policy',"default-src 'none'"),
                          ('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY'),
                          ('Referrer-Policy','no-referrer'),('Permissions-Policy','camera=()')]:
            headers[key]=value
        return dict(status=200,headers=headers,error='TimeoutError: incomplete GET' if method=='GET' else None)
    monkeypatch.setattr(web,'_request',request)
    findings=web.scan_web_target('http://127.0.0.1/')
    assert all(f.status=='WARNING' for f in findings)
