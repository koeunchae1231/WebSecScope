from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from websecscope.policy import ScanPolicy, evaluate_cookie, resource_decision, load_policy

TARGET='https://service.example/'


def policy(resources=None,cookies=None,target=TARGET):
    return ScanPolicy({'policy_version':1,'target_origin':target,'resources':resources or [],'cookies':cookies or []},target)


def preference(**extra):
    return dict(name='palette',purpose='preference',javascript_access_required=True,**extra)


def endpoint(body,status=200,**extra):
    return dict(url=TARGET+'admin',status_code=status,body_sample=body,headers={},
                **extra)


def public():return policy(resources=[{'path':'/admin','visibility':'public'}])


@pytest.mark.parametrize('body',[
    '{"examples":[{"secret":"replace-this-placeholder"}]}',
    '{"samples":[{"token":"<YOUR_TOKEN>"}]}',
])
def test_public_example_requires_context_and_placeholder(body):
    assert resource_decision(endpoint(body),public())['status']=='PASS'


@pytest.mark.parametrize('body',[
    '{"examples":[{"secret":"opaque-real-credential-2384"}]}',
    '{"secret":"example"}',
    'PASSWORD=live_credential',
    '-----BEGIN RSA PRIVATE KEY-----',
    '{"confidential":[{"salary":74000}]}',
])
def test_public_policy_never_waives_credential_or_private_evidence(body):
    assert resource_decision(endpoint(body),public())['status']=='WARNING'


def test_private_cache_conflicts_with_public_example():
    e=endpoint('{"examples":[{"secret":"placeholder"}]}')
    e['headers']={'Cache-Control':'private'}
    assert resource_decision(e,public())['policy_conflict']


@pytest.mark.parametrize('auth,expected',[(True,'FAIL'),(False,'WARNING'),(None,'WARNING')])
def test_private_success_requires_actual_request_auth_context(auth,expected):
    p=policy(resources=[{'path':'/admin','visibility':'private'}])
    assert resource_decision(endpoint('private report',unauthenticated_request=auth),p)['status']==expected


@pytest.mark.parametrize('status',[401,403])
def test_private_protected(status):
    p=policy(resources=[{'path':'/admin','visibility':'private'}])
    assert resource_decision(endpoint('login required',status),p)['status']=='PASS'


@pytest.mark.parametrize('extra',[{'response_kind':'public_shell'},{'body_truncated':True},{'error':'timeout'},
                                  {'redirected':True},{'final_url':'https://other.example/admin'}])
def test_private_incomplete_redirect_spa_not_confirmed(extra):
    p=policy(resources=[{'path':'/admin','visibility':'private'}])
    assert resource_decision(endpoint('shell',unauthenticated_request=True,**extra),p)['status']=='WARNING'


def test_unlisted_path_and_other_origin_have_no_rule():
    p=public()
    assert p.resource(TARGET+'admin/child') is None
    assert p.resource('https://other.example/admin') is None
    assert p.resource(TARGET+'admin?query=1') is not None
    assert resource_decision(endpoint('anything'),None) is None
    with pytest.raises(ValueError):p.ensure_target('http://service.example/')


@pytest.mark.parametrize('change',[
    {'policy_version':2},{'policy_version':True},{'unexpected':1},{'target_origin':'https://other.example'},
    {'resources':[{'path':'/a*','visibility':'public'}]},
    {'resources':[{'path':'/%2e%2e','visibility':'public'}]},
    {'resources':[{'path':'/admin','visibility':'public'},{'path':'/admin','visibility':'private'}]},
    {'cookies':[preference(),preference()]},
    {'cookies':[preference(domain='other.example')]},
    {'cookies':[dict(name='session',purpose='authentication',javascript_access_required=True)]},
    {'cookies':[dict(name='session',purpose='authentication',javascript_access_required='false')]},
])
def test_invalid_or_conflicting_policy_rejected(change):
    data={'policy_version':1,'target_origin':TARGET,'resources':[],'cookies':[]}
    data.update(change)
    with pytest.raises(ValueError):ScanPolicy(data,TARGET)


@pytest.mark.parametrize('text',['{bad','{"policy_version":1,"policy_version":1}','{"policy_version":NaN}'])
def test_malformed_policy_file_not_ignored(tmp_path,text):
    p=tmp_path/'policy.json';p.write_text(text,encoding='utf-8')
    with pytest.raises(ValueError):load_policy(p,TARGET)


def test_preference_http_only_adjustment_and_redacted_scope():
    result=evaluate_cookie('palette=private-cookie-value; Secure; SameSite=Lax',TARGET,policy(cookies=[preference()]))
    assert result['status']=='PASS'
    assert 'private-cookie-value' not in json.dumps(result)
    assert result['scope']['path']=='/'
    assert result['policy']['policy_sha256']


@pytest.mark.parametrize('header',[
    'palette=sepia; SameSite=Lax',
    'palette=sepia; Secure; SameSite=Invalid',
    'palette=sepia; SameSite=None',
    'palette=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.signature; Secure; SameSite=Lax',
])
def test_preference_not_blanket_exemption(header):
    assert evaluate_cookie(header,TARGET,policy(cookies=[preference()]))['status']!='PASS'


def test_javascript_required_but_http_only_present_is_conflict():
    r=evaluate_cookie('palette=sepia; HttpOnly; Secure; SameSite=Lax',TARGET,policy(cookies=[preference()]))
    assert r['status']=='WARNING' and r['policy_conflict']


@pytest.mark.parametrize('header',[
    'session=demo; Secure; SameSite=Lax',
    'session=demo; HttpOnly; SameSite=Lax',
    'session=demo; HttpOnly; Secure; SameSite=Bad',
])
def test_authentication_attributes_still_required(header):
    p=policy(cookies=[dict(name='session',purpose='authentication',javascript_access_required=False)])
    assert evaluate_cookie(header,TARGET,p)['status']=='FAIL'


def test_unmatched_purpose_name_domain_path_and_origin_do_not_get_exemption():
    p=policy(cookies=[preference()])
    for header,url in [('palette=x; Path=/sub; Secure; SameSite=Lax',TARGET),
                       ('palette=x; Domain=other.example; Secure; SameSite=Lax',TARGET),
                       ('palette=x; Secure; SameSite=Lax','https://other.example/'),
                       ('Palette=x; Secure; SameSite=Lax',TARGET),
                       ('session=x; Secure; SameSite=Lax',TARGET)]:
        assert evaluate_cookie(header,url,p)['status']=='FAIL'


def test_duplicate_names_scopes_and_domain_are_independent():
    p=policy(cookies=[preference(),preference(path='/sub'),preference(domain='service.example')])
    headers=['palette=x; Secure; SameSite=Lax','palette=y; Path=/sub; Secure; SameSite=Lax',
             'palette=z; Domain=.service.example; Secure; SameSite=Lax']
    results=[evaluate_cookie(h,TARGET,p) for h in headers]
    assert all(r['status']=='PASS' for r in results)
    assert len({(r['scope']['domain'],r['scope']['path']) for r in results})==3
    from websecscope.scanner.web import _scan_cookie_flags
    assert len(_scan_cookie_flags(headers+headers,policy=p,urls=[TARGET]*6)[0].metadata['cookies'])==6


def test_unknown_cookie_purpose_and_duplicate_scope_not_passed():
    p=policy(cookies=[dict(name='palette',purpose='unknown',javascript_access_required=True)])
    assert evaluate_cookie('palette=x; Secure; SameSite=Lax',TARGET,p)['status']=='FAIL'
    assert evaluate_cookie('palette=x; Secure; HttpOnly; SameSite=Lax; Path=/; Path=/sub',TARGET,p)['status']=='WARNING'


def test_default_cookie_result_identical_without_policy():
    from websecscope.rules.web.cookie_values import cookie_attributes
    for header in ['x=y','session=x; HttpOnly; Secure; SameSite=Strict','x="bad; Secure']:
        assert evaluate_cookie(header,TARGET)==cookie_attributes(header)


def test_admin_policy_and_sensitive_path_integration():
    from websecscope.analyzer.api_auth_analyzer import _analyze_endpoint_exposure
    from websecscope.rules.api_evidence import response_kind
    e=endpoint('{"examples":[{"secret":"replace-this-placeholder"}]}',unauthenticated_request=True)
    e.update(path='/admin',response_kind=response_kind(e))
    before=deepcopy(e)
    assert any(f.status=='FAIL' for f in _analyze_endpoint_exposure([e]))
    result=_analyze_endpoint_exposure([e],public())
    assert all(f.status=='PASS' for f in result)
    assert result[0].metadata['resource_policy_observations']
    assert e==before


def test_private_resource_and_public_signature_in_web(monkeypatch):
    from websecscope.scanner import web
    def request(url,**kw):
        return {'status':200,'headers':{},'body_sample':'TOKEN=live_key','error':None}
    monkeypatch.setattr(web,'_request',request)
    p=policy(resources=[{'path':'/internal/config','visibility':'private'},{'path':'/.env','visibility':'public'}])
    result=web._scan_sensitive_paths(TARGET,root_response={'status':404,'body_sample':'','error':None},policy=p)[0]
    assert result.status=='FAIL'
    private=next(r for r in result.metadata['paths'] if r['path'].lstrip('/')=='internal/config')
    assert private['policy_decision']['unauthenticated_request']
    public_env=next(r for r in result.metadata['paths'] if r['path']=='.env')
    assert public_env['policy_decision']['status']=='WARNING'


def test_cli_policy_args_validation_and_json_html(monkeypatch,tmp_path,capsys):
    from websecscope.cli.main import build_parser
    from websecscope.cli.commands import scan
    from websecscope.models import ScanResult,Finding
    from websecscope.reporter.html_reporter import write_html_report
    captured={}
    def run(target,**kw):
        captured.update(kw)
        detail=evaluate_cookie('palette=x; Secure; SameSite=Lax',target,kw.get('policy'))
        return ScanResult(target,[Finding('TEST','web','cookie',detail['status'],'INFO','observed','Review',detail)],100)
    monkeypatch.setattr(scan,'run_scan',run)
    parser=build_parser()
    invalid=tmp_path/'invalid.json';invalid.write_text('{bad',encoding='utf-8')
    args=parser.parse_args(['scan','--target',TARGET,'--policy',str(invalid)])
    with pytest.raises(SystemExit):args.handler(args)
    assert not captured
    config=tmp_path/'policy.json';config.write_text(json.dumps(policy(cookies=[preference()]).data),encoding='utf-8')
    output=tmp_path/'out.json'
    args=parser.parse_args(['scan','--target',TARGET,'--policy',str(config),'--output',str(output),'--skip-cve','--skip-linux'])
    args.handler(args)
    payload=json.loads(output.read_text(encoding='utf-8'))
    assert payload['findings'][0]['metadata']['policy']['policy_sha256']
    assert 'Security Score: 100' in capsys.readouterr().out
    monkeypatch.setattr('websecscope.reporter.html_reporter.generate_llm_report',lambda request:{'enabled':False,'content':''})
    assert write_html_report(payload,tmp_path/'out.html').exists()


def test_policy_paths_are_origin_absolute_even_with_nested_scan_target(monkeypatch):
    from websecscope.scanner import web
    observed=[]
    def request(url,**kwargs):
        observed.append(url)
        return {'status':404,'headers':{},'body_sample':'','error':None}
    monkeypatch.setattr(web,'_request',request)
    p=policy(resources=[{'path':'/internal/config','visibility':'private'}])
    web._scan_sensitive_paths(TARGET+'app/',root_response={'status':404,'body_sample':'','error':None},policy=p)
    assert TARGET+'internal/config' in observed
    assert TARGET+'app/internal/config' not in observed


def test_policy_file_size_port_and_path_validation(tmp_path):
    file=tmp_path/'large.json';file.write_text(' '*((1024*1024)+1),encoding='utf-8')
    with pytest.raises(ValueError,match='1 MiB'):load_policy(file,TARGET)
    for target in ['https://service.example:0/']:
        with pytest.raises(ValueError):policy(target=target)
    for path in ['/bad path','/非ASCII']:
        with pytest.raises(ValueError):policy(resources=[{'path':path,'visibility':'public'}])


@pytest.mark.parametrize('header,expected',[
    ('palette=x; Secure; SameSite=Lax; SameSite=Strict','WARNING'),
    ('palette=x; Secure=invalid; SameSite=Lax','WARNING'),
    ('palette=x; Secure; SameSite=Invalid; SameSite=Lax','FAIL'),
])
def test_waiving_http_only_preserves_remaining_warning_vs_failure(header,expected):
    result=evaluate_cookie(header,TARGET,policy(cookies=[preference()]))
    assert result['status']==expected
    assert 'httponly' not in result['attributes']


def test_cookie_finding_explains_waiver_and_observed_conflict():
    from websecscope.scanner.web import _scan_cookie_flags
    p=policy(cookies=[preference()])
    r=_scan_cookie_flags(['palette=x; Secure; SameSite=Lax'],policy=p,urls=[TARGET])[0]
    assert r.status=='PASS' and 'HttpOnly absence permitted' in r.evidence
    assert 'valid Secure, HttpOnly' not in r.evidence
    r=_scan_cookie_flags(['palette=x; HttpOnly; Secure; SameSite=Lax'],policy=p,urls=[TARGET])[0]
    assert r.status=='WARNING' and 'blocks declared' in r.evidence


def test_private_docs_unknown_request_context_is_not_confirmed_exposure():
    from websecscope.analyzer.api_auth_analyzer import _analyze_endpoint_exposure
    p=policy(resources=[{'path':'/openapi.json','visibility':'private'}])
    e=endpoint('{"openapi":"3.0.0"}');e.update(url=TARGET+'openapi.json',path='/openapi.json')
    r=next(f for f in _analyze_endpoint_exposure([e],p) if f.check_id=='API_DOCS_EXPOSED')
    assert r.status=='WARNING'
    e['unauthenticated_request']=True
    r=next(f for f in _analyze_endpoint_exposure([e],p) if f.check_id=='API_DOCS_EXPOSED')
    assert r.status=='FAIL'
