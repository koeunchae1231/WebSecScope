"""Optional, origin-bound service declarations. No secret values or pattern matching."""
from copy import deepcopy
import hashlib
from http.cookies import SimpleCookie, CookieError
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from websecscope.rules.api_evidence import private_response
from websecscope.rules.web.cookie_values import cookie_attributes


def origin(url):
    try:
        p=urlsplit(url)
        if p.scheme not in {'http','https'} or not p.hostname or p.username or p.password:
            raise ValueError('origin must be an HTTP(S) URL without credentials')
        if p.port == 0:raise ValueError('Origin port must be nonzero')
        return (p.scheme,p.hostname.lower(),p.port or (443 if p.scheme=='https' else 80))
    except (AttributeError,TypeError,ValueError) as exc:
        raise ValueError('Invalid policy/target origin') from exc


def _path(value):
    if (not isinstance(value,str) or not value.startswith('/') or value.startswith('//') or len(value)>1024
            or any(c in value for c in '?#%\\*[]{}') or any(ord(c)<33 or ord(c)>126 for c in value)
            or any(p in {'.','..'} for p in value.split('/'))):
        raise ValueError('Policy paths must be exact absolute paths without patterns, encoding or query')


class ScanPolicy:
    def __init__(self,data,target):
        if not isinstance(data,dict) or set(data)-{'policy_version','target_origin','resources','cookies','header_requirements'}:
            raise ValueError('Unknown policy fields or non-object policy')
        if type(data.get('policy_version')) is not int or data['policy_version']!=1:
            raise ValueError('Unsupported policy_version; expected integer 1')
        if not isinstance(data.get('target_origin'),str):raise ValueError('target_origin is required')
        p=urlsplit(data['target_origin'])
        if p.path not in {'','/'} or p.query or p.fragment:
            raise ValueError('target_origin must not include a path/query/fragment')
        self.origin=origin(data.get('target_origin',''))
        self.ensure_target(target)
        self.data=deepcopy(data)
        self.resources={};self.cookies={}
        from websecscope.rules.web.header_requirements import validate_requirements
        self.header_requirements=validate_requirements(data.get('header_requirements',[]),_path)
        for field in ('resources','cookies'):
            if not isinstance(data.get(field,[]),list) or len(data.get(field,[]))>1000:
                raise ValueError('Policy rule collections must be lists of at most 1000 entries')
        for rule in data.get('resources',[]):
            if not isinstance(rule,dict) or set(rule)!={'path','visibility'}:
                raise ValueError('Resource requires path and visibility only')
            _path(rule['path'])
            if not isinstance(rule['visibility'],str) or rule['visibility'] not in {'public','private'} or rule['path'] in self.resources:
                raise ValueError('Invalid or duplicate/conflicting resource declaration')
            self.resources[rule['path']]=deepcopy(rule)
        for rule in data.get('cookies',[]):
            if not isinstance(rule,dict) or set(rule)-{'name','purpose','javascript_access_required','domain','path'}:
                raise ValueError('Unknown cookie policy fields')
            if not isinstance(rule.get('name'),str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",rule['name']):
                raise ValueError('Invalid cookie name')
            if not isinstance(rule.get('purpose'),str) or rule['purpose'] not in {'authentication','session','preference','unknown'} or type(rule.get('javascript_access_required')) is not bool:
                raise ValueError('Cookie purpose and boolean javascript_access_required are required')
            if rule['purpose'] in {'authentication','session'} and rule['javascript_access_required']:
                raise ValueError('Authentication/session and required JavaScript access conflict')
            path=rule.get('path','/');_path(path)
            domain=rule.get('domain')
            if domain is not None and (not isinstance(domain,str) or domain.lstrip('.').lower()!=self.origin[1]):
                raise ValueError('Cookie policy domain must equal the bound target host')
            key=(rule['name'],domain.lstrip('.').lower() if domain is not None else None,path)
            if key in self.cookies:raise ValueError('Duplicate/conflicting cookie scope')
            self.cookies[key]=deepcopy(rule)
        self.digest=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def ensure_target(self,url):
        if origin(url)!=self.origin:raise ValueError('Policy target_origin does not match scan target')

    def matches_origin(self,url):
        try:return origin(url)==self.origin
        except ValueError:return False

    def resource(self,url):
        return self.resources.get(urlsplit(url).path) if self.matches_origin(url) else None

    def reference(self,rule):
        return {'policy_version':1,'policy_sha256':self.digest,'rule':deepcopy(rule)}


def load_policy(path,target):
    try:
        if Path(path).stat().st_size>1024*1024:raise ValueError('Policy file exceeds 1 MiB')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('Duplicate JSON policy key')
                result[key]=value
            return result
        data=json.loads(Path(path).read_text(encoding='utf-8'),object_pairs_hook=unique,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
        return ScanPolicy(data,target)
    except (OSError,UnicodeError,ValueError,TypeError) as exc:
        raise ValueError(f'Invalid policy file: {exc}') from exc


def evaluate_cookie(header,url,policy=None):
    result=cookie_attributes(header)
    if policy is None or not policy.matches_origin(url) or result['name']=='unparsed':return result
    parsed=SimpleCookie()
    try:parsed.load(header)
    except CookieError:return result
    if len(parsed)!=1 or result['name'] not in parsed:return result
    item=parsed[result['name']]
    domain=item['domain'].lstrip('.').lower() if item['domain'] else None
    request_path=urlsplit(url).path
    default_path=request_path.rsplit('/',1)[0] or '/'
    path=item['path'] or default_path
    if not path.startswith('/'):path=default_path
    # Ambiguous non-security scope attributes must never select an exemption.
    if any(len(re.findall(r'(?:^|;)\s*'+attr+r'\s*=',header,re.I))>1 for attr in ('domain','path')):
        result['scope_review']='Duplicate Domain/Path prevents policy matching'
        if result['status']=='PASS':result['status']='WARNING'
        return result
    rule=policy.cookies.get((result['name'],domain,path))
    if rule is None:return result
    result['policy']=policy.reference(rule)
    result['scope']={'response_origin':list(policy.origin),'domain':domain,'path':path}
    if rule['purpose']=='preference' and rule['javascript_access_required']:
        credential_like=bool(re.fullmatch(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',item.value))
        if credential_like:
            result['policy_conflict']='Credential-like value conflicts with non-sensitive preference declaration'
            if result['status']=='PASS':result['status']='WARNING'
        else:
            if 'httponly' not in result['attributes']:
                # Re-run the same parser with the waived requirement satisfied.
                # Preserve the original observed attributes, including HttpOnly absence.
                adjusted=cookie_attributes(header+'; HttpOnly')
                result.update(issues=adjusted['issues'],status=adjusted['status'])
            result['policy_adjustment']='HttpOnly absence permitted for declared JavaScript preference; Secure/SameSite remain required'
            if 'httponly' in result['attributes']:
                result['policy_conflict']='HttpOnly blocks declared required JavaScript access'
                if result['status']=='PASS':result['status']='WARNING'
    result['transport_note']='Observed on '+urlsplit(url).scheme+'; browser storage and transport enforcement not tested'
    return result


def cookie_summary(detail,valid_text):
    parts=list(detail['issues'])
    for key in ('policy_adjustment','policy_conflict','scope_review'):
        if detail.get(key):parts.append(detail[key])
    return ', '.join(parts) if parts else valid_text


def resource_decision(endpoint,policy=None):
    if policy is None:return None
    url=endpoint.get('url','')
    rule=policy.resource(url)
    if rule is None:return None
    result={'policy':policy.reference(rule),'status':'WARNING','reason':'Insufficient resource observation',
            'unauthenticated_request':endpoint.get('unauthenticated_request') is True}
    status=endpoint.get('status_code');body=endpoint.get('body_sample','')
    if endpoint.get('error') or endpoint.get('redirected') or endpoint.get('body_truncated'):
        result['reason']='Error, redirect or truncated content prevents policy conclusion';return result
    if endpoint.get('final_url') and not policy.matches_origin(endpoint['final_url']):
        result['reason']='Final response origin differs from policy target';return result
    if status in {404,410}:
        result.update(status='PASS',reason='Declared resource was not found');return result
    if status in {401,403}:
        result.update(status='PASS' if rule['visibility']=='private' else 'WARNING',reason='Authentication/authorization required')
        return result
    if endpoint.get('body_evidence',{}).get('supported_for_text_analysis') is False:
        result['reason']='Recorded body format, encoding or parsing does not support a policy conclusion';return result
    if status is None or not 200<=status<300 or not body.strip():return result
    if endpoint.get('response_kind')=='public_shell':
        result.update(status='PASS' if rule['visibility']=='public' else 'WARNING',reason='Public SPA shell does not establish access to the declared resource')
        return result
    if rule['visibility']=='private':
        result.update(status='FAIL' if result['unauthenticated_request'] else 'WARNING',
                      reason='Private resource content returned to an unauthenticated request' if result['unauthenticated_request'] else 'Request authentication context is unknown')
        return result
    reasons=private_response(endpoint)
    fields=[]
    try:obj=json.loads(body)
    except (ValueError,TypeError):obj=None
    def visit(value,example=False,depth=0):
        if depth>10:return
        if isinstance(value,dict):
            for key,item in value.items():
                words=set(re.split(r'[^a-z0-9]+',str(key).lower()))
                if words & {'private','confidential','password','passwd','secret','token','ssn'} and item not in (None,False,'',[],{}):
                    placeholder=isinstance(item,str) and bool(re.fullmatch(
                        r'(?:replace[-_ ](?:this[-_ ])?(?:placeholder|token|secret|password)|your[-_ ](?:token|secret|password)|<[^<>]+>|example|placeholder|changeme)',item,re.I))
                    fields.append(example and placeholder)
                visit(item,example or str(key).lower() in {'example','examples','sample','samples'},depth+1)
        elif isinstance(value,list):
            for item in value:visit(item,example,depth+1)
    visit(obj)
    if obj is None and (re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----',body) or
                        re.search(r'(?im)\b(?:password|secret|token|api_key)\s*[:=]\s*\S+',body)):
        reasons.append('Credential-like assignment or private-key signature requires review')
    if reasons and not (fields and all(fields) and all('JSON contains' in r for r in reasons)):
        result.update(reason='Public declaration conflicts with sensitive-content or private-cache evidence',policy_conflict=True)
    elif reasons:
        result.update(status='PASS',reason='Public declaration plus example container and explicit placeholder; no actual credential confirmed')
    else:
        # Successful public content is only an exposure-policy assessment, not a content safety guarantee.
        result.update(status='PASS',reason='Public declaration and complete response; no sensitive-content signature observed')
    return result
