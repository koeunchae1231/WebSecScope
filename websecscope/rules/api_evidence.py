"""Bounded response evidence; no fixture-specific strings or browser claims."""
import json
import re


def header(endpoint, name):
    return next((str(v) for k,v in endpoint.get('headers',{}).items() if k.lower()==name.lower()),'')


def private_response(endpoint):
    """Return reasons, never values. Labels are a heuristic, not an ownership oracle."""
    body=endpoint.get('body_sample','')
    if not body.strip():
        return []
    reasons=[]
    if 'private' in {p.strip().split('=')[0].lower() for p in header(endpoint,'Cache-Control').split(',')}:
        reasons.append('Cache-Control explicitly marks the nonempty response private')
    if endpoint.get('body_evidence',{}).get('supported_for_text_analysis') is False:
        return reasons
    try:
        obj=json.loads(body)
    except (ValueError,TypeError,RecursionError):
        return reasons
    def visit(value,depth=0):
        if depth>10:
            return False
        if isinstance(value,dict):
            for key,item in value.items():
                words=set(re.split(r'[^a-z0-9]+',str(key).lower()))
                if words & {'private','confidential','password','passwd','secret','token','ssn'} and item not in (None,False,'',[],{}):
                    return True
                if visit(item,depth+1):
                    return True
        if isinstance(value,list):
            return any(visit(item,depth+1) for item in value)
        return False
    if visit(obj):
        reasons.append('JSON contains a nonempty private/confidential/credential-like field')
    return reasons


def public_response(endpoint):
    return not endpoint.get('error') and not endpoint.get('body_truncated') and endpoint.get('body_evidence',{}).get('supported_for_text_analysis',True) and bool(endpoint.get('body_sample','').strip()) and not private_response(endpoint) and 'public' in {
        p.strip().split('=')[0].lower() for p in header(endpoint,'Cache-Control').split(',')}


def html_response(endpoint):
    return bool(re.search(r'<(?:!doctype\s+html|html|head|body)\b',endpoint.get('body_sample',''),re.I))


def response_kind(endpoint, controls=()):
    if endpoint.get('error') or endpoint.get('status_code') is None:
        return 'request_error'
    status=endpoint['status_code']
    if endpoint.get('redirected') or 300<=status<400:
        return 'redirected'
    if status==401:
        return 'authentication_required'
    if status==403:
        return 'access_denied'
    if status in {404,410}:
        return 'absent'
    if status>=500:
        return 'server_error'
    if 200<=status<300:
        body=endpoint.get('body_sample','').strip()
        if html_response(endpoint) and body and not endpoint.get('body_truncated') and endpoint.get('body_evidence',{}).get('supported_for_text_analysis',True) and len(controls)==2 and all(
            not c.get('error') and not c.get('redirected') and not c.get('body_truncated') and c.get('status_code')==200
            and c.get('body_evidence',{}).get('supported_for_text_analysis',True)
            and c.get('body_sample','').strip()==body for c in controls):
            return 'public_shell'
        if private_response(endpoint):
            return 'private_data'
        return 'unconfirmed'
    return 'unconfirmed'
