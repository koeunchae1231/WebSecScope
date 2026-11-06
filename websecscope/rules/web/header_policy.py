"""Bounded header semantics, not a browser, XSS proof, or service-requirement oracle."""
import re
from urllib.parse import urlsplit

REFERRER_POLICIES = {'no-referrer','no-referrer-when-downgrade','origin','origin-when-cross-origin',
                     'same-origin','strict-origin','strict-origin-when-cross-origin','unsafe-url'}
CSP_DIRECTIVES = {'default-src','script-src','script-src-elem','script-src-attr','style-src','style-src-elem',
                  'style-src-attr','img-src','font-src','connect-src','media-src','object-src','frame-src',
                  'child-src','worker-src','manifest-src','base-uri','frame-ancestors','form-action',
                  'sandbox','upgrade-insecure-requests','block-all-mixed-content','report-uri','report-to',
                  'require-trusted-types-for','trusted-types'}

TARGET_HEADERS={'content-security-policy','referrer-policy','permissions-policy'}
LIMIT=16384
FEATURES={'camera','microphone','geolocation','fullscreen','payment','autoplay','display-capture',
          'accelerometer','gyroscope','magnetometer','usb','serial','bluetooth','midi','encrypted-media',
          'picture-in-picture','clipboard-read','clipboard-write','screen-wake-lock','web-share',
          'publickey-credentials-get','publickey-credentials-create','xr-spatial-tracking','storage-access'}


def _result(status,reason,**details):
    return dict(status=status,reason=reason,model='bounded-header-semantics-v1',
                browser_enforcement_verified=False,**details)


def assess_header(name,values,report_only=()):
    name=name.lower()
    values=[v.strip() for v in values if v is not None and v.strip()]
    if not values:
        return _result('WARNING','No explicit enforcing policy observed; browser defaults and service requirements are not verified',
            explicit_policy=False,report_only_observed=bool(report_only),
            browser_default='strict-origin-when-cross-origin (modern model; not runtime verified)' if name=='referrer-policy' else 'feature/browser/context dependent' if name=='permissions-policy' else 'no header-delivered CSP restriction; other delivery channels untested')
    if sum(map(len,values))>LIMIT or len(values)>32:
        return _result('WARNING','Header analysis limit reached; do not infer a safe policy')
    if name=='content-security-policy':return _csp(values,report_only)
    if name=='referrer-policy':return _referrer(values)
    if name=='permissions-policy':return _permissions(values)
    return _result('WARNING','Unsupported policy header')


def _nonce_hash(token):
    return bool(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'",token,re.I))


def _sources(directives,names):
    for name in names:
        if name in directives:return dict(directive=name,sources=directives[name])
    return dict(directive=None,sources=None)


def _caps(source):
    values=source['sources']
    if values is None:return dict(network_broad=True,all_inline=True,anchor=False,strict_dynamic=False)
    lowered=[v.lower() for v in values]
    anchor=any(_nonce_hash(v) for v in values)
    dynamic="'strict-dynamic'" in lowered
    return dict(network_broad=not dynamic and any(v in {'*','http:','https:','data:','blob:'} for v in lowered),
                all_inline="'unsafe-inline'" in lowered and not anchor and not dynamic,anchor=anchor,strict_dynamic=dynamic)


def _parse_csp(value):
    directives={};duplicates=[];unknown=[];invalid=[];review=[]
    parts=value.split(';')
    if len(parts)>128:return dict(error='Directive count limit',directives={},duplicates=[],unknown=[],review=[])
    for part in parts:
        words=part.split()
        if not words:continue
        name=words[0].lower();tokens=words[1:]
        if not re.fullmatch(r'[a-z][a-z0-9-]*',name) or any(c in part for c in '{}\r\n'):
            invalid.append('malformed directive');continue
        if name in directives:duplicates.append(name);continue  # CSP keeps the first directive.
        if len(tokens)>256:invalid.append('source count limit');continue
        if any(t.startswith("'")!=t.endswith("'") for t in tokens):invalid.append('unbalanced source quoting')
        if name in {'upgrade-insecure-requests','block-all-mixed-content'} and tokens:invalid.append('flag directive carries values')
        if name not in CSP_DIRECTIVES:unknown.append(name)
        directives[name]=tokens
        for t in tokens:
            if name.endswith('-src') or name in {'script-src-elem','script-src-attr','base-uri'}:
                if '*' in t and t != '*':review.append('host wildcard scope requires review')
                if t.startswith("'") and t.lower() not in {"'self'","'none'","'unsafe-inline'","'unsafe-eval'","'strict-dynamic'","'unsafe-hashes'","'report-sample'","'wasm-unsafe-eval'"} and not _nonce_hash(t):review.append('unsupported source expression')
            if t.lower().startswith(("'nonce-","'sha256-","'sha384-","'sha512-")) and not _nonce_hash(t):review.append('invalid nonce/hash expression')
        if "'none'" in [t.lower() for t in tokens] and len(tokens)>1:review.append("none combined with other sources is not a deny-all proof")
    return dict(error='; '.join(invalid) if invalid else None,directives=directives,duplicates=duplicates,unknown=unknown,review=review)


def _csp(values,report_only):
    policies=[p.strip() for value in values for p in value.split(',') if p.strip()]
    if len(policies)>32:return _result('WARNING','Too many combined CSP policies')
    parsed=[_parse_csp(p) for p in policies]
    if any(p['error'] for p in parsed):
        return _result('FAIL' if len(parsed)==1 else 'WARNING','Malformed or unsupported CSP syntax; combined enforcement cannot be assumed',
                       policies=parsed,report_only_count=len(report_only))
    effective=[]
    for p in parsed:
        d=p['directives']
        elem=_sources(d,('script-src-elem','script-src','default-src'))
        attr=_sources(d,('script-src-attr','script-src','default-src'))
        evaluation=_sources(d,('script-src','default-src'))
        obj=_sources(d,('object-src','default-src'))
        ec=_caps(elem);ac=_caps(attr);oc=_caps({'sources': [t for t in obj['sources'] if t.lower()!="'strict-dynamic'"] if obj['sources'] is not None else None})
        ev=evaluation['sources']
        effective.append(dict(script_element=elem,script_attribute=attr,eval_source=evaluation,object_source=obj,
            element_caps=ec,attribute_caps=ac,object_broad=oc['network_broad'],
            eval_allowed=ev is None or "'unsafe-eval'" in [s.lower() for s in ev],
            base_uri=d.get('base-uri'),base_uri_missing='base-uri' not in d))
    joint=dict(network_broad=all(p['element_caps']['network_broad'] for p in effective),
               all_inline=all(p['element_caps']['all_inline'] for p in effective),
               all_inline_attributes=all(p['attribute_caps']['all_inline'] for p in effective),
               eval_allowed=all(p['eval_allowed'] for p in effective),object_broad=all(p['object_broad'] for p in effective))
    reviews=[s for p in parsed for s in p['review']]
    if any(p['unknown'] for p in parsed):reviews.append('unknown directives/browser support')
    if any(p['duplicates'] for p in parsed):reviews.append('duplicate directives; first value modeled')
    if any('sandbox' in p['directives'] for p in parsed):reviews.append('sandbox execution constraints require review')
    if all(p['script_element']['directive'] is None for p in effective):reviews.append('no governing script directive')
    if any(p['base_uri'] is not None and _caps({'sources':p['base_uri']})['network_broad'] for p in effective):reviews.append('broad base-uri')
    explicit_script=any(p['script_element']['directive'] is not None for p in effective)
    dangerous=explicit_script and all(joint[k] for k in ('network_broad','all_inline','all_inline_attributes','eval_allowed'))
    status='FAIL' if dangerous and not reviews else 'WARNING' if reviews or any(joint.values()) else 'PASS'
    reason=('Effective policies jointly admit broad script sources, arbitrary inline scripts/handlers and JavaScript eval; configuration hardening failure, not verified XSS'
            if status=='FAIL' else 'CSP meaning requires review: '+', '.join(reviews or [k for k,v in joint.items() if v]) if status=='WARNING'
            else 'Checked CSP3 script/object restrictions hold under the combined-policy model; this is not complete XSS prevention')
    return _result(status,reason,policies=parsed,effective=effective,joint=joint,report_only_count=len(report_only),
                   report_only_enforced=False,nonce_entropy_or_reuse_verified=False,
                   base_uri_note='Missing base-uri is reported, not assumed denied; no application injection test')


def _referrer(values):
    tokens=[p.strip().lower() for value in values for p in value.split(',')]
    valid=[p for p in tokens if p in REFERRER_POLICIES]
    if not valid:return _result('FAIL','No recognized Referrer-Policy token; browser fallback is not a configured policy',tokens=tokens)
    selected=valid[-1]
    rules={
        'no-referrer':('none','none','none'),
        'same-origin':('full URL','none','none'),
        'strict-origin':('origin','origin','none'),
        'strict-origin-when-cross-origin':('full URL','origin','none'),
        'origin':('origin','origin','origin'),
        'origin-when-cross-origin':('full URL','origin','origin'),
        'no-referrer-when-downgrade':('full URL','full URL','none'),
        'unsafe-url':('full URL','full URL','full URL'),
    }
    same,cross,down=rules[selected]
    restricted=selected in {'no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin'}
    return _result('PASS' if restricted else 'WARNING',
        f'Last recognized fallback policy: {selected}; same-origin={same}, cross-origin={cross}, HTTPS downgrade={down}; actual sensitive URL disclosure not verified',
        selected_policy=selected,tokens=tokens,same_origin=same,cross_origin=cross,downgrade=down,
        explicit_policy=True,sensitive_url_verified=False,service_requirement_known=False)


def _members(value):
    parts=[];start=0;depth=0;quoted=False;escaped=False
    for i,c in enumerate(value):
        if escaped:escaped=False;continue
        if quoted and c=='\\':escaped=True;continue
        if c=='"':quoted=not quoted
        elif not quoted:
            if c=='(':depth+=1
            elif c==')':depth-=1
            elif c==',' and depth==0:parts.append(value[start:i].strip());start=i+1
            if depth<0:return None
    if depth or quoted:return None
    parts.append(value[start:].strip());return parts


def _permissions(values):
    parts=_members(','.join(values))
    if parts is None:return _result('FAIL','Unbalanced Permissions-Policy list')
    features={};duplicates=[];unknown=[];reviews=[]
    for part in parts:
        match=re.fullmatch(r'([a-z][a-z0-9-]*)\s*=\s*(\*|\(.*\))',part)
        if not match:return _result('FAIL','Expected feature=(), feature=(self "origin") or feature=*')
        name,raw=match.groups()
        if name in features:duplicates.append(name)
        if raw=='*':allowlist='*'
        else:
            inner=raw[1:-1].strip();tokens=re.findall(r'"[^"\r\n]*"|[^\s]+',inner)
            if any(t!='self' and not (t.startswith('"') and t.endswith('"')) for t in tokens):
                return _result('FAIL','Unsupported or malformed allowlist item')
            allowlist=[]
            for t in tokens:
                if t=='self':allowlist.append('self');continue
                value=t[1:-1]
                try:
                    p=urlsplit(value)
                    valid=p.scheme in {'https','http'} and bool(p.hostname) and not p.username and not p.password and not p.path and not p.query and not p.fragment
                    p.port
                except ValueError:valid=False
                if not valid or '*' in value:reviews.append('invalid or unsupported origin expression')
                allowlist.append(value)
        features[name]=allowlist  # Structured dictionary duplicate semantics; review below.
        if name not in FEATURES:unknown.append(name)
    broad=[name for name in ('camera','microphone','geolocation') if features.get(name)=='*']
    if duplicates:reviews.append('duplicate feature declarations; do not infer author intent')
    if unknown:reviews.append('unknown feature support')
    if broad:reviews.append('unrestricted sensitive-feature delegation requires service context')
    return _result('WARNING' if reviews else 'PASS',
        'Feature allowlists parsed; '+('; '.join(reviews) if reviews else 'bounded explicit restrictions recognized')+'; user grants, embedding context and browser support not tested',
        features=features,duplicates=duplicates,unknown_features=unknown,broad_sensitive_features=broad,
        service_requirement_known=False,permission_grant_verified=False)
