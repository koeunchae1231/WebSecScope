"""New service scenarios. Ground truth describes application policy, not scanner output."""
import copy
import json

BASE = {
    'Strict-Transport-Security': 'max-age=63072000',
    'Content-Security-Policy': "default-src 'self'; img-src https: data:; object-src 'none'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), fullscreen=(self)',
}


def response(body='', status=200, headers=None, **extra):
    return dict(body=body, status=status, headers=headers or {}, **extra)


def cases():
    result = []
    def add(area, name, state, reason, fixture, check, observable='direct', requirement=None):
        result.append(dict(id=f'IE-{area.upper()}-{1+sum(c["area"]==area for c in result):02}', area=area,
                           name=name, input_conditions=fixture, security_state=state,
                           ground_truth_reason=reason, observability=observable, evaluable=state!='unknown',
                           requirement=requirement or reason, selector=check))
    def root_header(name, value, **extra):
        return {'root_headers': {name:value}, **extra}
    h = lambda n:'WEB_HEADER_'+n.upper().replace('-','_')
    for name, value, state, reason in [
        ('X-Content-Type-Options','NoSnIfF','safe','Case-insensitive nosniff enables MIME protection.'),
        ('X-Frame-Options','SAMEORIGIN','safe','Same-origin embedding is the declared service policy.'),
        ('Referrer-Policy','no-referrer, strict-origin','safe','Last recognized referrer policy is strict-origin.'),
        ('Permissions-Policy','camera=(self "https://meet.example"), payment=()','safe','Only self and explicit camera origin are permitted.'),
        ('Content-Security-Policy',"script-src 'nonce-QWxwaGFTZXJ2aWNl'; object-src 'none'",'safe','Nonce-based script allowlist and object denial satisfy declared script policy.'),
        ('Content-Security-Policy',"default-src * data: 'unsafe-inline' 'unsafe-eval'",'vulnerable','Service requires restrictive script execution; inline and eval plus broad sources violate it.'),
        ('Referrer-Policy','unsafe-url','vulnerable','Service URLs contain private query identifiers; full cross-origin referrer disclosure violates privacy policy.'),
        ('Permissions-Policy','camera=*','vulnerable','Service requires camera denial; unrestricted camera delegation violates it.'),
        ('Strict-Transport-Security','max-age=0','vulnerable','Clearing HSTS violates the deployment requirement for persistent HTTPS enforcement.'),
        ('X-Frame-Options','ALLOW-FROM https://portal.example','vulnerable','Obsolete directive does not implement required modern frame restriction.'),
    ]:
        add('headers',name+' '+value,state,reason,root_header(name,value),h(name),
            'configuration only; no browser or TLS enforcement test')
    add('headers','Different valid frame policies','unknown','Embedding requirements are unspecified; two valid method policies differ.',
        root_header('X-Frame-Options','DENY',get_headers={'X-Frame-Options':'SAMEORIGIN'}),h('X-Frame-Options'),'ambiguous policy')
    add('headers','Unreadable GET policy','unknown','HEAD configuration cannot establish the timed-out document policy.',
        {'get_delay':1.12},h('Content-Security-Policy'),'GET unavailable')

    cookie_rows = [
        ('Account session','acct=A7; Path=/; SameSite=Lax; HttpOnly; Secure','safe','Session requires all three protections.'),
        ('Expiry and case','acct=B8; Expires=Wed, 09 Jun 2032 10:18:14 GMT; sEcUrE; hTtPoNlY; sAmEsItE=Strict','safe','Expiry comma is not a cookie separator; attribute names ignore case.'),
        ('Cross-site session','embed=C9; SameSite=None; HttpOnly; Secure','safe','Embedded authenticated widget explicitly requires cross-site use with Secure.'),
        ('Two sessions',['acct=D1; HttpOnly; Secure; SameSite=Lax','refresh=E2; Path=/renew; Secure; SameSite=Strict; HttpOnly'],'safe','Both authentication cookies have required protections.'),
        ('Client preference','palette=sepia; SameSite=Lax; Secure','safe','Non-sensitive preference must be read by client JavaScript; HttpOnly is intentionally absent.'),
        ('Cleartext session','acct=F3; HttpOnly; SameSite=Strict','vulnerable','Authentication session lacks Secure.'),
        ('Script-readable session','acct=G4; Secure; SameSite=Lax','vulnerable','Authentication session must not be readable by JavaScript.'),
        ('Unrecognized same-site','acct=H5; Secure; HttpOnly; SameSite=CrossOrigin','vulnerable','Authentication cookie requires a recognized SameSite policy.'),
        ('Weak cookie among two',['acct=I6; Secure; HttpOnly; SameSite=Strict','refresh=J7; Secure; SameSite=Lax'],'vulnerable','Refresh credential lacks HttpOnly.'),
        ('Unprotected cross-site','acct=K8; HttpOnly; SameSite=None','vulnerable','SameSite=None requires Secure and credential transport protection.'),
    ]
    for name,cookie,state,reason in cookie_rows:
        add('cookies',name,state,reason,{'cookies':cookie},'WEB_COOKIE_FLAGS','attributes visible; browser storage untested')
    add('cookies','Conflicting same-site attributes','unknown','Deployment policy does not specify intended duplicate SameSite resolution.',
        {'cookies':'acct=L9; Secure; HttpOnly; SameSite=None; SameSite=Strict'},'WEB_COOKIE_FLAGS','conflicting policy')
    add('cookies','Malformed quoted session','unknown','Unterminated cookie value cannot establish intended server policy.',
        {'cookies':'acct="unfinished; Secure; HttpOnly; SameSite=Lax'},'WEB_COOKIE_FLAGS','malformed response')

    path_rows = [
        ('Absent archive',{'routes':{'/backup.zip':response('Archive retired',410)}},'safe','Removed archive returns 410.'),
        ('Protected environment',{'routes':{'/.env':response('Bearer credential required',401,{'WWW-Authenticate':'Bearer realm="settings"'})}},'safe','Configuration is inaccessible without authentication.'),
        ('Denied repository',{'routes':{'/.git/HEAD':response('Policy prohibits repository browsing',403)}},'safe','Repository content is denied.'),
        ('Public admin help',{'routes':{'/admin':response('<html><h1>Administrator help</h1><p>Public onboarding guide.</p></html>')}},'safe','Public help document contains no administrator data.'),
        ('Uniform JSON absence',{'fallback':response('{"error":{"code":"ROUTE_UNKNOWN","retryable":false}}',404)},'safe','Unknown resources return explicit JSON 404.'),
        ('Environment assignment',{'routes':{'/.env':response('SMTP_PASSWORD="mail-credential"\nBILLING_KEY="k_live_local"\n')}},'vulnerable','Unauthenticated configuration response exposes application credentials.'),
        ('JSON secret configuration',{'routes':{'/.env':response('{"database":{"username":"billing","password":"local-only-secret"}}',headers={'Content-Type':'application/json'})}},'vulnerable','JSON-formatted configuration exposes database credential.'),
        ('Repository detached commit',{'routes':{'/.git/HEAD':response('8a38d54ea318fbf54f78ed6e78bf432fd56798aa\n')}},'vulnerable','Repository HEAD discloses a detached private revision under deny-all repository policy.'),
        ('Archive bytes',{'routes':{'/backup.zip':response('PK\u0003\u0004INTERNAL_PAYROLL_EXPORT',headers={'Content-Type':'application/zip'})}},'vulnerable','Private payroll archive is served without authentication.'),
        ('Server runtime diagnostics',{'routes':{'/phpinfo.php':response('<html><title>PHP 8.3 diagnostics</title><table><tr><td>DB_PASSWORD</td><td>local-secret</td></tr></table></html>')}},'vulnerable','Runtime diagnostics disclose a database password.'),
    ]
    for name,fixture,state,reason in path_rows:
        add('paths',name,state,reason,fixture,'WEB_SENSITIVE_PATHS')
    add('paths','Gateway body','unknown','Upstream returned an error; resource access policy is unknown.',
        {'routes':{'/.env':response('upstream temporarily unavailable',502)}},'WEB_SENSITIVE_PATHS','origin unavailable')
    add('paths','Login redirect policy','unknown','Redirect alone does not show the protected resource or post-login authorization.',
        {'routes':{'/admin':response('',307,{'Location':'/login'})}},'WEB_SENSITIVE_PATHS','redirect only')

    admin_rows = [
        ('Static shell',{'fallback':response('<html><body><div id="app"></div><script src="/static/runtime.js"></script></body></html>')},'safe','Every route returns a public bootstrap document, without private data.'),
        ('Dynamic shell',{'dynamic_shell':True},'safe','Per-request nonce changes public bootstrap HTML; it still contains no private data.'),
        ('Login challenge',{'admin':response('{"error":"authentication_required"}',401,{'WWW-Authenticate':'Basic realm="operations"'})},'safe','Administrator access requires authentication.'),
        ('ACL refusal',{'admin':response('<html>Role required: operator</html>',403)},'safe','Unauthenticated access is denied by ACL.'),
        ('Public catalog example',{'admin':response('{"examples":[{"secret":"replace-this-placeholder"}],"notice":"public integration examples"}',headers={'Cache-Control':'public'})},'safe','Public documentation uses a secret-named example field; it contains no credential.'),
        ('Nested confidential rows',{'admin':response('{"result":{"confidential":[{"employee":"A","salary":74000}]}}')},'vulnerable','Private employee salary data is returned without authentication.'),
        ('Unlabelled salary table',{'admin':response('<html><h1>Payroll console</h1><table><tr><td>Employee 83</td><td>Salary 74000</td></tr></table></html>')},'vulnerable','Private payroll HTML is returned without authentication.'),
        ('Ordinary JSON fields',{'admin':response('{"items":[{"employee_id":83,"annual_pay":74000}],"total":1}')},'vulnerable','Private salary records use ordinary domain field names.'),
        ('Private cached report',{'admin':response('{"report":{"balance":4800,"account":"regional"}}',headers={'Cache-Control':'private, no-store'})},'vulnerable','Application contract marks this account report private; no login is enforced.'),
        ('Large public prefix',{'admin':response('<html>'+'<!-- layout padding -->'*230+'<p>Private employee salary: 74000</p></html>')},'vulnerable','Private data appears beyond the first 4096 bytes.','beyond sample boundary'),
    ]
    for row in admin_rows:
        name,fixture,state,reason,*observable = row
        if 'admin' in fixture:
            fixture={'routes':{'/admin':fixture['admin'],'/api/admin':fixture['admin']}}
        add('admin',name,state,reason,fixture,'admin',observable[0] if observable else 'direct')
    add('admin','Unclassified console', 'unknown','A console page title alone cannot establish whether any private data was returned.',
        {'routes':{'/admin':response('<html><h1>Operations console</h1><p>Loading...</p></html>')}},'admin','insufficient content')
    add('admin','Redirect to identity provider', 'unknown','Only local login redirect is observed; authorization after login is unknown.',
        {'routes':{'/admin':response('',302,{'Location':'/login'})}},'admin','redirect only')

    cors_rows = [
        ('Public weather','wild-public','safe','Public weather observations permit anonymous cross-origin reads.'),
        ('Fixed partner','allowlist','safe','Only the contracted partner origin receives CORS permission.'),
        ('Public echo','reflect-public','safe','Echoed origins without credentials are permitted for this public dataset.'),
        ('Same-origin private','no-cors','safe','CORS headers are absent; cross-origin reading is not enabled.'),
        ('Documented public without cache flag','wild-neutral','safe','Public catalog contract permits wildcard even without cache declaration.'),
        ('Invalid credential wildcard','wild-credential','vulnerable','Deployment requires a valid credentialed partner policy; wildcard+credentials violates configuration requirements. Browser reading is blocked.'),
        ('Private reflection marked','reflect-private','vulnerable','Private financial data is shared with arbitrary origins and credentials permission.'),
        ('Private reflection ordinary fields','reflect-neutral','vulnerable','Application contract marks account ledger private despite neutral JSON field names.'),
        ('Private reflection with field evidence','reflect-secret','vulnerable','Credential fields and arbitrary credentialed Origin reflection are combined.'),
        ('Null origin private','null-private','vulnerable','Private data grants credentials to opaque null origins contrary to partner-only policy.'),
    ]
    for name,mode,state,reason in cors_rows:
        add('cors',name,state,reason,{'cors_mode':mode},'cors','headers/content; no credentialed browser execution')
    add('cors','Unspecified data ownership','unknown','Reflected credentialed JSON has no known ownership/access policy.',
        {'cors_mode':'reflect-neutral'},'cors','ownership unknown')
    add('cors','Origin request timeout','unknown','Primary response succeeds but origin-specific requests time out.',
        {'cors_mode':'probe-timeout'},'cors','probes unavailable')

    auth_rows = [
        ('Bearer challenge',response('{"problem":{"status":401}}',401,{'WWW-Authenticate':'Bearer realm="ledger"'}),'safe','Unauthenticated request is rejected.'),
        ('Forbidden operations',response('{"code":"ACCESS_DENIED"}',403),'safe','Role check rejects anonymous access.'),
        ('Public health endpoint',response('{"service":"catalog","health":"green"}'),'safe','Health status is intentionally public and requires no authentication.'),
        ('Public version endpoint',response('{"release":"2026.11","region":"eu"}',headers={'Cache-Control':'public'}),'safe','Public release metadata does not require authentication.'),
        ('Authentication concealed by 404',response('{"message":"not available"}',404),'safe','Deployment deliberately conceals protected resources from unauthenticated callers.'),
        ('Unauthenticated profile',response('{"profile":{"email":"operator@example.invalid","phone":"555-0100"}}'),'vulnerable','Account profile contract requires authentication; records are public.'),
        ('Nested access token',response('{"payload":{"token":"local-evaluation-token"}}'),'vulnerable','Authentication credential is returned anonymously.'),
        ('Unprotected transactions',response('{"transactions":[{"amount":820,"currency":"EUR"}]}'),'vulnerable','Ledger endpoint requires account authentication.'),
        ('HTML customer report',response('<html><article>Customer invoice 382: EUR 820</article></html>'),'vulnerable','Private invoice is available to unauthenticated callers.'),
        ('Session attribute defect',response('{"signed_in":true}',headers={'Set-Cookie':'identity=M2; SameSite=None; HttpOnly'}),'vulnerable','Credential cookie is missing Secure.'),
    ]
    for name,r,state,reason in auth_rows:
        selector='AUTH_COOKIE_ATTRIBUTES' if name=='Session attribute defect' else 'auth_access'
        add('auth',name,state,reason,{'routes':{'/api/users':r}},selector,'unauthenticated response only')
    add('auth','Upstream unavailable','unknown','Gateway failure prevents authentication assessment.',
        {'routes':{'/api/users':response('{"error":"dependency unavailable"}',503)}},'auth_access','origin unavailable')
    add('auth','Transport stalls','unknown','Request deadline prevents authentication assessment.',
        {'routes':{'/api/users':response(delay=1.12)}},'auth_access','request timeout')
    assert len(result)==72 and sum(c['evaluable'] for c in result)==60
    return result
