"""Loopback-only ground-truth baseline; production sources are never edited.

Run from repository root with Python 3.10+: python tools/validation/baseline.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from websecscope.scanner import web, api_scanner, auth_scanner, orchestrator

OUT = ROOT / 'docs/validation/results'
HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=()',
}


def case(cid, family, truth, check, reason, **config):
    return dict(id=cid, family=family, vulnerable=truth, check=check,
                expected='FAIL' if truth else 'PASS', reason=reason, config=config)


def cases():
    result = []
    for key in HEADERS:
        check = 'WEB_HEADER_' + key.upper().replace('-', '_')
        result += [case('H-' + str(len(result)+1), 'headers', False, check,
                        'Configured restrictive nonempty header', header=key),
                   case('H-' + str(len(result)+2), 'headers', True, check,
                        'Required hardening header absent', missing=key)]
    result += [case('H-13', 'headers', True, 'WEB_HEADER_X_CONTENT_TYPE_OPTIONS',
                    'Invalid value does not enable nosniff', invalid=True),
               case('H-14', 'headers', True, 'WEB_HEADER_CONTENT_SECURITY_POLICY',
                    'GET document lacks CSP although HEAD includes it', head_get=True)]
    for cid, truth, cookie, reason in [
        ('C-01', False, 'session=demo; Secure; HttpOnly; SameSite=Strict', 'All attributes configured'),
        ('C-02', True, 'session=demo', 'Session cookie lacks all three attributes'),
        ('C-03', True, 'session=secure_httponly_samesite', 'Keywords occur only in value, no attributes'),
        ('C-04', True, 'session=demo; Secure; HttpOnly; SameSite=invalid', 'Invalid SameSite value'),
        ('C-05', False, None, 'No cookie issued; no cookie attribute violation')]:
        result.append(case(cid, 'cookies', truth, 'WEB_COOKIE_FLAGS', reason, cookie=cookie))
    for cid, truth, mode, reason in [
        ('P-01', False, '404', 'All candidate resources absent'),
        ('P-02', True, 'exposed', 'GET /.env serves synthetic secret without authentication'),
        ('P-03', False, '401', 'Administrator content rejected with 401'),
        ('P-04', False, '403', 'Administrator content rejected with 403'),
        ('P-05', False, 'spa', 'Unknown paths return public SPA shell, no secrets'),
        ('P-06', True, 'head404', 'GET /.env discloses secret; HEAD incorrectly returns 404'),
        ('P-07', False, 'head200', 'HEAD /.env returns 200 but GET returns 404 without secret'),
        ('P-08', False, '500', 'Generic empty 500; no sensitive resource exists'),
        ('P-09', False, 'redirect', 'Admin redirects to login; no sensitive content')]:
        result.append(case(cid, 'paths', truth, 'WEB_SENSITIVE_PATHS', reason, mode=mode))
    for cid, truth, mode, reason in [
        ('O-01', False, 'allowlist', 'Only trusted origin allowed'),
        ('O-02', True, 'wildcred', 'Invalid wildcard plus credentials policy (configuration defect; browsers block credentialed reads)'),
        ('O-03', True, 'reflect', 'Arbitrary Origin reflected with credentials on private response'),
        ('O-04', False, 'public', 'Intentionally public data with wildcard, no credentials')]:
        result.append(case(cid, 'cors', truth, 'cors', reason, cors=mode))
    for cid, truth, mode, reason in [
        ('A-01', False, '401', 'Admin requires authentication'),
        ('A-02', False, '403', 'Admin access forbidden'),
        ('A-03', True, 'admin', 'Admin GET serves synthetic private data'),
        ('A-04', False, 'spa', 'Admin URL serves only public SPA shell')]:
        result.append(case(cid, 'admin', truth, 'admin', reason, mode=mode))
    result += [case('D-01', 'docs', True, 'docs', 'OpenAPI schema intentionally private but served publicly', mode='docs'),
               case('D-02', 'docs', False, 'docs', 'Documentation absent'),
               case('U-01', 'unsupported', True, 'none', 'SQL injection exploitation is not implemented', unsupported=True),
               case('E-01', 'availability', None, 'none', 'Root HEAD and GET exceed native 1 second deadline', timeout=True),
               case('E-02', 'availability', None, 'none', 'Bound but non-listening loopback socket refuses connections', refused=True),
               case('E-03', 'availability', None, 'none', 'Sensitive HEAD probes time out; root and API remain reachable', path_timeout=True)]
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.respond()

    def do_GET(self):
        self.respond()

    def respond(self):
        cfg = self.server.cfg
        path = self.path.split('?', 1)[0]
        mode = cfg.get('mode')
        status, body = (200, b'public home') if path == '/' else (404, b'not found')
        extra = {}
        if cfg.get('timeout') and path == '/' or cfg.get('path_timeout') and path.lstrip('/') in web.SENSITIVE_PATHS:
            time.sleep(1.25)
        if mode == 'spa':
            status, body = 200, b'<html>public SPA shell</html>'
        if path == '/.env':
            if mode == 'exposed' or mode == 'head404' and self.command == 'GET':
                status, body = 200, b'SYNTHETIC_SECRET=fixture_only'
            if mode == 'head200' and self.command == 'HEAD':
                status = 200
        if path in {'/admin', '/api/admin'}:
            if mode in {'401', '403', '500'}:
                status, body = int(mode), b''
            if mode == 'admin':
                status, body = 200, b'{"private_admin":"fixture_only"}'
            if mode == 'redirect':
                status, body = 302, b''
                extra['Location'] = '/login'
        if mode == 'docs' and path == '/openapi.json':
            status, body = 200, b'{"openapi":"3.0.0","private_schema":true}'
        if cfg.get('cors') and path == '/api/users':
            status, body = 200, b'{"fixture_data":true}'
            cors = cfg['cors']
            extra['Access-Control-Allow-Origin'] = ('*' if cors in {'wildcred', 'public'} else
                self.headers.get('Origin', 'https://trusted.example') if cors == 'reflect' else 'https://trusted.example')
            if cors != 'public':
                extra['Access-Control-Allow-Credentials'] = 'true'
        headers = HEADERS.copy()
        headers.pop(cfg.get('missing'), None)
        if cfg.get('invalid'):
            headers['X-Content-Type-Options'] = 'invalid'
        if cfg.get('head_get') and self.command == 'GET':
            headers.pop('Content-Security-Policy')
        if cfg.get('cookie') and path == '/':
            headers['Set-Cookie'] = cfg['cookie']
        headers.update(extra)
        self.server.events.append(dict(method=self.command, path=path, status=status,
                                       origin=self.headers.get('Origin'), headers=headers, body=body.decode()))
        try:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command == 'GET':
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


def selected(c, findings):
    if c['family'] == 'cors':
        return [f for f in findings if f.category == 'cors']
    if c['family'] in {'admin', 'docs'}:
        cid = 'API_ADMIN_PATH_EXPOSED' if c['family'] == 'admin' else 'API_DOCS_EXPOSED'
        return [f for f in findings if f.check_id in {cid, 'API_ENDPOINT_EXPOSURE'}]
    return [f for f in findings if f.check_id == c['check']]


def metrics(rows):
    counts = Counter(r['classification'] for r in rows)
    tp, fp, fn, tn = (counts[k] for k in ('TP', 'FP', 'FN', 'TN'))
    ratio = lambda a, b: a / b if b else None
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=ratio(tp,tp+fp),
                recall=ratio(tp,tp+fn), fpr=ratio(fp,fp+tn), accuracy=ratio(tp+tn,tp+fp+fn+tn),
                abstained=counts['ABSTAIN'], errors=counts['ERROR'], excluded=counts['EXCLUDED'],
                coverage=ratio(tp+fp+fn+tn, len(rows)-counts['EXCLUDED']))


def stats(values):
    return dict(n=len(values), mean=statistics.mean(values), p95=sorted(values)[math.ceil(.95*len(values))-1])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for folder in ('websecscope', 'tests') for p in (ROOT/folder).rglob('*.py')}
    runs = []
    for c in cases():
        if c['config'].get('unsupported'):
            continue
        for repeat in range(3):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.cfg, server.events = c['config'], []
            if c['config'].get('refused'):
                # Keep port reserved, without listening; do not scan a possibly reused closed port.
                server.server_close()
                import socket
                reserved = socket.socket()
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            else:
                port = server.server_port
                threading.Thread(target=server.serve_forever, daemon=True).start()
            target = f'http://127.0.0.1:{port}/'
            timings, requests = {}, []
            def timed(name, fn):
                def call(*args, **kwargs):
                    start = time.perf_counter()
                    try:
                        return fn(*args, **kwargs)
                    finally:
                        timings[name] = timings.get(name, 0) + time.perf_counter()-start
                return call
            def traced(fn, method):
                def call(url, *args, **kwargs):
                    start = time.perf_counter()
                    obs = fn(url, *args, **kwargs)
                    requests.append(dict(url=url, method=kwargs.get('method', method),
                        elapsed=time.perf_counter()-start, observation={k:v for k,v in obs.items() if k != 'headers'}))
                    return obs
                return call
            start = time.perf_counter()
            error = None
            with patch.object(web, '_request', traced(web._request, 'HEAD')), \
                 patch.object(api_scanner, 'request_observation', traced(api_scanner.request_observation, 'GET')), \
                 patch.object(auth_scanner, 'request_observation', traced(auth_scanner.request_observation, 'GET')):
                from contextlib import ExitStack
                with ExitStack() as stack:
                    for name in ('scan_web_target', 'scan_api_endpoints', 'scan_auth_controls', 'analyze_api_auth', 'calculate_score'):
                        stack.enter_context(patch.object(orchestrator, name, timed(name, getattr(orchestrator, name))))
                    try:
                        scan = orchestrator.run_scan(target, include_linux=False, include_docker=False,
                                                     include_service_detect=False, include_cve=False)
                        findings = scan.findings
                    except Exception as exc:
                        error, findings, scan = repr(exc), [], None
            elapsed = time.perf_counter()-start
            chosen = selected(c, findings)
            status = ('FAIL' if any(f.status == 'FAIL' for f in chosen) else
                      'WARNING' if any(f.status == 'WARNING' for f in chosen) else 'PASS' if chosen else 'NO_RESULT')
            if c['vulnerable'] is None:
                classification = 'EXCLUDED'
            elif error or not chosen:
                classification = 'ERROR'
            elif status == 'WARNING':
                classification = 'ABSTAIN'
            else:
                classification = ('TP' if c['vulnerable'] else 'FP') if status == 'FAIL' else ('FN' if c['vulnerable'] else 'TN')
            if c['config'].get('refused'):
                reserved.close()
            else:
                server.shutdown()
                server.server_close()
                time.sleep(.3)  # Let timed-out fixture handlers append their events before copying.
            failed_requests = [r for r in requests if r['observation'].get('error')]
            runs.append(dict(case_id=c['id'], repeat=repeat+1, target=target, seconds=elapsed, modules=timings,
                status=status, classification=classification, selected=[asdict(f) for f in chosen],
                findings=[asdict(f) for f in findings], security_score=scan.score if scan else None,
                api_scan=scan.api_scan if scan else None, auth_scan=scan.auth_scan if scan else None,
                requests=requests, server_events=list(server.events), exception=error,
                request_errors=len(failed_requests), timeout_errors=sum('Timeout' in r['observation']['error'] for r in failed_requests)))
            print(c['id'], repeat+1, classification, status, round(elapsed, 4), flush=True)
    first = [r for r in runs if r['repeat'] == 1]
    regression = subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=ROOT, capture_output=True, text=True)
    (OUT/'regression.log').write_text(regression.stdout+regression.stderr, encoding='utf-8')
    after = {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in hashes}
    payload = dict(generated_at=datetime.now(timezone.utc).isoformat(), python=sys.version, platform=platform.platform(),
        command=[sys.executable, 'tools/validation/baseline.py'], repeats=3, cases=cases(), runs=runs,
        metrics=metrics(first), by_family={family:metrics([r for r in first if next(c for c in cases() if c['id']==r['case_id'])['family']==family])
            for family in sorted({c['family'] for c in cases()})},
        timing=dict(total=stats([r['seconds'] for r in runs]), modules={name:stats([r['modules'][name] for r in runs if name in r['modules']]) for name in sorted({n for r in runs for n in r['modules']})}),
        request_errors=sum(r['request_errors'] for r in runs), timeout_errors=sum(r['timeout_errors'] for r in runs),
        scan_exceptions=sum(r['exception'] is not None for r in runs), regression_exit_code=regression.returncode,
        source_hashes=hashes, production_and_existing_tests_unchanged=hashes==after)
    (OUT/'baseline_results.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    with (OUT/'baseline_summary.csv').open('w', newline='', encoding='utf-8-sig') as file:
        fields = ['case_id','repeat','status','classification','seconds','security_score','request_errors','timeout_errors']
        writer = csv.DictWriter(file, fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(runs)
    print(json.dumps({k:payload[k] for k in ('metrics','timing','request_errors','timeout_errors','scan_exceptions','regression_exit_code','production_and_existing_tests_unchanged')}, indent=2))


if __name__ == '__main__':
    main()
