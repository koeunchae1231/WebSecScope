"""Immutable, preregistered evaluation. Never imports historical fixtures."""
import argparse
import contextlib
import hashlib
import json
import platform
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'docs/validation/independent_evaluation'
sys.path.insert(0, str(ROOT))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write(name, obj):
    (OUT/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')


def read(name):
    return json.loads((OUT/name).read_text(encoding='utf-8'))


def git(*args):
    return subprocess.check_output(['git', *args],cwd=ROOT).decode('utf-8',errors='replace')


def initialize():
    resume = OUT.exists()
    if resume:
        assert (OUT/'runner_before_initialization_fix.py').exists() and not (OUT/'environment.json').exists(), 'Refusing to overwrite evaluation'
        verify()
    assert git('branch','--show-current').strip() == 'improve/sensitive-path-validation'
    OUT.mkdir(parents=True,exist_ok=True)
    sources={str(p.relative_to(ROOT)):sha(p) for folder in ('websecscope','tests') for p in (ROOT/folder).rglob('*.py')}
    sources['pytest.ini']=sha(ROOT/'pytest.ini')
    if not resume:
        write('target_hashes.json',sources)
    history={str(p.relative_to(ROOT)):sha(p) for folder in ('results','baseline_v1','improvement_01','improvement_02','improvement_03','improvement_04')
             for p in (ROOT/'docs/validation'/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    if not resume:
        write('history_hashes.json',history)
    checked=0
    for folder in ('improvement_02','improvement_03','improvement_04'):
        base=ROOT/'docs/validation'/folder
        history_file=base/'history_manifest.json'
        for rel,digest in (json.loads(history_file.read_text(encoding='utf-8')) if history_file.exists() else {}).items():
            assert sha(ROOT/rel)==digest,rel
            checked+=1
        for rel,digest in json.loads((base/'before/manifest.json').read_text(encoding='utf-8')).items():
            assert sha(base/'before'/rel)==digest,rel
            checked+=1
    base=ROOT/'docs/validation/baseline_v1'
    for rel,digest in json.loads((base/'manifest.json').read_text(encoding='utf-8')).items():
        assert sha(base/rel)==digest,rel
        checked+=1
    last=json.loads((ROOT/'docs/validation/improvement_04/results/baseline_results.json').read_text(encoding='utf-8'))
    for rel,digest in last['source_hashes'].items():
        assert sha(ROOT/rel)==digest,rel
        checked+=1
    comparison=json.loads((ROOT/'docs/validation/improvement_04/comparison.json').read_text(encoding='utf-8'))
    assert comparison['after_sha256']==sha(ROOT/'docs/validation/improvement_04/results/baseline_results.json')
    (OUT/'git_before.log').write_text(git('status','--porcelain=v1')+'\nHEAD '+git('rev-parse','HEAD')+'\n'+git('diff','--stat')+'\n'+git('diff')+'\nSTAGED\n'+git('diff','--cached'),encoding='utf-8')
    write('environment.json',dict(recorded_at=datetime.now(timezone.utc).isoformat(),python=sys.version,executable=sys.executable,
          platform=platform.platform(),branch=git('branch','--show-current').strip(),revision=git('rev-parse','HEAD').strip(),
          historical_digest_checks=checked,target='dirty working tree identified by target_hashes.json',
          external_scans=False,invocation=[sys.executable,*sys.argv[1:]]))
    p=subprocess.run([sys.executable,'-m','pytest','-q'],cwd=ROOT,capture_output=True,text=True)
    (OUT/'pytest_before.log').write_text(p.stdout+p.stderr,encoding='utf-8')
    assert p.returncode==0 and '153 passed' in p.stdout
    verify()
    print(f'Initialized: {len(sources)} target/test/config hashes, {len(history)} historical files, {checked} prior digest checks; 153 tests passed.')


def verify():
    for name in ('target_hashes.json','history_hashes.json'):
        for rel,digest in read(name).items():
            assert sha(ROOT/rel)==digest,rel
    if (OUT/'preregistration.json').exists():
        for rel,digest in read('preregistration.json')['hashes'].items():
            assert sha(ROOT/rel)==digest,rel


def freeze():
    from independent_cases import cases
    verify()
    assert not (OUT/'preregistration.json').exists()
    write('cases.json',cases())
    write('policy.json',dict(
        unit='One scenario; repeat 1 supplies accuracy. All 3 repeats supply timing and agreement.', repeats=3,
        positive='FAIL',negative='PASS',abstain='WARNING',error='exception or no selected Finding',
        selection='Scenario selector fixes scope before execution; FAIL dominates WARNING dominates PASS. No result is ERROR, never PASS.',
        truth='safe/vulnerable application contract independent of scanner capabilities; unknown has no binary label.',
        evaluable='60 labelled cases regardless of observability. 12 unknown scenarios excluded from binary accuracy, reported separately.',
        metrics='TP/FP/FN/TN exclude WARNING and ERROR; accuracy=(TP+TN)/binary decisions; coverage=binary decisions/60.',
        warning_negative='Convert labelled WARNING to FN if vulnerable, TN if safe; ERROR remains an error excluded from that denominator.',
        conservative='(TP+TN)/60; every WARNING/ERROR is incorrect.', zero_denominator=None,
        observations='Request deadlines stay at production defaults; no browser, login cookie, TLS, preflight or cross-user exploitation verification.',
        requests='Both logical calls and server HTTP events recorded; mean request cost uses server HTTP events including redirect hops.',
        agreement='Cases with identical selected statuses AND check_id/status sets across all 3 runs /72.',
        unknown='No TP/TN credit. Report PASS/FAIL/WARNING/ERROR counts and unresolved-evidence behaviour separately.',
        changes='No target, fixture, truth, selector or scoring edits after freeze. Harness failures retained; corrections versioned before rerun.',
        sources=['https://www.rfc-editor.org/rfc/rfc6265.html','https://fetch.spec.whatwg.org/#cors-protocol-and-credentials',
                 'https://www.rfc-editor.org/rfc/rfc6797','https://www.w3.org/TR/CSP3/'],
        corpus_limit='Constructed by the same agent that implemented improvements, not a blind external holdout. No pre-freeze scanner trial. Fixed candidate URLs are necessary interface constraints; service contracts and bodies are new.'))
    files=[OUT/'cases.json',OUT/'policy.json',OUT/'target_hashes.json',OUT/'history_hashes.json']
    files += [ROOT/'tools/validation'/name for name in ('independent_cases.py','independent_fixture.py','independent_evaluation.py','independent_report.py')]
    write('preregistration.json',dict(frozen_at=datetime.now(timezone.utc).isoformat(),cases=72,labelled=60,unknown=12,
                                   hashes={str(p.relative_to(ROOT)):sha(p) for p in files}))
    print('Preregistered 72 new scenarios, fixture code, truth, selectors and policy. Scanner has not been run on this corpus.')


def selected(case, findings):
    selector=case['selector']
    if selector=='admin':
        return [f for f in findings if f.check_id in {'API_ADMIN_PATH_EXPOSED','API_ENDPOINT_EXPOSURE'}]
    if selector=='cors':
        return [f for f in findings if f.category=='cors']
    if selector=='auth_access':
        return [f for f in findings if f.category=='auth' and f.check_id in {
            'AUTH_MAY_BE_MISSING_API_USERS','AUTH_PROTECTED_API_USERS','AUTH_PUBLIC_SHELL_API_USERS'}]
    return [f for f in findings if f.check_id==selector]


def run():
    from independent_fixture import Handler, Service, loopback_only
    from websecscope.scanner import orchestrator, web, api_scanner, auth_scanner
    verify()
    folder=OUT/'runs'
    assert not folder.exists(), 'Refusing to overwrite any prior trial'
    folder.mkdir()
    cases=read('cases.json')
    log=(OUT/'execution.log').open('x',encoding='utf-8')
    start_all=time.perf_counter()
    try:
        for case in cases:
            for repeat in (1,2,3):
                verify()
                server=Service(('127.0.0.1',0),Handler)
                server.fixture=case['input_conditions']
                server.events=[]
                server.counter=0
                thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
                thread.start()
                target=f'http://127.0.0.1:{server.server_port}/'
                requests=[]
                def traced(original, default_method):
                    def call(url,*args,**kwargs):
                        begin=time.perf_counter()
                        obs=original(url,*args,**kwargs)
                        requests.append(dict(url=url,method=kwargs.get('method',default_method),seconds=time.perf_counter()-begin,
                                             error=obs.get('error'),status=obs.get('status_code',obs.get('status'))))
                        return obs
                    return call
                start=time.perf_counter()
                error=None
                scan=None
                try:
                    with patch.object(socket.socket,'connect',loopback_only(socket.socket.connect)), \
                         patch.object(web,'_request',traced(web._request,'HEAD')), \
                         patch.object(api_scanner,'request_observation',traced(api_scanner.request_observation,'GET')), \
                         patch.object(auth_scanner,'request_observation',traced(auth_scanner.request_observation,'GET')):
                        scan=orchestrator.run_scan(target,include_linux=False,include_docker=False,include_service_detect=False,include_cve=False)
                    findings=scan.findings
                except Exception as exc:
                    error=f'{type(exc).__name__}: {exc}'
                    findings=[]
                seconds=time.perf_counter()-start
                server.shutdown()
                server.server_close()
                thread.join()
                chosen=selected(case,findings)
                status='ERROR' if error or not chosen else 'FAIL' if any(f.status=='FAIL' for f in chosen) else 'WARNING' if any(f.status=='WARNING' for f in chosen) else 'PASS'
                truth=case['security_state']
                classification='EXCLUDED' if not case['evaluable'] else 'ERROR' if status=='ERROR' else 'ABSTAIN' if status=='WARNING' else (
                    ('TP' if truth=='vulnerable' else 'FP') if status=='FAIL' else ('FN' if truth=='vulnerable' else 'TN'))
                row=dict(case_id=case['id'],area=case['area'],repeat=repeat,truth=truth,evaluable=case['evaluable'],
                         target=target,status=status,classification=classification,seconds=seconds,
                         selected=[asdict(f) for f in chosen],findings=[asdict(f) for f in findings],exception=error,
                         requests=requests,http_events=list(server.events),http_requests=len(server.events),logical_requests=len(requests),
                         errors=sum(bool(r['error']) for r in requests),timeouts=sum('Timeout' in (r['error'] or '') for r in requests),
                         api_scan=scan.api_scan if scan else None,auth_scan=scan.auth_scan if scan else None)
                (folder/f'{case["id"]}-{repeat}.json').write_text(json.dumps(row,indent=2,ensure_ascii=False),encoding='utf-8')
                log.write(f'{case["id"]} {repeat} truth={truth} status={status} class={classification} seconds={seconds:.6f} requests={len(server.events)}\n')
                log.flush()
        verify()
        (OUT/'git_after.log').write_text(git('status','--porcelain=v1'),encoding='utf-8')
        write('completion.json',dict(completed_at=datetime.now(timezone.utc).isoformat(),runs=216,wall_seconds=time.perf_counter()-start_all,
                                    target_unchanged=True,history_unchanged=True,preregistered_inputs_unchanged=True))
    finally:
        log.close()
    print('216 trials completed; target, histories and preregistered inputs unchanged.')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['initialize','freeze','run','verify'])
    globals()[parser.parse_args().action]()
