"""Replay unchanged holdout inputs on unchanged product code, locally only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',default='FH-HDR-01',help='Existing case ID or all')
    parser.add_argument('--mode',choices=['none','p1','headers'],default='none')
    parser.add_argument('--output',required=True)
    args=parser.parse_args();output=Path(args.output);assert not output.exists(),'Use a new output file'
    def read(p):return json.loads(p.read_text(encoding='utf-8'))
    for path,digest in read(ROOT/'docs/validation/reproduction_hashes.json').items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest,path
    hold=ROOT/'docs/validation/final_holdout'
    cases=[c for c in read(hold/'cases.json') if args.case=='all' or c['id']==args.case]
    assert cases,'Unknown existing case ID'
    spec=importlib.util.spec_from_file_location('public_holdout_fixture',hold/'fixture.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    from websecscope.scanner.orchestrator import run_scan
    from websecscope.policy import ScanPolicy
    connect=socket.socket.connect
    def guarded(sock,address):
        if address[0] not in ('127.0.0.1','::1','localhost'):raise OSError('Only loopback connections permitted')
        return connect(sock,address)
    results=[]
    for case in cases:
        server,thread=fixture.start(case['fixture']);target=f'http://127.0.0.1:{server.server_port}/'
        try:
            policy=None
            if args.mode!='none':
                data=read(hold/'policies'/f'{case["id"]}-{args.mode}.json');data['target_origin']=target
                policy=ScanPolicy(data,target)
            with patch.object(socket.socket,'connect',guarded):
                scan=run_scan(target,include_linux=False,include_docker=False,include_service_detect=False,include_cve=False,**({'policy':policy} if policy else {}))
            selected=[f.to_dict('en') for f in scan.findings if any(f.check_id.startswith(p) for p in case['selector'])]
            status='ERROR' if not selected else 'FAIL' if any(f['status']=='FAIL' for f in selected) else 'WARNING' if any(f['status']=='WARNING' for f in selected) else 'PASS'
            results.append(dict(case_id=case['id'],mode=args.mode,truth=case['truth'],status=status,selected=selected,http_requests=len(server.events)))
        finally:fixture.stop(server,thread)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(dict(scope='New local replay; not replacement historical measurement',results=results),indent=2,ensure_ascii=False),encoding='utf-8')
    print('Local replay cases:',len(results))

if __name__=='__main__':main()
