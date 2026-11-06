from copy import deepcopy
from dataclasses import asdict
from itertools import permutations
import json
import random

import pytest

from websecscope.models import Finding, ScanResult, summarize_findings
from websecscope.scoring import calculate_score_details


def f(status='FAIL', risk='HIGH', metadata=None, check_id='ISSUE', evidence='observed'):
    return Finding(check_id,'web','Same title',status,risk,evidence,'Review',metadata or {})


def canonical(details):
    value=deepcopy(details)
    for row in value['entries']:
        row.pop('finding_index'); row.pop('finding_id')
    return value


@pytest.mark.parametrize('fs',[
    [f(), f()],
    [f(metadata={'confidence':'low'}), f(metadata={'confidence':'medium'}), f()],
    [f(risk='LOW'), f(risk='CRITICAL'), f(risk='MEDIUM')],
    [f(status='PASS'), f(status='WARNING'), f()],
    [f(check_id='ONE'), f(check_id='TWO'), f(check_id='THREE')],
    [f(metadata={'skipped':True}), f(), f(status='WARNING')],
])
def test_all_small_permutations(fs):
    before=deepcopy(fs)
    expected=canonical(calculate_score_details(fs))
    for order in permutations(fs):
        assert canonical(calculate_score_details(list(order)))==expected
    assert fs==before


def test_many_groups_random_permutations_and_clamp():
    fs=[f(risk=risk, check_id=f'ISSUE_{i%8}',metadata={'confidence':confidence})
        for i in range(20) for risk,confidence in [('HIGH','high'),('CRITICAL','low')]]
    expected=canonical(calculate_score_details(fs))
    rng=random.Random(42)
    for _ in range(30):
        rng.shuffle(fs)
        result=calculate_score_details(fs)
        assert canonical(result)==expected
        assert result['score']==100-sum(e['final_penalty'] for e in result['entries'])==0


def test_paths_and_assets_are_not_automatically_merged():
    fs=[f(metadata={'asset_id':asset,'path':path}) for asset,path in [('one','/a'),('one','/b'),('two','/a')]]
    result=calculate_score_details(fs)
    assert result['score']==55
    assert len({e['group_id'] for e in result['entries']})==3


def test_explicit_global_scope_groups_path_observations_only_with_same_asset():
    fs=[f(metadata={'path':path,'scoring_scope':{'kind':'global','asset_id':'server-one'}}) for path in ['/a','/b']]
    result=calculate_score_details(fs)
    assert result['score']==80
    assert len({e['group_id'] for e in result['entries']})==1
    fs.append(f(metadata={'scoring_scope':{'kind':'global','asset_id':'server-two'}}))
    assert calculate_score_details(fs)['score']==65


def test_missing_asset_and_invalid_global_use_exact_evidence():
    fs=[f(metadata={'path':'/a'},evidence=value) for value in ['one','two']]
    assert calculate_score_details(fs)['score']==70
    fs=[f(metadata={'scoring_scope':{'kind':'global'}},evidence=value) for value in ['one','two']]
    assert calculate_score_details(fs)['score']==70
    assert calculate_score_details([f(),f()])['score']==80


def test_different_checks_not_merged_even_with_same_title_and_asset():
    fs=[f(check_id=check,metadata={'asset_id':'one'}) for check in ['A','B']]
    assert calculate_score_details(fs)['score']==70


def test_integer_truncation_and_warning_floor():
    result=calculate_score_details([f(),f()])
    assert sorted(e['computed_penalty'] for e in result['entries'])==[5,15]
    result=calculate_score_details([f(status='WARNING',risk='LOW')]*8)
    assert result['score']==92


@pytest.mark.parametrize('metadata,check,expected',[
    ({'skipped':True},'ISSUE',True),({'skipped':False},'ISSUE',False),({},'ISSUE',False),
    ({},'LINUX_SCAN_SKIPPED',True),({},'DOCKER_SCAN_SKIPPED',True),
])
def test_skip_consistency_raw_json_localized_html(metadata,check,expected,tmp_path,monkeypatch):
    from websecscope.reporter.html_reporter import write_html_report
    monkeypatch.setattr('websecscope.reporter.html_reporter.generate_llm_report',
                        lambda request: {'enabled':False,'content':'','status':'unavailable'})
    item=f(status='WARNING',metadata=metadata,check_id=check,evidence='not skipped')
    details=calculate_score_details([item])
    assert details['entries'][0]['skipped']==expected
    for lang in ['en','ko']:
        payload=ScanResult('test',[item],details['score'],score_details=details).to_dict(lang)
        assert payload['findings'][0]['skipped']==expected
        assert payload['summary']['skipped_total']==int(expected)
        raw=asdict(item)
        raw['skipped']=not expected  # stale presentation flag must not control state
        assert summarize_findings([raw])['skipped_total']==int(expected)
        path=write_html_report(payload,tmp_path/f'{lang}.html',lang)
        assert ('<span class="badge">SKIPPED</span>' in path.read_text(encoding='utf-8'))==expected
        assert payload['summary']['skipped_total']==int(expected)


def test_cli_uses_same_score_and_json(monkeypatch,tmp_path,capsys):
    from argparse import Namespace
    from websecscope.cli.commands import scan
    fs=[f(evidence='not skipped'),f(metadata={'skipped':True})]
    details=calculate_score_details(fs)
    result=ScanResult('test',fs,details['score'],score_details=details)
    monkeypatch.setattr(scan,'run_scan',lambda *a,**kw:result)
    path=tmp_path/'result.json'
    scan.run_scan_command(Namespace(target='unused',lang='en',skip_api_auth=True,skip_linux=True,
        skip_docker=True,skip_service_detect=True,skip_cve=True,output=str(path)))
    assert f'Security Score: {result.score}' in capsys.readouterr().out
    payload=json.loads(path.read_text(encoding='utf-8'))
    assert payload['summary']['skipped_total']==1
    assert payload['score_details']['score']==payload['score']
