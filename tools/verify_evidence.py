"""Verify preserved evidence and recompute published metrics without a scanner or ZAP."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'docs/validation'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def metrics(rows, status_key='status'):
    known = [row for row in rows if row['truth'] != 'unknown']
    counts = Counter()
    for row in known:
        status = row[status_key]
        if status in ('WARNING', 'ERROR'):
            counts['ABSTAIN' if status == 'WARNING' else 'ERROR'] += 1
        elif row['truth'] == 'vulnerable':
            counts['TP' if status == 'FAIL' else 'FN'] += 1
        else:
            counts['FP' if status == 'FAIL' else 'TN'] += 1
    result = {key: counts[key] for key in ('TP', 'FP', 'FN', 'TN', 'ABSTAIN', 'ERROR')}
    tp, fp, fn, tn = (result[key] for key in ('TP', 'FP', 'FN', 'TN'))
    result.update(precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                  f1=ratio(2 * tp, 2 * tp + fp + fn),
                  coverage=ratio(tp + fp + fn + tn, len(known)),
                  vulnerable_detection=ratio(tp, sum(row['truth'] == 'vulnerable' for row in known)))
    return result


def compare(actual, expected):
    for key, value in actual.items():
        if key not in expected:
            continue
        assert (value is expected[key]) if value is None else math.isclose(value, expected[key]), key


def main():
    manifest = read(DATA / 'evidence_manifest.json')
    archive = DATA / manifest['archive']
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest['sha256']
    cases = {case['id']: case for case in read(DATA / 'final_holdout/cases.json')}
    expected = read(DATA / 'final_holdout/metrics.json')
    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == set(manifest['members'])
        for name, metadata in manifest['members'].items():
            raw = bundle.read(name)
            assert len(raw) == metadata['bytes'], name
            assert hashlib.sha256(raw).hexdigest() == metadata['sha256'], name
        def archived(name):
            return json.loads(bundle.read(name))
        prefix = 'docs/validation/final_holdout/'
        rows = [archived(name) for name in bundle.namelist() if name.startswith(prefix + '04_raw_results/')]
        assert len(rows) == len({(r['case_id'], r['mode'], r['repeat']) for r in rows}) == 900
        for row in rows:
            case = cases[row['case_id']]
            assert row['truth'] == case['truth'] and row['expected'] == case['expected']
            assert row['http_requests'] == len(row['http_events'])
            assert row['logical_requests'] == len(row['requests'])
            if row.get('scan'):
                selected = [f for f in row['scan']['all_findings']
                            if any(f['check_id'].startswith(p) for p in case['selector'])]
                assert selected == row['selected']
                status = ('ERROR' if not selected else 'FAIL' if any(f['status'] == 'FAIL' for f in selected)
                          else 'WARNING' if any(f['status'] == 'WARNING' for f in selected) else 'PASS')
                assert status == row['status']
        for mode in ('none', 'p1', 'headers'):
            group = [row for row in rows if row['mode'] == mode]
            for repeat in (1, 2, 3):
                repeated = [row for row in group if row['repeat'] == repeat]
                assert len(repeated) == 100
                compare(metrics(repeated), expected[mode]['metrics'])
            assert sum(row['http_requests'] for row in group) == expected[mode]['http_requests']
        registration = read(DATA / 'final_holdout/preregistration.json')
        for relative, digest in registration['input_hashes'].items():
            path = DATA / 'final_holdout' / relative.replace('\\', '/')
            raw = path.read_bytes() if path.is_file() else bundle.read(prefix + relative.replace('\\', '/'))
            assert hashlib.sha256(raw).hexdigest() == digest, relative
        for relative, digest in read(DATA / 'reproduction_hashes.json').items():
            assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest, relative
        comparison = read(DATA / 'tool_comparison/final_run/analysis.json')
        registration = read(DATA / 'tool_comparison/final_run/preregistration.json')
        computed = []
        zap_prefix = 'docs/validation/tool_comparison/final_run/'
        for case in registration['cases']:
            if case['group'] == 'excluded':
                continue
            for mode in registration['modes']:
                stem = case['id'] + '-' + mode + '.json'
                wss = archived(zap_prefix + 'wss/' + stem)
                zap = archived(zap_prefix + 'zap/' + stem)
                selected = []
                for alert in zap['alerts']:
                    if urlsplit(alert['url']).path not in (('/', '/api/login') if 'COOKIE' in case['id'] else ('/',)):
                        continue
                    positive = int(alert['riskcode']) >= 1 if 'riskcode' in alert else alert.get('risk') in ('Low', 'Medium', 'High')
                    if str(alert['pluginId']) not in case['zap_plugin_ids'] or not positive:
                        continue
                    if str(alert['pluginId']) in ('10055', '10054') and alert.get('alertRef') not in case['zap_alert_refs']:
                        continue
                    selected.append(alert)
                computed.append(dict(id=case['id'], mode=mode, group=case['group'], truth=case['truth'],
                                     wss=wss['status'], zap='FAIL' if selected else 'NO_ALERT',
                                     zap_alert_refs=sorted({a.get('alertRef', '') for a in selected})))
        assert len(computed) == 52
        originals = {(row['id'], row['mode']): row for row in comparison['case_results']}
        for row in computed:
            original = originals[row['id'], row['mode']]
            assert all(original[key] == value for key, value in row.items()), row['id']
        for mode in registration['modes']:
            group = [row for row in computed if row['group'] == 'primary' and row['mode'] == mode]
            assert len(group) == 25
            for tool in ('wss', 'zap'):
                compare(metrics(group, tool), comparison['metrics'][mode][tool])
    print(f"Verified {len(manifest['members'])} evidence members; 900 holdout trials; 52 comparison trials; published metrics unchanged.")


if __name__ == '__main__':
    main()
