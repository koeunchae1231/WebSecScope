"""Optional service requirements, separate from bounded header observations."""
from copy import deepcopy
from urllib.parse import urlsplit

from websecscope.rules.web.header_policy import TARGET_HEADERS

CSP = 'content-security-policy'
REFERRER = 'referrer-policy'
PERMISSIONS = 'permissions-policy'
DENIABLE_FEATURES = {'camera', 'microphone', 'geolocation'}


def _names(values):
    if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
        raise ValueError('Header names must be a nonempty list of supported names')
    normalized = [v.lower() for v in values]
    if any(v not in TARGET_HEADERS for v in normalized) or len(set(normalized)) != len(normalized):
        raise ValueError('Unsupported or duplicate header name')
    return normalized


def validate_requirements(rules, validate_path):
    if not isinstance(rules, list) or len(rules) > 1000:
        raise ValueError('header_requirements must be a list of at most 1000 rules')
    result = []
    scopes = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {'scope', 'path', 'required_headers', 'strength'}:
            raise ValueError('Unknown header requirement fields')
        if ('path' in rule) == ('scope' in rule):
            raise ValueError('Specify exactly one header scope: path or scope=origin')
        if 'path' in rule:
            validate_path(rule['path'])
            scope = ('path', rule['path'])
        else:
            if rule['scope'] != 'origin':
                raise ValueError('Header scope must be origin')
            scope = ('origin', None)
        if scope in scopes:
            raise ValueError('Duplicate/conflicting header requirement scope; combine into one rule')
        scopes.add(scope)
        required = _names(rule['required_headers']) if 'required_headers' in rule else []
        raw_strength = rule.get('strength', {})
        if not isinstance(raw_strength, dict) or ('strength' in rule and not raw_strength):
            raise ValueError('strength must be a nonempty object')
        strength = {}
        for name, value in raw_strength.items():
            if not isinstance(name, str):
                raise ValueError('Strength header name must be a string')
            normalized = name.lower()
            if normalized not in TARGET_HEADERS or normalized in strength:
                raise ValueError('Unsupported or duplicate strength header')
            if normalized == CSP and value != 'p2-restricted-script-object':
                raise ValueError('Unsupported CSP strength requirement')
            if normalized == REFERRER and value != 'no-cross-origin-full-url':
                raise ValueError('Unsupported Referrer strength requirement')
            if normalized == PERMISSIONS:
                if not isinstance(value, dict) or set(value) != {'deny_features'}:
                    raise ValueError('Permissions strength requires deny_features only')
                features = value['deny_features']
                if (not isinstance(features, list) or not features or any(not isinstance(f, str) or f not in DENIABLE_FEATURES for f in features)
                        or len(set(features)) != len(features)):
                    raise ValueError('deny_features requires distinct supported feature names')
            strength[normalized] = deepcopy(value)
        if not required and not strength:
            raise ValueError('Empty header requirement rule')
        result.append(dict(scope=scope, required=required, strength=strength, original=deepcopy(rule)))
    return result


def matching_rules(policy, url):
    if policy is None or not policy.matches_origin(url):
        return []
    path = urlsplit(url).path or '/'
    return [r for r in policy.header_requirements if r['scope'][0] == 'origin' or r['scope'][1] == path]


def evaluate_requirement(name, values, analysis, baseline, policy, url, error=None):
    rules = [r for r in matching_rules(policy, url) if name in r['required'] or name in r['strength']]
    if not rules:
        return None
    expected = [dict(required=name in r['required'], strength=r['strength'].get(name)) for r in rules]
    outcomes = []
    reasons = []
    present = any(v.strip() for v in values)
    for r in rules:
        strength = r['strength'].get(name)
        if error:
            status, reason = 'WARNING', 'Incomplete response; requirement compliance cannot be established'
        elif not present:
            status, reason = 'FAIL', 'Required nonempty enforcing header is absent'
        elif strength is None:
            status, reason = 'PASS', 'Explicit header-presence requirement satisfied; no strength requirement implied'
        elif name == CSP:
            status = analysis['status']
            reason = 'P2 script/object restriction requirement: ' + analysis['reason']
        elif name == REFERRER:
            selected = analysis.get('selected_policy')
            if selected is None:
                status, reason = 'WARNING', 'Selected Referrer policy could not be determined'
            else:
                status = 'FAIL' if analysis['cross_origin'] == 'full URL' else 'PASS'
                reason = 'Declared cross-origin full-URL prohibition; selected policy: ' + selected
        else:
            features = analysis.get('features', {})
            if analysis.get('duplicates') or analysis.get('unknown_features') or not features:
                status, reason = 'WARNING', 'Ambiguous/unsupported feature declaration prevents a compliance conclusion'
            elif any(f in features and features[f] != [] for f in strength['deny_features']):
                status, reason = 'FAIL', 'Explicit nonempty feature allowlist violates declared empty-list requirement'
            elif any(f not in features for f in strength['deny_features']):
                status, reason = 'WARNING', 'Required feature denial is not explicit; browser defaults cannot establish compliance'
            else:
                status, reason = 'PASS', 'All declared feature denials are explicit empty allowlists'
        outcomes.append(status)
        reasons.append(reason)
    requirement_status = 'FAIL' if 'FAIL' in outcomes else 'WARNING' if 'WARNING' in outcomes else 'PASS'
    # Presence never waives independent P2 weaknesses. A selected Referrer rule
    # can resolve P2's service-context warning, but never a malformed-policy FAIL.
    resolved_referrer = name == REFERRER and any(e['strength'] for e in expected) and analysis.get('selected_policy') is not None
    status = ('FAIL' if 'FAIL' in {baseline, requirement_status} else
              'WARNING' if requirement_status == 'WARNING' or (baseline == 'WARNING' and not resolved_referrer) else 'PASS')
    return dict(status=status, requirement_status=requirement_status, baseline_status=baseline,
                reason='; '.join(reasons), expected=expected, observed_header_values=list(values),
                applied_path=urlsplit(url).path or '/', policy=[policy.reference(r['original']) for r in rules],
                finding_kind='service_requirement', exploitability_verified=False)
