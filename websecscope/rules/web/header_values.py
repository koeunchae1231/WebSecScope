"""Conservative configuration checks, not a browser or full CSP evaluator."""
import re

# Retain these public names for callers of the original validation module.
from websecscope.rules.web.header_policy import CSP_DIRECTIVES, REFERRER_POLICIES


def validate_header(name: str, value: str) -> tuple[str, str]:
    """Return PASS/FAIL/WARNING for configuration validity, independent of scheme."""
    name = name.lower()
    if name in {'content-security-policy', 'referrer-policy', 'permissions-policy'}:
        from websecscope.rules.web.header_policy import assess_header
        result = assess_header(name, [value])
        return result['status'], result['reason']
    value = value.strip()
    if not value:
        return 'FAIL', 'missing or empty value'
    if name == 'x-content-type-options':
        return ('PASS','nosniff configured') if value.lower()=='nosniff' else ('FAIL','expected nosniff')
    if name == 'x-frame-options':
        return ('PASS','recognized frame directive') if value.upper() in {'DENY','SAMEORIGIN'} else ('FAIL','expected DENY or SAMEORIGIN; ALLOW-FROM is obsolete')
    if name == 'strict-transport-security':
        directives=[p.strip() for p in value.split(';') if p.strip()]
        ages=[]
        names=[]
        for item in directives:
            key,sep,arg=item.partition('=')
            key=key.strip().lower()
            names.append(key)
            if key=='max-age':
                if not sep or not re.fullmatch(r'"?[0-9]+"?',arg.strip()) or arg.strip().count('"') not in {0,2}:
                    return 'FAIL','max-age must be a nonnegative decimal integer'
                ages.append(bool(arg.strip().strip('"').strip('0')))
            elif key in {'includesubdomains','preload'} and sep:
                return 'FAIL',f'{key} must not have a value'
        if not ages or not all(ages):
            return 'FAIL','missing max-age or max-age=0 disables HSTS persistence'
        if len(names)!=len(set(names)):
            return 'WARNING','duplicate HSTS directives require review'
        return 'PASS','positive max-age configured; TLS/browser effect is a separate question'
    return 'WARNING','validator unavailable for this header'
