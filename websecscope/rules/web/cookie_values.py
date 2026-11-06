"""Preserve duplicate attributes while parsing each Set-Cookie field separately."""
import re


def cookie_attributes(header: str) -> dict:
    # Split outside quoted values; do not split Expires dates or folded fields on commas.
    parts=[]
    start=0
    quoted=False
    escaped=False
    for i,ch in enumerate(header):
        if escaped:
            escaped=False
        elif ch=='\\' and quoted:
            escaped=True
        elif ch=='"':
            quoted=not quoted
        elif ch==';' and not quoted:
            parts.append(header[start:i].strip())
            start=i+1
    parts.append(header[start:].strip())
    name,sep,value=parts[0].partition('=')
    if quoted or not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or any(ch in value for ch in ';\r\n,'):
        return dict(name='unparsed',status='WARNING',issues=['malformed cookie field; attributes cannot be trusted'],attributes={})
    attrs={}
    for part in parts[1:]:
        if not part:
            continue
        key,sep,arg=part.partition('=')
        attrs.setdefault(key.strip().lower(),[]).append(arg.strip() if sep else None)
    missing=[key for key in ('secure','httponly','samesite') if key not in attrs]
    issues=[f'missing {key}' for key in missing]
    same=attrs.get('samesite',[])
    if any(v is None or v.lower() not in {'strict','lax','none'} for v in same):
        issues.append('invalid SameSite value; expected Strict, Lax or None')
    if any(v is not None and v.lower()=='none' for v in same) and 'secure' not in attrs:
        issues.append('SameSite=None requires Secure')
    status='FAIL' if issues else 'PASS'
    if any(len(values)>1 for key,values in attrs.items() if key in {'secure','httponly','samesite'}):
        issues.append('duplicate or conflicting security attributes; browser resolution is not assumed')
        if status=='PASS':
            status='WARNING'
    if any(v is not None for key in ('secure','httponly') for v in attrs.get(key,[])):
        issues.append('flag attribute carries a noncanonical value; presence is not a boolean value guarantee')
        if status=='PASS':
            status='WARNING'
    # Never return the cookie value or non-security attribute values in evidence.
    return dict(name=name,status=status,issues=issues,attributes={key:attrs[key] for key in ('secure','httponly','samesite') if key in attrs})
