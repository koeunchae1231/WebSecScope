"""Bounded body collection and explicit format evidence; no security verdicts."""
from email.message import Message
from http.client import HTTPException
from html.parser import HTMLParser
import json
import re
import time

BODY_LIMIT = 16 * 1024
BODY_SECONDS = 1.0


def _header(headers,name):
    return next((str(v) for k,v in headers.items() if k.lower()==name.lower()),'')


def inspect_body(raw,headers,*,collected=True,read_error=None):
    truncated=len(raw)>BODY_LIMIT
    sample=raw[:BODY_LIMIT]
    content_type=_header(headers,'Content-Type')
    message=Message();message['Content-Type']=content_type
    media=content_type.split(';',1)[0].strip().lower()
    charset=message.get_param('charset') or ('utf-8-sig' if sample.startswith(b'\xef\xbb\xbf') else 'utf-8')
    content_encoding=_header(headers,'Content-Encoding').strip().lower()
    decode_error=None
    try:body=sample.decode(charset,errors='strict')
    except (UnicodeError,LookupError,TypeError) as exc:
        body=sample.decode('utf-8',errors='replace')
        decode_error=f'{type(exc).__name__}: declared/default charset could not decode sample'
    declared=('json' if media=='application/json' or media.endswith('+json') else
              'html' if media in {'text/html','application/xhtml+xml'} else
              'text' if media.startswith('text/') else 'missing' if not media else 'unsupported')
    stripped=body.lstrip()
    detected=('json' if stripped.startswith(('{','[')) else
              'html' if re.search(r'<(?:!doctype\s+html|html|head|body|title|table|div|article|p|h1)\b',stripped,re.I) else
              declared if declared in {'json','html'} else
              'text' if declared in {'text','missing'} else 'unsupported')
    if not collected:detected='not_collected'
    parse_error=None
    if detected=='json':
        try:json.loads(body)
        except (ValueError,TypeError,RecursionError) as exc:parse_error=f'{type(exc).__name__}: JSON sample is incomplete or invalid'
    elif detected=='html':
        try:
            parser=HTMLParser();parser.feed(body);parser.close()
        except (ValueError,AssertionError,RecursionError) as exc:parse_error=f'{type(exc).__name__}: HTML tokenization failed'
    unsupported_encoding=content_encoding not in {'','identity'}
    complete=collected and not truncated and read_error is None
    evidence=dict(collected=collected,complete=complete,limit_bytes=BODY_LIMIT,bytes_read=len(raw),sample_bytes=len(sample),
        truncated=truncated,content_type=content_type or None,media_type=media or None,declared_format=declared,
        detected_format=detected,charset=charset,decode_error=decode_error,parse_error=parse_error,
        content_encoding=content_encoding or None,unsupported_content_encoding=unsupported_encoding,
        content_type_mismatch=collected and declared not in {'missing',detected},read_error=read_error,
        supported_for_text_analysis=collected and not (decode_error or parse_error or unsupported_encoding or detected=='unsupported'))
    evidence['content_type_values']=list(headers.get_all('Content-Type',[])) if hasattr(headers,'get_all') else [content_type] if content_type else []
    evidence['content_type_conflict']=len({v.split(';',1)[0].strip().lower() for v in evidence['content_type_values']})>1
    evidence['html_validation']='tokenization only; not browser/DOM validation' if detected=='html' else None
    return dict(body_sample=body,body_truncated=truncated,body_evidence=evidence,error=read_error)


def read_body(response,method='GET',deadline=None):
    if method=='HEAD':return inspect_body(b'',response.headers,collected=False)
    raw=bytearray();error=None
    deadline=min(deadline,time.monotonic()+BODY_SECONDS) if deadline is not None else time.monotonic()+BODY_SECONDS
    # Real HTTPResponse.read1 returns available bytes instead of waiting for a full buffer.
    read=getattr(response,'read1',response.read)
    try:
        while len(raw)<=BODY_LIMIT:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('body deadline exceeded')
            stream=response
            for _ in range(3):
                try:stream.fp.raw._sock.settimeout(remaining);break
                except (AttributeError,OSError):stream=getattr(stream,'fp',None)
            size=min(4096,BODY_LIMIT+1-len(raw))
            chunk=read(size)
            if not chunk:break
            raw.extend(chunk[:size])
    except (HTTPException,OSError,TimeoutError) as exc:
        error=f'{type(exc).__name__}: response body read failed or deadline exceeded'
    return inspect_body(bytes(raw),response.headers,read_error=error)
