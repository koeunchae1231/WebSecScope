"""Specific configuration/diagnostic structures, never keyword-only privacy claims."""
from html.parser import HTMLParser
import json
import re


def _concrete(value):
    return isinstance(value,str) and bool(value.strip()) and not re.fullmatch(
        r'(?:example|placeholder|changeme|demo|sample|test|username|password|secret|token|redacted|masked|hidden|\[redacted\]|your[-_ ].+|replace[-_ ].+|<[^<>]+>|\*+)',value.strip(),re.I)


def json_credential_configuration(body):
    try:value=json.loads(body)
    except (ValueError,TypeError,RecursionError):return False
    if not isinstance(value,dict):return False
    # A named configuration section and a concrete identity/credential pair are required.
    for name,section in value.items():
        if str(name).lower() not in {'database','db','credentials','smtp'} or not isinstance(section,dict):continue
        fields={str(k).lower():v for k,v in section.items()}
        if any(_concrete(fields.get(k)) for k in ('username','user','login')) and any(
                _concrete(fields.get(k)) for k in ('password','passwd','token','secret')):
            return True
    return False


class _DiagnosticTable(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title=False;self.title=[];self.in_cell=False;self.cell=[];self.row=[];self.rows=[]
        self.example_depth=0
    def handle_starttag(self,tag,attrs):
        if tag in {'pre','code'}:self.example_depth+=1
        if self.example_depth:return
        if tag=='title':self.in_title=True
        if tag=='tr':self.row=[]
        if tag in {'td','th'}:self.in_cell=True;self.cell=[]
    def handle_data(self,data):
        if self.example_depth:return
        if self.in_title:self.title.append(data)
        if self.in_cell:self.cell.append(data)
    def handle_endtag(self,tag):
        if tag in {'pre','code'}:self.example_depth=max(0,self.example_depth-1);return
        if self.example_depth:return
        if tag=='title':self.in_title=False
        if tag in {'td','th'} and self.in_cell:
            self.row.append(''.join(self.cell).strip());self.in_cell=False
        if tag=='tr':self.rows.append(self.row);self.row=[]


def html_diagnostic_credentials(body):
    parser=_DiagnosticTable()
    try:parser.feed(body)
    except (ValueError,AssertionError,RecursionError):return False
    title=''.join(parser.title)
    if re.search(r'\b(?:examples?|documentation|reference|tutorial|samples?)\b',title,re.I):return False
    if not re.search(r'\bPHP\b',title,re.I) or not re.search(r'\b(?:diagnostics?|information|phpinfo|configuration)\b',title,re.I):return False
    return any(len(row)>=2 and re.fullmatch(r'(?:[A-Z][A-Z0-9]*_)+(?:PASSWORD|PASSWD|TOKEN|SECRET|KEY)',row[0])
               and _concrete(row[1]) for row in parser.rows)
