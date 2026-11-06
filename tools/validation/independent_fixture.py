"""Standalone loopback service, not based on the historical baseline Handler."""
import ipaddress
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from independent_cases import BASE


class Service(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.respond()

    def do_GET(self):
        self.respond()

    def respond(self):
        cfg = self.server.fixture
        path = urlsplit(self.path).path
        origin = self.headers.get('Origin')
        spec = cfg.get('routes', {}).get(path)
        if spec is None:
            spec = cfg.get('fallback') or (
                {'status':200,'body':'<html><head><title>Regional records portal</title></head><body><main>Service directory</main></body></html>'}
                if path == '/' else {'status':404,'body':'{"problem":{"type":"route-not-registered","status":404}}'})
        spec = dict(spec)
        if cfg.get('dynamic_shell'):
            spec = {'status':200, 'body':f'<html><body><div id="application"></div><script nonce="request-{self.server.counter}"></script></body></html>'}
        self.server.counter += 1
        headers = {**BASE, **spec.get('headers', {})}
        if path == '/':
            for key,value in cfg.get('root_headers', {}).items():
                if value is None:
                    headers.pop(key, None)
                else:
                    headers[key] = value
            if self.command == 'GET':
                headers.update(cfg.get('get_headers', {}))
        body = spec.get('body','')
        delay = spec.get('delay', 0)
        if path == '/' and self.command == 'GET':
            delay = max(delay, cfg.get('get_delay',0))
        mode = cfg.get('cors_mode') if path == '/api/users' else None
        if mode:
            spec['status'] = 200
            body = '{"observations":[{"station":"harbor","temperature_c":18}],"revision":7}'
            if mode in {'reflect-private','reflect-neutral','null-private','reflect-secret'}:
                body = '{"ledger":{"account_ref":"regional-42","entries":[{"amount":820,"currency":"EUR"}]}}'
            if mode == 'reflect-secret':
                body = '{"credentials":{"token":"independent-local-credential"}}'
            if mode in {'wild-public','reflect-public'}:
                headers['Cache-Control'] = 'public, max-age=120'
            if mode == 'reflect-private':
                headers['Cache-Control'] = 'private, no-store'
            if mode.startswith('wild'):
                headers['Access-Control-Allow-Origin'] = '*'
            elif mode == 'allowlist':
                headers['Access-Control-Allow-Origin'] = 'https://partner.example'
            elif mode == 'null-private':
                headers['Access-Control-Allow-Origin'] = 'null'
            elif mode != 'no-cors':
                headers['Access-Control-Allow-Origin'] = origin or 'https://partner.example'
            if mode in {'wild-credential','allowlist','reflect-private','reflect-neutral','reflect-secret','null-private','probe-timeout'}:
                headers['Access-Control-Allow-Credentials'] = 'true'
            if mode == 'probe-timeout' and origin:
                delay = 1.12
        cookies = cfg.get('cookies', []) if path == '/' else []
        cookies = [cookies] if isinstance(cookies, str) else cookies
        raw = body.encode('utf-8')
        status = spec.get('status',200)
        self.server.events.append(dict(method=self.command,path=path,origin=origin,status=status,delay=delay))
        if delay:
            time.sleep(delay)
        try:
            self.send_response(status)
            for key,value in headers.items():
                self.send_header(key,str(value))
            for value in cookies:
                self.send_header('Set-Cookie', value)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError,OSError):
            pass


def loopback_only(original):
    def connect(sock, address):
        assert ipaddress.ip_address(address[0]).is_loopback, f'Non-loopback connection prohibited: {address[0]}'
        return original(sock,address)
    return connect
