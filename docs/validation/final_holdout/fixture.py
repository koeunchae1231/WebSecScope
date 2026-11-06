"""Independent, declarative HTTP fixture. No scanner imports or truth-based behavior."""
import base64
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
from urllib.parse import urlsplit


class Service(ThreadingHTTPServer):
    daemon_threads=True
    block_on_close=False
    def __init__(self,fixture):
        self.fixture=deepcopy(fixture)
        self.events=[]
        self.lock=threading.Lock()
        self.active=0
        super().__init__(('127.0.0.1',0),Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*args):pass
    def do_HEAD(self):self.respond()
    def do_GET(self):self.respond()
    def respond(self):
        server=self.server
        path=urlsplit(self.path).path
        routes=server.fixture['routes']
        spec=deepcopy(routes.get(self.command+' '+path,routes.get(path,
            server.fixture['root'] if path=='/' else routes.get('*',dict(status=404,body='{"route":"absent"}',headers={'Content-Type':'application/json'})))))
        origin=self.headers.get('Origin')
        event=dict(method=self.command,path=self.path,request_headers=list(self.headers.items()),
                   origin=origin,planned_status=spec.get('status',200),response_completed=False,
                   received_at=time.monotonic())
        with server.lock:
            server.active+=1;server.events.append(event)
        try:
            delay=spec.get('delay',0)
            if origin=='https://websecscope-probe.invalid':delay+=spec.get('second_origin_delay',0)
            if delay:time.sleep(delay)
            if spec.get('disconnect'):
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                event['transport_action']='closed_before_headers'
                return
            headers={k:v for k,v in spec.get('headers',{}).items() if v is not None}
            if spec.get('cors_mode')=='reflect':
                headers['Access-Control-Allow-Origin']=origin or 'https://widget.atlas.invalid'
                if spec.get('cors_credentials'):headers['Access-Control-Allow-Credentials']=spec['cors_credentials']
                headers['Vary']='Origin'
            elif spec.get('cors_mode')=='allowlist':
                headers['Vary']='Origin'
                if origin in spec.get('allowed_origins',[]):
                    headers['Access-Control-Allow-Origin']=origin
                    if spec.get('cors_credentials'):headers['Access-Control-Allow-Credentials']=spec['cors_credentials']
            body=base64.b64decode(spec['body_b64']) if 'body_b64' in spec else spec.get('body','').encode('utf-8')
            self.send_response(spec.get('status',200))
            sent=[]
            for key,values in headers.items():
                for value in values if isinstance(values,list) else [values]:
                    self.send_header(key,value);sent.append([key,value])
            self.send_header('Content-Length',str(len(body)));self.end_headers()
            event.update(response_headers=sent,response_bytes=len(body))
            if self.command!='HEAD':self.wfile.write(body)
            event['response_completed']=True
        except (BrokenPipeError,ConnectionResetError,OSError) as exc:
            event['write_error']=type(exc).__name__
        finally:
            event['finished_at']=time.monotonic()
            with server.lock:server.active-=1


def start(fixture):
    service=Service(fixture)
    worker=threading.Thread(target=service.serve_forever,kwargs={'poll_interval':.01},daemon=True)
    worker.start()
    return service,worker


def stop(service,worker):
    service.shutdown();service.server_close();worker.join()
    deadline=time.monotonic()+4
    while service.active and time.monotonic()<deadline:time.sleep(.01)
    assert service.active==0,'Fixture did not become idle'
