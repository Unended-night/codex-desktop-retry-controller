"""Replay White's exact token-limit text through the desktop SSE interface."""
import contextlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller.core import Manager, ROOT, atomic_json, detect_installation, now, profile, sha
from controller.verification import cached, cache_path
sys.path.insert(0,str(ROOT/'research'))
from appserver_probe import run
from research.probe_retries import retry_delays

MESSAGE='Your requests to gpt-6-astra for gpt-6-astra in eastus2 have exceeded token rate limit.'


def replay(exe, directory, stop_after=None, *, stream_retries=5, message=MESSAGE, timeout=45):
    events=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            success=stop_after is not None and len(events)>=stop_after
            events.append(time.monotonic())
            stream=[{'type':'response.created','response':{'id':'probe','status':'in_progress','output':[]}}]
            if success:
                item={'id':'msg_probe','type':'message','role':'assistant','status':'completed',
                      'content':[{'type':'output_text','text':'OK','annotations':[]}]}
                stream.extend([{'type':'response.output_item.done','output_index':0,'item':item},
                               {'type':'response.completed','response':{'id':'probe','status':'completed','output':[item],
                                'usage':{'input_tokens':1,'output_tokens':1,'total_tokens':2}}}])
            else:
                stream.append({'type':'response.failed','response':{'id':'probe','error':{'code':'rate_limit_exceeded','message':message}}})
            payload=''.join('data: '+json.dumps(e)+'\n\n' for e in stream).encode()
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream')
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    try:
        directory.mkdir()
        (directory/'config.toml').write_text('model = "retry-probe-model"\nmodel_provider = "probe"\n'
            '[features]\nplugins = false\n'
            '[model_providers.probe]\nname = "loopback probe"\n'
            f'base_url = "http://127.0.0.1:{server.server_port}/v1"\n'
            'env_key = "CODEX_LOCAL_PROBE_KEY"\nwire_api = "responses"\n'
            f'request_max_retries = 4\nstream_max_retries = {stream_retries}\nsupports_websockets = false\n',encoding='utf-8')
        env={k:v for k,v in os.environ.items() if not k.startswith(('OPENAI_','AZURE_OPENAI_','CODEX_'))}
        # app-server does not emit the required retry warnings by default.
        # Keep acceptance independent of the GUI launcher's inherited filter.
        env.update(CODEX_HOME=str(directory),CODEX_LOCAL_PROBE_KEY='not-a-real-key',
                   NO_PROXY='127.0.0.1,localhost',RUST_LOG='warn')
        stdout,stderr,code,timed_out=run(str(exe),str(directory),env,timeout)
        notices=[]
        for line in stdout.splitlines():
            try:m=json.loads(line)
            except ValueError:continue
            if m.get('method')=='error':notices.append(m.get('params',{}))
        return dict(requests=len(events),intervals_seconds=[round(b-a,3) for a,b in zip(events,events[1:])],
                    reconnects=re.findall(r'Reconnecting\.\.\. \d+/\d+',stdout),
                    sampling_retries=re.findall(r'retrying sampling request \(([^)]+)\)',stderr),
                    selected_delays_ms=retry_delays(stderr),
                    error_notices=notices,exact_error_seen=message in stdout or message in stderr,
                    turn_exit_code=code,timed_out=timed_out)
    finally:
        server.shutdown();server.server_close();worker.join()


def main():
    owner=Manager()
    installed=detect_installation()
    before=sha(installed.read_bytes())
    try:
        data,_=owner.baseline(installed,installed.read_bytes())
        approval=cached(owner,data)
        assert approval is not None,'Run native verification first'
        report=dict(version=approval['version'],base_sha256=sha(data),recipe_sha256=approval['recipe_sha256'],message=MESSAGE,cases=[])
        with tempfile.TemporaryDirectory(dir=owner.state/'.verification',prefix='reported-limit-') as tmp, contextlib.ExitStack() as cleanup:
            directory=Path(tmp)
            exe=directory/'codex.exe';exe.write_bytes(data)
            manager=Manager(directory/'tool');cleanup.callback(manager.close)
            atomic_json(cache_path(manager,data),approval)
            for name,settings,expected,stop in [('default',None,6,None),('two-retries',profile(2,'0.25'),3,None),('15-retries-5-seconds',profile(15,'5'),3,2)]:
                if settings:manager.apply(exe,settings)
                result=replay(exe,directory/name,stop)
                assert not result['timed_out'] and result['exact_error_seen'],result
                assert result['requests']==expected and result['turn_exit_code']==(0 if stop else 1),result
                limit=settings['max_retries'] if settings else 5
                assert result['reconnects']==[f'Reconnecting... {i}/{limit}' for i in range(1,expected)],result
                if settings:
                    wait=settings['interval_ms']/1000
                    assert all(wait-0.04<=v<=wait+0.5 for v in result['intervals_seconds']),result
                    assert result['sampling_retries'] and all(f"/{settings['max_retries']} in " in x for x in result['sampling_retries']),result
                report['cases'].append(dict(name=name,passed=True,**result))
                print(json.dumps(dict(name=name,requests=result['requests'],intervals=result['intervals_seconds'],retry_log=result['sampling_retries'])),flush=True)
            manager.restore(exe)
            assert sha(exe.read_bytes())==sha(data)
        assert sha(installed.read_bytes())==before
        report.update(passed=True,installed_unchanged=True,restored_sha256=sha(data),verified_at=now())
        atomic_json(ROOT/'logs/reported-rate-limit-verification.json',report)
    finally:
        owner.close()
        assert sha(installed.read_bytes())==before


if __name__=='__main__':main()
