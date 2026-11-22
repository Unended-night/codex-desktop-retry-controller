"""Loopback-only app-server acceptance of the staged HTTP timeout entry."""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from controller.core import ROOT, ControllerError, atomic_json


REQUIRED = ('no-headers','partial-headers','error-body','fatal-body','sse-long','sse-idle',
            'cancel-continue','concurrent','resume-fork','global-flags','overrides')
LIFECYCLE = ('stdio-eof', 'shim-exit', 'engine-exit')
TLS_CASES = ('tls-direct', 'tls-proxy')
STARTUP_CASES = ('policy-read', 'policy-sign-out', 'stdio', 'version', 'help')


def startup_valid(report):
    """Require real Node startup results and agreement with the official engine."""
    try:
        if (report['format'] != 1 or report['transport'] != 'node-child-process'
                or len(report['node_sha256']) != 64
                or [m['name'] for m in report['matrices']] != ['official', 'entry']):
            return False
        for matrix in report['matrices']:
            if [r['name'] for r in matrix['cases']] != list(STARTUP_CASES):
                return False
            for row in matrix['cases']:
                if (row.get('passed') is not True or row.get('timed_out') is not False
                        or row.get('exit_code') != 0 or row.get('failure')
                        or row.get('config_unchanged') is not True
                        or row.get('auth_present') is not (row['name'] != 'policy-sign-out')):
                    return False
                if row['name'] in ('version', 'help'):
                    if row['requests'] != 0 or row['stdout_bytes'] <= 0 or len(row['stdout_sha256']) != 64:
                        return False
                    continue
                if not isinstance(row.get('policy'), dict) or 'requirements' not in row['policy']:
                    return False
                if row['name'] == 'stdio':
                    if row['requests'] != 1 or not all(row.get(k) is True for k in
                            ('initialized', 'public_config_unchanged', 'thread_started', 'turn_completed')):
                        return False
                elif row['requests'] != 0 or not isinstance(row.get('app_server_version'), str):
                    return False
        official, entry = (matrix['cases'] for matrix in report['matrices'])
        return all(all(a.get(key) == b.get(key) for key in ('policy', 'app_server_version', 'stdout_sha256', 'stdout_bytes'))
                   for a, b in zip(official, entry))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def startup_matrix(resources, entry, work):
    """No UI, real home or live credentials: match Desktop's Node spawn modes."""
    from desktop_trial import digest
    node = resources / 'cua_node/bin/node.exe'
    if not node.is_file():
        raise ControllerError('未找到官方随附 Node，HTTP 超时入口无法完成桌面启动验收；自定义重试可独立使用。')
    work.mkdir(parents=True)
    report = dict(format=1, transport='node-child-process', node_sha256=digest(node), matrices=[])
    for name, exe in (('official', resources / 'codex.exe'), ('entry', entry)):
        matrix = dict(name=name, cases=[])
        report['matrices'].append(matrix)
        for mode in STARTUP_CASES:
            result = subprocess.run([str(node), str(ROOT / 'transport_startup.cjs'), str(exe),
                str(work / (name + '-' + mode)), mode], capture_output=True, timeout=40,
                creationflags=subprocess.CREATE_NO_WINDOW, encoding='utf-8')
            try:
                row = json.loads(result.stdout)
                if not isinstance(row, dict):
                    raise ValueError('invalid probe result')
            except (ValueError, TypeError):
                row = dict(name=mode, passed=False, failure='probe-output')
            row['name'] = mode
            if result.returncode != 0:
                row['passed'] = False
            matrix['cases'].append(row)
            atomic_json(work / 'startup-validation.json', report)
            if row.get('passed') is not True:
                raise ControllerError(f'HTTP 超时入口的桌面启动验收失败（{name}/{mode}）；超时未启用，自定义重试可独立使用。')
    if not startup_valid(report):
        raise ControllerError('HTTP 超时入口与官方启动行为不一致，未启用超时层。')
    return report


class Rpc:
    def __init__(self, exe, directory, *, arguments=None, env_overrides=None):
        self.directory=Path(directory)
        env={k:v for k,v in os.environ.items() if not k.startswith(('CODEX_','OPENAI_','AZURE_OPENAI_'))}
        env.update(CODEX_HOME=str(directory),CODEX_TIMEOUT_PROBE_KEY='fake-loopback-key',
                   NO_PROXY='127.0.0.1,localhost',RUST_LOG='warn')
        if env_overrides:
            env={k:v for k,v in env.items() if k.upper() not in env_overrides}
            env.update(env_overrides)
        self.proc=subprocess.Popen([str(exe),*(arguments or ['app-server','--stdio'])],cwd=directory,env=env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW)
        self.messages=queue.Queue();self.buffer=[];self.events=[];self.errors=[];self.sequence=0;self.turns={}
        def read_out():
            for raw in self.proc.stdout:
                try:self.messages.put(json.loads(raw))
                except ValueError:pass
        def read_err():
            for raw in self.proc.stderr:self.errors.append(raw.decode('utf-8',errors='replace'))
        self.readers=[threading.Thread(target=read_out,daemon=True),threading.Thread(target=read_err,daemon=True)]
        for reader in self.readers:reader.start()
        try:
            response=self.call('initialize',dict(clientInfo=dict(name='timeout_probe',version='1'),
                                                 capabilities=dict(experimentalApi=True)))
            if 'result' not in response:raise ControllerError('HTTP 超时验收：引擎初始化失败。')
            self.send(dict(method='initialized'))
        except BaseException:
            self.close()
            raise

    def send(self,value):
        self.proc.stdin.write(json.dumps(value).encode()+b'\n');self.proc.stdin.flush()

    def wait(self,predicate,timeout=15):
        deadline=time.monotonic()+timeout
        while True:
            for i,value in enumerate(self.buffer):
                if predicate(value):return self.buffer.pop(i)
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('isolated app-server observation timed out')
            try:value=self.messages.get(timeout=min(.2,remaining))
            except queue.Empty:
                if self.proc.poll() is not None:raise ControllerError('HTTP 超时验收：测试引擎提前退出。')
                continue
            self.events.append(value)
            if predicate(value):return value
            self.buffer.append(value)

    def call(self,method,params,timeout=15):
        self.sequence+=1;identity=self.sequence
        self.send(dict(id=identity,method=method,params=params))
        result=self.wait(lambda m:m.get('id')==identity,timeout)
        if 'error' in result:
            raise ControllerError(f'HTTP 超时验收：{method} 被测试引擎拒绝：{result["error"].get("message","")}')
        return result

    def start_thread(self, *, ephemeral=True, config=None):
        return self.call('thread/start',dict(cwd=str(self.directory),model='retry-probe-model',modelProvider='probe',
            approvalPolicy='never',sandbox='read-only',ephemeral=ephemeral,config=config))['result']['thread']['id']

    def turn(self,thread_id):
        result=self.call('turn/start',dict(threadId=thread_id,input=[dict(type='text',text='Reply OK.')]))
        self.turns[thread_id]=result['result']['turn']['id']

    def completed(self,thread_id,timeout):
        return self.wait(lambda m:m.get('method')=='turn/completed' and m['params']['threadId']==thread_id,
                         timeout)['params']['turn']['status']

    def close(self):
        with contextlib.suppress(OSError):self.proc.stdin.close()
        try:self.proc.wait(timeout=9)
        except subprocess.TimeoutExpired:
            self.proc.terminate();self.proc.wait(timeout=10)
        for reader in self.readers:reader.join(timeout=3)
        self.proc.stdout.close();self.proc.stderr.close()
        if hasattr(self.proc,'_handle'):self.proc._handle.Close()


class API:
    def __init__(self,mode):
        self.mode=mode;self.requests=[];self.first=threading.Event();self.disconnected=threading.Event()
        self.stop=threading.Event();self.lock=threading.Lock();self.connections=set()
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def handle(self):
                if owner.mode not in TLS_CASES:
                    return super().handle()
                self.connection.settimeout(5)
                if owner.mode=='tls-proxy':
                    if not self.rfile.readline(8192).startswith(b'CONNECT tls-probe.invalid:443 '):return
                    while self.rfile.readline(8192) not in (b'\r\n',b''):pass
                    self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush()
                if self.rfile.read(1)!=b'\x16':return
                started=time.monotonic()
                with owner.lock:
                    owner.requests.append(started);number=len(owner.requests)
                    owner.connections.add(self.connection)
                owner.first.set()
                try:
                    self.connection.settimeout(.2)
                    while not owner.stop.is_set():
                        try:
                            if self.connection.recv(65536):continue
                        except socket.timeout:continue
                        except OSError:pass
                        if number==1:
                            owner.tls_closed_ms=round((time.monotonic()-started)*1000)
                            owner.disconnected.set()
                        break
                finally:
                    with owner.lock:owner.connections.discard(self.connection)
            def do_POST(self):
                # Native requests normally have Content-Length; accepting
                # chunking makes the fixture useful for transport drift too.
                if self.headers.get('Transfer-Encoding','').lower()=='chunked':
                    while True:
                        size=int(self.rfile.readline().split(b';')[0],16)
                        if not size:self.rfile.readline();break
                        self.rfile.read(size);self.rfile.read(2)
                else:self.rfile.read(int(self.headers.get('Content-Length','0')))
                with owner.lock:
                    owner.requests.append(time.monotonic());number=len(owner.requests)
                    owner.connections.add(self.connection)
                owner.first.set()
                try:
                    first=number==1 and owner.mode not in ('resume-fork',)
                    if first and owner.mode in ('no-headers','concurrent','cancel-continue','configured-headers','global-flags','overrides'):
                        self.wait_disconnect();return
                    if first and owner.mode=='partial-headers':
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Incomplete: yes\r\n');self.wfile.flush()
                        self.wait_disconnect();return
                    if first and owner.mode in ('error-body','fatal-body'):
                        self.send_response(400 if owner.mode=='fatal-body' else 429)
                        self.send_header('Content-Length','100');self.end_headers()
                        self.wfile.write(b'{');self.wfile.flush();self.wait_disconnect();return
                    self.send_response(200);self.send_header('Content-Type','text/event-stream')
                    self.send_header('Transfer-Encoding','chunked');self.end_headers()
                    self.event(dict(type='response.created',response=dict(id='timeout-probe',status='in_progress',output=[])))
                    if first and owner.mode=='sse-idle':self.wait_disconnect();return
                    if owner.mode=='lifecycle':
                        while not owner.stop.wait(.1):
                            self.event(dict(type='response.output_text.delta',delta=''))
                        return
                    if first and owner.mode=='sse-long':
                        for _ in range(7):
                            if owner.stop.wait(.18):return
                            self.event(dict(type='response.output_text.delta',delta=''))
                    item=dict(id='msg_timeout_probe',type='message',role='assistant',status='completed',
                              content=[dict(type='output_text',text='OK',annotations=[])])
                    self.event(dict(type='response.output_item.done',output_index=0,item=item))
                    self.event(dict(type='response.completed',response=dict(id='timeout-probe',status='completed',
                        output=[item],usage=dict(input_tokens=1,output_tokens=1,total_tokens=2))))
                    self.wfile.write(b'0\r\n\r\n');self.wfile.flush()
                except (ConnectionError,OSError):
                    owner.disconnected.set()
                finally:
                    with owner.lock:owner.connections.discard(self.connection)
                    self.close_connection=True
            def event(self,value):
                payload=('data: '+json.dumps(value)+'\n\n').encode()
                self.wfile.write(f'{len(payload):x}\r\n'.encode()+payload+b'\r\n');self.wfile.flush()
            def wait_disconnect(self):
                self.connection.settimeout(.2)
                while not owner.stop.is_set():
                    try:
                        if not self.connection.recv(1):owner.disconnected.set();return
                    except socket.timeout:continue
                    except OSError:owner.disconnected.set();return
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()

    def configure(self,work, *, native_retries=0):
        work.mkdir(parents=True,exist_ok=True)
        base=(f'https://127.0.0.1:{self.server.server_port}/v1' if self.mode=='tls-direct'
              else 'https://tls-probe.invalid/v1' if self.mode=='tls-proxy'
              else f'http://127.0.0.1:{self.server.server_port}/v1')
        (work/'config.toml').write_text('model="retry-probe-model"\nmodel_provider="probe"\n'
            '[features]\nplugins=false\nresponses_websockets=false\nresponses_websockets_v2=false\n'
            '[model_providers.probe]\nname="loopback timeout verification"\n'
            f'base_url="{base}"\n'
            'env_key="CODEX_TIMEOUT_PROBE_KEY"\nwire_api="responses"\n'
            f'request_max_retries=0\nstream_max_retries={native_retries}\nsupports_websockets=false\n'
            'stream_idle_timeout_ms=400\n',encoding='utf-8')

    def close(self):
        self.stop.set()
        with self.lock:
            for connection in self.connections:
                with contextlib.suppress(OSError):connection.shutdown(socket.SHUT_RDWR)
        self.server.shutdown();self.server.server_close();self.worker.join(timeout=3)


def phase_case(exe,work,p,mode,timeout_ms):
    # Timeout-only uses the official provider retry option in this isolated
    # fixture. It must not be mistaken for the user's disabled custom budget.
    api=API(mode);api.configure(work,native_retries=0 if p.get('retry_enabled',True) else 1)
    expected_base=f'http://127.0.0.1:{api.server.server_port}/v1'
    override=None
    if mode=='overrides':
        override={'model_providers.probe': {'base_url':expected_base}}
        config=work/'config.toml'
        config.write_text(config.read_text(encoding='utf-8').replace(expected_base,'http://127.0.0.1:9/unselected'),encoding='utf-8')
        expected_base='http://127.0.0.1:9/unselected'
    original=(work/'config.toml').read_bytes()
    rpc=None;statuses=[];cancelled=False;resumed=False
    allowance=timeout_ms/1000+(p['interval_ms']+p.get('jitter_ms',0))/1000+25
    try:
        arguments=['-c','model="retry-probe-model"','app-server','--stdio'] if mode=='global-flags' else None
        rpc=Rpc(exe,work,arguments=arguments)
        identity=rpc.start_thread(ephemeral=mode!='resume-fork',config=override)
        rpc.turn(identity)
        if not api.first.wait(15):raise ControllerError('HTTP 超时验收：没有收到测试请求。')
        if mode=='cancel-continue':
            rpc.call('turn/interrupt',dict(threadId=identity,turnId=rpc.turns[identity]))
            statuses.append(rpc.completed(identity,10))
            cancelled=api.disconnected.wait(3)
            rpc.turn(identity);statuses.append(rpc.completed(identity,allowance))
        elif mode=='concurrent':
            second=rpc.start_thread();rpc.turn(second)
            statuses.append(rpc.completed(second,allowance))
            statuses.append(rpc.completed(identity,allowance))
        else:statuses.append(rpc.completed(identity,allowance))
        if mode=='resume-fork':
            rpc.close();rpc=None
            rpc=Rpc(exe,work)
            rpc.call('thread/resume',dict(threadId=identity,excludeTurns=True))
            rpc.turn(identity);statuses.append(rpc.completed(identity,allowance))
            fork=rpc.call('thread/fork',dict(threadId=identity,excludeTurns=True))['result']['thread']['id']
            rpc.turn(fork);statuses.append(rpc.completed(fork,allowance));resumed=True
        resolved=rpc.call('config/read',dict(cwd=str(work),includeLayers=False))['result']['config']
        config_unchanged=(work/'config.toml').read_bytes()==original and resolved['model_providers']['probe']['base_url']==expected_base
        text=json.dumps(rpc.events)
        reconnects=re.findall(r'Reconnecting\.\.\. \d+/\d+',text)
        # Events may contain the same retry message in both protocol families.
        reconnects=list(dict.fromkeys(reconnects))
        rpc.close()
        errors=rpc.errors
        rpc=None
        events=[]
        for line in errors:
            try:record=json.loads(line)
            except ValueError:continue
            if record.get('target')=='codex_response_timeout':events.append(record.get('fields',{}))
        result=dict(name=mode,statuses=statuses,requests=len(api.requests),reconnects=reconnects,
                    intervals=[round(b-a,3) for a,b in zip(api.requests,api.requests[1:])],
                    timeout_events=[e for e in events if e.get('event')=='timeout'],
                    cancelled=cancelled,resumed=resumed,config_unchanged=config_unchanged,timeout_ms=timeout_ms)
        result['passed']=case_valid(result,p)
        if not result['passed']:
            raise ControllerError('HTTP 超时行为验收失败：'+json.dumps(result,ensure_ascii=False))
        return result
    finally:
        if rpc:rpc.close()
        api.close()


def case_valid(row,p):
    limit=p['max_retries'] if p.get('retry_enabled',True) else 1
    mode=row['name'];retry=limit>0
    if row.get('config_unchanged') is not True:return False
    if mode=='sse-long':return row['requests']==1 and row['statuses']==['completed'] and not row['timeout_events']
    if mode=='cancel-continue':
        return row['cancelled'] and row['requests']==2 and row['statuses']==['interrupted','completed'] and not row['reconnects']
    if mode=='resume-fork':return row['resumed'] and row['requests']==3 and row['statuses']==['completed']*3
    if mode=='fatal-body':return (row['requests']==1 and row['statuses']==['failed'] and not row['reconnects']
        and len(row['timeout_events'])==1 and row['timeout_events'][0].get('phase')=='response_body')
    extra=1 if mode=='concurrent' else 0
    expected_status=(['completed'] if extra else [])+['completed' if retry else 'failed']
    if (row['requests']!=1+int(retry)+extra or row['statuses']!=expected_status
            or row['reconnects']!=([f"Reconnecting... 1/{limit}"] if retry else [])):
        return False
    if mode=='sse-idle':return not row['timeout_events']
    phase='response_body' if mode=='error-body' else 'response_headers'
    return (len(row['timeout_events'])==1 and row['timeout_events'][0].get('phase')==phase
            and row['timeout_ms']-150 <= row['timeout_events'][0].get('elapsed_ms',-1) <= row['timeout_ms']+2500)


def valid(report,p):
    try:
        return (report['timeout_ms']==p['http_timeout_ms'] and report['format']==1
            and [r['name'] for r in report['cases']]==list(REQUIRED)
            and all(r.get('passed') is True and r['timeout_ms']==500 and case_valid(r,p) for r in report['cases'])
            and [r['name'] for r in report['tls_handshakes']]==list(TLS_CASES)
            and all(r.get('passed') is True and tls_case_valid(r,p) for r in report['tls_handshakes'])
            and [r['name'] for r in report['lifecycle']]==list(LIFECYCLE)
            and all(r.get('passed') is True and r.get('children_exited') is True
                    and r.get('upstream_closed') is True and r.get('child_names')==['codex.exe','python.exe']
                    for r in report['lifecycle'])
            and report['configured']['name']=='configured-headers'
            and report['configured']['timeout_ms']==p['http_timeout_ms']
            and report['configured'].get('passed') is True and case_valid(report['configured'],p))
    except (KeyError,TypeError,ValueError):return False


def tls_case_valid(row,p):
    limit=p['max_retries'] if p.get('retry_enabled',True) else 1
    return (row['timeout_ms']==500 and row.get('config_unchanged') is True
        and row.get('tls_hello_received') is True and row.get('closed_before_shutdown') is True
        and 350<=row.get('disconnect_ms',-1)<=3000
        and row['statuses']==(['interrupted'] if limit else ['failed'])
        and row['reconnects']==([f'Reconnecting... 1/{limit}'] if limit else [])
        and len(row['timeout_events'])==1 and row['timeout_events'][0].get('phase')=='response_headers'
        and 350<=row['timeout_events'][0].get('elapsed_ms',-1)<=3000)


def tls_case(exe,work,p,mode):
    api=API(mode);api.configure(work,native_retries=0 if p.get('retry_enabled',True) else 1)
    original=(work/'config.toml').read_bytes()
    rpc=None
    try:
        env={'HTTPS_PROXY':f'http://127.0.0.1:{api.server.server_port}'} if mode=='tls-proxy' else None
        rpc=Rpc(exe,work,env_overrides=env)
        identity=rpc.start_thread();rpc.turn(identity)
        if not api.first.wait(15):raise ControllerError('TLS 超时验收未收到握手数据。')
        closed=api.disconnected.wait(3)
        limit=p['max_retries'] if p.get('retry_enabled',True) else 1
        if limit:
            notice=f'Reconnecting... 1/{limit}'
            rpc.wait(lambda m:notice in json.dumps(m),10)
            rpc.call('turn/interrupt',dict(threadId=identity,turnId=rpc.turns[identity]))
        statuses=[rpc.completed(identity,10)]
        rpc.close()
        errors=rpc.errors;messages=rpc.events;rpc=None
        events=[]
        for line in errors:
            try:record=json.loads(line)
            except ValueError:continue
            if record.get('target')=='codex_response_timeout':events.append(record.get('fields',{}))
        result=dict(name=mode,timeout_ms=500,tls_hello_received=api.first.is_set(),
            closed_before_shutdown=closed,disconnect_ms=getattr(api,'tls_closed_ms',-1),statuses=statuses,
            reconnects=list(dict.fromkeys(re.findall(r'Reconnecting\.\.\. \d+/\d+',json.dumps(messages)))),
            timeout_events=[e for e in events if e.get('event')=='timeout'],
            config_unchanged=(work/'config.toml').read_bytes()==original)
        result['passed']=tls_case_valid(result,p)
        if not result['passed']:raise ControllerError('TLS 握手超时或连接回收验收失败：'+json.dumps(result,ensure_ascii=False))
        return result
    finally:
        if rpc:rpc.close()
        api.close()


def lifecycle_case(exe,work,mode):
    from desktop_processes import Windows, Process, snapshot
    api=API('lifecycle');api.configure(work)
    rpc=None
    try:
        rpc=Rpc(exe,work)
        rpc.turn(rpc.start_thread())
        if not api.first.wait(15):raise ControllerError('超时入口生命周期验收未收到请求。')
        rows=snapshot()
        owned={rpc.proc.pid};children=[]
        while True:
            found=[row for row in rows if row.get('ParentProcessId') in owned and row['ProcessId'] not in owned]
            if not found:break
            children.extend(found);owned.update(row['ProcessId'] for row in found)
        names=sorted(Path(row['ExecutablePath']).name.lower() for row in children)
        primary=[name for name in names if name!='conhost.exe']
        if primary!=['codex.exe','python.exe']:
            raise ControllerError('超时入口生命周期验收无法确认自有 Python / 引擎子进程。')
        with contextlib.ExitStack() as handles:
            api_windows=Windows()
            processes=[handles.enter_context(Process(api_windows,row['ProcessId'],
                       terminate=mode=='engine-exit' and Path(row['ExecutablePath']).name.lower()=='codex.exe'))
                       for row in children]
            if not all(process.matches(row) for process,row in zip(processes,children)):
                raise ControllerError('生命周期验收的进程身份在读取期间变化，未停止进程。')
            if mode=='shim-exit':
                rpc.proc.terminate()  # Exact Popen owned by this isolated probe.
            elif mode=='engine-exit':
                next(process for process in processes if Path(process.exe).name.lower()=='codex.exe').stop()
                # Desktop input stays open: a dead engine must still release
                # its wrapper and HTTP server rather than waiting for new input.
                rpc.proc.wait(timeout=9)
            rpc.close();rpc=None
            exited=all(not process.alive(wait_ms=3000) for process in processes)
            disconnected=api.disconnected.wait(3)
        result=dict(name=mode,child_names=primary,console_hosts=names.count('conhost.exe'),
                    children_exited=exited,upstream_closed=disconnected,
                    passed=exited and disconnected)
        if not result['passed']:raise ControllerError('超时入口退出未回收自己的进程或连接。')
        return result
    finally:
        if rpc:rpc.close()
        api.close()


def run(target,work,p):
    from transport_runtime import stage
    # The same read-only patched image, with a separately compiled short timer.
    # The actual published entry gets its own full configured-deadline test.
    short=work/'short-timeout-entry';short.mkdir()
    os.link(target/'codex.exe',short/'codex.exe')
    for name in ('codex-code-mode-host.exe','codex-command-runner.exe','codex-windows-sandbox-setup.exe','rg.exe'):
        os.link(target/name,short/name)
    stage(short,500)
    try:
        with ThreadPoolExecutor(max_workers=4,thread_name_prefix='timeout-acceptance') as pool:
            configured=pool.submit(phase_case,target/'codex-guard.exe',work/'configured',p,'configured-headers',p['http_timeout_ms'])
            cases=list(pool.map(lambda mode:phase_case(short/'codex-guard.exe',work/mode,p,mode,500),REQUIRED))
            tls=list(pool.map(lambda mode:tls_case(short/'codex-guard.exe',work/mode,p,mode),TLS_CASES))
            lifecycle=list(pool.map(lambda mode:lifecycle_case(target/'codex-guard.exe',work/mode,mode),LIFECYCLE))
            actual=configured.result()
        report=dict(format=1,timeout_ms=p['http_timeout_ms'],cases=cases,tls_handshakes=tls,
                    configured=actual,lifecycle=lifecycle)
        if not valid(report,p):raise ControllerError('HTTP 超时验收收据不完整。')
        return report
    finally:
        # These are only this call's links/helpers, after every owned job exits.
        if short.resolve().parent!=work.resolve():raise ControllerError('超时验收目录越界。')
        shutil.rmtree(short)
