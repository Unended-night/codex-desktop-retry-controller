"""Stage a verified runtime and compare isolated app-server sandbox behavior.

Never starts/stops the user's desktop or edits the real configuration. The
staged runtime is not activated. All write probes target this test's directories.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controller.core import Manager, atomic_json, now, profile, sha, version_of
from controller.verification import cached, recipe_id
sys.path.insert(0, str(ROOT / 'tests'))
from verify_reported_rate_limit import replay

COMPONENTS = ('codex.exe', 'codex-code-mode-host.exe', 'codex-command-runner.exe',
              'codex-windows-sandbox-setup.exe', 'rg.exe')


def fingerprint(path):
    import hashlib
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def prepare(resources):
    data = (resources / 'codex.exe').read_bytes()
    owner = Manager()
    try:
        approval = cached(owner, data)
        if approval is None:
            approval = owner.verify(resources / 'codex.exe')
        files = {name: fingerprint(resources / name) for name in COMPONENTS}
        build = sha(json.dumps(files, sort_keys=True).encode())[:20]
        # New directory each run; never overwrite a potentially executing runtime.
        root = ROOT / 'runtime'
        root.mkdir(exist_ok=True)
        target = Path(tempfile.mkdtemp(prefix=build + '-', dir=root))
        for name in COMPONENTS:
            shutil.copyfile(resources / name, target / name)
            assert fingerprint(target / name) == files[name]
        patcher = Manager(target / 'controller-state')
        try:
            from controller.verification import cache_path
            atomic_json(cache_path(patcher, data), approval)
            patcher.apply(target / 'codex.exe', profile(25, '1'))
        finally:
            patcher.close()
        manifest = dict(format=1, created_at=now(), version=version_of(data),
                        resources=str(resources), desktop_exe=str(resources.parent / 'ChatGPT.exe'),
                        desktop_sha256=fingerprint(resources.parent / 'ChatGPT.exe'),
                        app_asar_sha256=fingerprint(resources / 'app.asar'),
                        official_files=files,
                        runtime_files={name: fingerprint(target / name) for name in COMPONENTS},
                        recipe_sha256=recipe_id(), profile=profile(25, '1'),
                        activation='not-approved', scope='isolated tests only')
        atomic_json(target / 'manifest.json', manifest)
        return target, manifest
    finally:
        owner.close()


class Rpc:
    def __init__(self, exe, cwd, env, registered):
        args = [str(exe), 'app-server', '--stdio']
        if registered:
            args += ['-c', 'features.windows_sandbox_service=true']
        self.proc = subprocess.Popen(args, cwd=str(cwd), env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW)
        self.messages = queue.Queue()
        self.stderr = []
        self.next_id = 0
        def read_out():
            for line in self.proc.stdout:
                try: self.messages.put(json.loads(line))
                except ValueError: pass
        def read_err():
            self.stderr.extend(self.proc.stderr)
        self.readers = [threading.Thread(target=read_out, daemon=True),
                        threading.Thread(target=read_err, daemon=True)]
        for reader in self.readers: reader.start()

    def call(self, method, params, timeout=35):
        self.next_id += 1
        request_id = self.next_id
        self.send({'id':request_id, 'method':method, 'params':params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try: message = self.messages.get(timeout=0.2)
            except queue.Empty:
                if self.proc.poll() is not None:
                    raise RuntimeError('test app-server exited: ' + ''.join(self.stderr)[-1600:])
                continue
            if message.get('id') == request_id:
                return message
        raise TimeoutError(method)

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + '\n')
        self.proc.stdin.flush()

    def close(self):
        if self.proc.poll() is None: self.proc.terminate()
        self.proc.wait(timeout=10)
        for reader in self.readers: reader.join(timeout=3)
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr): pipe.close()
        if hasattr(self.proc, '_handle'): self.proc._handle.Close()


PROBE = '''import ctypes, json, os, socket, sys, urllib.request
from ctypes import wintypes
from pathlib import Path
r = {}
for name, path in [('inside',sys.argv[1]),('outside',sys.argv[2])]:
    try:
        Path(path).write_text('sandbox-probe',encoding='utf-8');r[name]={'write':True}
    except OSError as e:r[name]={'write':False,'errno':e.errno,'winerror':getattr(e,'winerror',None)}
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
advapi=ctypes.WinDLL('advapi32',use_last_error=True)
kernel.GetCurrentProcess.restype=wintypes.HANDLE
advapi.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
advapi.IsTokenRestricted.argtypes=[wintypes.HANDLE]
advapi.IsTokenRestricted.restype=wintypes.BOOL
kernel.CloseHandle.argtypes=[wintypes.HANDLE]
token=wintypes.HANDLE()
if advapi.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):
    r['restricted_token']=bool(advapi.IsTokenRestricted(token));kernel.CloseHandle(token)
else:r['token_query_error']=ctypes.get_last_error()
r['offline_marker']=os.environ.get('SBX_NONET_ACTIVE')
r['http_proxy']=os.environ.get('HTTP_PROXY')
original_resolver=socket.getaddrinfo
def local_test_resolver(host,*args,**kwargs):
    # A non-local HTTP hostname exercises proxy policy without contacting the Internet.
    if host=='codex-sandbox-probe.invalid':host='127.0.0.1'
    return original_resolver(host,*args,**kwargs)
socket.getaddrinfo=local_test_resolver
try:
    with urllib.request.urlopen(sys.argv[3],timeout=2) as response:r['proxy_http']=response.read().decode()
except Exception as e:r['proxy_http_error']=type(e).__name__
try:
    with socket.create_connection(('127.0.0.1',int(sys.argv[4])),timeout=2):r['direct_loopback']=True
except OSError as e:r['direct_loopback']=False
print(json.dumps(r),flush=True)
'''


def sandbox_matrix(exe, parent, label, registered=False):
    case = parent / label
    case.mkdir()
    home, workspace, outside, temp = [case / s for s in ('home','workspace','outside','temp')]
    for path in (home, workspace, outside, temp): path.mkdir()
    script = case / 'probe.py'
    script.write_text(PROBE, encoding='utf-8')
    (home / 'config.toml').write_text(
        'model="retry-probe-model"\nmodel_provider="probe"\n'
        'sandbox_mode="workspace-write"\napproval_policy="never"\nweb_search="disabled"\n'
        '[features]\nplugins=false\n'
        '[windows]\nsandbox="unelevated"\n'
        '[model_providers.probe]\nname="offline test"\nbase_url="http://127.0.0.1:9/v1"\n'
        'env_key="CODEX_LOCAL_PROBE_KEY"\nwire_api="responses"\n', encoding='utf-8')
    env = {k:v for k,v in os.environ.items() if not k.startswith(('CODEX_','OPENAI_','AZURE_OPENAI_'))
           and k.upper() not in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')}
    env.update(CODEX_HOME=str(home), CODEX_LOCAL_PROBE_KEY='not-a-real-key',
               TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp), PYTHONDONTWRITEBYTECODE='1')
    if registered:
        for key in ('CODEX_WINDOWS_REGISTERED_CORE','CODEX_WINDOWS_SANDBOX_PACKAGE_FAMILY'):
            if key in os.environ: env[key] = os.environ[key]
    else:
        env['CODEX_CLI_PATH'] = str(exe)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b'loopback-ok')
    server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True);worker.start()
    rpc = Rpc(exe, workspace, env, registered)
    results = []
    try:
        init = rpc.call('initialize', {'clientInfo':{'name':'sandbox_equivalence_probe','version':'1'},
                                     'capabilities':{'experimentalApi':True}})
        assert 'result' in init, init
        rpc.send({'method':'initialized'})
        policies = [
            ('workspace-write-offline', {'type':'workspaceWrite','writableRoots':[str(workspace)],
                'networkAccess':False,'excludeTmpdirEnvVar':True,'excludeSlashTmp':True}),
            ('read-only-offline', {'type':'readOnly','networkAccess':False}),
            ('workspace-write-online', {'type':'workspaceWrite','writableRoots':[str(workspace)],
                'networkAccess':True,'excludeTmpdirEnvVar':True,'excludeSlashTmp':True}),
        ]
        for name, policy in policies:
            inside = workspace / (name + '.txt'); foreign = outside / (name + '.txt')
            result = rpc.call('command/exec', {
                'command':[sys.executable,'-B','-X','utf8',str(script),str(inside),str(foreign),
                           f'http://codex-sandbox-probe.invalid:{server.server_port}/',str(server.server_port)],
                'cwd':str(workspace),'timeoutMs':15000,'sandboxPolicy':policy})
            parsed = None
            if 'result' in result:
                for line in result['result'].get('stdout','').splitlines():
                    try: parsed = json.loads(line)
                    except ValueError: pass
            item = dict(name=name, response=result, observations=parsed,
                        inside_exists=inside.exists(), outside_exists=foreign.exists())
            results.append(item)
            print(json.dumps({'engine':label,**item},ensure_ascii=False),flush=True)
    finally:
        rpc.close();server.shutdown();server.server_close();worker.join()
    return dict(label=label, engine=str(exe), registered_env_inherited={
        k:k in env for k in ('CODEX_WINDOWS_REGISTERED_CORE','CODEX_WINDOWS_SANDBOX_PACKAGE_FAMILY')},
        cases=results, stderr_tail=''.join(rpc.stderr)[-2200:])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--resources',type=Path,required=True)
    args=parser.parse_args()
    resources=args.resources.resolve(strict=True)
    installed=Path(os.environ['LOCALAPPDATA'])/'OpenAI/Codex/bin/8aaf1547b825b104/codex.exe'
    real_config=Path.home()/'.codex/config.toml'
    before={str(p):fingerprint(p) for p in (installed,real_config)}
    target, manifest=prepare(resources)
    report=dict(started_at=now(), runtime=str(target), manifest=manifest, before=before,
                scope='app-server command/exec, temporary config, unelevated sandbox; desktop UI not restarted',
                comparisons=[])
    atomic_json(ROOT/'logs/desktop-runtime-candidate.json',report)
    work=ROOT/'research/.work';work.mkdir(exist_ok=True)
    testroot=Path(tempfile.mkdtemp(prefix='sandbox-equivalence-',dir=work))
    report['test_directory']=str(testroot)
    try:
        report['retry']=replay(target/'codex.exe',testroot/'retry',stop_after=2)
        assert report['retry']['reconnects']==['Reconnecting... 1/25','Reconnecting... 2/25']
        assert all(.96<=v<=1.5 for v in report['retry']['intervals_seconds'])
        assert report['retry']['turn_exit_code']==0
        print(json.dumps({'retry_passed':True,'intervals':report['retry']['intervals_seconds']}),flush=True)
        for label,exe,registered in [('official',installed,True),('copy',target/'codex.exe',False)]:
            result=sandbox_matrix(exe,testroot,label,registered)
            report['comparisons'].append(result)
            atomic_json(ROOT/'logs/desktop-runtime-candidate.json',report)
        observations=[[x['observations'] for x in e['cases']] for e in report['comparisons']]
        report['sandbox_observations_equal']=observations[0]==observations[1]
        report['filesystem_and_token_passed']=all(
            x['observations'] and x['observations'].get('restricted_token') is True
            and not x['outside_exists']
            and x['inside_exists']==(x['name']!='read-only-offline')
            for e in report['comparisons'] for x in e['cases'])
    finally:
        report['after']={str(p):fingerprint(p) for p in (installed,real_config)}
        report['installed_and_config_unchanged']=before==report['after']
        report['completed_at']=now()
        atomic_json(ROOT/'logs/desktop-runtime-candidate.json',report)
        assert report['installed_and_config_unchanged']
    print(json.dumps({k:v for k,v in report.items() if k in ('runtime','sandbox_observations_equal',
        'filesystem_and_token_passed','installed_and_config_unchanged')},ensure_ascii=False),flush=True)


if __name__=='__main__':main()
