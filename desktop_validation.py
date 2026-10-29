"""Behavior receipts for staged desktop runtimes; no real model requests."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from controller.core import ROOT, ControllerError, sha

COMPONENTS = ('codex.exe', 'codex-code-mode-host.exe', 'codex-command-runner.exe',
              'codex-windows-sandbox-setup.exe', 'rg.exe')


def configuration_notes(path):
    """Read-only coverage hints, never permission overrides or launch gates.

    Only generic messages leave this function; provider values and parser errors
    may contain credentials and must not enter logs or UI.
    """
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        value = tomllib.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError, ImportError):
        return ['未能读取配置覆盖范围，配置由 Codex 自行加载和检查']
    def table(item):
        return item if isinstance(item, dict) else {}
    notes = []
    if table(value.get('windows')).get('sandbox') != 'unelevated':
        notes.append('当前 Windows 沙盒组合尚未验证，已有对照覆盖 unelevated')
    features = table(value.get('features'))
    if (any(value.get(k) for k in ('permissions', 'profiles', 'profile'))
            or any(v and any(term in k.lower() for term in ('sandbox', 'mxc', 'network'))
                   for k, v in features.items())):
        notes.append('额外权限、profile 或网络组合尚未全面验证')
    provider_name = value.get('model_provider')
    provider = table(table(value.get('model_providers')).get(provider_name)) if isinstance(provider_name, str) else {}
    if (provider.get('supports_websockets')
            or any(v and 'websocket' in k.lower() for k, v in features.items())
            or provider.get('wire_api', 'responses') != 'responses'):
        notes.append('当前允许的传输路径未全部验证，已有重试测试覆盖 HTTP/SSE')
    return notes


def rules_id():
    paths = ['desktop_runtime.py', 'desktop_trial.py', 'desktop_validation.py', 'desktop_storage.py', 'desktop_processes.py',
             'research/verify_desktop_runtime.py', 'tests/verify_reported_rate_limit.py']
    return sha(b''.join(name.encode() + b'\0' + (ROOT / name).read_bytes() for name in paths))


def check_retry(result, p):
    limit = p['max_retries']
    attempts = min(limit, 2)
    # Small budgets are exhausted; larger budgets are sampled then succeed.
    expected_exit = 1 if limit <= 2 else 0
    delay = p['interval_ms'] / 1000
    spread = p.get('jitter_ms', 0)
    waits = [delay] * attempts
    if spread:
        selected = result.get('selected_delays_ms', [])
        if (len(selected) != attempts or any(type(v) is not int or
                not p['interval_ms']-spread <= v <= p['interval_ms']+spread for v in selected)):
            return False
        waits = [v/1000 for v in selected]
    return (result.get('timed_out') is False and result.get('exact_error_seen') is True
            and result.get('requests') == attempts + 1
            and result.get('turn_exit_code') == expected_exit
            and result.get('reconnects') == [f'Reconnecting... {i}/{limit}' for i in range(1, attempts + 1)]
            and len(result.get('intervals_seconds', [])) == attempts
            and all(max(0, wait - .06) <= v <= wait + 1.5
                    for v,wait in zip(result['intervals_seconds'], waits)))


def sandbox_valid(matrices):
    names = ['workspace-write-offline', 'read-only-offline', 'workspace-write-online']
    if len(matrices) != 2:
        return False
    for matrix in matrices:
        if [c.get('name') for c in matrix.get('cases', [])] != names:
            return False
        for case in matrix['cases']:
            obs = case.get('observations') or {}
            writable = case['name'] != 'read-only-offline'
            online = case['name'] == 'workspace-write-online'
            if not (case.get('response', {}).get('result', {}).get('exitCode') == 0
                    and obs.get('restricted_token') is True
                    and case.get('inside_exists') is writable and case.get('outside_exists') is False
                    and obs.get('inside', {}).get('write') is writable
                    and obs.get('outside', {}).get('write') is False):
                return False
            if online:
                if obs.get('proxy_http') != 'loopback-ok':
                    return False
            elif obs.get('offline_marker') != '1' or not obs.get('proxy_http_error') or 'proxy_http' in obs:
                return False
    return ([c['observations'] for c in matrices[0]['cases']]
            == [c['observations'] for c in matrices[1]['cases']])


SCOPE_PROBES = ('azure','encrypted','compact','automatic','post-turn')


def scope_results_valid(rows,p):
    """Actual saved settings must also reach each newly supported retry path."""
    try:
        if [r['name'] for r in rows] != list(SCOPE_PROBES):
            return False
        attempts=min(p['max_retries'],2)
        for row in rows:
            r=row['result'];compact=row['name'] in ('compact','automatic','post-turn')
            automatic=row['name'] in ('automatic','post-turn')
            if (r['timed_out'] or r['requests']!=attempts+1
                    or r['exit_code']!=(0 if automatic or p['max_retries']>2 else 1)
                    or r['reconnects'] != [f"Reconnecting... {i}/{p['max_retries']}" for i in range(1,attempts+1)]
                    or len(r['intervals_seconds'])!=attempts):
                return False
            if compact:
                if r['setup_requests']!=1 or r['setup_compaction_requests'] or r['compaction_requests']!=attempts+1:
                    return False
                lower=max(0,(p['interval_ms']-p.get('jitter_ms',0))/1000-.06)
                upper=(p['interval_ms']+p.get('jitter_ms',0))/1000+1.5
                if not all(lower<=v<=upper for v in r['intervals_seconds']):
                    return False
            else:
                adapted=dict(r,exact_error_seen=True,turn_exit_code=r['exit_code'])
                if not check_retry(adapted,p):
                    return False
        return True
    except (KeyError,TypeError,ValueError):
        return False


def receipt_valid(report, manifest):
    try:
        version = manifest.get('format')
        if version == 2:
            config_record_valid = report['config_sha256'] == manifest['config_sha256']
        elif version == 3:
            config_record_valid = report.get('config_policy') == manifest.get('config_policy') == 'user-managed'
        else:
            return False
        return (report.get('format') == version and config_record_valid and report.get('trial_eligible') is True
                and report['profile'] == manifest['profile']
                and report['engine_sha256'] == manifest['runtime_files']['codex.exe']
                and report['official_files'] == manifest['official_files']
                and report['recipe_sha256'] == manifest['recipe_sha256']
                and report['desktop_rules_sha256'] == manifest['desktop_rules_sha256']
                and check_retry(report['retry'], manifest['profile'])
                and (not manifest.get('supports_retry_scope') or
                     scope_results_valid(report.get('retry_scope',[]),manifest['profile']))
                and sandbox_valid(report['comparisons']))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def run(resources, target, manifest):
    # Called under python.exe, including when the UI itself runs under pythonw.
    from research.verify_desktop_runtime import sandbox_matrix, replay
    work = target / 'validation-work'
    work.mkdir()
    p = manifest['profile']
    retry = replay(target / 'codex.exe', work / 'retry',
                   stop_after=2 if p['max_retries'] > 2 else None,
                   timeout=45 + 2 * (p['interval_ms']+p.get('jitter_ms', 0)) / 1000)
    if not check_retry(retry, p):
        raise ControllerError(f'新参数的重试次数或实际等待时间未通过验收：{retry}')
    scope=[]
    if manifest.get('supports_retry_scope'):
        import sys
        sys.path.insert(0,str(ROOT/'research'))
        from probe_retries import probe
        from controller.native_errors import AZURE_RESOURCE_MESSAGE, ENCRYPTED_CONTENT_CODE
        options=[dict(error_status=400,error_type='invalid_request_error',error_message=AZURE_RESOURCE_MESSAGE+' [trace_id=local-parameters]'),
                 dict(error_status=400,error_type='invalid_request_error',error_code=ENCRYPTED_CONTENT_CODE,
                      error_message='bad response status code 400 (request id: local)'),
                 dict(compact=True),dict(compact='auto'),dict(compact='post-turn')]
        def run_probe(item):
            name,option=item
            result=probe(str(target/'codex.exe'),4,stream_retries=5,interface='app-server',
                         succeed=p['max_retries']>2,stop_after=2 if p['max_retries']>2 else 4,
                         timeout=45+2*(p['interval_ms']+p.get('jitter_ms',0))/1000,**option)
            return dict(name=name,result=result)
        # Each probe owns its temporary config/server and only reads the image.
        # Keep the native suite's concurrency bound and deterministic receipts;
        # any failed future still prevents publication after workers finish.
        with ThreadPoolExecutor(max_workers=4,thread_name_prefix='retry-parameters') as pool:
            scope=list(pool.map(run_probe,zip(SCOPE_PROBES,options)))
        if not scope_results_valid(scope,p):
            raise ControllerError('新参数的两类错误或压缩重试验收失败，未切换入口。')
    matrices = [sandbox_matrix(resources / 'codex.exe', work, 'official', registered=True),
                sandbox_matrix(target / 'codex.exe', work, 'copy', registered=False)]
    if not sandbox_valid(matrices):
        raise ControllerError('原版与副本的 unelevated 沙盒对照未通过；详见本次验证日志。')
    return dict(format=3, config_policy='user-managed', trial_eligible=True, profile=p,
                engine_sha256=manifest['runtime_files']['codex.exe'],
                official_files=manifest['official_files'],
                recipe_sha256=manifest['recipe_sha256'], desktop_rules_sha256=manifest['desktop_rules_sha256'],
                retry=retry, retry_scope=scope, comparisons=matrices,
                scope='Isolated app-server SSE and unelevated command/exec. No elevated/service or firewall equivalence claim.')
