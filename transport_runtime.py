"""Stage and verify the small protocol wrapper alongside the real engine."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from controller.core import ROOT, ControllerError, atomic_json, sha, validate_profile
from desktop_trial import digest


SOURCES = ('transport_guard.py', 'transport_bridge.py', 'transport_runner.py')
FILES = (*SOURCES, 'codex-guard.exe')


def rules_id():
    paths = (*SOURCES, 'transport_runtime.py', 'transport_validation.py', 'transport_shim.cs',
             'transport_startup.cjs', 'requirements.txt')
    return sha(b''.join(name.encode() + b'\0' + (ROOT / name).read_bytes() for name in paths))


def dependency_identity():
    from importlib.metadata import version, PackageNotFoundError
    python = Path(sys.executable)
    if python.name.lower() == 'pythonw.exe':
        python = python.with_name('python.exe')
    try:
        packages={name:version(name) for name in ('httpx','httpcore','h11','anyio','sniffio')}
    except PackageNotFoundError:
        raise ControllerError('HTTP 超时依赖缺失，请安装本项目 requirements.txt 后重新验证。') from None
    return dict(python=str(python), python_sha256=digest(python), python_version=sys.version,packages=packages)


def stage(target, timeout_ms):
    target = Path(target)
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if not compiler.is_file():
        raise ControllerError('缺少 Windows .NET Framework C# 编译器，不能制作 HTTP 超时入口。')
    python = Path(sys.executable)
    if python.name.lower() == 'pythonw.exe':
        python = python.with_name('python.exe')
    source = (ROOT / 'transport_shim.cs').read_text(encoding='utf-8')
    source = source.replace('@@PYTHON@@', json.dumps(str(python))).replace('@@TIMEOUT@@', json.dumps(str(timeout_ms)))
    build = target / 'guard-build.cs'
    try:
        build.write_text(source, encoding='utf-8-sig')
        output = subprocess.run([str(compiler), '/nologo', '/optimize+', '/platform:x64', '/target:exe',
                                 '/out:' + str(target / 'codex-guard.exe'), str(build)],
                                capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        if output.returncode:
            raise ControllerError('HTTP 超时入口编译失败，未切换副本。')
    finally:
        build.unlink(missing_ok=True)
    for name in SOURCES:
        shutil.copyfile(ROOT / name, target / name)
    return {name: digest(target / name) for name in FILES}


def valid(target, files):
    return isinstance(files, dict) and set(files) == set(FILES) and all(
        digest(Path(target) / name) == files[name] for name in FILES)


def checked_profile(target, manifest):
    """Validate only the optional layer; callers may retain a valid native entry."""
    from desktop_validation import receipt_valid
    from transport_validation import valid as protocol_valid, startup_valid
    descriptor = manifest['http_timeout']
    p = validate_profile(dict(manifest['profile'], http_timeout_ms=descriptor['timeout_ms']))
    if not p.get('http_timeout_ms') or p['http_timeout_ms'] != manifest['requested_profile'].get('http_timeout_ms'):
        raise ControllerError('HTTP 超时期限与已保存设置不一致。')
    if descriptor['rules_sha256'] != rules_id():
        raise ControllerError('HTTP 超时规则已更新，需要重新验收。')
    if not valid(target, descriptor['files']) or dependency_identity() != descriptor['dependencies']:
        raise ControllerError('HTTP 超时组件或 Python 依赖发生变化，需要重新验收。')
    path = Path(target) / 'http-validation.json'
    if digest(path) != descriptor['validation_sha256']:
        raise ControllerError('HTTP 超时独立验收报告缺失或发生变化。')
    report = json.loads(path.read_text(encoding='utf-8'))
    if not (receipt_valid(report, manifest) and report.get('http_profile') == p
            and report.get('guard_files') == descriptor['files']
            and report.get('guard_dependencies') == descriptor['dependencies']
            and report.get('guard_rules_sha256') == descriptor['rules_sha256']
            and startup_valid(report.get('desktop_startup', {}))
            and protocol_valid(report.get('http_timeout', {}), p)):
        raise ControllerError('HTTP 超时独立验收报告不完整或与当前引擎不匹配。')
    return p


def prepare(resources, target, manifest, timeout_ms):
    """An independent wrapper receipt, after the unwrapped entry has passed."""
    import desktop_validation
    from transport_validation import run, startup_matrix
    descriptor = dict(timeout_ms=timeout_ms, rules_sha256=rules_id(), dependencies=dependency_identity())
    descriptor['files'] = stage(target, timeout_ms)
    p = validate_profile(dict(manifest['profile'], http_timeout_ms=timeout_ms))
    startup = startup_matrix(resources, target / 'codex-guard.exe', target / 'validation-work/desktop-startup')
    report = desktop_validation.run(resources, target, manifest,
                                    entry=target / 'codex-guard.exe', work_name='http-timeout')
    report.update(http_profile=p, guard_files=descriptor['files'], guard_dependencies=descriptor['dependencies'],
                  guard_rules_sha256=descriptor['rules_sha256'], desktop_startup=startup,
                  http_timeout=run(target, target / 'validation-work/http-timeout', p))
    atomic_json(target / 'http-validation.json', report)
    descriptor['validation_sha256'] = digest(target / 'http-validation.json')
    checked_profile(target, dict(manifest, http_timeout=descriptor))
    return descriptor
