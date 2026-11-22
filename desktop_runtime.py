"""Stage, validate and atomically select immutable desktop retry runtimes."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from controller.core import (ROOT, ControllerError, Manager, atomic_json, now, profile, profile_label,
                             retry_profile, validate_profile, version_of)
from controller.verification import cache_path, recipe_id
import desktop_trial as launcher
import desktop_validation as validation


def config_path():
    return Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))) / 'config.toml'


def read_pointer(root):
    try:
        value = json.loads((root / 'state/desktop-trial.json').read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def runtime_manifest(root, runtime):
    target = Path(runtime).resolve(strict=True)
    target.relative_to((root / 'runtime').resolve())
    return target, json.loads((target / 'manifest.json').read_text(encoding='utf-8'))


def saved_profile(root):
    pointer = read_pointer(root)
    try:
        if pointer.get('last_profile') is not None:
            return validate_profile(pointer['last_profile'])
        return validate_profile(runtime_manifest(root, pointer['runtime'])[1]['profile'])
    except (OSError, ValueError, KeyError, TypeError, ControllerError):
        return profile(25, '1')


@contextlib.contextmanager
def operation_lock(root, action='保存或验证'):
    # Separate lock from Manager.apply; nesting its process mutex would deadlock.
    import msvcrt
    from desktop_processes import lock_error, owner_record, recovery_guard
    state = Path(root) / 'state'
    state.mkdir(parents=True, exist_ok=True)
    owner_path = state / 'desktop-controller-owner.json'
    stream = None
    acquired = False
    try:
        # Recovery must be able to stop an owner without waiting on its file lock.
        with recovery_guard(root):
            stream = (state / 'desktop-controller.lock').open('a+b')
            if stream.seek(0, 2) == 0:
                stream.write(b'\0'); stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                if exc.errno not in (13, 36):
                    raise
                raise ControllerError(lock_error(root)) from None
            acquired = True
            atomic_json(owner_path, owner_record(action))
        try:
            yield
        finally:
            owner_path.unlink(missing_ok=True)
    finally:
        if stream is not None:
            try:
                if acquired:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                stream.close()


def snapshot(resources):
    # Only build and implementation changes invalidate the isolated tests.
    return dict(resources=str(resources.resolve()),
                desktop_sha256=launcher.digest(resources.parent / 'ChatGPT.exe'),
                app_asar_sha256=launcher.digest(resources / 'app.asar'),
                official_files={n: launcher.digest(resources / n) for n in validation.COMPONENTS},
                recipe_sha256=recipe_id(), desktop_rules_sha256=validation.rules_id())


def adaptation_identity(build, p):
    identity = dict(build=build, profile=p)
    if p.get('http_timeout_ms'):
        try:
            from transport_runtime import dependency_identity, rules_id as guard_rules_id
            identity['http_timeout'] = dict(rules=guard_rules_id(), dependencies=dependency_identity())
        except Exception as exc:
            # Missing optional dependencies must not prevent a native update.
            identity['http_timeout'] = dict(error=type(exc).__name__ + ': ' + str(exc))
    return identity


def publish(root, p, config, resources_getter=launcher.installed_resources):
    """Caller holds desktop lock. Never writes source files or a previous runtime."""
    p = validate_profile(p)
    resources = resources_getter().resolve(strict=True)
    before = snapshot(resources)
    identity = adaptation_identity(before, p)
    previous = read_pointer(root)
    owner = Manager(root)
    target = None
    try:
        runtime_root = root / 'runtime'
        runtime_root.mkdir(parents=True, exist_ok=True)
        target = Path(tempfile.mkdtemp(prefix=before['official_files']['codex.exe'][:12] + '-', dir=runtime_root))
        atomic_json(target / 'candidate.json', dict(kind='codex-retry-candidate', created_at=now()))
        for name in validation.COMPONENTS:
            shutil.copyfile(resources / name, target / name)
            if launcher.digest(target / name) != before['official_files'][name]:
                raise ControllerError('复制期间官方组件发生变化，请重新检测。')
        try:
            version = version_of((target / 'codex.exe').read_bytes())
        except ControllerError:
            version = '未识别'
        manifest = dict(before, format=5, config_policy='user-managed', supports_retry_scope=False,
                        created_at=now(), version=version, profile=retry_profile(p), requested_profile=p,
                        desktop_exe=str(resources.parent / 'ChatGPT.exe'), activation='not-approved',
                        runtime_files=dict(before['official_files']), feature_errors={})

        def official_base():
            # A failed native preparation may have partially patched its own
            # candidate. Timeout-only starts from verified official bytes.
            shutil.copyfile(resources / 'codex.exe', target / 'codex.exe')
            if launcher.digest(target / 'codex.exe') != before['official_files']['codex.exe']:
                raise ControllerError('准备原生引擎期间官方文件变化，未切换入口。')
            manifest.update(profile=validate_profile(dict(retry_profile(p), retry_enabled=False)),
                            recipe_sha256=None, supports_retry_scope=False,
                            runtime_files={n: launcher.digest(target / n) for n in validation.COMPONENTS})
            return validation.run(resources, target, manifest, work_name='official')

        if p.get('retry_enabled', True):
            try:
                approval = owner.verify(resources / 'codex.exe')
                patcher = Manager(target / 'controller-state')
                try:
                    atomic_json(cache_path(patcher, (target / 'codex.exe').read_bytes()), approval)
                    patcher.apply(target / 'codex.exe', retry_profile(p))
                finally:
                    patcher.close()
                manifest.update(version=approval['version'], supports_retry_scope=approval.get('supports_retry_scope',False),
                                runtime_files={n: launcher.digest(target / n) for n in validation.COMPONENTS})
                report = validation.run(resources, target, manifest, work_name='retry')
                if not validation.receipt_valid(report, manifest):
                    raise ControllerError('自定义重试独立验收报告不完整。')
            except Exception as exc:
                if not p.get('http_timeout_ms'):
                    raise
                manifest['feature_errors']['retry'] = str(exc)
                owner.logger.exception('Custom retries unavailable; validating timeout-only candidate')
                report = official_base()
        else:
            report = official_base()
        if not validation.receipt_valid(report, manifest):
            raise ControllerError('验证报告不完整；未切换入口。')
        atomic_json(target / 'validation.json', report)
        manifest['validation_sha256'] = launcher.digest(target / 'validation.json')
        if p.get('http_timeout_ms'):
            try:
                from transport_runtime import prepare as prepare_timeout
                manifest['http_timeout'] = prepare_timeout(resources, target, manifest, p['http_timeout_ms'])
            except Exception as exc:
                manifest['feature_errors']['http_timeout'] = str(exc)
                owner.logger.exception('HTTP timeout unavailable; retaining independently verified retry entry')
        if not manifest['profile'].get('retry_enabled', True) and not manifest.get('http_timeout'):
            raise ControllerError('请求的功能均未通过独立验收；旧入口保留。\n' +
                                  '\n'.join(f'{key}: {value}' for key,value in manifest['feature_errors'].items()))
        after = snapshot(resources_getter().resolve(strict=True))
        if not manifest['profile'].get('retry_enabled', True):
            after['recipe_sha256'] = before['recipe_sha256']
        if before != after:
            raise ControllerError('验证期间官方安装或规则发生变化；未切换入口，请重新检测。')
        manifest.update(activation='app-server-tested-desktop-trial',
                        scope=report['scope'])
        atomic_json(target / 'manifest.json', manifest)
        selected = launcher.selection(resources, target, manifest, config, recipe_id())
        if selected['mode'] != 'custom-trial':
            raise ControllerError(selected['reason'])
        if read_pointer(root) != previous:
            raise ControllerError('验证期间启动入口被其他程序修改；未覆盖。')
        # The only activation write. A failed/crashed preparation leaves the old pointer intact.
        atomic_json(root / 'state/desktop-trial.json', dict(runtime=str(target), enabled=True,
                    last_profile=p, created_at=now()))
        result = dict(action='apply', changed=True, profile=p, effective_profile=selected['profile'],
                    degraded=selected.get('degraded',False), warnings=selected.get('warnings',[]),
                    features=selected.get('features',{}), version=manifest['version'],
                    runtime=str(target), validation=str(target / 'validation.json'))
        if result['degraded']:
            # Manual partial success also defers the same failed optional layer;
            # the next launch should not immediately repeat minutes of tests.
            record = dict(identity=identity, passed=False, completed_at=now(), result=result,
                          retry_after=time.time()+6*3600, reason='；'.join(result['warnings']))
            try:
                atomic_json(root / 'state/automatic-update.json', record)
                atomic_json(root / 'logs/automatic-update.json', record)
            except OSError:
                owner.logger.exception('Published partial runtime; could not record automatic retry cooldown')
        return result
    except Exception:
        owner.logger.exception('Desktop runtime preparation failed; candidate=%s', target)
        from desktop_storage import best_effort
        best_effort(root)
        raise
    finally:
        owner.close()


def restore(root):
    with operation_lock(root, '恢复官方默认'):
        pointer = read_pointer(root)
        changed = pointer.get('enabled', True) is not False
        pointer.update(enabled=False, last_profile=saved_profile(root), updated_at=now())
        atomic_json(root / 'state/desktop-trial.json', pointer)
        from desktop_storage import best_effort
        cleanup = best_effort(root)
    return dict(action='restore', changed=changed, cleanup=cleanup)


def prepare(root, p, config, *, force=False):
    """Reuse only a currently selected, fully validated matching generation."""
    p = validate_profile(p)
    if not p.get('retry_enabled',True) and not p.get('http_timeout_ms'):
        pointer=read_pointer(root)
        changed=pointer.get('enabled',True) is not False or saved_profile(root)!=p
        pointer.update(enabled=False,last_profile=p,updated_at=now())
        atomic_json(root/'state/desktop-trial.json',pointer)
        return dict(action='apply',changed=changed,enabled=False,profile=p,effective_profile=p,degraded=False,warnings=[])
    if not force:
        selected = launcher.get_selection(root, config_path=config)
        if selected['mode'] == 'custom-trial' and selected['profile'] == p and not selected.get('degraded'):
            target = Path(selected['engine']).parent
            manifest = runtime_manifest(root, target)[1]
            return dict(action='apply', changed=False, reused=True, profile=p,
                        version=manifest['version'], runtime=str(target),
                        validation=str(target / 'validation.json'))
    return publish(root, p, config)


def auto_prepare(root, config):
    """Caller holds desktop lock. Upgrade only a previously enabled custom entry.

    Failed builds have a six-hour cooldown. A build, recipe or saved-profile
    change retries immediately; explicit apply/verify always bypass the cooldown.
    """
    pointer = read_pointer(root)
    if pointer.get('enabled', True) is False or not pointer.get('runtime'):
        return dict(action='auto', changed=False, reason='未启用自定义入口。')
    if launcher.running_desktops(launcher.process_snapshot()):
        return dict(action='auto', changed=False, reason='桌面正在运行，等待下次启动。')
    selected = launcher.get_selection(root, config_path=config)
    if selected['mode'] == 'custom-trial' and not selected.get('degraded'):
        return dict(action='auto', changed=False, reused=True)
    p = saved_profile(root)
    resources = launcher.installed_resources().resolve(strict=True)
    identity = adaptation_identity(snapshot(resources), p)
    cache = root / 'state/automatic-update.json'
    try:
        previous = json.loads(cache.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        previous = {}
    if (isinstance(previous, dict) and previous.get('identity') == identity
            and previous.get('passed') is False
            and isinstance(previous.get('retry_after'), (int, float))
            and time.time() < previous['retry_after']):
        return dict(action='auto', changed=False, deferred=True,
                    degraded=selected.get('degraded',False),
                    reason='上次有功能未通过适配，本次保留已验收功能；可在控制器立即重新验证。',
                    detail=previous.get('reason'))
    started = time.time()
    atomic_json(cache, dict(identity=identity, passed=False, attempted_at=now(),
                           retry_after=started+6*3600, reason='上次自动验收被中断。'))
    try:
        result = prepare(root, p, config)
    except Exception as exc:
        record = dict(identity=identity, passed=False, attempted_at=now(),
                      retry_after=time.time()+6*3600, reason=str(exc))
        atomic_json(cache, record)
        atomic_json(root / 'logs/automatic-update.json', record)
        return dict(action='auto', changed=False, reason='自动适配未通过：'+str(exc))
    record=dict(identity=identity,passed=not result.get('degraded'),completed_at=now(),result=result)
    if result.get('degraded'):
        record.update(retry_after=time.time()+6*3600,reason='；'.join(result.get('warnings',[])))
    atomic_json(cache, record)
    atomic_json(root / 'logs/automatic-update.json', record)
    return dict(result, action='auto')


def python_console():
    exe = Path(sys.executable)
    if exe.name.lower() == 'pythonw.exe':
        exe = exe.with_name('python.exe')
    if not exe.is_file():
        raise ControllerError('没有找到用于隔离验证的 python.exe。')
    return exe


def running_state(root, processes, selected):
    desktops = launcher.running_desktops(processes)
    ids = {p['ProcessId'] for p in desktops}
    engines = launcher.desktop_engines(processes,ids)
    if not desktops:
        return '当前运行：未启动 Codex 桌面', False
    if not engines:
        return '当前运行：桌面已打开，尚未确认引擎', None
    labels, matches = [], []
    for process in engines:
        exe = Path(process['ExecutablePath']).resolve()
        try:
            _, manifest = runtime_manifest(root, exe.parent)
            p = retry_profile(manifest['profile'])
            if launcher.digest(exe) != manifest['runtime_files']['codex.exe']:
                raise ValueError('hash')
            entry=Path(process.get('ControllerEntryPath',str(exe))).resolve()
            if entry == exe.with_name('codex-guard.exe'):
                timeout=(manifest.get('http_timeout') or {}).get('timeout_ms') if manifest.get('format')==5 else manifest['profile'].get('http_timeout_ms')
                if timeout:
                    p=validate_profile(dict(p,http_timeout_ms=timeout))
            labels.append(profile_label(p))
            matches.append(selected['mode'] == 'custom-trial' and exe == Path(selected['engine']).resolve()
                           and entry == Path(selected.get('cli',selected['engine'])).resolve())
        except (OSError, ValueError, KeyError, TypeError, ControllerError):
            # A path outside managed runtime is only called official after hashing it.
            official = Path(selected['desktop']).parent / 'resources/codex.exe'
            try:
                is_official = launcher.digest(exe) == launcher.digest(official)
            except OSError:
                is_official = False
            labels.append('官方引擎' if is_official else '引擎未验明')
            matches.append(is_official and selected['mode'] == 'official')
    return '当前运行：' + '；'.join(dict.fromkeys(labels)), not all(matches)


class DesktopManager:
    def __init__(self, root=ROOT, *, config=None):
        self.root = Path(root).resolve()
        self.config = Path(config) if config is not None else config_path()
        self.owner = Manager(self.root)
        self.logs, self.logger = self.owner.logs, self.owner.logger
        self._operation = threading.local()

    @contextlib.contextmanager
    def cancellable(self, event):
        self._operation.cancel = event
        try:
            if event.is_set():
                raise ControllerError('操作已由进程清理取消。')
            yield
        finally:
            self._operation.cancel = None

    def close(self):
        self.owner.close()

    def inspect(self):
        resources = launcher.installed_resources()
        native = self.owner.inspect(resources / 'codex.exe')
        selected = launcher.get_selection(self.root, resources=resources, config_path=self.config)
        try:
            current, pending = running_state(self.root, launcher.process_snapshot(), selected)
        except Exception:
            current, pending = '当前运行：无法读取进程状态', None
        p = saved_profile(self.root)
        custom = selected['mode'] == 'custom-trial'
        enabled = read_pointer(self.root).get('enabled', True) is not False
        next_text = (f"下次启动：{profile_label(selected['profile'])}"
                     if custom else '下次启动：官方默认')
        if not custom and enabled and read_pointer(self.root).get('runtime'):
            next_text = f"下次启动：自动适配 {profile_label(p)}（验收失败则使用官方）"
        if pending:
            next_text += '（待正常退出后从自定义入口启动）'
        reason = selected['reason'] if custom else (native.get('reason') if not native['compatible'] else '') or selected['reason']
        if custom and pending is False and current != '当前运行：未启动 Codex 桌面':
            reason = reason.replace('首次桌面引擎选择待确认', '当前桌面已确认选中此副本')
        notes = selected.get('config_notes', [])
        if notes:
            reason += '\n范围提示（不拦截启动）：' + '；'.join(notes)
        return dict(native, status='custom' if custom else 'default', profile=p,
                    enabled=enabled, compatible=custom or native['compatible'],
                    verified=custom or native.get('verified',False),
                    retry_compatible=native['compatible'], retry_verified=native.get('verified',False),
                    can_restore=True, current_text=current, next_text=next_text,
                    selected=selected, pending_restart=pending, reason=reason,
                    features=selected.get('features',{}),degraded=selected.get('degraded',False))

    def _worker(self, action, p=None, *, extra=()):
        from desktop_processes import CANCELLED, run_worker
        jobs = self.logs / 'desktop-jobs'
        jobs.mkdir(exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=action + '-', suffix='.json', dir=jobs)
        os.close(fd)
        output = Path(name)
        command = [str(python_console()), '-B', '-X', 'utf8', str(ROOT / 'desktop_runtime.py'),
                   action, '--worker', '--root', str(self.root), '--config', str(self.config), '--result', str(output)]
        if p is not None:
            p = validate_profile(p)
            command += ['--retries', str(p['max_retries']), '--interval-ms', str(p['interval_ms']),
                        '--jitter-ms', str(p.get('jitter_ms', 0))]
            command += ['--http-timeout-ms', str(p.get('http_timeout_ms',0))]
            if not p.get('retry_enabled',True):
                command += ['--no-custom-retry']
        command += list(extra)
        # Pipe native probe output to a file; pythonw has no reliable stdout.
        with output.with_suffix('.log').open('w', encoding='utf-8') as log:
            log.write(f'{now()} 开始 {action}；结果：{output}\n')
            log.flush()
            try:
                returncode = run_worker(command, self.root, log, getattr(self._operation, 'cancel', None))
                if returncode == CANCELLED:
                    raise ControllerError('操作已由进程清理取消。')
            except Exception as exc:
                log.write(f'{now()} {exc}\n')
                atomic_json(output, {'error': str(exc)})
                returncode = 1
        try:
            result = json.loads(output.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raise ControllerError(f'验证进程未正常结束；旧入口保留。日志：{output.with_suffix(".log")}') from None
        if returncode or 'error' in result:
            raise ControllerError(result.get('error', '验证进程失败') + f'\n结果：{output}\n日志：{output.with_suffix(".log")}')
        return result

    def apply(self, p):
        return self._worker('apply', p)

    def verify(self):
        return self._worker('verify')

    def restore(self):
        return self._worker('restore')

    def cleanup(self, dry_run=False, *, keep_history=False):
        extra = (['--dry-run'] if dry_run else []) + (['--keep-history'] if keep_history else [])
        return self._worker('cleanup', extra=extra)

    def recover_processes(self, dry_run=False):
        from desktop_processes import recover
        return recover(self.root, dry_run=dry_run)

    def launch(self):
        cancel = getattr(self._operation, 'cancel', None)
        if cancel is not None and cancel.is_set():
            raise ControllerError('启动已由进程清理取消。')
        exe = python_console().with_name('pythonw.exe')
        if not exe.is_file():
            exe = python_console()
        from desktop_processes import recovery_guard
        with recovery_guard(self.root):
            if cancel is not None and cancel.is_set():
                raise ControllerError('启动已由进程清理取消。')
            subprocess.Popen([str(exe), '-B', '-X', 'utf8', str(ROOT / 'desktop_trial.py')],
                             cwd=str(ROOT), creationflags=subprocess.CREATE_NO_WINDOW)


def main():
    parser = argparse.ArgumentParser(description='管理自定义重试桌面入口')
    parser.add_argument('action', choices=['status', 'apply', 'verify', 'restore', 'cleanup', 'auto', 'recover'])
    parser.add_argument('--dry-run', action='store_true', help='cleanup 仅列出清理计划')
    parser.add_argument('--keep-history', action='store_true', help='cleanup 按自动策略保留一个历史版本；默认清空可删除历史')
    parser.add_argument('--retries')
    units = parser.add_mutually_exclusive_group()
    units.add_argument('--interval', help='基础等待秒数，支持三位小数')
    units.add_argument('--interval-ms', help='基础等待毫秒数')
    parser.add_argument('--jitter-ms', help='对称随机扰动毫秒数，0 表示固定等待')
    parser.add_argument('--http-timeout-ms', type=int, default=0,
                        help='HTTP 上传/响应头及非流式正文的各阶段期限，1000～600000 毫秒；0 关闭')
    parser.add_argument('--no-custom-retry', action='store_true',
                        help='保留原生重试次数与等待；可单独启用 HTTP 超时')
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--config', type=Path, default=config_path())
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--result', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--job-gate', help=argparse.SUPPRESS)
    args = parser.parse_args()
    def requested_profile():
        stored = saved_profile(args.root) if args.no_custom_retry else {}
        count = args.retries if args.retries is not None else stored.get('max_retries')
        jitter = args.jitter_ms if args.jitter_ms is not None else stored.get('jitter_ms',0)
        if args.no_custom_retry and args.interval_ms is None and args.interval is None:
            return profile(count, stored['interval_ms'], jitter, unit='ms',
                           http_timeout_ms=args.http_timeout_ms, retry_enabled=False)
        if args.interval_ms is not None:
            return profile(count, args.interval_ms, jitter, unit='ms',
                           http_timeout_ms=args.http_timeout_ms,retry_enabled=not args.no_custom_retry)
        base = profile(count, args.interval)
        return profile(count, base['interval_ms'], jitter, unit='ms',
                       http_timeout_ms=args.http_timeout_ms,retry_enabled=not args.no_custom_retry)
    from desktop_processes import wait_worker_gate
    wait_worker_gate(args.job_gate)
    manager = DesktopManager(args.root, config=args.config)
    try:
        if args.worker:
            print(f'{now()} PID {os.getpid()} 准备执行 {args.action}', flush=True)
            if args.action == 'restore':
                result = restore(args.root)
            else:
                with operation_lock(args.root, {'apply': '保存并验收新副本', 'verify': '重新验证已存设置',
                                               'auto': '自动适配更新', 'cleanup': '清理历史副本'}.get(args.action, args.action)):
                    if args.action == 'cleanup':
                        from desktop_storage import maintain
                        result = maintain(args.root, dry_run=args.dry_run, keep_history=args.keep_history)
                    elif args.action == 'auto':
                        result = auto_prepare(args.root, args.config)
                    else:
                        p = requested_profile() if args.action == 'apply' else saved_profile(args.root)
                        result = prepare(args.root, p, args.config, force=args.action == 'verify')
                    result['action'] = args.action
                    if args.action != 'cleanup':
                        from desktop_storage import best_effort
                        result['cleanup'] = best_effort(args.root)
        elif args.action == 'status':
            result = manager.inspect()
        elif args.action == 'apply':
            result = manager.apply(requested_profile())
        elif args.action == 'auto':
            result = manager._worker('auto')
        elif args.action == 'cleanup':
            result = manager.cleanup(dry_run=args.dry_run, keep_history=args.keep_history)
        elif args.action == 'recover':
            result = manager.recover_processes(dry_run=args.dry_run)
        else:
            result = getattr(manager, args.action)()
        if args.result:
            atomic_json(args.result, result)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        if args.worker:
            traceback.print_exc()
        if args.result:
            atomic_json(args.result, {'error': str(exc)})
        else:
            print(str(exc), file=sys.stderr)
        return 1
    finally:
        manager.close()


if __name__ == '__main__':
    raise SystemExit(main())
