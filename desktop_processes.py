"""Owned controller jobs and recovery, with live process identity checks.

Desktop applications are never job members. A verification worker and all of
its probes share a Windows Job Object; closing that job also reaps its children.
The lock file is persistent. Recovery releases locks by stopping their owners,
never by deleting/replacing a file that another process may still have open.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from controller.core import ControllerError, atomic_json, now

ROOT = Path(__file__).resolve().parent
CANCELLED = 1223
WORKER_ACTIONS = {'apply', 'verify', 'auto', 'restore', 'cleanup'}


def same_path(left, right):
    return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(str(Path(right).resolve()))


def root_key(root):
    return hashlib.sha256(os.path.normcase(str(Path(root).resolve())).encode('utf-8')).hexdigest()[:20]


class BasicLimits(C.Structure):
    _fields_ = [('process_time', C.c_longlong), ('job_time', C.c_longlong), ('flags', W.DWORD),
                ('min_working_set', C.c_size_t), ('max_working_set', C.c_size_t),
                ('active_processes', W.DWORD), ('affinity', C.c_size_t),
                ('priority', W.DWORD), ('scheduling', W.DWORD)]


class IoCounters(C.Structure):
    _fields_ = [(name, C.c_ulonglong) for name in ('reads', 'writes', 'other', 'read_bytes', 'write_bytes', 'other_bytes')]


class ExtendedLimits(C.Structure):
    _fields_ = [('basic', BasicLimits), ('io', IoCounters), ('process_memory', C.c_size_t),
                ('job_memory', C.c_size_t), ('peak_process_memory', C.c_size_t), ('peak_job_memory', C.c_size_t)]


class Windows:
    def __init__(self):
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.shell = C.WinDLL('shell32', use_last_error=True)
        def bind(dll, name, result, *args):
            function = getattr(dll, name)
            function.restype, function.argtypes = result, list(args)
        bind(self.kernel, 'OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
        bind(self.kernel, 'CloseHandle', W.BOOL, W.HANDLE)
        bind(self.kernel, 'QueryFullProcessImageNameW', W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD))
        bind(self.kernel, 'GetProcessTimes', W.BOOL, W.HANDLE, *([C.POINTER(W.FILETIME)] * 4))
        bind(self.kernel, 'WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
        bind(self.kernel, 'TerminateProcess', W.BOOL, W.HANDLE, W.UINT)
        bind(self.kernel, 'CreateMutexW', W.HANDLE, C.c_void_p, W.BOOL, W.LPCWSTR)
        bind(self.kernel, 'ReleaseMutex', W.BOOL, W.HANDLE)
        bind(self.kernel, 'CreateEventW', W.HANDLE, C.c_void_p, W.BOOL, W.BOOL, W.LPCWSTR)
        bind(self.kernel, 'OpenEventW', W.HANDLE, W.DWORD, W.BOOL, W.LPCWSTR)
        bind(self.kernel, 'SetEvent', W.BOOL, W.HANDLE)
        bind(self.kernel, 'CreateJobObjectW', W.HANDLE, C.c_void_p, W.LPCWSTR)
        bind(self.kernel, 'OpenJobObjectW', W.HANDLE, W.DWORD, W.BOOL, W.LPCWSTR)
        bind(self.kernel, 'SetInformationJobObject', W.BOOL, W.HANDLE, C.c_int, C.c_void_p, W.DWORD)
        bind(self.kernel, 'AssignProcessToJobObject', W.BOOL, W.HANDLE, W.HANDLE)
        bind(self.kernel, 'TerminateJobObject', W.BOOL, W.HANDLE, W.UINT)
        bind(self.kernel, 'IsProcessInJob', W.BOOL, W.HANDLE, W.HANDLE, C.POINTER(W.BOOL))
        bind(self.shell, 'CommandLineToArgvW', C.POINTER(W.LPWSTR), W.LPCWSTR, C.POINTER(C.c_int))
        bind(self.kernel, 'LocalFree', W.HANDLE, W.HANDLE)

    def check(self, result):
        if not result:
            raise C.WinError(C.get_last_error())
        return result

    def argv(self, command):
        count = C.c_int()
        items = self.check(self.shell.CommandLineToArgvW(command, C.byref(count)))
        try:
            return [items[i] for i in range(count.value)]
        finally:
            self.kernel.LocalFree(items)


class Process:
    def __init__(self, api, pid, *, terminate=False, assign_job=False):
        self.api, self.pid = api, int(pid)
        access = 0x1000 | 0x100000 | (1 if terminate else 0) | (0x100 if assign_job else 0)
        self.handle = api.check(api.kernel.OpenProcess(access, False, self.pid))
        try:
            text = C.create_unicode_buffer(32768)
            size = W.DWORD(len(text))
            api.check(api.kernel.QueryFullProcessImageNameW(self.handle, 0, text, C.byref(size)))
            times = [W.FILETIME() for _ in range(4)]
            api.check(api.kernel.GetProcessTimes(self.handle, *[C.byref(t) for t in times]))
            self.exe = text.value
            self.created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        except Exception:
            self.close()
            raise

    def alive(self, wait_ms=0):
        result = self.api.kernel.WaitForSingleObject(self.handle, wait_ms)
        if result == 0xffffffff:
            raise C.WinError(C.get_last_error())
        return result == 258

    def matches(self, row):
        # CIM's CreationDate has microsecond precision; native FILETIME has 100 ns.
        return (self.pid == row['ProcessId'] and self.created // 10 == int(row['Created']) // 10
                and same_path(self.exe, row['ExecutablePath']))

    def stop(self):
        if self.alive():
            if not self.api.kernel.TerminateProcess(self.handle, CANCELLED):
                error = C.get_last_error()
                # A concurrent job cancellation may have started termination but
                # not signalled the process handle yet (ERROR_ACCESS_DENIED).
                if self.alive(wait_ms=5000):
                    raise C.WinError(error)
                return True
        return not self.alive(wait_ms=5000)

    def close(self):
        if self.handle:
            self.api.kernel.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@contextmanager
def recovery_guard(root):
    """Serialize recovery against new lock acquisition, without waiting on that lock."""
    api = Windows()
    handle = api.check(api.kernel.CreateMutexW(None, False, 'Local\\CodexRetry.Recovery.' + root_key(root)))
    acquired = False
    try:
        result = api.kernel.WaitForSingleObject(handle, 0)
        if result == 258:
            raise ControllerError('正在清理控制器进程，请稍后重试。')
        if result not in (0, 128):
            raise C.WinError(C.get_last_error())
        acquired = True
        yield
    finally:
        if acquired:
            api.kernel.ReleaseMutex(handle)
        api.kernel.CloseHandle(handle)


def owner_record(action):
    api = Windows()
    with Process(api, os.getpid()) as process:
        return dict(pid=process.pid, created=process.created, executable=process.exe,
                    action=action, acquired_at=now(), acquired_unix=time.time())


def lock_status(root):
    """Probe the existing byte lock without creating files or altering its owner."""
    import msvcrt
    path = Path(root) / 'state/desktop-controller.lock'
    try:
        stream = path.open('r+b')
    except FileNotFoundError:
        return dict(available=True)
    except OSError as exc:
        return dict(available=False, error=f'无法检查操作锁：{exc}')
    with stream:
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno not in (13, 36):
                return dict(available=False, error=f'操作锁检查失败：{exc}')
        else:
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            return dict(available=True)
    result = dict(available=False)
    try:
        owner = json.loads((Path(root) / 'state/desktop-controller-owner.json').read_text(encoding='utf-8'))
        api = Windows()
        with Process(api, owner['pid']) as process:
            if process.alive() and process.created == owner['created'] and same_path(process.exe, owner['executable']):
                result['owner'] = dict(owner, elapsed_seconds=max(0, int(time.time() - owner['acquired_unix'])))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return result


def lock_error(root):
    status = lock_status(root)
    if status.get('error'):
        return status['error']
    owner = status.get('owner')
    detail = (f"占用进程 PID {owner['pid']}，阶段：{owner['action']}，已持续 {owner['elapsed_seconds']} 秒。"
              if owner else '占用进程未记录（可能是旧版启动器）。')
    return '控制器操作锁被占用。' + detail + '可点击“清理控制器进程”恢复。'


def wait_worker_gate(name):
    if not name:
        return
    api = Windows()
    handle = api.check(api.kernel.OpenEventW(0x100000, False, name))
    try:
        if api.kernel.WaitForSingleObject(handle, 30000) != 0:
            raise ControllerError('验证进程未获得启动许可，已退出。')
    finally:
        api.kernel.CloseHandle(handle)


def run_worker(command, root, log, cancel=None, *, timeout=1200):
    """Do not let a worker spawn any probes before its job has been assigned."""
    api = Windows()
    prefix = 'Local\\CodexRetry.Worker.' + root_key(root) + '.'
    name = prefix + uuid.uuid4().hex
    job = api.check(api.kernel.CreateJobObjectW(None, name))
    gate = None
    child = None
    assigned = False
    record_path = None
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        api.check(api.kernel.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
        gate = api.check(api.kernel.CreateEventW(None, True, False, name + '.Ready'))
        if cancel is not None and cancel.is_set():
            raise ControllerError('操作已由进程清理取消。')
        child = subprocess.Popen(command + ['--job-gate', name + '.Ready'], stdout=log, stderr=log,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        with Process(api, child.pid, terminate=True, assign_job=True) as process:
            try:
                api.check(api.kernel.AssignProcessToJobObject(job, process.handle))
                assigned = True
            except Exception:
                process.stop()
                raise
            record_path = Path(root) / 'state/controller-processes' / f'{process.pid}-{process.created}.json'
            atomic_json(record_path, dict(pid=process.pid, created=process.created, executable=process.exe,
                                         job=name, root=str(Path(root).resolve()), started_at=now()))
        api.check(api.kernel.SetEvent(gate))
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if cancel is not None and cancel.is_set():
                api.check(api.kernel.TerminateJobObject(job, CANCELLED))
                child.wait(timeout=5)
                raise ControllerError('操作已由进程清理取消。')
            if time.monotonic() >= deadline:
                api.check(api.kernel.TerminateJobObject(job, CANCELLED))
                child.wait(timeout=5)
                raise ControllerError('验证任务超过等待时限，已停止验证进程及其测试子进程。')
            try:
                child.wait(timeout=.1)
            except subprocess.TimeoutExpired:
                pass
        return child.returncode
    finally:
        # If inspection/assignment failed, the child is still waiting at its gate
        # and is not protected by the job yet. Reap that exact Popen handle too.
        if child is not None and not assigned and child.poll() is None:
            child.terminate()
        # All descendants, including orphaned native probes, leave with this job.
        api.kernel.CloseHandle(job)
        if gate:
            api.kernel.CloseHandle(gate)
        if child is not None:
            child.wait(timeout=5)
        if record_path is not None:
            record_path.unlink(missing_ok=True)


def snapshot():
    script = '''[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,
  @{Name='Created';Expression={if ($_.CreationDate) {$_.CreationDate.ToFileTimeUtc()} else {0}}}) | ConvertTo-Json -Compress'''
    completed = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
                                '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
                               capture_output=True, encoding='utf-8', errors='replace', timeout=20,
                               creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    rows = json.loads(completed.stdout)
    if not isinstance(rows, list):
        raise ControllerError('进程快照不完整，未执行进程清理。')
    return rows


def python_script(row, api):
    """Only accept an actual Python script argument, not text inside -c or -m."""
    exe = row.get('ExecutablePath')
    command = row.get('CommandLine')
    if not exe or Path(exe).name.lower() not in ('python.exe', 'pythonw.exe') or not command:
        return None, []
    args = api.argv(command)
    if not args or not same_path(args[0], exe):
        return None, []
    index = 1
    while index < len(args):
        if args[index] in ('-B', '-u', '-E', '-s', '-I'):
            index += 1
        elif args[index] in ('-X', '-W'):
            index += 2
        else:
            break
    if index >= len(args) or args[index].startswith('-') or not Path(args[index]).is_absolute():
        return None, []
    return Path(args[index]), args[index + 1:]


def role(row, root, api):
    script, args = python_script(row, api)
    if script is None:
        return None
    if same_path(script, Path(root) / 'desktop_trial.py'):
        return '启动器'
    if same_path(script, ROOT / 'desktop_runtime.py') and '--worker' in args and args and args[0] in WORKER_ACTIONS:
        try:
            scoped_root = args[args.index('--root') + 1]
        except (ValueError, IndexError):
            return None
        if Path(scoped_root).is_absolute() and same_path(scoped_root, root):
            return '验证任务'
    return None


def recovery_plan(rows, root, api, *, current_pid=None):
    current_pid = os.getpid() if current_pid is None else current_pid
    indexed = {row['ProcessId']: row for row in rows}
    ancestors = set()
    pid = current_pid
    while pid in indexed and pid not in ancestors:
        ancestors.add(pid)
        pid = indexed[pid].get('ParentProcessId')
    def protected(row):
        if row['ProcessId'] in ancestors or str(row.get('Name', '')).lower() == 'chatgpt.exe':
            return True
        script, _ = python_script(row, api)
        return script is not None and same_path(script, Path(root) / 'app.pyw')
    candidates = {}
    for row in rows:
        kind = role(row, root, api)
        if kind and not protected(row) and row.get('Created') and row.get('ExecutablePath'):
            candidates[row['ProcessId']] = dict(row, role=kind, depth=0)
    while True:
        added = False
        for row in rows:
            if row['ProcessId'] in candidates or protected(row):
                continue
            parent = candidates.get(row.get('ParentProcessId'))
            if (parent and row.get('Created') and row.get('ExecutablePath')
                    and int(row['Created']) >= int(parent['Created'])):
                candidates[row['ProcessId']] = dict(row, role='测试子进程', depth=parent['depth'] + 1)
                added = True
        if not added:
            break
    return sorted(candidates.values(), key=lambda row: (row['depth'], row['ProcessId']))


def stop_recorded_job(api, process, root):
    path = Path(root) / 'state/controller-processes' / f'{process.pid}-{process.created}.json'
    try:
        record = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return False
    prefix = 'Local\\CodexRetry.Worker.' + root_key(root) + '.'
    name = record.get('job', '')
    if (record.get('pid') != process.pid or record.get('created') != process.created
            or not same_path(record.get('executable', ''), process.exe)
            or not same_path(record.get('root', ''), root) or not name.startswith(prefix)
            or len(name[len(prefix):]) != 32 or any(ch not in '0123456789abcdef' for ch in name[len(prefix):])):
        raise ControllerError('验证进程所有权记录不匹配，未按该记录清理。')
    job = api.kernel.OpenJobObjectW(0x4 | 0x8, False, name)  # QUERY | TERMINATE
    if not job:
        if not process.alive():
            return False
        raise C.WinError(C.get_last_error())
    try:
        member = W.BOOL()
        api.check(api.kernel.IsProcessInJob(process.handle, job, C.byref(member)))
        if not member.value:
            raise ControllerError('进程与验证作业不匹配，未结束其他作业。')
        api.check(api.kernel.TerminateJobObject(job, CANCELLED))
        return True
    finally:
        api.kernel.CloseHandle(job)


def recover(root=ROOT, *, dry_run=False):
    root = Path(root).resolve()
    api = Windows()
    result = dict(time=now(), action='recover', dry_run=dry_run, stopped=[], skipped=[], remaining=[])
    with recovery_guard(root):
        plan = recovery_plan(snapshot(), root, api)
        result['candidates'] = [dict(pid=row['ProcessId'], executable=row['ExecutablePath'], role=row['role']) for row in plan]
        if not dry_run:
            # Stop producers first. Native process handles keep PID reuse harmless.
            for row in plan:
                pid = row['ProcessId']
                try:
                    with Process(api, pid, terminate=True) as process:
                        if not process.matches(row):
                            result['skipped'].append(dict(pid=pid, reason='进程身份已变化'))
                            continue
                        if not process.alive():
                            continue
                        by_job = row['role'] == '验证任务' and stop_recorded_job(api, process, root)
                        exited = not process.alive(wait_ms=5000) if by_job else process.stop()
                        if not exited:
                            raise ControllerError('进程未在期限内退出')
                        result['stopped'].append(dict(pid=pid, role=row['role'], job=bool(by_job)))
                except OSError as exc:
                    if getattr(exc, 'winerror', None) != 87:  # Already exited.
                        result['skipped'].append(dict(pid=pid, reason=str(exc)))
                except (ControllerError, ValueError, TypeError) as exc:
                    result['skipped'].append(dict(pid=pid, reason=str(exc)))
            fresh = snapshot()
            fresh_ids = {row['ProcessId'] for row in fresh}
            result['already_exited'] = [row['pid'] for row in result['skipped'] if row['pid'] not in fresh_ids]
            result['skipped'] = [row for row in result['skipped'] if row['pid'] in fresh_ids]
            remaining = {row['ProcessId'] for row in recovery_plan(fresh, root, api)}
            old = {row['ProcessId']: row for row in plan}
            # A child whose parent has exited is still ours if its complete live
            # identity matches the original plan. Do not lose it from the report.
            for row in fresh:
                previous = old.get(row['ProcessId'])
                if (previous and row.get('Created') == previous['Created']
                        and row.get('ExecutablePath') and same_path(row['ExecutablePath'], previous['ExecutablePath'])):
                    remaining.add(row['ProcessId'])
            result['remaining'] = sorted(remaining)
        result['lock'] = lock_status(root)
    result['recovered'] = result['lock'].get('available') is True and not result['remaining']
    if not dry_run:
        atomic_json(root / 'logs/process-recovery.json', result)
    return result
