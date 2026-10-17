"""Stable Shell identity for the custom desktop entry, independent of retry builds.

Only the entry's own shortcuts and windows of a verified launcher child are
managed. The controller and official application registration are not targets.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from windows_shell import Process, Shortcut, WindowsShell

ROOT = Path(__file__).resolve().parent
APP_ID = 'White.Codex.CustomRetry'
ENTRY_NAME = 'Codex自定义重试.lnk'
PROGRAMS = 'a77f5d77-2e2b-44c3-a6a2-aba601054a51'
DESKTOP = 'b4bfcc3a-db2c-424c-b029-7fe99a87c641'
ROAMING = '3eb685db-65f9-4cf6-a03a-e3ef65729f3d'


def same_path(left, right):
    # Installed package paths may be C:\\Program Files\\WindowsApps junctions
    # while QueryFullProcessImageName returns their E:\\WindowsApps destination.
    return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(str(Path(right).resolve()))


def python_windowed():
    exe = Path(sys.executable)
    windowed = exe.with_name('pythonw.exe')
    return windowed if windowed.is_file() else exe


def command(root=ROOT):
    return [str(python_windowed()), '-B', '-X', 'utf8', str(root / 'desktop_trial.py')]


def window_properties(root=ROOT):
    return dict(command=subprocess.list2cmdline(command(root)),
                icon=str(root / 'assets/codex.ico') + ',0',
                display_name='Codex 自定义重试', app_id=APP_ID)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, path)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()


def valid_icon(data):
    if len(data) < 6:
        return False
    reserved, kind, count = struct.unpack_from('<HHH', data)
    if reserved or kind != 1 or not 0 < count <= 256 or len(data) < 6 + count * 16:
        return False
    for index in range(count):
        size, offset = struct.unpack_from('<II', data, 6 + index * 16 + 8)
        if not size or offset < 6 + count * 16 or offset + size > len(data):
            return False
    return True


def ensure_icon(root):
    icon = root / 'assets/codex.ico'
    if icon.is_file() and valid_icon(icon.read_bytes()):
        return icon
    from desktop_trial import installed_resources
    data = (installed_resources() / 'icon-chatgpt.ico').read_bytes()
    if not valid_icon(data):
        raise ValueError('官方图标无效，未替换项目图标。')
    icon.parent.mkdir(parents=True, exist_ok=True)
    if icon.exists():
        backup = root / 'logs/taskbar-repair' / datetime.now().strftime('%Y%m%d-%H%M%S-%f') / 'codex.ico'
        backup.parent.mkdir(parents=True)
        shutil.copy2(icon, backup)
    # Write bytes, not WindowsApps encryption or filesystem attributes.
    fd, temporary = tempfile.mkstemp(prefix='.codex-icon-', dir=icon.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.replace(temporary, icon)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()
    return icon


def managed_shortcut(value, root, api):
    target = value['target']
    if same_path(target, root / 'desktop_trial.py'):
        return not api.argv(value['arguments'])
    if Path(target).name.lower() not in ('python.exe', 'pythonw.exe'):
        return False
    args = api.argv(value['arguments'])
    return (not any(arg in ('--official', '--check') for arg in args)
            and any(same_path(arg, root / 'desktop_trial.py') for arg in args))


def shortcut_paths(directories):
    found = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for parent, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [name for name in dirs
                       if not (Path(parent) / name).stat().st_file_attributes & 0x400]
            for name in files:
                if name.lower().endswith('.lnk'):
                    found.add(Path(parent) / name)
    return sorted(found)


def repair_shortcuts(api, root, paths, canonical, icon, backup):
    records = []
    if canonical.exists():
        with Shortcut(api, canonical) as existing:
            if not managed_shortcut(existing.read(), root, api):
                raise ValueError(f'开始菜单有同名的其他入口，未覆盖：{canonical}')
    for path in sorted(set(paths) | {canonical}):
        existed = path.exists()
        if existed:
            try:
                with Shortcut(api, path) as original:
                    before = original.read()
            except (OSError, ValueError) as exc:
                if path == canonical:
                    raise
                records.append(dict(path=str(path), changed=False, skipped=str(exc)))
                continue
            if path != canonical and not managed_shortcut(before, root, api):
                continue
        with Shortcut(api, path if existed else None, writable=True) as link:
            current = link.read()
            if existed and current != before:
                raise ValueError(f'快捷方式正在被其他程序修改，未覆盖：{path}')
            before = current
            if path == canonical:
                entry = command(root)
                link.configure(target=entry[0], arguments=subprocess.list2cmdline(entry[1:]),
                               directory=root, description='Codex 自定义重试启动入口（由本项目维护）')
            link.set_icon(icon)
            link.store.set('app_id', APP_ID)
            expected = link.read()
            changed = before != expected or not existed
            record = dict(path=str(path), changed=changed, created=not existed,
                          before=before, after=expected, backup=None)
            if changed:
                if existed:
                    backup.mkdir(parents=True, exist_ok=True)
                    saved = backup / (f'{len(records):03d}-' + path.name)
                    shutil.copy2(path, saved)
                    record['backup'] = str(saved)
                path.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix='.codex-taskbar-', suffix='.lnk', dir=path.parent)
                os.close(fd)
                try:
                    link.save(temporary)
                    with Shortcut(api, temporary) as check:
                        if check.read() != expected:
                            raise ValueError('快捷方式写入验证失败，原入口保留。')
                    os.replace(temporary, path)
                finally:
                    if Path(temporary).exists():
                        Path(temporary).unlink()
                api.notify(path, created=not existed)
            records.append(record)
    return records


def prepare(root=ROOT, *, directories=None, programs=None):
    root = Path(root).resolve()
    if not (root / 'desktop_trial.py').is_file():
        raise FileNotFoundError('自定义启动器不存在。')
    with WindowsShell() as api:
        lock_id = hashlib.sha256(str(root).lower().encode()).hexdigest()[:16]
        with api.lock('Local\\CodexRetry.Shell.' + lock_id) as acquired:
            if not acquired:
                raise TimeoutError('另一个入口正在维护任务栏关联。')
            icon = ensure_icon(root)
            programs = Path(programs) if programs is not None else api.known_folder(PROGRAMS)
            if directories is None:
                directories = [api.known_folder(DESKTOP), programs,
                               api.known_folder(ROAMING) / 'Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar']
            canonical = programs / ENTRY_NAME
            backup = root / 'logs/taskbar-repair' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
            records = repair_shortcuts(api, root, shortcut_paths(directories), canonical, icon, backup)
            result = dict(time=datetime.now().astimezone().isoformat(), app_id=APP_ID,
                          entry=str(canonical), icon=str(icon),
                          changed=sum(row['changed'] for row in records), shortcuts=records)
            if result['changed']:
                write_json(backup / 'report.json', result)
            write_json(root / 'logs/taskbar-repair.json', result)
            return result


def bind_windows(api, pid, root=ROOT):
    desired = window_properties(root)
    changes = []
    for hwnd in api.windows(pid):
        if not api.belongs(hwnd, pid):
            continue
        try:
            with api.window_store(hwnd) as store:
                before = {key: store.get(key, api) for key in desired}
                if before == desired:
                    continue
                if not api.belongs(hwnd, pid):
                    continue
                # Windows requires relaunch data before the window-level identity.
                for name in ('command', 'icon', 'display_name', 'app_id'):
                    store.set(name, desired[name])
                after = {key: store.get(key, api) for key in desired}
                if after != desired:
                    raise ValueError('窗口任务栏关联写入验证失败。')
                changes.append(dict(hwnd=hwnd, before=before, after=after))
        except OSError:
            if api.belongs(hwnd, pid):
                raise
            # A window closing between enumeration and SetValue is normal.
    return changes


def watch(pid, desktop, created, root=ROOT):
    root = Path(root).resolve()
    with WindowsShell() as api, Process(api, pid) as process:
        if process.created != created or not same_path(process.exe, desktop):
            raise ValueError('桌面进程已变化，未修改其他进程的窗口。')
        with api.lock(f'Local\\CodexRetry.Taskbar.{pid}.{created}', timeout_ms=0) as acquired:
            if not acquired:
                return dict(already_watching=True)
            state = dict(pid=pid, created=created, desktop=str(desktop), app_id=APP_ID, windows={}, errors=[])
            log = root / 'logs/taskbar-windows' / f'{pid}-{created}.json'
            while process.alive():
                try:
                    changes = bind_windows(api, pid, root)
                    for change in changes:
                        state['windows'].setdefault(str(change['hwnd']), change)
                    if changes:
                        state['updated_at'] = datetime.now().astimezone().isoformat()
                        write_json(log, state)
                except Exception as exc:
                    message = str(exc)
                    if message not in state['errors']:
                        state['errors'].append(message)
                        write_json(log, state)
                if not process.alive(wait_ms=2000):
                    break
            state['exited_at'] = datetime.now().astimezone().isoformat()
            write_json(log, state)
            return state


def start_watch(pid, desktop, root=ROOT):
    with WindowsShell() as api, Process(api, pid) as process:
        if not same_path(process.exe, desktop):
            raise ValueError('桌面 PID 与本次启动文件不一致。')
        created = process.created
    args = [str(python_windowed()), '-B', '-X', 'utf8', str(ROOT / 'desktop_shell.py'),
            'watch', '--pid', str(pid), '--desktop', str(desktop), '--created', str(created), '--root', str(root)]
    helper = subprocess.Popen(args, cwd=str(root), creationflags=subprocess.CREATE_NO_WINDOW)
    return dict(watcher_pid=helper.pid, desktop_pid=pid, created=created)


def recorded_desktop(api, root=ROOT):
    """Recognize our prior child without attaching to unrelated official instances."""
    record = json.loads((root / 'logs/desktop-last-launch.json').read_text(encoding='utf-8'))
    if record.get('forced_official'):
        raise ValueError('本次为显式官方启动，保留其原应用标识。')
    pid = record['launcher_child_pid']
    launched = datetime.fromisoformat(record['time']).timestamp()
    with Process(api, pid) as process:
        created = process.created / 10_000_000 - 11_644_473_600
        if (not process.alive() or not same_path(process.exe, record['desktop'])
                or abs(created - launched) > 3):
            raise ValueError('没有匹配本项目启动记录的运行桌面。')
        return pid, process.exe


def repair(root=ROOT):
    result = prepare(root)
    with WindowsShell() as api:
        try:
            pid, desktop = recorded_desktop(api, root)
        except (OSError, ValueError, KeyError) as exc:
            result['running_desktop'] = dict(attached=False, reason=str(exc))
        else:
            result['running_desktop'] = dict(attached=True, pid=pid, windows=bind_windows(api, pid, root),
                                             watcher=start_watch(pid, desktop, root))
    write_json(root / 'logs/taskbar-repair-result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='自定义 Codex 任务栏关联维护')
    parser.add_argument('action', choices=['repair', 'watch'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--desktop', type=Path)
    parser.add_argument('--created', type=int)
    args = parser.parse_args(argv)
    if args.action == 'watch':
        if None in (args.pid, args.desktop, args.created):
            parser.error('watch 需要指定 PID、桌面路径与进程创建时间')
        result = watch(args.pid, args.desktop, args.created, args.root)
    else:
        result = repair(args.root)
    if sys.stdout is not None:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        write_json(ROOT / 'logs/taskbar-error.json', dict(time=datetime.now().astimezone().isoformat(), error=str(exc)))
        raise
