"""Bounded runtime retention. Call mutations under desktop operation_lock."""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from controller.core import ControllerError, atomic_json, now


def process_paths():
    names = ['codex.exe', 'codex-code-mode-host.exe', 'codex-command-runner.exe',
             'codex-windows-sandbox-setup.exe', 'rg.exe']
    query = ' OR '.join("Name = '%s'" % n for n in names)
    script = ('[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); '
              '@(Get-CimInstance Win32_Process -Filter "' + query +
              '" | Select-Object ExecutablePath) | ConvertTo-Json -Compress')
    result = subprocess.run([str(Path(os.environ['SystemRoot']) /
        'System32/WindowsPowerShell/v1.0/powershell.exe'), '-NoProfile', '-NonInteractive',
        '-Command', script], capture_output=True, encoding='utf-8', check=True,
        timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    items = json.loads(result.stdout) if result.stdout.strip() else []
    if isinstance(items, dict):
        items = [items]
    if any(not x.get('ExecutablePath') for x in items):
        raise ControllerError('部分相关进程路径不可读，暂不清理。')
    return [Path(x['ExecutablePath']).resolve() for x in items]


def inside(path, parent):
    return path == parent or parent in path.parents


def checked_tree(root, path):
    """Reject escapes and every reparse point before walking/removing a tree."""
    root = Path(root).resolve(strict=True)
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    if resolved == root or not inside(resolved, root):
        raise ControllerError('清理路径超出工具目录。')
    current = path
    while current != root:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ControllerError('目录包含链接或重解析点，暂不清理。')
        current = current.parent
        if not inside(current, root):
            raise ControllerError('清理路径不是工具目录的直接子路径。')
    total = 0
    for base, dirs, files in os.walk(path, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
        for name in dirs + files:
            info = (Path(base) / name).lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ControllerError('目录包含链接或重解析点，暂不清理。')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def read_json(path):
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError('expected object')
    return value


def inventory(root, processes, *, keep_history=True):
    root = Path(root).resolve()
    pointer_file = root / 'state/desktop-trial.json'
    pointer = read_json(pointer_file) if pointer_file.exists() else {}
    selected = Path(pointer['runtime']).resolve() if pointer.get('runtime') else None
    if selected is not None and (selected.parent != root / 'runtime' or not selected.is_dir()):
        raise ControllerError('启动指针路径异常，暂不清理。')
    rows, skipped = [], []
    runtime_root = root / 'runtime'
    for target in sorted(runtime_root.iterdir()) if runtime_root.exists() else []:
        if not target.is_dir():
            continue
        try:
            size = checked_tree(root, target)
            manifest_file = target / 'manifest.json'
            manifest = read_json(manifest_file) if manifest_file.exists() else {}
            marker = target / 'candidate.json'
            owned = marker.exists() and read_json(marker).get('kind') == 'codex-retry-candidate'
            approved = (manifest.get('activation') == 'app-server-tested-desktop-trial'
                        and isinstance(manifest.get('runtime_files'), dict)
                        and 'codex.exe' in manifest['runtime_files'])
            if not approved and not owned:
                raise ValueError('不是可识别的控制器副本')
            created = datetime.fromisoformat(manifest.get('created_at') or
                                            read_json(marker)['created_at']).timestamp()
            rows.append(dict(path=str(target), bytes=size, approved=approved, created=created,
                             selected=target == selected,
                             running=any(inside(p, target) for p in processes)))
        except (OSError, ValueError, KeyError, TypeError, ControllerError) as exc:
            skipped.append(dict(path=str(target), reason=str(exc)))
    history = max((r for r in rows if r['approved'] and not r['selected']),
                  key=lambda r: (r['created'], r['path']), default=None) if keep_history else None
    for row in rows:
        row['history'] = row is history
        row['keep'] = row['selected'] or row['running'] or row['history']
    return rows, skipped


def archive(root, target):
    """Keep small diagnostic receipts, not databases, credentials or executables."""
    base = root / 'logs/storage-receipts'
    base.mkdir(parents=True, exist_ok=True)
    checked_tree(root, base)
    key = '__'.join(target.relative_to(root).parts)
    report = {'source': str(target), 'archived_at': now(), 'files': {}}
    for name in ('manifest.json', 'validation.json', 'candidate.json', 'gui-result.json',
                 'completed.json', 'state/desktop-trial.json'):
        p = target / name
        if p.is_file():
            report['files'][name] = read_json(p)
    # Integration receipts live one level below their runtime/ directory.
    for p in target.glob('runtime/*/*.json'):
        if p.name in ('manifest.json', 'validation.json', 'candidate.json'):
            report['files'][str(p.relative_to(target))] = read_json(p)
    atomic_json(base / (key + '.json'), report)


def maintain(root, *, dry_run=False, keep_history=True, process_getter=None):
    """Caller holds the same lock as publication and launcher selection."""
    root = Path(root).resolve()
    process_getter = process_getter or process_paths
    processes = process_getter()  # Failure must abort before any deletion.
    rows, skipped = inventory(root, processes, keep_history=keep_history)
    candidates = [Path(r['path']) for r in rows if not r['keep']]
    # Work directories can be reclaimed only when that generation is not running.
    candidates += [Path(r['path']) / 'validation-work' for r in rows
                   if r['keep'] and not r['running'] and r['approved']
                   and (Path(r['path']) / 'validation-work').is_dir()]
    integrations = root / 'logs/integration-runs'
    for target in sorted(integrations.iterdir()) if integrations.exists() else []:
        if not target.is_dir():
            continue
        try:
            checked_tree(root, target)
            # Old successful tests restored their isolated pointer to official.
            legacy = (target / 'gui-result.json').is_file() and (target / 'state/desktop-trial.json').is_file()
            completed = (target / 'completed.json').is_file()
            if not completed and not (legacy and read_json(target / 'state/desktop-trial.json').get('enabled') is False):
                continue
            if not any(inside(p, target) for p in processes):
                candidates.append(target)
        except (OSError, ValueError, ControllerError) as exc:
            skipped.append(dict(path=str(target), reason=str(exc)))
    report = dict(action='cleanup', dry_run=dry_run, keep_history=keep_history,
                  time=now(), retained=[r for r in rows if r['keep']],
                  removed=[], planned=[], skipped=skipped, reclaimed_bytes=0)
    for target in candidates:
        try:
            size = checked_tree(root, target)
            report['planned'].append(dict(path=str(target), bytes=size))
            if dry_run:
                continue
            fresh = process_getter()
            if any(inside(p, target) for p in fresh):
                raise ControllerError('目录仍有进程使用，已跳过。')
            # Recheck pointer and retention immediately before each removal.
            current, _ = inventory(root, fresh, keep_history=keep_history)
            if target.parent == root / 'runtime' and any(r['path'] == str(target) and r['keep'] for r in current):
                raise ControllerError('副本现在需要保留，已跳过。')
            checked_tree(root, target)
            if target.name != 'validation-work':
                archive(root, target)
            shutil.rmtree(target)
            report['removed'].append(str(target))
            report['reclaimed_bytes'] += size
        except (OSError, ValueError, KeyError, ControllerError, subprocess.SubprocessError) as exc:
            report['skipped'].append(dict(path=str(target), reason=str(exc)))
    if not dry_run:
        atomic_json(root / 'logs/storage-cleanup.json', report)
    return report


def best_effort(root):
    try:
        return maintain(root)
    except Exception as exc:
        return dict(action='cleanup', reclaimed_bytes=0, removed=[], skipped=[{'reason': str(exc)}])
