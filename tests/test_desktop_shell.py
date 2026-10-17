"""Real Shell shortcuts in temporary directories; window/process lifecycle fakes."""
from contextlib import contextmanager
from ctypes import wintypes as W
from pathlib import Path
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import desktop_shell as shell
import desktop_trial as launcher
from windows_shell import Shortcut, WindowsShell


@unittest.skipUnless(os.name == 'nt', 'Windows Shell integration')
class ShortcutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='Codex shell test ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'desktop_trial.py').write_text('# isolated launcher', encoding='utf-8')
        (self.root / 'app.pyw').write_text('# controller', encoding='utf-8')
        (self.root / 'assets').mkdir()
        # A plain 16x16 icon keeps clean checkouts independent of local app assets.
        pixels = bytes((0x90, 0x60, 0x20, 0xFF)) * (16 * 16)
        mask = bytes(4 * 16)
        bitmap = struct.pack('<IiiHHIIiiII', 40, 16, 32, 1, 32, 0,
                             len(pixels) + len(mask), 0, 0, 0, 0) + pixels + mask
        icon = (struct.pack('<HHH', 0, 1, 1)
                + struct.pack('<BBBBHHII', 16, 16, 0, 0, 1, 32, len(bitmap), 22)
                + bitmap)
        (self.root / 'assets/codex.ico').write_bytes(icon)
        self.programs = self.root / 'programs'
        self.programs.mkdir()
        self.desktop = self.root / 'desktop'
        self.desktop.mkdir()
        self.api = WindowsShell()
        self.addCleanup(self.api.close)

    def make_link(self, path, script, *, app_id=None):
        args = subprocess.list2cmdline(['-B', '-X', 'utf8', str(script)])
        with Shortcut(self.api) as link:
            link.configure(target=shell.python_windowed(), arguments=args,
                           directory=self.root, description='保留这段描述')
            link.link.call(13, (W.WORD,), 0x0241)
            if app_id:
                link.store.set('app_id', app_id)
            link.save(path)
        return self.read(path)

    def read(self, path):
        with Shortcut(self.api, path) as link:
            return link.read()

    def prepare(self):
        return shell.prepare(self.root, programs=self.programs, directories=[self.desktop, self.programs])

    def test_managed_entry_preserves_launch_properties_and_controller_bytes(self):
        custom = self.desktop / 'Codex自定义.lnk'
        original = self.make_link(custom, self.root / 'desktop_trial.py')
        self.assertEqual(original['hotkey'], 0x0241)
        self.assertEqual(original['show'], 7)
        controller = self.desktop / 'Codex重试控制器.lnk'
        self.make_link(controller, self.root / 'app.pyw')
        untouched = controller.read_bytes()
        report = self.prepare()
        self.assertEqual(report['changed'], 2)
        updated = self.read(custom)
        for field in original.keys() - {'icon', 'icon_index', 'app_id'}:
            self.assertEqual(updated[field], original[field], field)
        self.assertEqual(updated['app_id'], shell.APP_ID)
        self.assertEqual(updated['icon'], str(self.root / 'assets/codex.ico'))
        self.assertEqual(controller.read_bytes(), untouched)
        record = next(row for row in report['shortcuts'] if row['path'] == str(custom))
        self.assertEqual(self.read(record['backup']), original)

    def test_repeated_repairs_do_not_rewrite_links_or_make_more_backups(self):
        first = self.prepare()
        entry = Path(first['entry'])
        before = entry.read_bytes(), entry.stat().st_mtime_ns
        reports = list((self.root / 'logs/taskbar-repair').rglob('report.json'))
        second = self.prepare()
        self.assertEqual(second['changed'], 0)
        self.assertEqual((entry.read_bytes(), entry.stat().st_mtime_ns), before)
        self.assertEqual(list((self.root / 'logs/taskbar-repair').rglob('report.json')), reports)

    def test_official_and_forced_official_links_are_not_reclassified(self):
        official = self.desktop / 'ChatGPT.lnk'
        with Shortcut(self.api) as link:
            link.configure(target=self.root / 'old WindowsApps/app/ChatGPT.exe', arguments='',
                           directory=self.root, description='official')
            link.store.set('app_id', 'com.openai.codex')
            link.save(official)
        forced = self.desktop / 'Codex official.lnk'
        self.make_link(forced, self.root / 'desktop_trial.py')
        with Shortcut(self.api, forced, writable=True) as link:
            link.link.call(11, (W.LPCWSTR,),
                           link.read()['arguments'] + ' --official')
            link.save(forced)
        before = official.read_bytes(), forced.read_bytes()
        self.prepare()
        self.assertEqual((official.read_bytes(), forced.read_bytes()), before)

    def test_same_named_unmanaged_start_entry_is_not_overwritten(self):
        entry = self.programs / shell.ENTRY_NAME
        self.make_link(entry, self.root / 'app.pyw')
        before = entry.read_bytes()
        with self.assertRaisesRegex(ValueError, '同名'):
            self.prepare()
        self.assertEqual(entry.read_bytes(), before)

    def test_temp_save_failure_leaves_original_entry_intact(self):
        custom = self.desktop / 'Codex.lnk'
        self.make_link(custom, self.root / 'desktop_trial.py')
        before = custom.read_bytes()
        with patch.object(Shortcut, 'save', side_effect=OSError('fixture save failure')):
            with self.assertRaises(OSError):
                self.prepare()
        self.assertEqual(custom.read_bytes(), before)
        self.assertEqual(list(self.desktop.glob('.codex-taskbar-*')), [])

    def test_stable_entry_contains_no_package_or_runtime_directory(self):
        result = self.prepare()
        entry = self.read(result['entry'])
        args = self.api.argv(entry['arguments'])
        self.assertEqual(args, ['-B', '-X', 'utf8', str(self.root / 'desktop_trial.py')])
        self.assertEqual(entry['app_id'], shell.APP_ID)
        for value in [entry['target'], entry['arguments'], entry['icon'], *shell.window_properties(self.root).values()]:
            self.assertNotIn('WindowsApps', value)
            self.assertNotIn('runtime', value)

    def test_installed_directory_alias_matches_real_process_location(self):
        # Use an existing redirect read-only; no junction is created or removed.
        try:
            package_root = launcher.installed_resources().parent.parent
        except (OSError, RuntimeError):
            self.skipTest('No installed Codex package is registered')
        resolved = package_root.resolve()
        if str(resolved).lower() == str(package_root).lower():
            self.skipTest('This Windows installation does not redirect WindowsApps')
        self.assertTrue(shell.same_path(package_root / 'new-package/app/ChatGPT.exe',
                                        resolved / 'new-package/app/ChatGPT.exe'))


class FakeStore:
    def __init__(self):
        self.data = {}
        self.writes = []

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def get(self, key, _): return self.data.get(key)
    def set(self, key, value):
        self.writes.append(key)
        self.data[key] = value


class FakeApi:
    def __init__(self):
        self.stores = {100: FakeStore(), 200: FakeStore()}
        self.owner = {100: 42, 200: 77}
        self.enumerated = [100, 200]

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def windows(self, _): return self.enumerated
    def belongs(self, hwnd, pid): return self.owner.get(hwnd) == pid
    def window_store(self, hwnd): return self.stores[hwnd]
    @contextmanager
    def lock(self, *_args, **_kwargs): yield True


class WindowTests(unittest.TestCase):
    def test_ownership_property_order_and_idempotence(self):
        api = FakeApi()
        self.assertEqual(len(shell.bind_windows(api, 42)), 1)
        self.assertEqual(api.stores[100].writes, ['command', 'icon', 'display_name', 'app_id'])
        self.assertEqual(api.stores[200].writes, [])
        self.assertEqual(shell.bind_windows(api, 42), [])
        self.assertEqual(len(api.stores[100].writes), 4)

    def test_new_windows_and_app_property_reset_are_repaired(self):
        api = FakeApi()
        shell.bind_windows(api, 42)
        api.owner[300] = 42
        api.stores[300] = FakeStore()
        api.enumerated.append(300)
        api.stores[100].data['app_id'] = 'com.openai.codex'
        changes = shell.bind_windows(api, 42)
        self.assertEqual({row['hwnd'] for row in changes}, {100, 300})
        self.assertEqual(api.stores[200].writes, [])

    def test_reused_pid_is_rejected_before_writing_window_properties(self):
        api = FakeApi()
        with patch.object(shell, 'WindowsShell', return_value=api), patch.object(shell, 'Process') as process:
            process.return_value.__enter__.return_value.created = 99
            with self.assertRaisesRegex(ValueError, '进程已变化'):
                shell.watch(42, 'ChatGPT.exe', 1)
        self.assertEqual(api.stores[100].writes, [])

    def test_watcher_ends_with_desktop_without_starting_other_processes(self):
        api = FakeApi()
        with tempfile.TemporaryDirectory() as folder, patch.object(shell, 'WindowsShell', return_value=api), \
                patch.object(shell, 'Process') as process, patch.object(shell.subprocess, 'Popen') as popen:
            child = process.return_value.__enter__.return_value
            child.created, child.exe = 1, Path('ChatGPT.exe')
            child.alive.side_effect = [True, False]
            result = shell.watch(42, 'ChatGPT.exe', 1, Path(folder))
            self.assertIn('exited_at', result)
            self.assertEqual(result['errors'], [])
            popen.assert_not_called()

    def test_duplicate_watcher_exits_without_writes(self):
        api = FakeApi()
        @contextmanager
        def occupied(*_args, **_kwargs): yield False
        api.lock = occupied
        with patch.object(shell, 'WindowsShell', return_value=api), patch.object(shell, 'Process') as process:
            child = process.return_value.__enter__.return_value
            child.created, child.exe = 1, Path('ChatGPT.exe')
            self.assertTrue(shell.watch(42, 'ChatGPT.exe', 1)['already_watching'])
        self.assertEqual(api.stores[100].writes, [])


class LauncherBoundaryTests(unittest.TestCase):
    def test_read_only_check_does_not_repair_shortcuts_or_launch_watcher(self):
        selected = dict(mode='custom-trial', desktop='ChatGPT.exe', engine='copy.exe', reason='fixture')
        with patch.object(launcher, 'get_selection', return_value=selected), \
                patch.object(launcher, 'process_snapshot', return_value=[]), \
                patch.object(launcher, 'save_status'), patch.object(launcher, 'taskbar') as taskbar, \
                patch.object(launcher.subprocess, 'Popen') as popen:
            self.assertEqual(launcher._main(['--check']), 0)
            taskbar.assert_not_called()
            popen.assert_not_called()

    def test_existing_desktop_is_not_restarted_for_icons(self):
        selected = dict(mode='custom-trial', desktop='ChatGPT.exe', engine='copy.exe', reason='fixture')
        with patch.object(launcher, 'get_selection', return_value=selected), \
                patch.object(launcher, 'process_snapshot', return_value=[{'ProcessId': 42}]), \
                patch.object(launcher, 'running_desktops', return_value=[{'ProcessId': 42}]), \
                patch.object(launcher, 'save_status'), patch.object(launcher, 'message'), \
                patch.object(launcher, 'taskbar') as taskbar, patch.object(launcher.subprocess, 'Popen') as popen:
            self.assertEqual(launcher._main([]), 2)
            taskbar.assert_not_called()
            popen.assert_not_called()

    def test_shell_failure_is_logged_without_becoming_engine_failure(self):
        with patch.object(shell, 'prepare', side_effect=OSError('fixture unavailable')), \
                patch.object(launcher, 'save_status') as log:
            self.assertIsNone(launcher.taskbar('prepare'))
            self.assertEqual(log.call_args.args[0], 'taskbar-error.json')


if __name__ == '__main__':
    unittest.main()
