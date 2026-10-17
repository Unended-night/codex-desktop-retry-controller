"""Regression tests for held notices, cancellation, ownership and Windows jobs."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import desktop_processes as processes
import desktop_runtime as runtime
import desktop_trial as launcher
from controller.core import ControllerError, atomic_json, profile


class TemporaryRoot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='codex-recovery-test-')
        self.root = Path(self.temp.name).resolve()
        self.assertEqual(self.root.parent, Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)


class NoticeLockTests(TemporaryRoot):
    def run_launcher(self, mode='custom-trial', existing=True, fail=False):
        selected = dict(mode=mode, engine=str(self.root / 'copy.exe'), desktop=str(self.root / 'ChatGPT.exe'), reason='fixture')
        active = [dict(ProcessId=42, ExecutablePath=r'C:\WindowsApps\OpenAI.Codex_fixture\app\ChatGPT.exe')] if existing else []
        observed = []
        def notification(title, text):
            # Simulate a notice left open: another operation must already be able
            # to take the real Windows byte lock, before this callback returns.
            with runtime.operation_lock(self.root, 'another controller'):
                observed.append(title)
        with patch.object(launcher, 'ROOT', self.root), \
             patch.object(runtime, 'read_pointer', return_value={}), \
             patch.object(launcher, 'get_selection', return_value=selected), \
             patch.object(launcher, 'process_snapshot', return_value=active), \
             patch.object(launcher, 'save_status'), patch.object(launcher, 'taskbar'), \
             patch.object(launcher, 'message', side_effect=notification), \
             patch.object(launcher.subprocess, 'Popen') as spawn, \
             patch.object(launcher.time, 'monotonic', side_effect=[0, 26]), \
             patch('desktop_storage.best_effort', return_value={}):
            if fail:
                spawn.side_effect = OSError('fixture spawn failure')
                with self.assertRaises(OSError):
                    launcher.main([])
                self.assertTrue(processes.lock_status(self.root)['available'])
                return
            result = launcher.main([])
            if existing:
                spawn.assert_not_called()
                self.assertEqual(result, 2)
            else:
                spawn.assert_called_once()
        return observed

    def test_existing_desktop_notice_does_not_hold_lock(self):
        self.assertEqual(self.run_launcher(), ['Codex 已经在运行'])

    def test_fallback_notice_does_not_hold_lock(self):
        self.assertEqual(self.run_launcher('official', existing=False), ['使用官方引擎'])

    def test_unconfirmed_engine_notice_does_not_hold_lock(self):
        self.assertEqual(self.run_launcher(existing=False), ['试用入口需要检查'])

    def test_spawn_error_releases_lock(self):
        self.run_launcher(existing=False, fail=True)

    def test_read_only_check_works_while_an_operation_holds_lock(self):
        selected = dict(mode='official', engine='official.exe', desktop='ChatGPT.exe', reason='fixture')
        with runtime.operation_lock(self.root), patch.object(launcher, 'ROOT', self.root), \
             patch.object(launcher, 'get_selection', return_value=selected), \
             patch.object(launcher, 'process_snapshot', return_value=[]), \
             patch.object(launcher, 'save_status'), patch('builtins.print'):
            self.assertEqual(launcher.main(['--check']), 0)


class LockDiagnosticsTests(TemporaryRoot):
    def test_live_owner_has_pid_stage_and_age_and_stale_record_is_ignored(self):
        with runtime.operation_lock(self.root, 'fixture verification'):
            status = processes.lock_status(self.root)
            self.assertFalse(status['available'])
            self.assertEqual(status['owner']['pid'], os.getpid())
            self.assertEqual(status['owner']['action'], 'fixture verification')
            self.assertIn('elapsed_seconds', status['owner'])
            with self.assertRaisesRegex(ControllerError, f'PID {os.getpid()}'):
                with runtime.operation_lock(self.root):
                    self.fail('Concurrent lock was admitted')
        # A persistent lock file and even a stale owner record do not mean locked.
        atomic_json(self.root / 'state/desktop-controller-owner.json', status['owner'])
        self.assertTrue((self.root / 'state/desktop-controller.lock').is_file())
        self.assertEqual(processes.lock_status(self.root), {'available': True})

    def test_worker_lock_failure_writes_both_result_and_nonempty_log(self):
        manager = runtime.DesktopManager(self.root)
        self.addCleanup(manager.close)
        with runtime.operation_lock(self.root, 'fixture blocker'):
            with self.assertRaisesRegex(ControllerError, 'fixture blocker'):
                manager.apply(profile(20, '1'))
        result = next((self.root / 'logs/desktop-jobs').glob('apply-*.json'))
        self.assertIn('fixture blocker', json.loads(result.read_text(encoding='utf-8'))['error'])
        detail = result.with_suffix('.log').read_text(encoding='utf-8')
        self.assertIn('fixture blocker', detail)
        self.assertIn('PID', detail)

    def test_recovery_never_deletes_lock_or_changes_pointer(self):
        pointer = self.root / 'state/desktop-trial.json'
        atomic_json(pointer, {'runtime': 'saved-runtime', 'last_profile': profile(20, '1')})
        before = pointer.read_bytes()
        with runtime.operation_lock(self.root):
            pass
        lock_path = self.root / 'state/desktop-controller.lock'
        original = lock_path.stat()
        with patch.object(processes, 'snapshot', return_value=[]):
            result = processes.recover(self.root)
        self.assertTrue(result['recovered'])
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(lock_path.stat().st_ino, original.st_ino)


class OwnershipTests(TemporaryRoot):
    def row(self, pid, *, script=None, arguments=(), parent=1, created=100, name='python.exe', exe=None):
        exe = exe or str(Path(sys.executable).resolve())
        command = subprocess.list2cmdline([exe, '-B', '-X', 'utf8', str(script), *arguments]) if script else ''
        return dict(ProcessId=pid, ParentProcessId=parent, Name=name, Created=created,
                    ExecutablePath=exe, CommandLine=command)

    def test_exact_scripts_only_and_desktop_subtree_and_gui_are_protected(self):
        owned = self.row(10, script=self.root / 'desktop_trial.py')
        worker = self.row(11, script=processes.ROOT / 'desktop_runtime.py', arguments=['apply', '--worker', '--root', str(self.root)])
        probe = self.row(12, parent=11, created=110, exe=str(self.root / 'runtime/codex.exe'), name='codex.exe')
        desktop = self.row(20, parent=10, created=110, name='ChatGPT.exe', exe=str(self.root / 'app/ChatGPT.exe'))
        real_engine = self.row(21, parent=20, created=120, name='codex.exe', exe=str(self.root / 'runtime/selected/codex.exe'))
        gui = self.row(30, script=self.root / 'app.pyw')
        other = self.row(40, script=self.root / 'other/desktop_trial.py')
        wrong_root = self.row(41, script=processes.ROOT / 'desktop_runtime.py', arguments=['apply', '--worker', '--root', str(self.root / 'other')])
        embedded = self.row(42)
        embedded['CommandLine'] = subprocess.list2cmdline([sys.executable, '-c', f'print({str(self.root / "desktop_trial.py")!r})'])
        reused_parent = self.row(43, parent=11, created=90)
        rows = [owned, worker, probe, desktop, real_engine, gui, other, wrong_root, embedded, reused_parent]
        plan = processes.recovery_plan(rows, self.root, processes.Windows(), current_pid=999)
        self.assertEqual({row['ProcessId'] for row in plan}, {10, 11, 12})

    def test_pid_reuse_refused_on_same_handle(self):
        process = object.__new__(processes.Process)
        process.pid, process.created, process.exe = 7, 200, sys.executable
        row = self.row(7, created=100)
        self.assertFalse(process.matches(row))
        row['Created'] = 200
        self.assertTrue(process.matches(row))
        row['ExecutablePath'] = str(self.root / 'other/python.exe')
        self.assertFalse(process.matches(row))

    def test_failed_child_is_reported_even_after_parent_exits(self):
        parent = self.row(10, script=self.root / 'desktop_trial.py')
        child = self.row(11, parent=10, created=110)
        class FakeProcess:
            def __init__(self, api, pid, **kwargs): self.pid = pid
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def matches(self, row): return True
            def alive(self): return True
            def stop(self):
                if self.pid == 11: raise ControllerError('fixture access denied')
                return True
        with patch.object(processes, 'snapshot', side_effect=[[parent, child], [child]]), \
             patch.object(processes, 'Process', FakeProcess):
            result = processes.recover(self.root)
        self.assertFalse(result['recovered'])
        self.assertEqual(result['remaining'], [11])

    def test_preview_does_not_terminate_or_write_a_report(self):
        row = self.row(10, script=self.root / 'desktop_trial.py')
        with patch.object(processes, 'snapshot', return_value=[row]), patch.object(processes, 'Process') as native:
            report = processes.recover(self.root, dry_run=True)
        native.assert_not_called()
        self.assertEqual(report['candidates'][0]['pid'], 10)
        self.assertFalse((self.root / 'logs').exists())


class RealProcessRecoveryTests(TemporaryRoot):
    def setUp(self):
        super().setUp()
        self.code = self.root / 'fixture-code'
        self.code.mkdir()
        self.marker = self.root / 'started.json'
        self.command = [sys.executable, '-B', '-X', 'utf8', str(self.code / 'desktop_runtime.py'),
                        'apply', '--worker', '--root', str(self.root)]
        fixture = '''import json, os, pathlib, subprocess, sys, time
sys.path.insert(0, PROJECT)
from desktop_processes import wait_worker_gate
from desktop_runtime import operation_lock
root = pathlib.Path(sys.argv[sys.argv.index('--root') + 1])
if '--job-gate' in sys.argv:
    wait_worker_gate(sys.argv[sys.argv.index('--job-gate') + 1])
with operation_lock(root, 'fixture native probes'):
    child = subprocess.Popen([sys.executable, '-B', '-X', 'utf8', '-c', 'import time; time.sleep(90)'], creationflags=subprocess.CREATE_NO_WINDOW)
    (root / 'started.json').write_text(json.dumps({'worker': os.getpid(), 'child': child.pid}), encoding='utf-8')
    time.sleep(90)
'''.replace('PROJECT', repr(str(processes.ROOT)))
        (self.code / 'desktop_runtime.py').write_text(fixture, encoding='utf-8')

    def wait_marker(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.marker.exists():
                try:
                    return json.loads(self.marker.read_text(encoding='utf-8'))
                except ValueError:
                    pass
            time.sleep(.03)
        self.fail('Fixture worker did not start')

    @contextlib.contextmanager
    def worker(self):
        cancel, outcome = threading.Event(), []
        def run():
            try:
                with (self.root / 'worker.log').open('w', encoding='utf-8') as log:
                    outcome.append(processes.run_worker(self.command, self.root, log, cancel))
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            yield cancel, outcome
        finally:
            cancel.set()
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), outcome)

    def test_cancel_job_reaps_worker_and_child_and_releases_lock(self):
        with self.worker() as (cancel, outcome):
            ids = self.wait_marker()
            api = processes.Windows()
            with processes.Process(api, ids['worker']) as worker, processes.Process(api, ids['child']) as child:
                self.assertFalse(processes.lock_status(self.root)['available'])
                cancel.set()
                self.assertFalse(worker.alive(wait_ms=5000))
                self.assertFalse(child.alive(wait_ms=5000))
        self.assertIsInstance(outcome[0], ControllerError)
        self.assertTrue(processes.lock_status(self.root)['available'])

    def test_failed_process_inspection_reaps_unassigned_worker(self):
        original = subprocess.Popen
        started = []
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            started.append(child)
            return child
        with (self.root / 'worker.log').open('w', encoding='utf-8') as log, \
             patch.object(processes.subprocess, 'Popen', side_effect=spawn), \
             patch.object(processes, 'Process', side_effect=OSError('fixture inspection failure')):
            with self.assertRaisesRegex(OSError, 'fixture inspection failure'):
                processes.run_worker(self.command, self.root, log)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].returncode)

    def test_already_cancelled_operation_does_not_start_a_worker(self):
        cancel = threading.Event()
        cancel.set()
        with (self.root / 'worker.log').open('w', encoding='utf-8') as log, \
             patch.object(processes.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ControllerError, '取消'):
                processes.run_worker(self.command, self.root, log, cancel)
        spawn.assert_not_called()

    def test_recovery_terminates_verified_job_and_legacy_launcher(self):
        with self.worker() as (_, outcome):
            ids = self.wait_marker()
            api = processes.Windows()
            with processes.Process(api, ids['child']) as child, patch.object(processes, 'ROOT', self.code):
                result = processes.recover(self.root)
                self.assertTrue(result['recovered'], result)
                self.assertTrue(any(row.get('job') for row in result['stopped']), result)
                self.assertFalse(child.alive(wait_ms=5000))
        self.assertEqual(outcome, [processes.CANCELLED])

        self.marker.unlink()
        entry = self.root / 'desktop_trial.py'
        entry.write_text('import sys\nsys.path.insert(0, ' + repr(str(processes.ROOT)) + ')\n'
                         'import time\nfrom pathlib import Path\nfrom desktop_runtime import operation_lock\n'
                         'with operation_lock(Path(__file__).parent):\n'
                         '    (Path(__file__).parent / "started.json").write_text("{}", encoding="utf-8")\n'
                         '    time.sleep(90)\n', encoding='utf-8')
        legacy = subprocess.Popen([sys.executable, '-B', '-X', 'utf8', str(entry)], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            self.wait_marker()
            report = processes.recover(self.root)
            self.assertTrue(report['recovered'], report)
            self.assertEqual(legacy.wait(timeout=5), processes.CANCELLED)
        finally:
            if legacy.poll() is None:
                legacy.terminate()
            legacy.wait(timeout=5)

    def test_worker_probes_exit_if_owner_process_crashes(self):
        parent_script = ('import sys\nsys.path.insert(0, ' + repr(str(processes.ROOT)) + ')\n'
                         'from pathlib import Path\nfrom desktop_processes import run_worker\n'
                         'with open(' + repr(str(self.root / 'worker.log')) + ', "w", encoding="utf-8") as log:\n'
                         '    run_worker(' + repr(self.command) + ', Path(' + repr(str(self.root)) + '), log)\n')
        owner = subprocess.Popen([sys.executable, '-B', '-X', 'utf8', '-c', parent_script], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            ids = self.wait_marker()
            api = processes.Windows()
            with processes.Process(api, ids['worker']) as worker, processes.Process(api, ids['child']) as child:
                owner.terminate()
                owner.wait(timeout=5)
                self.assertFalse(worker.alive(wait_ms=5000))
                self.assertFalse(child.alive(wait_ms=5000))
        finally:
            if owner.poll() is None:
                owner.terminate()
            owner.wait(timeout=5)
        self.assertTrue(processes.lock_status(self.root)['available'])


if __name__ == '__main__':
    unittest.main()
