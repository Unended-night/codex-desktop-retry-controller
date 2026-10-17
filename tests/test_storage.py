import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from controller.core import ControllerError, atomic_json
import desktop_storage as storage
from desktop_runtime import DesktopManager, operation_lock


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.running = []
        self.old = self.generation('old', 1)
        self.history = self.generation('history', 2)
        self.active = self.generation('active', 3)
        atomic_json(self.root / 'state/desktop-trial.json', {'runtime': str(self.active), 'enabled': True})

    def generation(self, name, day):
        path = self.root / 'runtime' / name
        path.mkdir(parents=True)
        (path / 'codex.exe').write_bytes(b'x' * 1024)
        atomic_json(path / 'manifest.json', {'activation': 'app-server-tested-desktop-trial',
                    'runtime_files': {'codex.exe': 'fixture'}, 'created_at': f'2026-10-{day:02}T00:00:00+00:00'})
        atomic_json(path / 'validation.json', {'fixture': True})
        return path

    def clean(self, **kwargs):
        with operation_lock(self.root):
            return storage.maintain(self.root, process_getter=lambda: self.running, **kwargs)

    def test_keep_selected_and_one_history_and_archive_receipts(self):
        pointer = (self.root / 'state/desktop-trial.json').read_bytes()
        report = self.clean()
        self.assertFalse(self.old.exists())
        self.assertTrue(self.active.exists() and self.history.exists())
        self.assertGreater(report['reclaimed_bytes'], 1024)
        self.assertEqual(pointer, (self.root / 'state/desktop-trial.json').read_bytes())
        receipt = storage.read_json(self.root / 'logs/storage-receipts/runtime__old.json')
        self.assertIn('manifest.json', receipt['files'])
        self.assertEqual(self.clean()['removed'], [])

    def test_running_old_generation_is_extra_protected_then_reclaimed(self):
        self.running = [self.old / 'codex-command-runner.exe']
        self.clean()
        self.assertTrue(self.old.exists())
        self.running = []
        self.clean()
        self.assertFalse(self.old.exists())

    def test_manual_clears_all_history_leaving_only_current(self):
        self.running = [self.active / 'codex.exe']
        report = self.clean(keep_history=False)
        self.assertFalse(self.old.exists() or self.history.exists())
        self.assertTrue(self.active.exists())
        self.assertFalse(report['keep_history'])
        self.assertEqual(len(report['retained']), 1)
        # Automatic maintenance cannot recreate a manually removed history.
        self.assertEqual(len(self.clean()['retained']), 1)

    def test_manual_protects_pending_selection_and_running_then_converges(self):
        self.running = [self.old / 'codex.exe']
        pointer = (self.root / 'state/desktop-trial.json').read_bytes()
        self.clean(keep_history=False)
        self.assertFalse(self.history.exists())
        self.assertTrue(self.old.exists() and self.active.exists())
        self.assertEqual(pointer, (self.root / 'state/desktop-trial.json').read_bytes())
        self.running = [self.active / 'codex.exe']
        self.clean(keep_history=False)
        self.assertFalse(self.old.exists())
        self.assertTrue(self.active.exists())

    def test_public_manual_entry_and_preview_use_zero_history(self):
        manager = DesktopManager(self.root)
        self.addCleanup(manager.close)
        with patch.object(storage, 'process_paths', return_value=[]):
            report = manager.cleanup(dry_run=True)
            self.assertFalse(report['keep_history'])
            self.assertEqual(len(report['planned']), 2)
            self.assertTrue(self.old.exists() and self.history.exists())
            manager.cleanup()
        self.assertFalse(self.old.exists() or self.history.exists())

    def test_automatic_entry_retains_one_history(self):
        with patch.object(storage, 'process_paths', return_value=[]):
            report = storage.best_effort(self.root)
        self.assertTrue(report['keep_history'])
        self.assertTrue(self.active.exists() and self.history.exists())
        self.assertFalse(self.old.exists())

    def test_dry_run_does_not_write_or_delete(self):
        report = self.clean(dry_run=True)
        self.assertEqual(len(report['planned']), 1)
        self.assertTrue(self.old.exists())
        self.assertFalse((self.root / 'logs').exists())

    def test_disabled_pointer_still_protects_last_selected(self):
        atomic_json(self.root / 'state/desktop-trial.json', {'runtime': str(self.old), 'enabled': False})
        self.clean()
        self.assertTrue(self.old.exists() and self.active.exists())
        self.assertFalse(self.history.exists())

    def test_failed_candidate_removed_unknown_directory_preserved(self):
        failed = self.root / 'runtime/failed'
        atomic_json(failed / 'candidate.json', {'kind': 'codex-retry-candidate', 'created_at': '2026-10-04T00:00:00+00:00'})
        unknown = self.root / 'runtime/personal'
        unknown.mkdir()
        (unknown / 'keep.txt').write_text('keep')
        report = self.clean()
        self.assertFalse(failed.exists())
        self.assertTrue(unknown.exists())
        self.assertTrue(report['skipped'])

    def test_process_query_failure_aborts_before_deletion(self):
        with patch.object(storage, 'process_paths', side_effect=ControllerError('unreadable')):
            with self.assertRaises(ControllerError): storage.maintain(self.root)
        self.assertTrue(self.old.exists())

    def test_corrupt_or_escaping_pointer_aborts(self):
        pointer = self.root / 'state/desktop-trial.json'
        for value in ('{bad', json.dumps({'runtime': str(self.root.parent)})):
            pointer.write_text(value, encoding='utf-8')
            with self.assertRaises((ValueError, ControllerError)): self.clean()
            self.assertTrue(self.old.exists())

    def test_new_process_before_removal_is_protected(self):
        with patch.object(storage, 'process_paths', side_effect=[[], [self.old / 'codex.exe']]):
            report = storage.maintain(self.root)
        self.assertTrue(self.old.exists())
        self.assertTrue(report['skipped'])

    def test_receipt_failure_keeps_original(self):
        with patch.object(storage, 'archive', side_effect=OSError('disk full')):
            report = self.clean()
        self.assertTrue(self.old.exists())
        self.assertTrue(report['skipped'])

    def test_completed_test_removed_but_incomplete_test_kept(self):
        done = self.root / 'logs/integration-runs/desktop-done'
        atomic_json(done / 'completed.json', {'finished': True})
        (done / 'codex.exe').write_bytes(b'x' * 300)
        pending = self.root / 'logs/integration-runs/desktop-pending'
        pending.mkdir()
        self.clean()
        self.assertFalse(done.exists())
        self.assertTrue(pending.exists())

    def test_running_test_and_work_directory_kept(self):
        work = self.active / 'validation-work'
        work.mkdir()
        (work / 'db').write_bytes(b'fixture')
        self.running = [self.active / 'codex.exe']
        self.clean()
        self.assertTrue(work.exists())
        self.running = []
        self.clean()
        self.assertFalse(work.exists())
        self.assertTrue((self.active / 'validation.json').exists())

    def test_reparse_point_is_never_traversed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        link = self.old / 'linked'
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError:
            # Junction creation does not require the symbolic-link privilege.
            subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(link), str(outside)],
                           capture_output=True, check=True)
        report = self.clean()
        self.assertTrue((outside / 'keep').exists())
        self.assertTrue(self.old.exists())
        self.assertTrue(report['skipped'])

    def test_cleanup_uses_publication_lock(self):
        manager = DesktopManager(self.root)
        self.addCleanup(manager.close)
        with operation_lock(self.root), self.assertRaises(ControllerError):
            manager.cleanup()

    def test_same_profile_reuses_but_verify_forces_preparation(self):
        import desktop_runtime as runtime
        p = {'max_retries': 20, 'interval_ms': 1000}
        selected = dict(mode='custom-trial', engine=str(self.active / 'codex.exe'), profile=p)
        manifest = storage.read_json(self.active / 'manifest.json')
        manifest['version'] = 'fixture'
        atomic_json(self.active / 'manifest.json', manifest)
        with patch.object(runtime.launcher, 'get_selection', return_value=selected), \
                patch.object(runtime, 'publish', return_value={'changed': True}) as publish:
            self.assertTrue(runtime.prepare(self.root, p, self.root / 'config.toml')['reused'])
            publish.assert_not_called()
            runtime.prepare(self.root, p, self.root / 'config.toml', force=True)
            publish.assert_called_once()

    def test_changed_profile_or_invalid_selection_cannot_reuse(self):
        import desktop_runtime as runtime
        p = {'max_retries': 20, 'interval_ms': 1000}
        for selected in ({'mode': 'official'}, {'mode': 'custom-trial', 'profile': dict(p, max_retries=10)}):
            with patch.object(runtime.launcher, 'get_selection', return_value=selected), \
                    patch.object(runtime, 'publish', return_value={'changed': True}) as publish:
                runtime.prepare(self.root, p, self.root / 'config.toml')
                publish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
