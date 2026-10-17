"""A hung operation must not disable recovery or overwrite its eventual result."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import desktop_runtime as runtime


class RecoveryUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / 'app.pyw'
        loader = importlib.machinery.SourceFileLoader('recovery_test_ui', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.module = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.module)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='codex-recovery-ui-')
        self.assertEqual(Path(self.temp.name).resolve().parent, Path(tempfile.gettempdir()).resolve())
        self.manager = runtime.DesktopManager(self.temp.name)
        with patch.object(self.module, 'DesktopManager', return_value=self.manager):
            self.app = self.module.App()
        self.app.withdraw()
        for task in self.app.tk.call('after', 'info'):
            self.app.after_cancel(task)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.app.destroy)
        self.addCleanup(self.manager.close)

    def wait_for(self, condition):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.app.update()
            if condition():
                return
            time.sleep(.01)
        self.fail('UI operation did not complete')

    def test_recovery_remains_clickable_and_late_worker_result_is_ignored(self):
        entered, release, returned = threading.Event(), threading.Event(), threading.Event()
        old_result = []
        def blocked():
            entered.set()
            release.wait(timeout=5)
            returned.set()
            return 'old operation'
        try:
            self.app._run('fixture busy', blocked, old_result.append)
            self.assertTrue(entered.wait(timeout=2))
            cancel = self.app.cancel_active
            self.assertEqual(str(self.app.recover_button['state']), 'normal')
            with patch.object(self.manager, 'recover_processes', return_value=dict(recovered=True, stopped=[])):
                self.app.recover_button.invoke()
                self.app._poll()
                self.wait_for(lambda: not self.app.busy)
            self.assertTrue(cancel.is_set())
            self.assertIn('操作锁已释放', self.app.notice.get())
            release.set()
            self.assertTrue(returned.wait(timeout=2))
            self.wait_for(lambda: self.app.jobs.empty())
            self.assertEqual(old_result, [])
            self.assertIn('操作锁已释放', self.app.notice.get())
            self.assertEqual(str(self.app.recover_button['state']), 'normal')
        finally:
            release.set()
            returned.wait(timeout=2)


if __name__ == '__main__':
    unittest.main()
