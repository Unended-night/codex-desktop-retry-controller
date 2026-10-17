"""Launcher routing: auto preparation precedes the final locked selection."""
import contextlib
import unittest
from unittest.mock import patch, MagicMock
import desktop_trial as launcher
import desktop_runtime as runtime


class AutomaticLaunchTests(unittest.TestCase):
    def launch(self,args,enabled=True,mode='official'):
        manager=MagicMock()
        manager._worker.return_value={'changed':True}
        with patch.object(runtime,'operation_lock',side_effect=lambda root, *args:contextlib.nullcontext()), \
             patch.object(runtime,'read_pointer',return_value=dict(enabled=enabled,runtime='old')), \
             patch.object(runtime,'DesktopManager',return_value=manager), \
             patch.object(launcher,'get_selection',return_value=dict(mode=mode)), \
             patch.object(launcher,'process_snapshot',return_value=[]), \
             patch.object(launcher,'automatic_update',side_effect=lambda m:m._worker('auto')), \
             patch.object(launcher,'_main',return_value=2) as actual:
            launcher.main(args)
        return manager,actual

    def test_stale_entry_prepares_then_rechecks_under_launcher_lock(self):
        manager,actual=self.launch([])
        manager._worker.assert_called_once_with('auto')
        actual.assert_called_once_with([],{'changed':True},notifications=[])
        manager.close.assert_called_once()

    def test_check_official_disabled_and_current_entry_do_not_prepare(self):
        for args,enabled,mode in [(['--check'],True,'official'),(['--official'],True,'official'),
                                  ([],False,'official'),([],True,'custom-trial')]:
            with self.subTest(args=args,enabled=enabled,mode=mode):
                manager,_=self.launch(args,enabled,mode)
                manager._worker.assert_not_called()


if __name__=='__main__': unittest.main()
