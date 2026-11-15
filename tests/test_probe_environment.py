"""Retry evidence must not depend on the shell or GUI logging environment."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'research'))
sys.path.insert(0,str(ROOT/'tests'))
import probe_retries
import verify_reported_rate_limit as reported
from research import verify_desktop_runtime as desktop_probe


class ProbeEnvironmentTests(unittest.TestCase):
    def test_sandbox_comparison_never_inherits_desktop_package_identity(self):
        markers=dict(CODEX_WINDOWS_REGISTERED_CORE='1',CODEX_WINDOWS_SANDBOX_PACKAGE_FAMILY='fixture-package')
        calls=[]
        def rpc(exe,cwd,env):
            self.assertTrue(all(key not in env for key in markers))
            self.assertEqual(env['CODEX_CLI_PATH'],str(exe))
            self.assertTrue((Path(env['CODEX_HOME'])/'config.toml').is_file())
            calls.append(exe)
            result=Mock(stderr=[])
            result.call.return_value={'result':{'stdout':''}}
            return result
        with patch.dict(os.environ,markers), tempfile.TemporaryDirectory() as folder, \
                patch.object(desktop_probe,'Rpc',side_effect=rpc), patch('builtins.print'):
            for label in ('official','copy'):
                exe=Path(folder)/label/'codex.exe'
                result=desktop_probe.sandbox_matrix(exe,Path(folder),label)
                self.assertEqual(result['launch_mode'],'standalone-override')
                self.assertEqual(result['registered_env_inherited'],dict.fromkeys(markers,False))
            self.assertEqual({k:os.environ[k] for k in markers},markers)
        self.assertEqual(len(calls),2)

    def test_probes_enable_retry_warnings_without_changing_parent_environment(self):
        calls=[]
        def run(exe,directory,env,timeout,**options):
            self.assertEqual(env['RUST_LOG'],'warn')
            self.assertEqual(env['CODEX_HOME'],directory)
            self.assertTrue((Path(directory)/'config.toml').is_file())
            calls.append(directory)
            return '', 'retrying sampling request (1/2 in 1.07s)', 1, False
        for setting in (None,'off','error'):
            with self.subTest(setting=setting), patch.dict(os.environ), tempfile.TemporaryDirectory() as folder:
                if setting is None:
                    os.environ.pop('RUST_LOG',None)
                else:
                    os.environ['RUST_LOG']=setting
                with patch('appserver_probe.run',side_effect=run), patch.object(reported,'run',side_effect=run):
                    a=probe_retries.probe('fixture.exe',4,interface='app-server')
                    b=reported.replay(Path('fixture.exe'),Path(folder)/'replay')
                self.assertEqual(a['selected_delays_ms'],[1070])
                self.assertEqual(b['selected_delays_ms'],[1070])
                self.assertEqual(os.environ.get('RUST_LOG'),setting)
        self.assertEqual(len(calls),6)
