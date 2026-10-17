"""Guard against stale runtime selection or global environment mutation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from desktop_trial import digest, launch_environment, running_desktops, selection


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.resources=root/'app/resources';self.resources.mkdir(parents=True)
        self.runtime=root/'runtime';self.runtime.mkdir()
        self.config=root/'config.toml';self.config.write_text('sandbox_mode="workspace-write"',encoding='utf-8')
        (self.resources.parent/'ChatGPT.exe').write_bytes(b'desktop')
        (self.resources/'app.asar').write_bytes(b'desktop-source')
        names=['codex.exe','codex-code-mode-host.exe','codex-command-runner.exe','codex-windows-sandbox-setup.exe','rg.exe']
        for name in names:
            (self.resources/name).write_bytes(('official-'+name).encode())
            (self.runtime/name).write_bytes(('verified-'+name).encode())
        (self.runtime/'validation.json').write_text(json.dumps({'trial_eligible':True}),encoding='utf-8')
        self.manifest=dict(format=1,profile={'max_retries':25,'interval_ms':1000},activation='app-server-tested-desktop-trial',resources=str(self.resources),
            desktop_sha256=digest(self.resources.parent/'ChatGPT.exe'),app_asar_sha256=digest(self.resources/'app.asar'),
            recipe_sha256='recipe',config_path=str(self.config),config_sha256=digest(self.config),
            official_files={n:digest(self.resources/n) for n in names},runtime_files={n:digest(self.runtime/n) for n in names},
            validation_sha256=digest(self.runtime/'validation.json'))

    def select(self,**changes):
        return selection(self.resources,self.runtime,dict(self.manifest,**changes),self.config,'recipe')

    def test_verified_build_uses_copy(self):
        self.assertEqual(self.select()['mode'],'custom-trial')

    def test_updated_desktop_and_helper_fall_back(self):
        for path in [self.resources/'app.asar',self.resources/'codex.exe',self.resources/'codex-code-mode-host.exe']:
            original=path.read_bytes();path.write_bytes(b'updated')
            self.assertEqual(self.select()['mode'],'official')
            path.write_bytes(original)
        self.assertEqual(self.select(resources=str(self.resources/'new-package'))['mode'],'official')

    def test_damaged_copy_missing_helper_or_report_falls_back(self):
        for path in [self.runtime/'codex.exe',self.runtime/'codex-command-runner.exe',self.runtime/'validation.json']:
            original=path.read_bytes();path.unlink()
            self.assertEqual(self.select()['mode'],'official')
            path.write_bytes(original)

    def test_new_recipe_or_unapproved_runtime_falls_back(self):
        self.assertEqual(self.select(recipe_sha256='changed')['mode'],'official')
        self.assertEqual(self.select(activation='not-approved')['mode'],'official')

    def test_legacy_runtime_allows_changed_or_missing_configuration(self):
        self.config.write_text('sandbox_mode="danger-full-access"',encoding='utf-8')
        self.assertEqual(self.select()['mode'],'custom-trial')
        self.config.unlink()
        self.assertEqual(self.select()['mode'],'custom-trial')

    def test_environment_is_process_local_and_fallback_clears_override(self):
        original={'CODEX_CLI_PATH':'old.exe','CODEX_HOME':'existing-home','ELECTRON_RUN_AS_NODE':'1'}
        custom=launch_environment(original,{'mode':'custom-trial','engine':'copy.exe'})
        fallback=launch_environment(original,{'mode':'official','engine':'official.exe'})
        self.assertEqual(custom['CODEX_CLI_PATH'],'copy.exe')
        self.assertNotIn('CODEX_CLI_PATH',fallback)
        self.assertNotIn('ELECTRON_RUN_AS_NODE',custom)
        self.assertEqual(custom['CODEX_HOME'],'existing-home')
        self.assertEqual(original['CODEX_CLI_PATH'],'old.exe')

    def test_active_desktop_detection(self):
        processes=[{'ProcessId':7,'ExecutablePath':r'C:\Program Files\WindowsApps\OpenAI.Codex_1\app\ChatGPT.exe'},
                   {'ProcessId':8,'ExecutablePath':r'C:\Other\ChatGPT.exe'}]
        self.assertEqual([p['ProcessId'] for p in running_desktops(processes)],[7])


if __name__=='__main__':unittest.main()
