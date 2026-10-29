import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from controller.core import Manager, ControllerError, atomic_json, b64, sha, version_of
from controller.verification import cached, cache_path
from controller.native_suite import REQUIRED_CASES, JITTER_CASES, SCOPE_CASES


class Compatibility(unittest.TestCase):
    def test_approved_status_and_verify_skip_disassembly_but_recheck_bytes_and_recipe(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            manager=Manager(Path(d)/'tool')
            cleanup.callback(manager.close)
            exe=Path(d)/'engine.exe'
            data=b'MZ codex-app-server99.12.3 original'
            exe.write_bytes(data)
            record=dict(format=1,passed=True,recipe_sha256='recipe',base_sha256=sha(data),
                        restored_sha256=sha(data),interrupted_write_recovery=True,unrelated_change_refused=True,
                        undo_bytes=42,cases=[dict(name=n,passed=True) for n in REQUIRED_CASES])
            atomic_json(cache_path(manager,data),record)
            with patch('controller.verification.recipe_id',return_value='recipe'), \
                 patch('controller.core.build_plan',side_effect=AssertionError('unexpected analysis')):
                status=manager.inspect(exe)
                self.assertTrue(status['verified'] and status['compatible'])
                self.assertEqual(status['undo_bytes'],42)
                self.assertEqual(manager.verify(exe),record)
            with patch('controller.verification.recipe_id',return_value='changed'), \
                 patch('controller.core.build_plan',return_value=[]) as analyze:
                self.assertFalse(manager.inspect(exe)['verified'])
                analyze.assert_called_once()
            exe.write_bytes(data[:-1]+b'X')
            with patch('controller.verification.recipe_id',return_value='recipe'), \
                 patch('controller.core.build_plan',return_value=[]) as analyze:
                self.assertFalse(manager.inspect(exe)['verified'])
                analyze.assert_called_once()

    def test_version_read_is_independent_of_support(self):
        self.assertEqual(version_of(b'MZ codex-app-server99.12.3failed to start'),'99.12.3')

    def test_inspection_preserves_version_when_structure_rejected(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            m=Manager(Path(d)/'tool')
            cleanup.callback(m.close)
            exe=Path(d)/'engine.exe'
            exe.write_bytes(b'MZ codex-app-server99.12.3 unknown structure')
            with patch('controller.core.build_plan',side_effect=ControllerError('unsupported structure')):
                r=m.inspect(exe)
            self.assertEqual(r['version'],'99.12.3')
            self.assertFalse(r['compatible'])
            self.assertFalse(r['verified'])

    def test_changed_file_cannot_reuse_approval_at_write_time(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            m=Manager(Path(d)/'tool')
            cleanup.callback(m.close)
            exe=Path(d)/'engine.exe'
            original=b'MZ codex-app-server99.12.3 new build'
            exe.write_bytes(original)
            with patch.object(m,'verify',return_value={'passed':True}), self.assertRaises(ControllerError):
                m.apply(exe,{'max_retries':2,'interval_ms':500})
            self.assertEqual(exe.read_bytes(),original)
            self.assertFalse(m.journal_path(exe).exists())

    def test_old_undo_restores_even_when_new_recipe_cannot_patch(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            m=Manager(Path(d)/'tool')
            cleanup.callback(m.close)
            exe=Path(d)/'engine.exe'
            baseline=b'MZ codex-app-server99.12.3 ORIGINAL'
            changed=baseline[:-8]+b'MODIFIED'
            exe.write_bytes(changed)
            j=dict(format=1,path=str(exe.resolve()),version='99.12.3',size=len(baseline),
                   base_sha256=sha(baseline),patched_sha256=sha(changed),profile={'max_retries':2,'interval_ms':500},
                   slots=[dict(offset=len(baseline)-8,before=b64(b'ORIGINAL'),after=b64(b'MODIFIED'))])
            atomic_json(m.journal_path(exe),j)
            with patch('controller.core.build_plan',side_effect=ControllerError('unsupported structure')):
                r=m.inspect(exe)
                self.assertTrue(r['can_restore'])
                self.assertFalse(r['compatible'])
                m.restore(exe)
            self.assertEqual(exe.read_bytes(),baseline)

    def test_recipe_upgrade_removes_old_ranges_and_preserves_undo(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            m=Manager(Path(d)/'tool',verify_writes=False)
            cleanup.callback(m.close)
            exe=Path(d)/'engine.exe'
            original=b'MZ codex-app-server99.12.3 '+b'AAA---BBB'
            exe.write_bytes(original)
            first=[dict(offset=len(original)-9,before=b64(b'AAA'),after=b64(b'111'),label='old')]
            second=[dict(offset=len(original)-3,before=b64(b'BBB'),after=b64(b'222'),label='new')]
            with patch('controller.core.build_plan',return_value=first):
                m.apply(exe,{'max_retries':1,'interval_ms':500})
            with patch('controller.core.build_plan',return_value=second):
                m.apply(exe,{'max_retries':2,'interval_ms':500})
            self.assertEqual(exe.read_bytes(),original[:-3]+b'222')
            m.restore(exe)
            self.assertEqual(exe.read_bytes(),original)

    def test_cache_binds_build_recipe_and_complete_suite(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as cleanup:
            m=Manager(Path(d)/'tool')
            cleanup.callback(m.close)
            data=b'original build'
            record=dict(format=1,passed=True,recipe_sha256='recipe',base_sha256=sha(data),
                        restored_sha256=sha(data),interrupted_write_recovery=True,unrelated_change_refused=True,cases=[dict(name=n,passed=True) for n in REQUIRED_CASES])
            with patch('controller.verification.recipe_id',return_value='recipe'):
                atomic_json(cache_path(m,data),record)
                self.assertIsNotNone(cached(m,data))
                self.assertIsNone(cached(m,data+b'changed'))
                with patch('controller.verification.recipe_id',return_value='changed recipe'):
                    self.assertIsNone(cached(m,data))
                record['cases'].pop()
                atomic_json(cache_path(m,data),record)
                self.assertIsNone(cached(m,data))

    def test_jitter_approval_requires_all_jitter_cases(self):
        with tempfile.TemporaryDirectory() as d:
            manager=Manager(Path(d))
            try:
                data=b'fixture'
                record=dict(format=1,passed=True,supports_jitter=True,recipe_sha256='recipe',
                            base_sha256=sha(data),restored_sha256=sha(data),
                            interrupted_write_recovery=True,unrelated_change_refused=True,
                            cases=[dict(name=n,passed=True) for n in REQUIRED_CASES])
                with patch('controller.verification.recipe_id',return_value='recipe'):
                    atomic_json(cache_path(manager,data),record)
                    self.assertIsNone(cached(manager,data))
                    record['cases'] += [dict(name=n,passed=True) for n in JITTER_CASES]
                    atomic_json(cache_path(manager,data),record)
                    self.assertIsNotNone(cached(manager,data))
                    record['cases'][-1]['passed']=False
                    atomic_json(cache_path(manager,data),record)
                    self.assertIsNone(cached(manager,data))
                    record['cases'][-1]['passed']=True
                    record['supports_retry_scope']=True
                    atomic_json(cache_path(manager,data),record)
                    self.assertIsNone(cached(manager,data))
                    record['cases'] += [dict(name=n,passed=True) for n in SCOPE_CASES]
                    atomic_json(cache_path(manager,data),record)
                    self.assertIsNotNone(cached(manager,data))
            finally:
                manager.close()


if __name__=='__main__':
    unittest.main()
