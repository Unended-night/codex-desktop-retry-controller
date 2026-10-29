"""Publication, rollback, configuration and receipt boundaries (small fixtures)."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import desktop_runtime as runtime
import desktop_trial as launcher
import desktop_validation as validation
from controller.core import ControllerError, atomic_json, profile


def retry_result(p):
    attempts = min(p['max_retries'], 2)
    return dict(timed_out=False, exact_error_seen=True, requests=attempts + 1,
                turn_exit_code=1 if p['max_retries'] <= 2 else 0,
                reconnects=[f"Reconnecting... {i}/{p['max_retries']}" for i in range(1, attempts + 1)],
                intervals_seconds=[p['interval_ms'] / 1000 + .03] * attempts,
                selected_delays_ms=[p['interval_ms']] * attempts)


def matrices():
    cases = []
    for name in ('workspace-write-offline', 'read-only-offline', 'workspace-write-online'):
        writable = name != 'read-only-offline'
        online = name == 'workspace-write-online'
        obs = dict(inside={'write': writable}, outside={'write': False}, restricted_token=True,
                   direct_loopback=True, offline_marker=None if online else '1')
        obs.update({'proxy_http': 'loopback-ok'} if online else {'proxy_http_error': 'URLError'})
        cases.append(dict(name=name, response={'result': {'exitCode': 0}}, observations=obs,
                          inside_exists=writable, outside_exists=False))
    return [{'cases': cases}, {'cases': json.loads(json.dumps(cases))}]


def receipt(resources, target, manifest):
    return dict(format=3, config_policy='user-managed', trial_eligible=True, profile=manifest['profile'],
                engine_sha256=manifest['runtime_files']['codex.exe'],
                official_files=manifest['official_files'], recipe_sha256=manifest['recipe_sha256'],
                desktop_rules_sha256=manifest['desktop_rules_sha256'],
                retry=retry_result(manifest['profile']), comparisons=matrices(), scope='fixture')


class RetryScopeReceiptTests(unittest.TestCase):
    def rows(self,p):
        rows=[]
        for name in validation.SCOPE_PROBES:
            result=retry_result(p)
            result['exit_code']=result['turn_exit_code']
            if name in ('automatic','post-turn'):
                result['exit_code']=0
            result.update(setup_requests=1,setup_compaction_requests=0,
                          compaction_requests=result['requests'])
            rows.append(dict(name=name,result=result))
        return rows

    def test_actual_settings_require_all_paths_and_original_budget(self):
        for p in (profile(0,'0'),profile(2,'.125'),profile(300,'1.5','.5')):
            rows=self.rows(p)
            self.assertTrue(validation.scope_results_valid(rows,p))
            self.assertFalse(validation.scope_results_valid(rows[:-1],p))
            rows[2]['result']['requests']+=1
            self.assertFalse(validation.scope_results_valid(rows,p))
        p=profile(300,'1.5','.5');rows=self.rows(p)
        rows[2]['result']['reconnects']=['Reconnecting... 1/5','Reconnecting... 2/5']
        self.assertFalse(validation.scope_results_valid(rows,p))

    def test_noncompaction_requests_or_out_of_range_waits_do_not_pass(self):
        p=profile(300,'1.5','.5')
        rows=self.rows(p);rows[2]['result']['compaction_requests']=0
        self.assertFalse(validation.scope_results_valid(rows,p))
        rows=self.rows(p);rows[4]['result']['intervals_seconds']=[.1,.1]
        self.assertFalse(validation.scope_results_valid(rows,p))

    def test_parameter_probes_overlap_but_keep_complete_ordered_receipts(self):
        sys.path.insert(0,str(validation.ROOT/'research'))
        p=profile(300,'1.5','.5')
        results={row['name']:row['result'] for row in self.rows(p)}
        barrier=threading.Barrier(4,timeout=5)
        lock=threading.Lock();active=0;peak=0
        def probe(*args,**kwargs):
            nonlocal active,peak
            mode=kwargs.get('compact')
            name=({True:'compact','auto':'automatic','post-turn':'post-turn'}[mode] if mode
                  else 'encrypted' if kwargs.get('error_code') else 'azure')
            with lock:
                active+=1;peak=max(peak,active)
            try:
                if name!='post-turn':barrier.wait()
                return results[name]
            finally:
                with lock:active-=1
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);target=root/'runtime';target.mkdir()
            manifest=dict(profile=p,supports_retry_scope=True,runtime_files={'codex.exe':'fixture'},
                          official_files={},recipe_sha256='fixture',desktop_rules_sha256='fixture')
            with patch('research.verify_desktop_runtime.replay',return_value=retry_result(p)), \
                 patch('research.verify_desktop_runtime.sandbox_matrix',return_value=matrices()[0]), \
                 patch('probe_retries.probe',side_effect=probe):
                report=validation.run(root,target,manifest)
            self.assertEqual(peak,4)
            self.assertEqual([r['name'] for r in report['retry_scope']],list(validation.SCOPE_PROBES))
            self.assertTrue(validation.receipt_valid(report,dict(manifest,format=3,config_policy='user-managed')))

    def test_parameter_worker_failure_does_not_reach_sandbox_or_approval(self):
        sys.path.insert(0,str(validation.ROOT/'research'))
        p=profile(300,'1.5','.5')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with patch('research.verify_desktop_runtime.replay',return_value=retry_result(p)), \
                 patch('research.verify_desktop_runtime.sandbox_matrix') as sandbox, \
                 patch('probe_retries.probe',side_effect=RuntimeError('probe failed')):
                with self.assertRaisesRegex(RuntimeError,'probe failed'):
                    validation.run(root,root,dict(profile=p,supports_retry_scope=True))
                sandbox.assert_not_called()


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.resources = self.root / 'official/app/resources'
        self.resources.mkdir(parents=True)
        for name in validation.COMPONENTS:
            (self.resources / name).write_bytes(('official-' + name).encode())
        (self.resources.parent / 'ChatGPT.exe').write_bytes(b'desktop')
        (self.resources / 'app.asar').write_bytes(b'asar')
        self.config = self.root / 'config.toml'
        self.config.write_text('sandbox_mode="workspace-write"\n[windows]\nsandbox="unelevated"\n', encoding='utf-8')
        self.old = self.root / 'runtime/old'
        self.old.mkdir(parents=True)
        (self.old / 'codex.exe').write_bytes(b'currently-running')
        self.pointer = self.root / 'state/desktop-trial.json'
        atomic_json(self.pointer, {'runtime': str(self.old), 'last_profile': profile(25, '1')})
        self.before = self.pointer.read_bytes()
        self.source = runtime.snapshot(self.resources)
        self.original_config = self.config.read_bytes()
        self.addCleanup(patch.stopall)
        patch('desktop_storage.process_paths', return_value=[]).start()
        patch.object(runtime.Manager, 'verify', return_value={'version': '99.1.0'}).start()
        def fake_apply(manager, path, p):
            self.assertNotEqual(path, self.old / 'codex.exe')
            path.relative_to(self.root / 'runtime')
            path.write_bytes(b'patched-' + json.dumps(p).encode())
        patch.object(runtime.Manager, 'apply', fake_apply).start()
        self.validator = patch.object(validation, 'run', side_effect=receipt).start()

    def publish(self, p=None):
        with runtime.operation_lock(self.root):
            return runtime.publish(self.root, p or profile(2, '.25'), self.config, lambda: self.resources)

    def selected(self):
        return launcher.get_selection(self.root, resources=self.resources, config_path=self.config)

    def test_publish_changes_only_pointer_and_new_copy(self):
        result = self.publish()
        self.assertEqual(self.selected()['profile'], profile(2, '.25'))
        self.assertIn('2 次 / 0.25 秒', self.selected()['reason'])
        self.assertEqual(runtime.snapshot(self.resources), self.source)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertEqual((self.old / 'codex.exe').read_bytes(), b'currently-running')
        self.assertNotEqual(result['runtime'], str(self.old))
        self.assertEqual(runtime.saved_profile(self.root), profile(2, '.25'))

    def test_zero_and_max_parameters(self):
        for p in (profile(0, '0'), profile(1, '60'), profile(1000000, '.001')):
            self.publish(p)
            self.assertEqual(self.selected()['profile'], p)

    def test_jitter_profile_survives_publication_selection_and_saved_settings(self):
        p=profile(50,1000,70,unit='ms')
        self.publish(p)
        self.assertEqual(self.selected()['profile'],p)
        self.assertEqual(runtime.saved_profile(self.root),p)
        self.assertIn('±70 毫秒',self.selected()['reason'])

    def test_failed_validation_keeps_pointer(self):
        self.validator.side_effect = ControllerError('fixture failure')
        with self.assertRaises(ControllerError):
            self.publish()
        self.assertEqual(self.pointer.read_bytes(), self.before)

    def test_changes_during_validation_refuse_commit(self):
        targets = [self.resources / 'codex.exe', self.resources / 'app.asar',
                   self.resources / 'codex-command-runner.exe']
        for target in targets:
            old = target.read_bytes()
            def mutate(resources, staged, manifest):
                report = receipt(resources, staged, manifest)
                target.write_bytes(old + b'\n#changed')
                return report
            self.validator.side_effect = mutate
            with self.assertRaises(ControllerError):
                self.publish()
            self.assertEqual(self.pointer.read_bytes(), self.before)
            target.write_bytes(old)

    def test_config_change_during_verification_does_not_block_publication(self):
        def changed(resources, target, manifest):
            self.config.write_text('sandbox_mode="workspace-write"\n[windows]\nsandbox="elevated"', encoding='utf-8')
            return receipt(resources, target, manifest)
        self.validator.side_effect = changed
        self.publish()
        self.assertEqual(self.selected()['mode'], 'custom-trial')
        self.assertTrue(self.selected()['config_notes'])
        self.assertIn('elevated', self.config.read_text(encoding='utf-8'))

    def test_changed_candidate_or_pointer_refuses_commit(self):
        def mutate(resources, target, manifest):
            report = receipt(resources, target, manifest)
            (target / 'rg.exe').write_bytes(b'damaged')
            return report
        self.validator.side_effect = mutate
        with self.assertRaises(ControllerError): self.publish()
        self.assertEqual(self.pointer.read_bytes(), self.before)
        def change_pointer(resources, target, manifest):
            atomic_json(self.pointer, {'enabled': False})
            return receipt(resources, target, manifest)
        self.validator.side_effect = change_pointer
        with self.assertRaises(ControllerError): self.publish()
        self.assertEqual(runtime.read_pointer(self.root), {'enabled': False})

    def test_bad_receipt_and_rule_change_refuse_commit(self):
        def bad(resources, target, manifest):
            report = receipt(resources, target, manifest)
            report['profile'] = profile(3, '4')
            return report
        self.validator.side_effect = bad
        with self.assertRaises(ControllerError): self.publish()
        self.validator.side_effect = receipt
        with patch.object(validation, 'rules_id', side_effect=['old', 'new']):
            with self.assertRaises(ControllerError): self.publish()
        self.assertEqual(self.pointer.read_bytes(), self.before)

    def test_restore_does_not_require_compatible_or_running_files(self):
        self.publish()
        active = Path(runtime.read_pointer(self.root)['runtime']) / 'codex.exe'
        original = active.read_bytes()
        runtime.restore(self.root)
        self.assertEqual(self.selected()['mode'], 'official')
        self.assertEqual(runtime.saved_profile(self.root), profile(2, '.25'))
        self.assertEqual(active.read_bytes(), original)
        self.assertFalse(runtime.restore(self.root)['changed'])

    def test_official_update_still_falls_back(self):
        self.publish()
        (self.resources / 'codex.exe').write_bytes(b'updated')
        self.assertEqual(self.selected()['mode'], 'official')

    def test_provider_model_comments_permissions_and_transport_keep_selection(self):
        self.publish()
        original = self.selected()['engine']
        configs = [
            'model_provider="provider_a"\nmodel="model_a"\n[model_providers.provider_a]\nbase_url="http://127.0.0.1:9/v1"',
            'model_provider="provider_b"\nmodel="model_b"\n[model_providers.provider_b]\nbase_url="http://127.0.0.1:8/v1"',
            '# changed comment\n\n[windows]\nsandbox = "unelevated"\n',
            'sandbox_mode="read-only"\napproval_policy="on-request"\n[windows]\nsandbox="elevated"',
            'profile="custom"\n[profiles.custom]\nsandbox_mode="workspace-write"\n[permissions.custom]\nnetwork=true',
            '[features]\nwindows_sandbox_service=true\nnetwork_proxy=true\n',
            'model_provider="provider_b"\n[model_providers.provider_b]\nsupports_websockets=true\n',
            'not valid TOML (possibly being rewritten by a switcher)',
        ]
        for config in configs:
            with self.subTest(config=config):
                self.config.write_text(config, encoding='utf-8')
                selected = self.selected()
                self.assertEqual(selected['mode'], 'custom-trial')
                self.assertEqual(selected['engine'], original)
                self.assertEqual(selected['profile'], profile(2, '.25'))
                self.assertEqual(self.config.read_text(encoding='utf-8'), config)
        self.config.unlink()
        self.assertEqual(self.selected()['engine'], original)
        other_home = self.root / 'another-home'
        other_home.mkdir()
        (other_home / 'config.toml').write_text('[windows]\nsandbox="unelevated"', encoding='utf-8')
        selected = launcher.get_selection(self.root, resources=self.resources, config_path=other_home / 'config.toml')
        self.assertEqual(selected['engine'], original)
        env = {'CODEX_HOME': str(other_home), 'CODEX_TEST_SETTING': 'unchanged'}
        self.assertEqual(launcher.launch_environment(env, selected), dict(env, CODEX_CLI_PATH=original))

    def test_rule_and_policy_receipt_tampering_still_falls_back(self):
        result = self.publish()
        with patch.object(validation, 'rules_id', return_value='changed-rule'):
            self.assertEqual(self.selected()['mode'], 'official')
        target = Path(result['runtime'])
        report = json.loads((target / 'validation.json').read_text(encoding='utf-8'))
        report['config_policy'] = 'unknown'
        atomic_json(target / 'validation.json', report)
        manifest = json.loads((target / 'manifest.json').read_text(encoding='utf-8'))
        manifest['validation_sha256'] = launcher.digest(target / 'validation.json')
        atomic_json(target / 'manifest.json', manifest)
        self.assertEqual(self.selected()['mode'], 'official')

    def test_invalid_receipt_falls_back_even_with_updated_report_digest(self):
        result = self.publish()
        target = Path(result['runtime'])
        report = json.loads((target / 'validation.json').read_text(encoding='utf-8'))
        report['retry']['intervals_seconds'] = [0, 0]
        atomic_json(target / 'validation.json', report)
        manifest = json.loads((target / 'manifest.json').read_text(encoding='utf-8'))
        manifest['validation_sha256'] = launcher.digest(target / 'validation.json')
        atomic_json(target / 'manifest.json', manifest)
        self.assertEqual(self.selected()['mode'], 'official')

    def test_running_old_copy_is_pending_new_selection(self):
        first = self.publish()
        second = self.publish(profile(9, '2'))
        processes = [dict(ProcessId=1, ExecutablePath=r'C:\WindowsApps\OpenAI.Codex_1\app\ChatGPT.exe'),
                     dict(ProcessId=2, ParentProcessId=1, ExecutablePath=str(Path(first['runtime']) / 'codex.exe'))]
        text, pending = runtime.running_state(self.root, processes, self.selected())
        self.assertIn('2 次 / 0.25 秒', text)
        self.assertTrue(pending)
        processes[1]['ExecutablePath'] = str(Path(second['runtime']) / 'codex.exe')
        self.assertFalse(runtime.running_state(self.root, processes, self.selected())[1])

    def test_sandbox_config_is_user_managed_and_does_not_disable_controller(self):
        self.config.write_text('sandbox_mode="workspace-write"\n[windows]\nsandbox="elevated"', encoding='utf-8')
        original = self.config.read_bytes()
        self.publish()
        self.assertEqual(self.selected()['mode'], 'custom-trial')
        self.assertEqual(self.config.read_bytes(), original)
        manager = runtime.DesktopManager(self.root, config=self.config)
        try:
            with patch.object(launcher, 'installed_resources', return_value=self.resources), \
                 patch.object(launcher, 'process_snapshot', return_value=[]), \
                 patch.object(runtime.Manager, 'inspect', return_value=dict(compatible=True, reason='', version='99.1.0')):
                status = manager.inspect()
            self.assertTrue(status['compatible'])
            self.assertIn('不拦截启动', status['reason'])
        finally:
            manager.close()

    def test_lock_refuses_concurrent_controller(self):
        with runtime.operation_lock(self.root):
            with self.assertRaises(ControllerError):
                with runtime.operation_lock(self.root): pass

    def auto(self, processes=None):
        publisher = runtime.publish
        with patch.object(launcher, 'installed_resources', return_value=self.resources), \
             patch.object(launcher, 'process_snapshot', return_value=processes or []), \
             patch.object(runtime, 'publish', side_effect=lambda root,p,config: publisher(root,p,config,lambda:self.resources)), \
             runtime.operation_lock(self.root):
            return runtime.auto_prepare(self.root,self.config)

    def test_auto_update_publishes_current_build_with_saved_profile(self):
        self.publish(profile(20,'1'))
        old_pointer=self.pointer.read_bytes()
        (self.resources/'codex.exe').write_bytes(b'new-engine')
        result=self.auto()
        self.assertTrue(result['changed'])
        self.assertEqual(self.selected()['profile'],profile(20,'1'))
        self.assertNotEqual(self.pointer.read_bytes(),old_pointer)
        self.assertEqual((self.resources/'codex.exe').read_bytes(),b'new-engine')
        self.assertEqual(self.config.read_bytes(),self.original_config)

    def test_auto_desktop_only_update_rebinds_and_validates(self):
        self.publish()
        (self.resources/'app.asar').write_bytes(b'new-desktop')
        self.validator.reset_mock()
        self.assertTrue(self.auto()['changed'])
        self.assertEqual(self.validator.call_count,1)
        self.assertEqual(self.selected()['mode'],'custom-trial')

    def test_auto_failure_keeps_pointer_and_cooldown_avoids_repeated_tests(self):
        self.validator.side_effect=ControllerError('unsupported build')
        self.assertFalse(self.auto()['changed'])
        self.assertEqual(self.pointer.read_bytes(),self.before)
        calls=self.validator.call_count
        self.assertTrue(self.auto()['deferred'])
        self.assertEqual(self.validator.call_count,calls)
        self.assertEqual(runtime.saved_profile(self.root),profile(25,'1'))
        # A changed engine or rules should retry without waiting six hours.
        (self.resources/'codex.exe').write_bytes(b'next-build')
        self.auto()
        self.assertGreater(self.validator.call_count,calls)

    def test_auto_cooldown_expires_and_manual_publish_bypasses_it(self):
        self.validator.side_effect=ControllerError('temporary failure')
        self.auto()
        attempts=self.validator.call_count
        with patch.object(runtime.time,'time',return_value=runtime.time.time()+7*3600):
            self.auto()
        self.assertGreater(self.validator.call_count,attempts)
        self.validator.side_effect=receipt
        self.publish()
        self.assertEqual(self.selected()['mode'],'custom-trial')

    def test_auto_does_not_reenable_official_or_work_while_desktop_running(self):
        running=[dict(ProcessId=1,ExecutablePath=r'C:\WindowsApps\OpenAI.Codex_1\app\ChatGPT.exe')]
        self.assertFalse(self.auto(running)['changed'])
        self.validator.assert_not_called()
        atomic_json(self.pointer,dict(enabled=False,last_profile=profile(20,'1'),runtime=str(self.old)))
        self.assertFalse(self.auto()['changed'])
        self.validator.assert_not_called()

    def test_auto_reuses_valid_selection_without_new_tests(self):
        self.publish()
        self.validator.reset_mock()
        self.assertTrue(self.auto()['reused'])
        self.validator.assert_not_called()


class ValidationTests(unittest.TestCase):
    def test_jitter_receipt_checks_chosen_waits_and_measured_intervals(self):
        p=profile(2,1000,70,unit='ms')
        result=dict(retry_result(p),selected_delays_ms=[930,1070],intervals_seconds=[.94,1.08])
        self.assertTrue(validation.check_retry(result,p))
        for changes in (dict(selected_delays_ms=[929,1070]),dict(selected_delays_ms=[930,1071]),
                        dict(selected_delays_ms=[]),dict(selected_delays_ms=[930,True]),
                        dict(intervals_seconds=[.1,.1])):
            self.assertFalse(validation.check_retry(dict(result,**changes),p))

    def test_native_duration_log_units_preserve_millisecond_values(self):
        from research.probe_retries import retry_delays
        stderr='\n'.join(f'retrying sampling request (1/2 in {value})' for value in ('930ms','1.07s','1ms','0ns'))
        self.assertEqual(retry_delays(stderr),[930,1070,1,0])

    def test_config_notes_never_expose_provider_values_or_parser_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.toml'
            path.write_text('[windows]\nsandbox="unelevated"\nmodel="secret-value"', encoding='utf-8')
            self.assertEqual(validation.configuration_notes(path), [])
            path.write_text('api_key="secret-value\n', encoding='utf-8')
            notes = validation.configuration_notes(path)
            self.assertTrue(notes)
            self.assertNotIn('secret-value', str(notes))

    def test_retry_rejects_wrong_limit_wait_and_timeout(self):
        p = profile(2, '1')
        self.assertTrue(validation.check_retry(retry_result(p), p))
        for key, value in [('requests', 4), ('timed_out', True), ('turn_exit_code', 0),
                           ('reconnects', ['Reconnecting... 1/5']), ('intervals_seconds', [0, 0])]:
            self.assertFalse(validation.check_retry(dict(retry_result(p), **{key: value}), p))

    def test_sandbox_requires_boundaries_not_just_equality(self):
        self.assertTrue(validation.sandbox_valid(matrices()))
        for key, value in [('restricted_token', False), ('proxy_http', 'loopback-ok')]:
            data = matrices()
            for engine in data: engine['cases'][0]['observations'][key] = value
            self.assertFalse(validation.sandbox_valid(data))


if __name__ == '__main__': unittest.main()
