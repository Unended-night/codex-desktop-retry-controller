"""Receipt completeness and profile compatibility; fixtures are not live approval."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from controller.core import ControllerError, profile, validate_profile
from transport_validation import REQUIRED, LIFECYCLE, TLS_CASES, STARTUP_CASES, valid, startup_valid


def startup_report():
    cases = []
    for name in STARTUP_CASES:
        row = dict(name=name, passed=True, timed_out=False, exit_code=0, config_unchanged=True,
                   auth_present=name != 'policy-sign-out', requests=1 if name == 'stdio' else 0)
        if name in ('version', 'help'):
            row.update(stdout_bytes=30, stdout_sha256='a'*64)
        else:
            row['policy'] = dict(requirements=None)
            if name == 'stdio':
                row.update(initialized=True, public_config_unchanged=True, thread_started=True, turn_completed=True)
            else:
                row['app_server_version'] = 'fixture'
        cases.append(row)
    return dict(format=1, transport='node-child-process', node_sha256='b'*64,
                matrices=[dict(name=name, cases=copy.deepcopy(cases)) for name in ('official', 'entry')])


def timeout_report(p):
    limit=p['max_retries'] if p.get('retry_enabled',True) else 1
    retry = limit > 0
    def row(name, timeout_ms):
        value = dict(name=name, timeout_ms=timeout_ms, config_unchanged=True, passed=True,
                     requests=1+int(retry), statuses=['completed' if retry else 'failed'],
                     reconnects=[f"Reconnecting... 1/{limit}"] if retry else [],
                     timeout_events=[dict(phase='response_headers', elapsed_ms=timeout_ms)])
        if name in ('fatal-body', 'error-body'):
            value['timeout_events'][0]['phase'] = 'response_body'
        if name == 'fatal-body':
            value.update(requests=1, statuses=['failed'], reconnects=[])
        if name in ('sse-long', 'sse-idle', 'resume-fork', 'cancel-continue'):
            value['timeout_events'] = []
        if name == 'sse-long':
            value.update(requests=1, statuses=['completed'], reconnects=[])
        if name == 'resume-fork':
            value.update(requests=3, statuses=['completed']*3, reconnects=[], resumed=True)
        if name == 'cancel-continue':
            value.update(requests=2, statuses=['interrupted','completed'], reconnects=[], cancelled=True)
        if name == 'concurrent':
            value.update(requests=2+int(retry), statuses=['completed']+value['statuses'])
        return value
    return dict(format=1, timeout_ms=p['http_timeout_ms'], cases=[row(name, 500) for name in REQUIRED],
                configured=row('configured-headers', p['http_timeout_ms']),
                tls_handshakes=[dict(name=name,passed=True,timeout_ms=500,config_unchanged=True,
                    tls_hello_received=True,closed_before_shutdown=True,disconnect_ms=500,
                    statuses=['interrupted'] if retry else ['failed'],
                    reconnects=[f'Reconnecting... 1/{limit}'] if retry else [],
                    timeout_events=[dict(phase='response_headers',elapsed_ms=500)]) for name in TLS_CASES],
                lifecycle=[dict(name=name, passed=True, children_exited=True, upstream_closed=True,
                                child_names=['codex.exe','python.exe']) for name in LIFECYCLE])


class TimeoutReceiptTests(unittest.TestCase):
    def test_desktop_startup_requires_both_transports_and_native_policy_equivalence(self):
        self.assertTrue(startup_valid(startup_report()))
        for name in STARTUP_CASES:
            report = startup_report()
            report['matrices'][1]['cases'] = [r for r in report['matrices'][1]['cases'] if r['name'] != name]
            self.assertFalse(startup_valid(report), name)
        for field, value in (('policy', {}), ('policy', {'requirements': {'application': 'changed'}}),
                             ('exit_code', 1), ('timed_out', True), ('auth_present', False)):
            report = startup_report()
            report['matrices'][1]['cases'][0][field] = value
            self.assertFalse(startup_valid(report), field)
        report = startup_report()
        report['matrices'][1]['cases'][2]['turn_completed'] = False
        self.assertFalse(startup_valid(report))

    def test_empty_or_changed_one_shot_output_cannot_approve_desktop_startup(self):
        for field, value in (('stdout_bytes', 0), ('stdout_sha256', 'c'*64)):
            report = startup_report()
            report['matrices'][1]['cases'][3][field] = value
            self.assertFalse(startup_valid(report), field)
        self.assertFalse(startup_valid({}))

    def test_http_source_changes_do_not_invalidate_base_rules(self):
        import desktop_validation
        import transport_runtime
        base=desktop_validation.rules_id()
        guard=transport_runtime.rules_id()
        original=Path.read_bytes
        for name in ('transport_guard.py', 'transport_runner.py', 'transport_startup.cjs'):
            def changed(path):
                data=original(path)
                return data+b'\n// changed HTTP implementation\n' if path.name==name else data
            with patch.object(Path,'read_bytes',changed):
                self.assertEqual(desktop_validation.rules_id(),base)
                self.assertNotEqual(transport_runtime.rules_id(),guard)

    def test_retry_switch_is_independent_and_distinct_from_zero_budget(self):
        disabled=profile(0,'1',http_timeout_ms=120000,retry_enabled=False)
        self.assertEqual(validate_profile(disabled),disabled)
        self.assertTrue(valid(timeout_report(disabled),disabled))
        report=timeout_report(disabled)
        report['configured']['reconnects']=['Reconnecting... 1/0']
        self.assertFalse(valid(report,disabled))
        for invalid in (0,1,None,'false'):
            with self.assertRaises(ControllerError):
                validate_profile(dict(disabled,retry_enabled=invalid))
        self.assertNotIn('retry_enabled',profile(0,'1'))

    def test_real_configured_deadline_and_every_phase_are_required(self):
        for count in (0, 300):
            p = profile(count, '1.5', '.5', http_timeout_ms=300000)
            report = timeout_report(p)
            self.assertTrue(valid(report, p))
            for key in ('configured', 'lifecycle', 'cases', 'tls_handshakes'):
                damaged = copy.deepcopy(report)
                del damaged[key]
                self.assertFalse(valid(damaged, p))
            damaged = copy.deepcopy(report)
            damaged['configured']['timeout_ms'] = 500
            self.assertFalse(valid(damaged, p))
            damaged = copy.deepcopy(report)
            damaged['cases'][0]['timeout_events'][0]['phase'] = 'response_body'
            self.assertFalse(valid(damaged, p))
            damaged = copy.deepcopy(report)
            damaged['cases'][0]['config_unchanged'] = False
            self.assertFalse(valid(damaged, p))

    def test_tls_sockets_must_close_before_stopping_the_test_process(self):
        p=profile(3,'1',http_timeout_ms=1000)
        for field,value in (('tls_hello_received',False),('closed_before_shutdown',False),
                            ('disconnect_ms',5000),('statuses',['completed']),('timeout_events',[])):
            report=timeout_report(p)
            report['tls_handshakes'][0][field]=value
            self.assertFalse(valid(report,p),field)
        report=timeout_report(p)
        report['tls_handshakes'].pop()
        self.assertFalse(valid(report,p))

    def test_orphaned_child_or_connection_cannot_approve_publication(self):
        p = profile(3, '1', http_timeout_ms=1000)
        for field in ('passed', 'children_exited', 'upstream_closed'):
            report = timeout_report(p)
            report['lifecycle'][1][field] = False
            self.assertFalse(valid(report, p))

    def test_old_profiles_stay_disabled_and_new_values_survive_normalization(self):
        old = profile(300, '1.5', '.5')
        self.assertNotIn('http_timeout_ms', old)
        self.assertEqual(validate_profile(dict(old, http_timeout_ms=0)), old)
        for timeout in (1000, 300000, 600000):
            value = dict(old, http_timeout_ms=timeout)
            self.assertEqual(validate_profile(value), value)
        for invalid in (-1, 1, 999, 600001, True, '300000', 1000.0):
            with self.subTest(value=invalid), self.assertRaises(ControllerError):
                validate_profile(dict(old, http_timeout_ms=invalid))
