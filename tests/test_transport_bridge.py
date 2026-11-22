"""Exercise the actual line bridge, including private RPC and cancellation races."""
import copy
import json
import os
import queue
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from transport_bridge import StdioBridge
from transport_runner import serves_stdio


class Sink:
    def __init__(self):
        self.lines = queue.Queue()

    def write(self, raw):
        self.lines.put(raw)

    def flush(self):
        pass


def pipe():
    read, write = os.pipe()
    return os.fdopen(read, 'rb', buffering=0), os.fdopen(write, 'wb', buffering=0)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.source, self.client = pipe()
        self.engine_read, engine_input = pipe()
        engine_output, self.engine = pipe()
        self.destination = Sink()
        self.route = Mock(return_value='http://127.0.0.1:43210/token/route')
        self.bridge = StdioBridge(SimpleNamespace(stdin=engine_input, stdout=engine_output), self.route,
                                  source=self.source, destination=self.destination, rpc_timeout=.35)
        self.requests = queue.Queue()
        self.reader = threading.Thread(target=lambda: [self.requests.put(raw) for raw in self.engine_read], daemon=True)
        self.worker = threading.Thread(target=self.bridge.run, daemon=True)
        self.reader.start()
        self.worker.start()
        self.config = dict(model_provider='test', model_providers=dict(test=dict(base_url='https://example.test/v1',
                           env_key='PRIVATE_KEY_NAME')), windows=dict(sandbox='unelevated'))

    def tearDown(self):
        self.client.close()
        self.worker.join(timeout=3)
        self.engine.close()
        self.reader.join(timeout=3)
        self.source.close()
        self.engine_read.close()
        self.bridge.process.stdout.close()
        self.assertFalse(self.worker.is_alive())
        self.assertFalse(self.reader.is_alive())

    def send(self, stream, value):
        stream.write(json.dumps(value).encode()+b'\n')
        stream.flush()

    def receive(self):
        return json.loads(self.requests.get(timeout=2))

    def output(self):
        return json.loads(self.destination.lines.get(timeout=2))

    def test_private_configuration_does_not_leak_and_permissions_stay_unchanged(self):
        params = dict(cwd='E:/project', approvalPolicy='on-request', sandbox='workspace-write',
                      config={'model_providers.test': {'base_url':'https://project.test/v1', 'env_key':'PRIVATE'}})
        original = copy.deepcopy(params)
        self.send(self.client, dict(id=7, method='thread/start', params=params))
        private = self.receive()
        self.assertEqual(private['method'], 'config/read')
        self.assertEqual(private['params']['cwd'], 'E:/project')
        self.send(self.engine, dict(id=private['id'], result=dict(config=self.config)))
        forwarded = self.receive()
        self.assertEqual(forwarded['id'], 7)
        self.assertEqual(forwarded['params']['approvalPolicy'], 'on-request')
        self.assertEqual(forwarded['params']['sandbox'], 'workspace-write')
        self.assertEqual(forwarded['params']['config']['model_providers.test'],
                         dict(base_url=self.route.return_value, env_key='PRIVATE'))
        self.route.assert_called_once_with('https://project.test/v1')
        self.send(self.engine, dict(id=7, result=dict(thread=dict(id='new'))))
        self.assertEqual(self.output()['id'], 7)
        self.assertTrue(self.destination.lines.empty())
        self.assertEqual(params, original)

    def test_pending_config_does_not_block_interrupt_and_late_private_reply_is_swallowed(self):
        self.send(self.client, dict(id=8, method='thread/start', params={}))
        private = self.receive()
        interrupt = dict(id=9, method='turn/interrupt', params=dict(threadId='running', turnId='turn'))
        self.send(self.client, interrupt)
        self.assertEqual(self.receive(), interrupt)
        failure = self.output()
        self.assertEqual(failure['id'], 8)
        self.assertIn('超时', failure['error']['message'])
        self.send(self.engine, dict(id=private['id'], result=dict(config=self.config)))
        self.send(self.engine, dict(id=9, result={}))
        self.assertEqual(self.output(), dict(id=9, result={}))
        self.assertTrue(self.destination.lines.empty())
        self.route.assert_not_called()

    def test_unknown_rpc_and_engine_notifications_are_exactly_transparent(self):
        raw = b'{ "id" : "new-protocol", "method" : "future/read", "params" : {"q":1} }\n'
        self.client.write(raw)
        self.assertEqual(self.requests.get(timeout=2), raw)
        response = b'{"method":"future/notification","params":{"hello":true}}\n'
        self.engine.write(response)
        self.assertEqual(self.destination.lines.get(timeout=2), response)

    def test_long_json_line_crosses_pipe_chunks_without_rewriting(self):
        raw = json.dumps(dict(id=42, method='future/write', params=dict(value='汉字'*40000)),
                         ensure_ascii=False).encode()+b'\n'
        self.client.write(raw)
        self.assertEqual(self.requests.get(timeout=3), raw)

    def test_resume_resolves_saved_cwd_but_unsupported_transport_never_starts(self):
        self.send(self.client, dict(id=10, method='thread/resume', params=dict(threadId='old')))
        read = self.receive()
        self.assertEqual(read['method'], 'thread/read')
        self.send(self.engine, dict(id=read['id'], result=dict(thread=dict(cwd='E:/saved'))))
        config = self.receive()
        self.assertEqual(config['params']['cwd'], 'E:/saved')
        self.config['model_providers']['test']['supports_websockets'] = True
        self.send(self.engine, dict(id=config['id'], result=dict(config=self.config)))
        result = self.output()
        self.assertEqual(result['id'], 10)
        self.assertIn('HTTP/SSE', result['error']['message'])
        self.route.assert_not_called()
        self.assertTrue(self.requests.empty())

    def test_path_restore_is_explicitly_refused_without_private_config_access(self):
        self.send(self.client, dict(id=11, method='thread/resume', params=dict(threadId='old', path='rollout.jsonl')))
        self.assertIn('路径', self.output()['error']['message'])
        self.assertTrue(self.requests.empty())


class EntryArgumentsTests(unittest.TestCase):
    def test_public_global_flags_before_or_after_command_are_guarded(self):
        for args in (['app-server','--stdio'], ['--config','x=1','app-server','--listen=stdio://'],
                     ['--enable','future_feature','app-server','--config','x=1'],
                     ['--profile','work','app-server','--listen','stdio://'], ['-cx=1','app-server']):
            self.assertTrue(serves_stdio(args), args)

    def test_tools_version_schema_and_option_values_are_not_app_server(self):
        for args in (['--version'], ['exec','app-server'], ['--profile','app-server'],
                     ['app-server','generate-json-schema'], ['app-server','--help']):
            self.assertFalse(serves_stdio(args), args)

    def test_desktop_policy_read_and_sign_out_are_one_shot_native_commands(self):
        info = json.dumps(dict(name='codex_desktop', title='Codex Desktop', version='test'))
        for suffix in ([], ['--startup-sign-out']):
            for prefix in ([], ['-c', 'features.plugins=false']):
                args = prefix + ['app-server', '--analytics-default-enabled', '--print-startup-config',
                                 '--startup-client-info', info] + suffix
                self.assertFalse(serves_stdio(args), args)
        self.assertFalse(serves_stdio(['app-server', '--startup-client-info='+info, '--print-startup-config']))

    def test_startup_option_values_do_not_disable_interactive_supervision(self):
        self.assertTrue(serves_stdio(['app-server', '--startup-client-info', '--print-startup-config']))
        self.assertTrue(serves_stdio(['--config', '--print-startup-config', 'app-server']))
        self.assertTrue(serves_stdio(['app-server', '--startup-client-info', 'app-server']))

    def test_non_stdio_transport_is_never_silently_unguarded(self):
        for args in (['app-server','--listen','ws://127.0.0.1:12'],
                     ['-c','x=1','app-server','--listen=ws://127.0.0.1:12'], ['app-server','daemon']):
            with self.assertRaisesRegex(ValueError, 'stdio'):
                serves_stdio(args)
