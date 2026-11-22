"""Real loopback traffic; no model account or production process involved."""
import asyncio
import contextlib
import gzip
import json
import os
import time
import unittest
from unittest.mock import patch, Mock

import httpx

from transport_guard import ResponseGuard, tls_context
from transport_bridge import BridgeError, configured_provider, engine_environment, override_base_url


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.handlers = set()
        self.writers = set()
        self.requests = []
        self.received = asyncio.Event()
        self.disconnected = asyncio.Event()
        self.behavior = 'silent'
        self.server = await asyncio.start_server(self.upstream, '127.0.0.1', 0)
        self.events = []
        self.guard = await ResponseGuard(180, on_event=self.events.append, trust_env=False).start()
        self.port = self.server.sockets[0].getsockname()[1]
        self.local = self.guard.route(f'http://127.0.0.1:{self.port}/v1')
        self.client = httpx.AsyncClient(timeout=3, trust_env=False)

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.guard.close()
        self.server.close()
        await self.server.wait_closed()
        pending = list(self.handlers)
        for writer in list(self.writers):
            writer.close()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def upstream(self, reader, writer):
        task = asyncio.current_task()
        self.handlers.add(task)
        self.writers.add(writer)
        try:
            if self.behavior in ('tls-stall', 'tls-proxy'):
                if self.behavior == 'tls-proxy':
                    header = await reader.readuntil(b'\r\n\r\n')
                    self.assertTrue(header.startswith(b'CONNECT '))
                    writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    await writer.drain()
                self.assertEqual(await reader.readexactly(1), b'\x16')
                self.received.set()
                await reader.read()
                self.disconnected.set()
                return
            header = await reader.readuntil(b'\r\n\r\n')
            fields = dict(line.split(b': ', 1) for line in header.split(b'\r\n')[1:-2])
            lower = {k.lower(): v for k, v in fields.items()}
            body = b''
            if lower.get(b'transfer-encoding') == b'chunked':
                while True:
                    size = int((await reader.readline()).strip(), 16)
                    if not size:
                        await reader.readline()
                        break
                    body += await reader.readexactly(size)
                    await reader.readexactly(2)
            elif b'content-length' in lower:
                body = await reader.readexactly(int(lower[b'content-length']))
            self.requests.append(dict(line=header.split(b'\r\n')[0], headers=lower, body=body))
            self.received.set()
            behavior = self.behavior
            if b'/healthy' in header.split(b'\r\n')[0]:
                behavior = 'echo'
            if behavior in ('partial', 'drip'):
                writer.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                await writer.drain()
                if behavior == 'drip':
                    for _ in range(20):
                        writer.write(b'x')
                        await writer.drain()
                        await asyncio.sleep(.03)
            elif behavior.startswith('redirect') and b'/v1/responses' in header.split(b'\r\n')[0]:
                port = getattr(self, 'redirect_port', self.port)
                path = 'healthy' if behavior == 'redirect' else 'stalled'
                location = f'http://127.0.0.1:{port}/v1/{path}'.encode()
                writer.write(b'HTTP/1.1 307 Temporary Redirect\r\nLocation: '+location+b'\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
                return
            elif behavior in ('error-body', 'fatal-body', 'delayed-error-body'):
                if behavior == 'delayed-error-body':
                    await asyncio.sleep(.1)
                status = b'401 Unauthorized' if behavior == 'fatal-body' else b'429 Too Many Requests'
                writer.write(b'HTTP/1.1 '+status+b'\r\nContent-Length: 100\r\n\r\nx')
                await writer.drain()
            elif behavior in ('sse', 'sse-idle'):
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
                for n in range(8 if behavior == 'sse' else 1):
                    data = f'data: {n}\n\n'.encode()
                    writer.write(f'{len(data):x}\r\n'.encode()+data+b'\r\n')
                    await writer.drain()
                    await asyncio.sleep(.06)
                if behavior == 'sse':
                    writer.write(b'0\r\n\r\n')
                    await writer.drain()
                    return
            elif behavior == 'echo':
                content = gzip.compress(body or b'OK')
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nX-Trace: preserved\r\nContent-Length: '
                             + str(len(content)).encode()+b'\r\n\r\n'+content)
                await writer.drain()
                return
            await reader.read()
            self.disconnected.set()
        except (ConnectionError, asyncio.IncompleteReadError):
            self.disconnected.set()
        finally:
            self.handlers.discard(task)
            self.writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def test_headers_deadline_covers_silence_partial_headers_and_dripping(self):
        for behavior in ('silent', 'partial', 'drip'):
            self.behavior = behavior
            started = time.monotonic()
            response = await self.client.post(self.local+'/responses', content=b'{}')
            self.assertEqual(response.status_code, 504)
            self.assertEqual(response.json()['error']['code'], 'response_timeout')
            self.assertLess(time.monotonic()-started, 1.2)
        self.assertEqual(len(self.requests), 3)  # The guard never retries.
        self.assertTrue(all(e['phase'] == 'response_headers' for e in self.events))

    async def tls_route(self, proxy):
        await self.guard.close()
        self.received.clear()
        self.disconnected.clear()
        self.events.clear()
        self.behavior = 'tls-proxy' if proxy else 'tls-stall'
        env = {'HTTPS_PROXY': f'http://127.0.0.1:{self.port}'} if proxy else {}
        with patch.dict(os.environ, env, clear=True):
            self.guard = await ResponseGuard(500, on_event=self.events.append, trust_env=proxy).start()
        return self.guard.route(f'https://127.0.0.1:{self.port}/v1')

    async def test_tls_handshake_timeout_closes_direct_and_proxy_connections(self):
        for proxy in (False, True):
            local = await self.tls_route(proxy)
            response = await self.client.post(local+'/responses', content=b'{}')
            self.assertEqual(response.status_code, 504)
            self.assertTrue(self.received.is_set())
            await asyncio.wait_for(self.disconnected.wait(), 1)
            self.assertEqual(self.events[-1]['phase'], 'response_headers')

    async def test_cancellation_during_tls_handshake_closes_direct_and_proxy_connections(self):
        for proxy in (False, True):
            url = httpx.URL(await self.tls_route(proxy)+'/responses')
            self.guard.timeout = 5
            reader, writer = await asyncio.open_connection('127.0.0.1', url.port)
            try:
                writer.write(b'POST '+url.raw_path+b' HTTP/1.1\r\nHost: local\r\nContent-Length: 2\r\n\r\n{}')
                await writer.drain()
                await asyncio.wait_for(self.received.wait(), 1)
            finally:
                writer.close()
                await writer.wait_closed()
            await asyncio.wait_for(self.disconnected.wait(), 1)
            self.assertTrue(any(e['event'] == 'cancelled' for e in self.events))

    async def test_incomplete_error_body_is_bounded_and_known_4xx_status_is_preserved(self):
        for behavior, status in [('error-body', 504), ('fatal-body', 401)]:
            self.behavior = behavior
            response = await self.client.post(self.local+'/responses', content=b'{}')
            self.assertEqual(response.status_code, status)
            self.assertEqual(response.json()['error']['code'], 'response_timeout')
        self.assertTrue(all(e['phase'] == 'response_body' for e in self.events))

    async def test_body_deadline_starts_after_complete_headers(self):
        self.guard.timeout = .5
        self.behavior = 'delayed-error-body'
        started = time.monotonic()
        response = await self.client.post(self.local+'/responses', content=b'{}')
        elapsed = time.monotonic()-started
        self.assertEqual(response.status_code, 504)
        self.assertGreater(elapsed, .57)
        self.assertLess(elapsed, 2.25)
        self.assertEqual(self.events[0]['phase'], 'response_body')
        self.assertGreaterEqual(self.events[0]['elapsed_ms'], 450)
        self.assertLess(self.events[0]['elapsed_ms'], 1500)

    async def test_partial_request_upload_has_the_same_bounded_deadline(self):
        url = httpx.URL(self.local+'/responses')
        reader, writer = await asyncio.open_connection('127.0.0.1', url.port)
        try:
            writer.write(b'POST '+url.raw_path+b' HTTP/1.1\r\nHost: local\r\nContent-Length: 100\r\n\r\n{}')
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(), 1.2)
            self.assertTrue(reply.startswith(b'HTTP/1.1 504 '))
            self.assertEqual(self.requests, [])
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_redirects_preserve_request_and_do_not_escape_the_guard(self):
        self.behavior = 'redirect'
        response = await self.client.post(self.local+'/responses', content=b'compressed-or-json',
                                          headers={'Authorization':'Bearer fake-token'})
        self.assertEqual(response.content, b'compressed-or-json')
        self.assertEqual([r['body'] for r in self.requests], [b'compressed-or-json']*2)
        self.assertEqual(self.requests[1]['headers'][b'authorization'], b'Bearer fake-token')
        self.requests.clear()
        self.behavior = 'redirect-stall'
        response = await self.client.post(self.local+'/responses', content=b'{}')
        self.assertEqual(response.status_code, 504)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.events[-1]['phase'], 'response_headers')

    async def test_cross_origin_redirect_does_not_leak_bearer_authorization(self):
        other = await asyncio.start_server(self.upstream, '127.0.0.1', 0)
        try:
            self.behavior = 'redirect'
            self.redirect_port = other.sockets[0].getsockname()[1]
            response = await self.client.post(self.local+'/responses', content=b'{}',
                                              headers={'Authorization':'Bearer fake-private'})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b'authorization', self.requests[1]['headers'])
        finally:
            other.close()
            await other.wait_closed()

    async def test_sse_can_outlast_deadline_without_truncation_or_proxy_retry(self):
        self.behavior = 'sse'
        started = time.monotonic()
        response = await self.client.post(self.local+'/responses', content=b'{}')
        self.assertEqual(response.text, ''.join(f'data: {n}\n\n' for n in range(8)))
        self.assertGreater(time.monotonic()-started, self.guard.timeout*2)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.events, [])

    async def test_exact_payload_query_auth_and_compressed_response(self):
        self.behavior = 'echo'
        payload = gzip.compress('提示词\x00\r\n'.encode())
        response = await self.client.post(self.local+'/responses?x=%2F%2b&x=2', content=payload,
                                          headers={'Authorization':'Bearer fake-local-secret',
                                                   'Content-Encoding':'gzip', 'X-Api-Key':'fake-key'})
        self.assertEqual(response.content, payload)
        self.assertEqual(response.headers['x-trace'], 'preserved')
        request = self.requests[0]
        self.assertEqual(request['body'], payload)
        self.assertEqual(request['line'], b'POST /v1/responses?x=%2F%2b&x=2 HTTP/1.1')
        self.assertEqual(request['headers'][b'authorization'], b'Bearer fake-local-secret')
        self.assertEqual(request['headers'][b'x-api-key'], b'fake-key')
        self.assertEqual(request['headers'][b'host'], f'127.0.0.1:{self.port}'.encode())
        self.assertEqual(self.events, [])

    async def test_concurrent_request_is_not_cancelled_by_another_timeout(self):
        stuck, healthy = await asyncio.gather(self.client.post(self.local+'/responses', content=b'{}'),
                                             self.client.post(self.local+'/healthy', content=b'good'))
        self.assertEqual(stuck.status_code, 504)
        self.assertEqual(healthy.content, b'good')
        self.assertEqual(len(self.requests), 2)

    async def test_engine_disconnect_closes_only_its_upstream_before_timeout(self):
        self.guard.timeout = 5
        url = httpx.URL(self.local+'/responses')
        reader, writer = await asyncio.open_connection('127.0.0.1', url.port)
        writer.write(b'POST '+url.raw_path+b' HTTP/1.1\r\nHost: local\r\nContent-Length: 2\r\n\r\n{}')
        await writer.drain()
        await asyncio.wait_for(self.received.wait(), 1)
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(self.disconnected.wait(), 1)
        self.assertTrue(any(e['event'] == 'cancelled' for e in self.events))

    async def test_guard_shutdown_closes_a_silent_sse_connection(self):
        self.behavior = 'sse-idle'
        async with self.client.stream('POST', self.local+'/responses', content=b'{}') as response:
            self.assertEqual(response.status_code, 200)
            await self.guard.close()
            await asyncio.wait_for(self.disconnected.wait(), 1)
        self.assertEqual(self.guard.active, 0)

    async def test_unknown_route_and_upgrade_do_not_reach_upstream(self):
        url = httpx.URL(self.local).copy_with(raw_path=b'/unregistered/responses')
        self.assertEqual((await self.client.get(url)).status_code, 404)
        self.assertEqual((await self.client.get(self.local+'/responses', headers={'Upgrade':'websocket'})).status_code, 400)
        self.assertEqual(self.requests, [])


class ConfigTests(unittest.TestCase):
    def config(self):
        return dict(model_provider='custom', model_providers=dict(custom=dict(base_url='https://example.test/v1',
                    env_key='SECRET_NAME', http_headers={'x-key':'secret'})), windows=dict(sandbox='unelevated'))

    def test_nested_and_dotted_overrides_preserve_input_and_auth(self):
        original = self.config()
        params = dict(config={'model_providers.custom.base_url':'https://project.test/v1'})
        self.assertEqual(configured_provider(original, params), ('custom', 'https://project.test/v1'))
        self.assertEqual(original, self.config())
        self.assertEqual(params['config']['model_providers.custom.base_url'], 'https://project.test/v1')
        self.assertEqual(configured_provider(original, dict(config={'model_providers': {'custom': {'base_url':'http://local.test'}}})),
                         ('custom', 'http://local.test'))

    def test_url_replacement_never_leaves_overlapping_override_keys(self):
        for overrides in ({'model_providers': {'custom': {'base_url':'http://old', 'env_key':'PRIVATE'}}},
                          {'model_providers.custom': {'base_url':'http://old', 'env_key':'PRIVATE'}},
                          {'model_providers.custom.base_url':'http://old', 'model_providers.custom.env_key':'PRIVATE'},
                          {'model_providers': {'another': {'base_url':'http://other'}}}):
            original = json.dumps(overrides)
            params = override_base_url(dict(config=overrides), 'custom', 'http://loopback')
            self.assertEqual(configured_provider(self.config(), params), ('custom', 'http://loopback'))
            self.assertEqual(json.dumps(overrides), original)
            if 'PRIVATE' in original:
                self.assertIn('PRIVATE', json.dumps(params))

    def test_ambiguous_ancestor_and_child_overrides_are_refused_in_any_order(self):
        items = [('model_providers.custom', {'base_url':'http://a'}),
                 ('model_providers.custom.base_url', 'http://b')]
        for pairs in (items, items[::-1]):
            with self.assertRaisesRegex(BridgeError, '重叠'):
                configured_provider(self.config(), dict(config=dict(pairs)))

    def test_unsupported_transport_is_explicit_and_does_not_claim_protection(self):
        for override in ({'model_providers.custom.supports_websockets':True},
                         {'features.responses_websockets_v2':True}, {'model_providers.custom.wire_api':'chat'},
                         {'model_provider':'openai'}, {'profile':'other'}):
            with self.subTest(override=override), self.assertRaises(BridgeError):
                configured_provider(self.config(), dict(config=override))

    def test_loopback_exclusion_does_not_change_parent_or_upstream_proxy(self):
        base = {'HTTPS_PROXY':'http://proxy.test', 'NO_PROXY':'example.test'}
        child = engine_environment(base)
        self.assertEqual(base['NO_PROXY'], 'example.test')
        self.assertEqual(child['HTTPS_PROXY'], base['HTTPS_PROXY'])
        self.assertEqual(child['NO_PROXY'], 'example.test,127.0.0.1,localhost')

    def test_custom_ca_uses_codex_precedence_without_disabling_verification(self):
        for variables, expected in [({'CODEX_CA_CERTIFICATE':'codex.pem','SSL_CERT_FILE':'general.pem'}, 'codex.pem'),
                                    ({'CODEX_CA_CERTIFICATE':'','SSL_CERT_FILE':'general.pem'}, 'general.pem'), ({}, None)]:
            context = Mock()
            with patch.dict(os.environ, variables, clear=True), patch('transport_guard.ssl.create_default_context', return_value=context):
                self.assertIs(tls_context(), context)
            if expected:
                context.load_verify_locations.assert_called_once_with(cafile=expected)
            else:
                context.load_verify_locations.assert_not_called()
