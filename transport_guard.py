"""Per-request HTTP deadlines, outside the version-dependent retry patch.

The loopback server never retries. It preserves upstream payload bytes and
returns a bounded transport failure to Codex's own retry loop. A successful
SSE stream has no total deadline here: the engine owns its stream idle timer.
No credentials, URLs, headers, prompts or responses are logged or persisted.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import ssl
import time

import h11
import httpx


HOP_HEADERS = {b'connection', b'keep-alive', b'proxy-authenticate', b'proxy-authorization',
               b'te', b'trailer', b'transfer-encoding', b'upgrade'}


def tls_context():
    context = ssl.create_default_context()
    # Match Codex's documented precedence and add custom roots to native trust.
    certificate = os.environ.get('CODEX_CA_CERTIFICATE') or os.environ.get('SSL_CERT_FILE')
    if certificate:
        context.load_verify_locations(cafile=certificate)
    return context


def end_to_end(headers, *, request=False):
    """Strip connection-specific headers, including names in Connection."""
    skip = set(HOP_HEADERS)
    for key, value in headers:
        if key.lower() == b'connection':
            skip.update(token.strip().lower() for token in value.split(b','))
    skip.add(b'content-length')
    if request:
        skip.add(b'host')
    return [(key, value) for key, value in headers if key.lower() not in skip]


class ResponseGuard:
    def __init__(self, timeout_ms, *, on_event=None, trust_env=True):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 3_600_000:
            raise ValueError('HTTP response timeout must be 1..3600000 milliseconds')
        self.timeout = timeout_ms / 1000
        self.on_event = on_event or (lambda event: None)
        self.trust_env = trust_env
        self.token = secrets.token_urlsafe(32).encode('ascii')
        self.routes = {}
        self.server = None
        self.client = None
        self.tasks = set()
        self.active = 0

    async def start(self):
        # Use OS trust (including Windows's certificate store) and standard CA
        # environment overrides, rather than silently replacing it with certifi.
        self.client = httpx.AsyncClient(verify=tls_context(),
            timeout=None, follow_redirects=True, max_redirects=10, trust_env=self.trust_env,
            limits=httpx.Limits(max_connections=None, max_keepalive_connections=8))
        try:
            self.server = await asyncio.start_server(self._accept, '127.0.0.1', 0,
                                                      limit=262144, reuse_address=False)
        except BaseException:
            await self.client.aclose()
            raise
        return self

    def route(self, base_url):
        """Register only controller-selected destinations; never an open proxy."""
        url = httpx.URL(base_url)
        if (url.scheme not in ('http', 'https') or not url.host or url.query
                or url.fragment or url.userinfo):
            raise ValueError('HTTP timeout requires an HTTP(S) provider base URL without userinfo, query or fragment')
        for key, existing in self.routes.items():
            if existing == url:
                break
        else:
            key = secrets.token_hex(12).encode('ascii')
            self.routes[key] = url
        port = self.server.sockets[0].getsockname()[1]
        return f'http://127.0.0.1:{port}/{self.token.decode()}/{key.decode()}'

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if self.client:
            await self.client.aclose()

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *args):
        await self.close()

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.active += 1
        try:
            await self._serve(reader, writer)
        except (ConnectionError, OSError, h11.ProtocolError, asyncio.IncompleteReadError):
            pass  # The engine disconnected or sent an invalid local request.
        finally:
            self.active -= 1
            self.tasks.discard(task)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _serve(self, reader, writer):
        wire = h11.Connection(h11.SERVER, max_incomplete_event_size=262144)
        response = None
        sent = False
        body_done = asyncio.Event()
        started = time.monotonic()
        phase = 'request_headers'

        async def event():
            while True:
                value = wire.next_event()
                if value is not h11.NEED_DATA:
                    return value
                data = await reader.read(65536)
                wire.receive_data(data)

        async def emit(value):
            writer.write(wire.send(value))
            await writer.drain()

        async def respond(status, headers, body):
            nonlocal sent
            headers = end_to_end(headers) + [(b'content-length', str(len(body)).encode()),
                                            (b'connection', b'close')]
            await emit(h11.Response(status_code=status, headers=headers))
            sent = True
            await emit(h11.Data(data=body))
            await emit(h11.EndOfMessage())

        async def failure(status, code):
            payload = json.dumps({'error': {'type': 'controller_transport_error', 'code': code,
                'message': f'Codex controller: {phase} {code.replace("_", " ")}'}}).encode()
            await respond(status, [(b'content-type', b'application/json')], payload)

        async def body():
            while True:
                value = await event()
                if isinstance(value, h11.Data):
                    yield bytes(value.data)
                elif isinstance(value, h11.EndOfMessage):
                    body_done.set()
                    return
                else:
                    raise ConnectionError('local request body closed')

        async def disconnected():
            # There is exactly one request per connection. Wait until the upload
            # parser finishes before monitoring EOF, so two tasks never read the
            # same stream. EOF cancels the matching upstream request only.
            await body_done.wait()
            await reader.read(1)

        async def exchange(request, url):
            nonlocal response, sent, phase, started
            phase = 'response_headers'
            started = time.monotonic()
            headers = end_to_end(list(request.headers), request=True)
            async def send():
                connecting_stream = None

                async def trace(name, info):
                    nonlocal connecting_stream
                    action = name.rsplit('.', 2)[-2:]
                    if action in (['connect_tcp', 'complete'], ['start_tls', 'complete']):
                        connecting_stream = info['return_value']
                    elif (action == ['start_tls', 'failed']
                          and isinstance(info.get('exception'), asyncio.CancelledError)
                          and connecting_stream is not None):
                        # httpcore's TLS wrapper catches Exception, while task
                        # cancellation is a BaseException. Its TCP stream is
                        # not yet owned by an established pooled connection.
                        # The public trace extension also covers proxy CONNECT.
                        with contextlib.suppress(ConnectionError, OSError):
                            await connecting_stream.aclose()

                # Responses requests are finite JSON payloads. Keep their raw
                # bytes replayable for 307/308 redirects, with the same deadline
                # covering upload and redirects. HTTPX strips cross-origin auth;
                # forwarding Location to Codex would bypass this guard entirely.
                payload = b''.join([chunk async for chunk in body()])
                upstream = self.client.build_request(request.method.decode('ascii'), url,
                    headers=headers, content=payload, extensions={'trace': trace})
                return await self.client.send(upstream, stream=True)
            # Includes request upload, DNS, proxy connection, TLS and complete
            # response headers. Dribbling partial headers cannot reset it.
            response = await asyncio.wait_for(send(), self.timeout)
            if (200 <= response.status_code < 300
                    and response.headers.get('content-type', '').split(';')[0].strip().lower() == 'text/event-stream'):
                phase = 'sse'
                headers = end_to_end(response.headers.raw) + [(b'transfer-encoding', b'chunked'),
                                                              (b'connection', b'close')]
                await emit(h11.Response(status_code=response.status_code, headers=headers))
                sent = True
                async for chunk in response.aiter_raw():
                    await emit(h11.Data(data=chunk))
                await emit(h11.EndOfMessage())
            else:
                phase = 'response_body'
                started = time.monotonic()
                async def collect():
                    return b''.join([chunk async for chunk in response.aiter_raw()])
                # Error bodies must finish before their headers are forwarded;
                # otherwise Codex can hang in resp.text() after a known 429.
                payload = await asyncio.wait_for(collect(), self.timeout)
                await respond(response.status_code, response.headers.raw, payload)

        operation = watcher = None
        try:
            request = await asyncio.wait_for(event(), self.timeout)
            if not isinstance(request, h11.Request):
                return
            parts = request.target.split(b'/', 3)
            if (len(parts) < 3 or parts[0] or parts[1] != self.token
                    or parts[2] not in self.routes or request.method == b'CONNECT'):
                await failure(404, 'unknown_route')
                return
            if any(k.lower() == b'upgrade' for k, _ in request.headers):
                await failure(400, 'unsupported_upgrade')
                return
            original = self.routes[parts[2]]
            suffix = b'/' + (parts[3] if len(parts) == 4 else b'')
            url = original.copy_with(raw_path=original.raw_path.rstrip(b'/') + suffix)
            if wire.they_are_waiting_for_100_continue:
                await emit(h11.InformationalResponse(status_code=100, headers=[]))
            operation = asyncio.create_task(exchange(request, url))
            watcher = asyncio.create_task(disconnected())
            finished, _ = await asyncio.wait((operation, watcher), return_when=asyncio.FIRST_COMPLETED)
            if operation in finished:
                await operation
            else:
                self.on_event(dict(event='cancelled', phase=phase))
        except (asyncio.TimeoutError, httpx.RequestError) as exc:
            timeout = isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException))
            self.on_event(dict(event='timeout' if timeout else 'transport_error', phase=phase,
                               elapsed_ms=round((time.monotonic()-started)*1000)))
            if not sent:
                status = 504 if timeout else 502
                # Preserve known 4xx status classification even if the body
                # stalls. Whether 401/403/etc. retry remains Codex's decision.
                if response and 400 <= response.status_code < 500 and response.status_code not in (408, 429):
                    status = response.status_code
                await failure(status, 'response_timeout' if timeout else 'upstream_disconnected')
        finally:
            tasks = [t for t in (operation, watcher) if t is not None]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if response:
                await response.aclose()
