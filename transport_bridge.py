"""Transparent app-server stdio bridge with per-chat provider URL overrides.

Configuration resolution stays in Codex (config/read with the chat's cwd).
Only thread/start, resume and fork gain a session-only provider base_url.
All other RPC traffic, tools, permissions and authentication stay untouched.
"""
from __future__ import annotations

import copy
import contextlib
import json
import os
import queue
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor


THREAD_METHODS = {'thread/start', 'thread/resume', 'thread/fork'}


class BridgeError(Exception):
    pass


def config_overrides(params):
    overrides = params.get('config')
    if overrides is None:
        return {}
    if not isinstance(overrides, dict):
        raise BridgeError('对话配置格式不受 HTTP 超时层支持。')
    # JSON objects have no semantic ordering. Reject overlapping representations
    # rather than guessing whether a nested or dotted override wins in this build.
    keys = sorted(overrides)
    for index, key in enumerate(keys):
        if not isinstance(key, str) or not all(key.split('.')):
            raise BridgeError('对话配置字段格式不受 HTTP 超时层支持。')
        if key.split('.')[0] in ('profile', 'profiles'):
            raise BridgeError('HTTP 超时层尚未验收对话级 profile 切换；请在控制器关闭 HTTP 超时后使用。')
        if any(other.startswith(key + '.') for other in keys[index+1:]):
            raise BridgeError('对话配置同时含有重叠的嵌套与点分字段；无法确定 HTTP 超时覆盖顺序。')
    return overrides


def override_base_url(params, name, url):
    params = copy.deepcopy(params)
    overrides = params['config'] = copy.deepcopy(config_overrides(params))
    path = ('model_providers', name, 'base_url')
    # Update the caller's existing table when present, so the resulting map
    # never contains both an ancestor override and a child override.
    for count in range(1, len(path)+1):
        key = '.'.join(path[:count])
        if key not in overrides:
            continue
        if count == len(path):
            overrides[key] = url
        else:
            target = overrides[key]
            for part in path[count:-1]:
                if not isinstance(target, dict):
                    raise BridgeError('供应商覆盖字段不是配置表。')
                target = target.setdefault(part, {})
            if not isinstance(target, dict):
                raise BridgeError('供应商覆盖字段不是配置表。')
            target[path[-1]] = url
        return params
    overrides['.'.join(path)] = url
    return params


def configured_provider(config, params):
    """Resolve transport fields after session overrides; do not copy secrets."""
    value = copy.deepcopy(config)
    overrides = config_overrides(params)

    def merge(left, right):
        for key, item in right.items():
            if isinstance(item, dict) and isinstance(left.get(key), dict):
                merge(left[key], item)
            else:
                left[key] = copy.deepcopy(item)

    for key, item in overrides.items():
        target = value
        parts = key.split('.')
        for part in parts[:-1]:
            if not isinstance(target.get(part), dict):
                target[part] = {}
            target = target[part]
        merge(target, {parts[-1]: item})
    name = params.get('modelProvider') or value.get('model_provider') or 'openai'
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise BridgeError('HTTP 超时层无法安全覆盖此供应商名称。')
    provider = (value.get('model_providers') or {}).get(name) or {}
    if not isinstance(provider, dict):
        raise BridgeError('供应商配置格式不受 HTTP 超时层支持。')
    features = value.get('features') or {}
    if (provider.get('wire_api', 'responses') != 'responses'
            or provider.get('supports_websockets')
            or any(enabled for key, enabled in features.items() if key.startswith('responses_websockets'))):
        raise BridgeError('HTTP 超时层目前验收的是 Responses HTTP/SSE；请关闭此超时选项后使用其他传输。')
    base = provider.get('base_url')
    if not isinstance(base, str) or not base:
        raise BridgeError('HTTP 超时层需要供应商显式配置 base_url；请关闭此超时选项后使用内置供应商。')
    # Provider-managed signing authenticates the original authority/path. It
    # cannot be changed to loopback before signing without a separate adapter.
    if provider.get('aws'):
        raise BridgeError('HTTP 超时层尚未验收供应商签名认证；请关闭此超时选项后使用。')
    return name, base


def engine_environment(base):
    env = dict(base)
    prior = env.get('NO_PROXY', env.get('no_proxy', ''))
    hosts = [x.strip() for x in prior.split(',') if x.strip()]
    for host in ('127.0.0.1', 'localhost'):
        if host not in hosts:
            hosts.append(host)
    env.pop('no_proxy', None)
    env['NO_PROXY'] = ','.join(hosts)
    return env


class StdioBridge:
    def __init__(self, process, route, *, source, destination, rpc_timeout=15):
        self.process, self.route = process, route
        self.source, self.destination = source, destination
        self.rpc_timeout = rpc_timeout
        self.prefix = 'codex-timeout-' + secrets.token_hex(24) + '-'
        self.sequence = 0
        self.pending = {}
        self.lock = threading.Lock()
        self.input_lock = threading.Lock()
        self.output_lock = threading.Lock()
        self.closed = threading.Event()
        self.input_events = queue.Queue()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='timeout-config')

    def _write(self, stream, lock, raw):
        with lock:
            stream.write(raw)
            stream.flush()

    def _send(self, message):
        self._write(self.process.stdin, self.input_lock,
                    json.dumps(message, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')

    def _output(self, raw):
        self._write(self.destination, self.output_lock, raw)

    def _rpc(self, method, params):
        with self.lock:
            if self.closed.is_set():
                raise BridgeError('引擎连接已关闭。')
            self.sequence += 1
            identity = self.prefix + str(self.sequence)
            answer = queue.Queue(maxsize=1)
            self.pending[identity] = answer
        try:
            self._send(dict(id=identity, method=method, params=params))
            try:
                message = answer.get(timeout=self.rpc_timeout)
            except queue.Empty:
                raise BridgeError('读取引擎配置超时，未启动这次对话。') from None
            if not isinstance(message, dict) or 'result' not in message:
                # Native errors can contain paths and auth material; keep them
                # on the original channel instead of copying them into a log.
                raise BridgeError('引擎未提供可验证的对话配置，未启动这次对话。')
            return message['result']
        finally:
            with self.lock:
                self.pending.pop(identity, None)

    def _engine_output(self):
        try:
            for raw in self.process.stdout:
                try:
                    message = json.loads(raw)
                except ValueError:
                    self._output(raw)
                    continue
                identity = message.get('id') if isinstance(message, dict) else None
                if isinstance(identity, str) and identity.startswith(self.prefix):
                    with self.lock:
                        pending = self.pending.get(identity)
                        if pending is not None and pending.empty():
                            pending.put_nowait(message)
                    continue  # Includes late replies after a private RPC timeout.
                self._output(raw)
        finally:
            self.closed.set()
            with self.lock:
                for pending in self.pending.values():
                    if pending.empty():
                        pending.put_nowait(None)
            self.input_events.put(None)

    def _client_input(self):
        try:
            pending = b''
            while not self.closed.is_set():
                chunk = self.source.read(65536)
                if not chunk:
                    if pending:
                        self.input_events.put(pending)
                    break
                if self.closed.is_set():
                    break
                lines = (pending+chunk).split(b'\n')
                pending = lines.pop()
                for line in lines:
                    self.input_events.put(line+b'\n')
        finally:
            self.input_events.put(None)

    def _prepare_thread(self, message):
        try:
            params = message.get('params') or {}
            if not isinstance(params, dict):
                raise BridgeError('对话参数格式不受 HTTP 超时层支持。')
            if params.get('path') or params.get('history') is not None:
                raise BridgeError('HTTP 超时层尚未验收按路径或原始历史恢复；请关闭此超时选项后使用。')
            cwd = params.get('cwd')
            if not cwd and message['method'] != 'thread/start':
                metadata = self._rpc('thread/read', dict(threadId=params['threadId'], includeTurns=False))
                cwd = metadata['thread']['cwd']
            resolved = self._rpc('config/read', dict(cwd=cwd, includeLayers=False))
            name, base = configured_provider(resolved['config'], params)
            try:
                local = self.route(base)
            except (ValueError, TypeError):
                raise BridgeError('此供应商地址格式不受 HTTP 超时层支持。') from None
            params = override_base_url(params, name, local)
            self._send(dict(message, params=params))
        except Exception:
            import sys
            error = sys.exc_info()[1]
            text = str(error) if isinstance(error, BridgeError) else 'HTTP 超时层未能核实配置，未启动这次对话。'
            reply = dict(id=message.get('id'), error=dict(code=-32000, message=text))
            with contextlib.suppress(OSError, ValueError):
                self._output(json.dumps(reply, ensure_ascii=False).encode('utf-8') + b'\n')

    def run(self):
        # Daemon readers cannot keep a dead engine alive if the desktop leaves
        # its stdin open. Only our owned child is closed by the runner/job.
        threads = [threading.Thread(target=self._engine_output, daemon=True),
                   threading.Thread(target=self._client_input, daemon=True)]
        for thread in threads:
            thread.start()
        try:
            while not self.closed.is_set():
                raw = self.input_events.get()
                if raw is None:
                    break
                try:
                    message = json.loads(raw)
                except ValueError:
                    message = None
                if isinstance(message, dict) and message.get('method') in THREAD_METHODS and 'id' in message:
                    self.pool.submit(self._prepare_thread, message)
                else:
                    self._write(self.process.stdin, self.input_lock, raw)
        finally:
            self.closed.set()
            with self.lock:
                for pending in self.pending.values():
                    if pending.empty():
                        pending.put_nowait(None)
            self.pool.shutdown(wait=True, cancel_futures=True)
            with contextlib.suppress(OSError, ValueError):
                self.process.stdin.close()
