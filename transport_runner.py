"""Owned child of codex-guard.exe; all descendants belong to its Windows job."""
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

from transport_bridge import StdioBridge, engine_environment
from transport_guard import ResponseGuard


def serves_stdio(arguments):
    # Global config/feature flags may precede app-server after a desktop update.
    # Parse their values, so an option value named app-server is not a command.
    values = {'-c', '--config', '--enable', '--disable', '-p', '--profile',
              '--config-profile', '-C', '--cd', '-m', '--model', '--listen', '--startup-client-info'}
    positionals = []
    startup_config = False
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word == '--':
            break
        if word in values:
            index += 2
            continue
        if word in ('--help', '-h', '--version', '-V'):
            return False
        if word == '--print-startup-config':
            startup_config = True
        if not word.startswith('-'):
            positionals.append(word)
        index += 1
    if not positionals or positionals[0] != 'app-server':
        return False
    if len(positionals) > 1:
        if positionals[1] in ('generate-json-schema', 'generate-ts'):
            return False
        raise ValueError('HTTP timeout entry requires app-server stdio, not a daemon or another subcommand')
    # Desktop reads policies (and signs out) with stdin ignored and one JSON
    # document on stdout. This command must finish in the native engine; it is
    # not the long-lived JSONL server that supervises model requests.
    if startup_config:
        return False
    for index, word in enumerate(arguments):
        if word == '--listen':
            if index+1 == len(arguments) or arguments[index+1] != 'stdio://':
                raise ValueError('HTTP timeout entry requires app-server stdio')
        elif word.startswith('--listen=') and word != '--listen=stdio://':
            raise ValueError('HTTP timeout entry requires app-server stdio')
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--timeout-ms', type=int, required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    arguments = options.arguments
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    if not serves_stdio(arguments):
        return subprocess.call([str(options.engine), *arguments],
                               stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    if os.name == 'nt':
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    loop = asyncio.new_event_loop()
    ready = concurrent.futures.Future()
    stop = None
    guard = None

    def event(value):
        # Deliberately excludes the route, URL and all request/response data.
        print(json.dumps(dict(level='WARN', target='codex_response_timeout',
                              fields=dict(message='HTTP request supervision', **value))),
              file=sys.stderr, flush=True)

    async def serve():
        nonlocal guard, stop
        try:
            stop = asyncio.Event()
            async with ResponseGuard(options.timeout_ms, on_event=event) as guard:
                ready.set_result(None)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                event(dict(event='guard_stopped'))
            raise

    def run_loop():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(serve())
        except BaseException:
            # Reported through ready/event above. Library exception strings can
            # contain proxy credentials; never print a background traceback.
            pass
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    thread = threading.Thread(target=run_loop, name='response-timeout-http', daemon=True)
    thread.start()
    process = None
    try:
        ready.result(timeout=15)
        process = subprocess.Popen([str(options.engine), *arguments],
                                   env=engine_environment(os.environ), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=None,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        def route(url):
            async def register():
                return guard.route(url)
            future = asyncio.run_coroutine_threadsafe(register(), loop)
            try:
                return future.result(timeout=5)
            except BaseException:
                future.cancel()
                raise
        # A daemon can still be blocked on desktop input when the engine exits.
        # Raw input has no BufferedReader lock to deadlock interpreter shutdown.
        bridge = StdioBridge(process, route, source=sys.stdin.buffer.raw, destination=sys.stdout.buffer)
        bridge.run()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()  # Only this runner's own child, after stdio EOF.
            return process.wait(timeout=5)
    finally:
        if process:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
        if not loop.is_closed() and stop:
            loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=10)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Exceptions from HTTP clients/config parsing may embed private values.
        print('Codex HTTP timeout entry failed; no unguarded engine was started.', file=sys.stderr)
        raise SystemExit(1)
