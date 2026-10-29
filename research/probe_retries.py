"""Probe the installed Codex engine against a loopback-only fake API.

Uses isolated CODEX_HOME, fake credentials, and temporary configuration.
Does not modify installed programs or real user configuration.
"""
import argparse
import json
import os
import re
from decimal import Decimal
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def retry_delays(stderr):
    """Native Duration logs reveal the selected wait, separate from scheduling."""
    factors = {'s': Decimal(1000), 'ms': Decimal(1), 'µs': Decimal('.001'), 'ns': Decimal('.000001')}
    return [int(Decimal(value)*factors[unit]) for value,unit in
            re.findall(r'retrying sampling request \(\d+/\d+ in ([0-9.]+)(ms|µs|ns|s)\)', stderr)]


def probe(exe, retries, *, stream_retries=0, mode="http", debug_patches=None, retry_after=None, stop_after=7, error_status=500, succeed=False, timeout=45, error_code=None, interface="exec", error_message="local retry probe", error_type="server_error", compact=False):
    if compact and interface != "app-server":
        raise ValueError("compaction probes require app-server")
    events = []
    setup_events = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request=self.rfile.read(int(self.headers.get("Content-Length", "0")))
            setup = compact and not setup_events
            is_compaction = b'CONTEXT CHECKPOINT COMPACTION' in request
            continuation = compact and not setup and not is_compaction
            success = setup or continuation or (len(events) >= stop_after and succeed)
            status = 200 if success else ((200 if mode in ("stream", "stream-rate-limit", "stream-error") else error_status) if len(events) < stop_after else 401)
            if not continuation:
                (setup_events if setup else events).append({"time": time.monotonic(), "path": self.path, "status": status,
                                                            "compaction":is_compaction})
            if mode == "disconnect":
                self.close_connection = True
                return
            payload = (b'data: {"type":"response.created","response":{"id":"probe","status":"in_progress","output":[]}}\n\n'
                       if status == 200 else json.dumps({"error": {"message": error_message, "type": error_type, "code":error_code}}).encode())
            if mode == "stream-rate-limit" and not success:
                payload += b'data: {"type":"response.failed","response":{"id":"probe","error":{"code":"rate_limit_exceeded","message":"Rate limit reached. Please try again in 4s."}}}\n\n'
            if mode == "stream-error" and not success:
                payload += ("data: " + json.dumps({"type":"response.failed", "response":{"id":"probe", "error":{"code":error_code,"type":error_type,"message":error_message}}}) + "\n\n").encode()
            if success:
                item = {"id":"msg_probe", "type":"message", "role":"assistant", "status":"completed",
                        "content":[{"type":"output_text", "text":"OK", "annotations":[]}]}
                usage = (150000 if compact=='auto' else 600000) if setup and isinstance(compact,str) else 1
                for event in [{"type":"response.output_item.done", "output_index":0, "item":item},
                              {"type":"response.completed", "response":{"id":"probe", "status":"completed", "output":[item],
                               "usage":{"input_tokens":usage, "output_tokens":1, "total_tokens":usage+1}}}]:
                    payload += ("data: " + json.dumps(event) + "\n\n").encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/event-stream" if status == 200 else "application/json")
            if retry_after is not None:
                self.send_header("Retry-After", str(retry_after))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="codex-retry-probe-") as directory:
            root = Path(directory)
            (root / "config.toml").write_text(
                'model = "retry-probe-model"\nmodel_provider = "probe"\n'
                + ('model_context_window = 1000000\nmodel_auto_compact_token_limit = 100000\n'
                   f'model_post_turn_compact_threshold_percent = {50 if compact=="post-turn" else 100}\n'
                   if isinstance(compact,str) else '') +
                '[features]\nplugins = false\n'
                '[model_providers.probe]\nname = "loopback probe"\n'
                f'base_url = "http://127.0.0.1:{server.server_port}/v1"\n'
                'env_key = "CODEX_LOCAL_PROBE_KEY"\nwire_api = "responses"\n'
                f'request_max_retries = {retries}\nstream_max_retries = {stream_retries}\n'
                'supports_websockets = false\n', encoding="utf-8")
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("OPENAI_", "AZURE_OPENAI_", "CODEX_"))}
            env.update(CODEX_HOME=directory, CODEX_LOCAL_PROBE_KEY="not-a-real-key",
                       NO_PROXY="127.0.0.1,localhost", RUST_LOG="warn")
            args = [exe, "exec", "--strict-config", "--skip-git-repo-check", "--ephemeral",
                    "--ignore-rules", "--sandbox", "read-only", "--json", "Reply OK."]
            start = time.monotonic()
            timed_out = False
            debug_hits = []
            if interface == "app-server":
                from appserver_probe import run
                stdout, stderr, exit_code, timed_out = run(exe, directory, env, timeout, compact=compact)
            else:
                proc = subprocess.Popen(args, cwd=directory, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
                                        encoding="utf-8", errors="replace",
                                        creationflags=(2 if debug_patches else subprocess.CREATE_NO_WINDOW))
                if debug_patches:
                    from debug_probe import monitor
                    debug_hits, timed_out = monitor(proc, dict(debug_patches), timeout)
                try:
                    stdout, stderr = proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    proc.kill()
                    stdout, stderr = proc.communicate()
                exit_code = proc.returncode
                if os.name == "nt":
                    proc._handle.Close()
            return {"request_max_retries": retries, "stream_max_retries": stream_retries,
                    "mode": mode, "retry_after": retry_after, "debug_hits": debug_hits,
                    "requests": len(events), "intervals_seconds": [round(b["time"] - a["time"], 3)
                    for a, b in zip(events, events[1:])],
                    "statuses": [e["status"] for e in events],
                    "paths": sorted(set(e["path"] for e in events)),
                    "interface": interface, "compact": compact, "setup_requests": len(setup_events),
                    "setup_compaction_requests":sum(e['compaction'] for e in setup_events),
                    "compaction_requests":sum(e['compaction'] for e in events),
                    "reconnects": re.findall(r'Reconnecting\.\.\. \d+/\d+', stdout),
                    "exit_code": exit_code, "timed_out": timed_out,
                    "duration_seconds": round(time.monotonic() - start, 3),
                    "selected_delays_ms": retry_delays(stderr),
                    "stdout_tail": stdout[-2000:], "stderr_tail": stderr[-2000:]}
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()
    report = {"executable": options.exe,
              "version": subprocess.check_output([options.exe, "--version"], text=True, encoding="utf-8").strip(),
              "cases": []}
    for count in [0, 2, 1000]:
        case = probe(options.exe, count)
        report["cases"].append(case)
        print(json.dumps(case, ensure_ascii=False), flush=True)
    Path(options.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
