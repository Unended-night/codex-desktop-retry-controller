"""Exercise a temporary Codex engine using the desktop app-server protocol."""
import json
import queue
import subprocess
import threading
import time


def run(exe, directory, env, timeout):
    proc = subprocess.Popen([exe, "app-server", "--stdio"], cwd=directory, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    messages = queue.Queue()
    output, errors = [], []

    def reader(pipe, destination, events=False):
        for line in pipe:
            destination.append(line)
            if events:
                try:
                    messages.put(json.loads(line))
                except ValueError:
                    pass

    threads = [threading.Thread(target=reader, args=(proc.stdout,output,True), daemon=True),
               threading.Thread(target=reader, args=(proc.stderr,errors), daemon=True)]
    for thread in threads:
        thread.start()

    def send(message):
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    timed_out = False
    turn = None
    try:
        send({"id":1, "method":"initialize", "params":{"clientInfo":{"name":"retry_probe", "version":"1.0"},
              "capabilities":{"experimentalApi":True}}})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = messages.get(timeout=0.2)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue
            if message.get("error"):
                break
            if message.get("id") == 1:
                send({"method":"initialized"})
                send({"id":2, "method":"thread/start", "params":{"cwd":directory, "model":"retry-probe-model",
                      "modelProvider":"probe", "approvalPolicy":"never", "sandbox":"read-only", "ephemeral":True}})
            elif message.get("id") == 2:
                thread_id = message["result"]["thread"]["id"]
                send({"id":3, "method":"turn/start", "params":{"threadId":thread_id,
                      "input":[{"type":"text", "text":"Reply OK."}]}})
            elif message.get("method") == "turn/completed":
                turn = message["params"]["turn"]
                break
        else:
            timed_out = True
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=5)
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
        if hasattr(proc, "_handle"):
            proc._handle.Close()
    # This is the turn result, not the deliberately terminated server exit code.
    return "".join(output), "".join(errors), 0 if turn and turn.get("status") == "completed" else 1, timed_out
