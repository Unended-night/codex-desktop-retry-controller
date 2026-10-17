"""Structure-checked reversible patches; verification precedes installed writes."""
from __future__ import annotations

import base64
import contextlib
import ctypes
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import struct
import tempfile
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_VERSION = "0.158.0-alpha.2.1"
SUPPORTED_SHA256 = "8f0554ede25bbc5450921897c468b2e84635aa513c5017457997af0954581f49"
SUPPORTED_SIZE = 321953584
MAX_RETRIES = 1000000
MAX_INTERVAL_MS = 60000

# All offsets refer to the exact SHA-256 above, not just a version string.
PATCH_SITES = [
    (123945105, "483b87d0030000", "model_http_budget"),
    (116031915, "418b96b001000081fa00ca9a3b7521e8217e3afe90", "model_outer_policy"),
    (116033703, "488b85e8020000", "bounded_connection_retry"),
    (116031483, "48baf3ec3feb23000000", "generic_429_retry"),
]


def detect_installation() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "OpenAI/Codex/bin"
    paths = list(base.glob("*/codex.exe"))
    if len(paths) != 1:
        raise ControllerError("未找到唯一桌面版引擎。请使用“选择程序”；不会自动选择终端 CLI 或旧版本。")
    return paths[0].resolve()


def version_of(data: bytes) -> str:
    if data[:2] != b'MZ':
        raise ControllerError('不是 Windows 可执行文件。')
    versions = set(re.findall(rb'codex-app-server(\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)(?:\.\d+)*)?)',data))
    if len(versions) != 1:
        raise ControllerError('无法唯一读取引擎内嵌版本。')
    return versions.pop().decode('ascii')


def build_plan(data: bytes, p: dict) -> list[dict]:
    p = validate_profile(p)
    version_of(data)
    if sha(data) != SUPPORTED_SHA256:
        from .native import replacements
        result=[]
        for off,size,new,label in replacements(data,p,ControllerError):
            if len(new)>size: raise ControllerError('补丁空间不足。')
            result.append(dict(offset=off,before=b64(data[off:off+size]),
                               after=b64(new.ljust(size,b'\x90')),label=label))
        return sorted(result,key=lambda x:x['offset'])
    seconds, ms = divmod(p["interval_ms"], 1000)
    duration = b"\xb8" + struct.pack("<I", seconds) + b"\xba" + struct.pack("<I", ms * 1000000)
    replacements = {
        "model_http_budget": bytes.fromhex("4839c0"),
        "model_outer_policy": bytes.fromhex("49c786f0000000") + struct.pack("<I", p["max_retries"]) + duration,
        "bounded_connection_retry": b"\xe9" + struct.pack("<i", 0x146ea95a6 - 0x146ea94a7 - 5),
        "generic_429_retry": b"\x48\xba" + struct.pack("<Q", 0x23eb3fecf3 & ~(1 << 27)),
    }
    result = []
    for off, expected, label in PATCH_SITES:
        old = bytes.fromhex(expected)
        new = replacements[label]
        if data[off:off+len(old)] != old or len(new) > len(old):
            raise ControllerError(f"程序结构检查失败：{label}。未写入文件。")
        result.append({"offset": off, "before": b64(old), "after": b64(new.ljust(len(old), b"\x90")), "label": label})
    return sorted(result, key=lambda item: item["offset"])


class ControllerError(Exception):
    pass


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def profile(retries: int | str, interval_seconds: str) -> dict:
    try:
        if not re.fullmatch(r"[0-9]+", str(retries).strip()):
            raise ValueError
        count = int(retries)
        seconds = Decimal(str(interval_seconds).strip())
        if not seconds.is_finite() or seconds < 0:
            raise ValueError
        ms = seconds * 1000
        if ms != ms.to_integral_value():
            raise ValueError
        ms = int(ms)
        if not 0 <= count <= MAX_RETRIES or not 0 <= ms <= MAX_INTERVAL_MS:
            raise ValueError
        return {"max_retries": count, "interval_ms": ms}
    except (ValueError, InvalidOperation, OverflowError):
        raise ControllerError("次数须为 0～1000000 的整数；间隔须为 0～60 秒，最多三位小数。") from None


def validate_profile(p: dict) -> dict:
    if not isinstance(p, dict) or type(p.get("interval_ms")) is not int:
        raise ControllerError("无效的重试设置。")
    return profile(p.get("max_retries"), str(Decimal(p["interval_ms"]) / 1000))


def patched_bytes(original: bytes, slots: list[dict]) -> bytes:
    output = bytearray(original)
    for item in slots:
        offset, before, after = item["offset"], unb64(item["before"]), unb64(item["after"])
        if len(before) != len(after) or output[offset:offset + len(before)] != before:
            raise ControllerError("原始字节与补丁不匹配。")
        output[offset:offset + len(before)] = after
    return bytes(output)


def transition_slots(baseline: bytes, target: bytes, new_slots: list[dict], old_journal: dict | None) -> list[dict]:
    """Journal the union when a newer recipe changes the patched byte ranges."""
    if not old_journal:
        return new_slots
    ranges = sorted((x["offset"], x["offset"] + len(unb64(x["before"])))
                    for x in new_slots + old_journal["slots"])
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [dict(offset=a, before=b64(baseline[a:z]), after=b64(target[a:z]),
                 label="current and previous recipe") for a, z in merged]


def recover_baseline(data: bytes, journal: dict) -> bytes:
    try:
        if journal["format"] != 1 or len(data) != journal["size"]:
            raise ValueError("format or size")
        output = bytearray(data)
        previous_end = -1
        for item in journal["slots"]:
            offset = item["offset"]
            old, new = unb64(item["before"]), unb64(item["after"])
            previous = unb64(item.get("previous", item["before"]))
            if type(offset) is not int or offset < previous_end or offset < 0 or not old:
                raise ValueError("slot offset")
            if len(old) != len(new) or len(old) != len(previous) or offset + len(old) > len(data):
                raise ValueError("slot length")
            current = data[offset:offset + len(old)]
            # Also accepts an interrupted write that contains an old/new mixture.
            if any(c not in (a, b, p) for c, a, b, p in zip(current, old, new, previous)):
                raise ValueError("unexpected modified bytes")
            output[offset:offset + len(old)] = old
            previous_end = offset + len(old)
        if sha(output) != journal["base_sha256"]:
            raise ValueError("baseline hash")
        return bytes(output)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControllerError("程序与撤销记录不一致：可能已更新或被其他工具修改。拒绝覆盖。") from exc


def atomic_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".journal-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def exclusive_binary(path: Path):
    """Exclusive shared-file handle: affects all hard links, never replaces them."""
    if os.name != "nt":
        raise ControllerError("目前只支持 Windows。")
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                  ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    deadline = time.monotonic() + 15
    while True:
        handle = kernel.CreateFileW(str(path), 0xC0000000, 0, None, 3, 0x80, None)
        if handle != ctypes.c_void_p(-1).value:
            break
        code = ctypes.get_last_error()
        if code not in (32, 33) or time.monotonic() >= deadline:
            raise ControllerError(f"无法独占打开程序（Windows {code}）。请先关闭 Codex 桌面版；文件权限也可能阻止写入。")
        time.sleep(0.2)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "r+b", buffering=0) as stream:
        yield stream


_process_mutex = threading.Lock()


class Manager:
    def __init__(self, root: Path = ROOT, *, verify_writes: bool = True):
        self.verify_writes = verify_writes
        self.root = Path(root).resolve()
        self.state = self.root / "state"
        self.logs = self.root / "logs"
        self.state.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("codex_retry." + sha(str(self.root).encode())[:12])
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = RotatingFileHandler(self.logs / "controller.log", maxBytes=1_048_576,
                                          backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            self.logger.addHandler(handler)

    def close(self):
        for handler in list(self.logger.handlers):
            handler.close()
            self.logger.removeHandler(handler)

    def journal_path(self, path: Path) -> Path:
        key = sha(os.path.normcase(str(path.resolve())).encode("utf-8"))[:20]
        return self.state / f"{key}.json"

    def read_journal(self, path: Path) -> dict | None:
        file = self.journal_path(path)
        if not file.exists():
            return None
        try:
            value = json.loads(file.read_text(encoding="utf-8"))
            if value.get("path") != str(path.resolve()):
                raise ValueError("path")
            return value
        except (ValueError, OSError) as exc:
            raise ControllerError("撤销记录损坏或路径不匹配，未修改程序。") from exc

    @contextlib.contextmanager
    def operation_lock(self):
        import msvcrt
        with _process_mutex:
            with (self.state / "controller.lock").open("a+b") as lock:
                if lock.seek(0, 2) == 0:
                    lock.write(b"\0")
                    lock.flush()
                lock.seek(0)
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise ControllerError("另一个控制器正在操作，请稍后重试。") from None
                try:
                    yield
                finally:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)

    def baseline(self, path: Path, data: bytes) -> tuple[bytes, dict | None]:
        journal = self.read_journal(path)
        if journal:
            try:
                return recover_baseline(data, journal), journal
            except ControllerError:
                if version_of(data) != journal.get("version"):
                    build_plan(data, {"max_retries": 1000, "interval_ms": 500})
                    return data, None
                raise
        return data, None

    def inspect(self, path: Path | None = None) -> dict:
        path = (path or detect_installation()).resolve()
        data = path.read_bytes()
        try:
            version = version_of(data)
        except ControllerError:
            version = "未识别"
        result = dict(path=str(path), version=version, status="incompatible", profile=None,
                      sha256=sha(data), compatible=False, verified=False, can_restore=False,
                      reason="", undo_bytes=0, hard_links=path.stat().st_nlink)
        try:
            baseline, journal = self.baseline(path, data)
            modified = journal and sha(data) != journal["base_sha256"]
            result["can_restore"] = bool(modified)
            if modified:
                result["status"] = "custom" if sha(data) == journal["patched_sha256"] else "interrupted"
                result["profile"] = journal["profile"]
            plan = build_plan(baseline, {"max_retries": 1000, "interval_ms": 500})
            result["compatible"] = True
            if not modified:
                result["status"] = "default"
            result["undo_bytes"] = sum(len(unb64(item["before"])) for item in (journal["slots"] if modified else plan))
            from .verification import cached
            result["verified"] = cached(self, baseline) is not None
            if not result["verified"]:
                result["reason"] = "结构已识别；首次应用前将自动验证，也可先点击验证兼容性。"
        except ControllerError as exc:
            result["reason"] = str(exc)
        self.logger.info("inspect path=%s version=%s status=%s", path, version, result["status"])
        return result

    def verify(self, path: Path) -> dict:
        from .verification import verify
        data = path.read_bytes()
        baseline, _ = self.baseline(path, data)
        build_plan(baseline, {"max_retries": 1000, "interval_ms": 500})
        report = verify(self, baseline)
        if path.read_bytes() != data:
            raise ControllerError("验证期间安装程序发生变化，请重新检测。")
        return report

    def apply(self, path: Path, p: dict) -> dict:
        p = validate_profile(p)
        if self.verify_writes:
            self.verify(path)
        return self._change(path, p)

    def restore(self, path: Path) -> dict:
        return self._change(path, None)

    def _change(self, path: Path, p: dict | None) -> dict:
        path = path.resolve()
        action = "restore" if p is None else "apply"
        self.logger.info("%s requested path=%s profile=%s", action, path, p)
        try:
            with self.operation_lock(), exclusive_binary(path) as stream:
                current = stream.read()
                baseline, old_journal = self.baseline(path, current)
                actual_version = version_of(baseline)
                if p is not None and self.verify_writes:
                    from .verification import cached
                    if cached(self, baseline) is None:
                        raise ControllerError("当前文件尚未通过行为验证，或验证后已更新。请重新验证。")
                if p is None:
                    if old_journal is None:
                        build_plan(baseline, {"max_retries": 1000, "interval_ms": 500})
                        return {"action": "restore", "changed": False, "sha256": sha(current), "version": actual_version}
                    journal = dict(old_journal)
                    target = baseline
                    slots = journal["slots"]
                else:
                    slots = build_plan(baseline, p)
                    target = patched_bytes(baseline, slots)
                    slots = transition_slots(baseline, target, slots, old_journal)
                    journal = {"format": 1, "path": str(path), "version": version_of(baseline),
                               "size": len(baseline), "base_sha256": sha(baseline),
                               "patched_sha256": sha(target), "profile": p, "slots": slots}
                if current == target:
                    return {"action": action, "changed": False, "sha256": sha(target), "profile": p, "version": actual_version}
                for item in slots:
                    off = item["offset"]
                    item["previous"] = b64(current[off:off + len(unb64(item["before"]))])
                journal.update(phase="prepared", operation=action, updated_at=now())
                atomic_json(self.journal_path(path), journal)  # Must precede binary writes.
                try:
                    for item in slots:
                        off = item["offset"]
                        value = target[off:off + len(unb64(item["before"]))]
                        stream.seek(off)
                        if stream.write(value) != len(value):
                            raise OSError("short write")
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(0)
                    if sha(stream.read()) != sha(target):
                        raise ControllerError("写入后校验失败。")
                except BaseException:
                    # Restore the clean baseline immediately where possible.
                    for item in slots:
                        stream.seek(item["offset"])
                        stream.write(unb64(item["before"]))
                    stream.flush()
                    os.fsync(stream.fileno())
                    self.logger.exception("write failed; attempted rollback to clean baseline")
                    raise
                journal.update(phase="restored" if p is None else "active", updated_at=now())
                atomic_json(self.journal_path(path), journal)
            self.logger.info("%s completed sha256=%s", action, sha(target))
            return {"action": action, "changed": True, "sha256": sha(target), "profile": p, "version": actual_version}
        except Exception:
            self.logger.exception("%s failed", action)
            raise

