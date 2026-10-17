"""Launch a temporary test executable under a minimal Windows debugger.

Only handles research breakpoints in its own child; never attaches to Codex.
"""
import ctypes as C
from ctypes import wintypes as W
import subprocess
import time

K = C.WinDLL("kernel32", use_last_error=True)
U64 = C.c_ulonglong


class EXCEPTION_RECORD(C.Structure):
    _fields_ = [("code", W.DWORD), ("flags", W.DWORD), ("record", C.c_void_p),
                ("address", C.c_void_p), ("count", W.DWORD), ("info", U64 * 15)]


class EXCEPTION_INFO(C.Structure):
    _fields_ = [("record", EXCEPTION_RECORD), ("first_chance", W.DWORD)]


class CREATE_INFO(C.Structure):
    _fields_ = [("file", W.HANDLE), ("process", W.HANDLE), ("thread", W.HANDLE),
                ("base", C.c_void_p), ("debug_offset", W.DWORD), ("debug_size", W.DWORD),
                ("tls", C.c_void_p), ("start", C.c_void_p), ("image", C.c_void_p), ("unicode", W.WORD)]


class DATA(C.Union):
    _fields_ = [("exception", EXCEPTION_INFO), ("create", CREATE_INFO), ("raw", C.c_byte * 160)]


class EVENT(C.Structure):
    _fields_ = [("code", W.DWORD), ("pid", W.DWORD), ("tid", W.DWORD), ("u", DATA)]


K.WaitForDebugEvent.argtypes = [C.POINTER(EVENT), W.DWORD]
K.ContinueDebugEvent.argtypes = [W.DWORD, W.DWORD, W.DWORD]
K.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p]
K.WriteProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p]
K.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]
K.OpenThread.restype = W.HANDLE
K.GetThreadContext.argtypes = [W.HANDLE, C.c_void_p]
K.SetThreadContext.argtypes = [W.HANDLE, C.c_void_p]
K.FlushInstructionCache.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t]
K.CloseHandle.argtypes = [W.HANDLE]


def check(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


def monitor(proc, patches, timeout=45):
    """patches maps RVA to original first byte; child contains on-disk INT3s."""
    base = None
    process = None
    hits = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        event = EVENT()
        if not K.WaitForDebugEvent(C.byref(event), 100):
            continue
        status = 0x00010002  # DBG_CONTINUE
        if event.code == 3:
            base = event.u.create.base
            process = event.u.create.process
            if event.u.create.file:
                K.CloseHandle(event.u.create.file)
            if event.u.create.thread:
                K.CloseHandle(event.u.create.thread)
        elif event.code == 2:  # CREATE_THREAD
            handle = C.cast(C.byref(event.u), C.POINTER(W.HANDLE))[0]
            if handle:
                K.CloseHandle(handle)
        elif event.code == 6:  # LOAD_DLL, first union member is hFile
            handle = C.cast(C.byref(event.u), C.POINTER(W.HANDLE))[0]
            if handle:
                K.CloseHandle(handle)
        elif event.code == 1:
            record = event.u.exception.record
            rva = record.address - base if base else -1
            if record.code == 0x80000003 and rva in patches:
                thread = K.OpenThread(0x001A, False, event.tid)
                check(thread)
                raw = C.create_string_buffer(1248)
                aligned = (C.addressof(raw) + 15) & ~15
                # CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
                C.c_uint32.from_address(aligned + 48).value = 0x100003
                check(K.GetThreadContext(thread, aligned))
                rsp = U64.from_address(aligned + 152).value
                stack = (U64 * 12)()
                check(K.ReadProcessMemory(process, rsp, C.byref(stack), C.sizeof(stack), None))
                hits.append({"breakpoint_rva": hex(rva), "return_rva": hex(stack[0] - base),
                             "rax": hex(U64.from_address(aligned + 120).value),
                             "rcx": hex(U64.from_address(aligned + 128).value),
                             "rdx": hex(U64.from_address(aligned + 136).value),
                             "stack_rvas": [hex(x-base) for x in stack]})
                old = C.c_ubyte(patches.pop(rva))
                check(K.WriteProcessMemory(process, record.address, C.byref(old), 1, None))
                check(K.FlushInstructionCache(process, record.address, 1))
                U64.from_address(aligned + 248).value = record.address
                check(K.SetThreadContext(thread, aligned))
                K.CloseHandle(thread)
            elif record.code != 0x80000003:
                status = 0x80010001  # DBG_EXCEPTION_NOT_HANDLED
        elif event.code == 5:
            K.ContinueDebugEvent(event.pid, event.tid, status)
            if process:
                K.CloseHandle(process)
            return hits, False
        check(K.ContinueDebugEvent(event.pid, event.tid, status))
    proc.kill()
    # Drain the exit event so the child can actually terminate.
    for _ in range(100):
        event = EVENT()
        if K.WaitForDebugEvent(C.byref(event), 100):
            K.ContinueDebugEvent(event.pid, event.tid, 0x00010002)
            if event.code == 5:
                break
    if process:
        K.CloseHandle(process)
    return hits, True
