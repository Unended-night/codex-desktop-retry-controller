"""Small wrappers around documented Windows Shell APIs. No app or engine imports."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import uuid


class GUID(C.Structure):
    _fields_ = [('a', W.DWORD), ('b', W.WORD), ('c', W.WORD), ('d', C.c_ubyte * 8)]

    @classmethod
    def parse(cls, text):
        return cls.from_buffer_copy(uuid.UUID(text).bytes_le)


class PropertyKey(C.Structure):
    _fields_ = [('fmtid', GUID), ('pid', W.DWORD)]


class Value(C.Union):
    _fields_ = [('pointer', C.c_void_p), ('integer', C.c_longlong), ('raw', C.c_ubyte * 16)]


class PropVariant(C.Structure):
    _fields_ = [('vt', W.WORD), ('r1', W.WORD), ('r2', W.WORD), ('r3', W.WORD), ('value', Value)]


PROPERTY_IDS = {'command': 2, 'icon': 3, 'display_name': 4, 'app_id': 5}
PROPERTY_GUID = '9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3'
STORE_IID = '886d8eeb-8cf2-4446-8d02-cdba1dbdcf99'


def checked(result):
    if result < 0:
        raise OSError(f'Windows Shell HRESULT 0x{result & 0xffffffff:08x}')


class ComObject:
    def __init__(self, pointer):
        self.pointer = pointer
        self.table = C.cast(pointer, C.POINTER(C.POINTER(C.c_void_p))).contents

    def call(self, slot, types=(), *args):
        result = C.WINFUNCTYPE(C.c_long, C.c_void_p, *types)(self.table[slot])(self.pointer, *args)
        checked(result)

    def query(self, iid):
        pointer = C.c_void_p()
        self.call(0, (C.POINTER(GUID), C.POINTER(C.c_void_p)), C.byref(GUID.parse(iid)), C.byref(pointer))
        return ComObject(pointer)

    def close(self):
        if self.pointer:
            C.WINFUNCTYPE(W.ULONG, C.c_void_p)(self.table[2])(self.pointer)
            self.pointer = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PropertyStore(ComObject):
    def get(self, name, api):
        key = PropertyKey(GUID.parse(PROPERTY_GUID), PROPERTY_IDS[name])
        value = PropVariant()
        self.call(5, (C.POINTER(PropertyKey), C.POINTER(PropVariant)), C.byref(key), C.byref(value))
        try:
            if value.vt == 0:
                return None
            if value.vt not in (8, 31):
                raise ValueError(f'Unexpected {name} property type: {value.vt}')
            return C.wstring_at(value.value.pointer) if value.value.pointer else ''
        finally:
            api.ole.PropVariantClear(C.byref(value))

    def set(self, name, text):
        key = PropertyKey(GUID.parse(PROPERTY_GUID), PROPERTY_IDS[name])
        value = PropVariant()
        # SetValue copies the string; this buffer remains Python-owned.
        buffer = C.create_unicode_buffer(text) if text is not None else None
        if buffer is not None:
            value.vt = 31
            value.value.pointer = C.cast(buffer, C.c_void_p).value
        self.call(6, (C.POINTER(PropertyKey), C.POINTER(PropVariant)), C.byref(key), C.byref(value))


class Shortcut:
    def __init__(self, api, path=None, *, writable=False):
        self.api = api
        self.link = api.create('00021401-0000-0000-c000-000000000046',
                               '000214f9-0000-0000-c000-000000000046')
        self.persist = self.link.query('0000010b-0000-0000-c000-000000000046')
        store = self.link.query(STORE_IID)
        self.store = PropertyStore(store.pointer)
        store.pointer = None
        if path is not None:
            try:
                self.persist.call(5, (W.LPCWSTR, W.DWORD), str(path), 2 if writable else 0)
            except Exception:
                self.close()
                raise

    def read(self):
        result = {}
        for key, slot in [('target', 3), ('description', 6), ('directory', 8), ('arguments', 10)]:
            buffer = C.create_unicode_buffer(32768)
            if key == 'target':
                self.link.call(slot, (W.LPWSTR, C.c_int, C.c_void_p, W.DWORD), buffer, len(buffer), None, 4)
            else:
                self.link.call(slot, (W.LPWSTR, C.c_int), buffer, len(buffer))
            result[key] = buffer.value
        buffer = C.create_unicode_buffer(32768)
        index = C.c_int()
        self.link.call(16, (W.LPWSTR, C.c_int, C.POINTER(C.c_int)), buffer, len(buffer), C.byref(index))
        result.update(icon=buffer.value, icon_index=index.value, app_id=self.store.get('app_id', self.api))
        for key, slot, typ in [('show', 14, C.c_int), ('hotkey', 12, W.WORD)]:
            value = typ()
            self.link.call(slot, (C.POINTER(typ),), C.byref(value))
            result[key] = value.value
        return result

    def configure(self, *, target, arguments, directory, description):
        for slot, value in [(20, target), (11, arguments), (9, directory), (7, description)]:
            self.link.call(slot, (W.LPCWSTR,), str(value))
        self.link.call(13, (W.WORD,), 0)
        self.link.call(15, (C.c_int,), 7)

    def set_icon(self, icon):
        self.link.call(17, (W.LPCWSTR, C.c_int), str(icon), 0)

    def save(self, path):
        self.store.call(7)
        self.persist.call(6, (W.LPCWSTR, W.BOOL), str(path), True)

    def close(self):
        self.store.close()
        self.persist.close()
        self.link.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Process:
    def __init__(self, api, pid):
        self.api, self.pid = api, pid
        self.handle = api.kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not self.handle:
            raise C.WinError(C.get_last_error())
        try:
            buffer = C.create_unicode_buffer(32768)
            size = W.DWORD(len(buffer))
            if not api.kernel.QueryFullProcessImageNameW(self.handle, 0, buffer, C.byref(size)):
                raise C.WinError(C.get_last_error())
            times = [W.FILETIME() for _ in range(4)]
            if not api.kernel.GetProcessTimes(self.handle, *[C.byref(t) for t in times]):
                raise C.WinError(C.get_last_error())
            self.exe = Path(buffer.value)
            self.created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        except Exception:
            self.close()
            raise

    def alive(self, wait_ms=0):
        result = self.api.kernel.WaitForSingleObject(self.handle, wait_ms)
        if result == 0xffffffff:
            raise C.WinError(C.get_last_error())
        return result == 258

    def close(self):
        if self.handle:
            self.api.kernel.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class WindowsShell:
    def __init__(self):
        self.user = C.WinDLL('user32', use_last_error=True)
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.shell = C.WinDLL('shell32', use_last_error=True)
        self.ole = C.WinDLL('ole32', use_last_error=True)
        def bind(dll, name, result, *args):
            function = getattr(dll, name)
            function.restype, function.argtypes = result, list(args)
        bind(self.ole, 'CoInitializeEx', C.c_long, C.c_void_p, W.DWORD)
        self.initialized = self.ole.CoInitializeEx(None, 2)
        checked(self.initialized)
        bind(self.ole, 'CoTaskMemFree', None, C.c_void_p)
        bind(self.ole, 'PropVariantClear', C.c_long, C.POINTER(PropVariant))
        bind(self.ole, 'CoCreateInstance', C.c_long, C.POINTER(GUID), C.c_void_p, W.DWORD,
             C.POINTER(GUID), C.POINTER(C.c_void_p))
        bind(self.shell, 'SHGetPropertyStoreForWindow', C.c_long, W.HWND, C.POINTER(GUID), C.POINTER(C.c_void_p))
        bind(self.shell, 'SHGetKnownFolderPath', C.c_long, C.POINTER(GUID), W.DWORD, W.HANDLE, C.POINTER(C.c_void_p))
        bind(self.shell, 'SHChangeNotify', None, C.c_long, W.UINT, C.c_void_p, C.c_void_p)
        bind(self.shell, 'CommandLineToArgvW', C.POINTER(W.LPWSTR), W.LPCWSTR, C.POINTER(C.c_int))
        bind(self.kernel, 'LocalFree', W.HANDLE, W.HANDLE)
        bind(self.kernel, 'OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
        bind(self.kernel, 'CloseHandle', W.BOOL, W.HANDLE)
        bind(self.kernel, 'QueryFullProcessImageNameW', W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD))
        bind(self.kernel, 'GetProcessTimes', W.BOOL, W.HANDLE, *([C.POINTER(W.FILETIME)] * 4))
        bind(self.kernel, 'WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
        bind(self.kernel, 'CreateMutexW', W.HANDLE, C.c_void_p, W.BOOL, W.LPCWSTR)
        bind(self.kernel, 'ReleaseMutex', W.BOOL, W.HANDLE)
        bind(self.user, 'IsWindow', W.BOOL, W.HWND)
        bind(self.user, 'IsWindowVisible', W.BOOL, W.HWND)
        bind(self.user, 'GetWindow', W.HWND, W.HWND, W.UINT)
        bind(self.user, 'GetWindowLongPtrW', C.c_ssize_t, W.HWND, C.c_int)
        bind(self.user, 'GetWindowThreadProcessId', W.DWORD, W.HWND, C.POINTER(W.DWORD))

    def close(self):
        if self.initialized is not None:
            self.ole.CoUninitialize()
            self.initialized = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def create(self, clsid, iid):
        value = C.c_void_p()
        checked(self.ole.CoCreateInstance(C.byref(GUID.parse(clsid)), None, 1,
                                         C.byref(GUID.parse(iid)), C.byref(value)))
        return ComObject(value)

    def known_folder(self, guid):
        value = C.c_void_p()
        checked(self.shell.SHGetKnownFolderPath(C.byref(GUID.parse(guid)), 0, None, C.byref(value)))
        try:
            return Path(C.wstring_at(value))
        finally:
            self.ole.CoTaskMemFree(value)

    def argv(self, arguments):
        count = C.c_int()
        result = self.shell.CommandLineToArgvW('launcher.exe ' + arguments, C.byref(count))
        if not result:
            raise C.WinError(C.get_last_error())
        try:
            return [result[i] for i in range(1, count.value)]
        finally:
            self.kernel.LocalFree(result)

    def notify(self, path, created=False):
        buffer = C.create_unicode_buffer(str(path))
        self.shell.SHChangeNotify(2 if created else 0x2000, 5 | 0x1000, C.cast(buffer, C.c_void_p), None)

    def window_store(self, hwnd):
        value = C.c_void_p()
        checked(self.shell.SHGetPropertyStoreForWindow(hwnd, C.byref(GUID.parse(STORE_IID)), C.byref(value)))
        return PropertyStore(value)

    def belongs(self, hwnd, pid):
        owner = W.DWORD()
        self.user.GetWindowThreadProcessId(hwnd, C.byref(owner))
        return bool(self.user.IsWindow(hwnd)) and owner.value == pid

    def windows(self, pid):
        handles = []
        callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        @callback_type
        def collect(hwnd, _):
            if (self.belongs(hwnd, pid) and self.user.IsWindowVisible(hwnd)
                    and not self.user.GetWindow(hwnd, 4)
                    and not self.user.GetWindowLongPtrW(hwnd, -20) & 0x80):
                handles.append(hwnd)
            return True
        self.user.EnumWindows.argtypes = [callback_type, W.LPARAM]
        if not self.user.EnumWindows(collect, 0):
            raise C.WinError(C.get_last_error())
        return handles

    @contextmanager
    def lock(self, name, timeout_ms=5000):
        handle = self.kernel.CreateMutexW(None, False, name)
        if not handle:
            raise C.WinError(C.get_last_error())
        acquired = False
        try:
            result = self.kernel.WaitForSingleObject(handle, timeout_ms)
            if result not in (0, 128, 258):
                raise C.WinError(C.get_last_error())
            acquired = result in (0, 128)
            yield acquired
        finally:
            if acquired:
                self.kernel.ReleaseMutex(handle)
            self.kernel.CloseHandle(handle)
