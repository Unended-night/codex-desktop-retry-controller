"""Execute only our small Duration emitter in an isolated Windows child."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


class DurationEmitterTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows x64 emitter')
    def test_emitted_durations_cover_boundaries_without_divide_overflow(self):
        script = r'''
import ctypes as c
import json
from controller.core import profile
from controller.native_v4 import delay_code
k=c.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong,c.c_ulong]
k.VirtualAlloc.restype=c.c_void_p
k.VirtualProtect.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong,c.POINTER(c.c_ulong)]
k.VirtualFree.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong]
k.FlushInstructionCache.argtypes=[c.c_void_p,c.c_void_p,c.c_size_t]
results=[]
for base,spread in [(0,0),(1,0),(1000,70),(5,4),(30000,30000),(60000,0)]:
    # Pack both return registers so the Python caller sees seconds and nanos.
    raw=delay_code(profile(8,base,spread,unit='ms'))+bytes.fromhex('48c1e0204809d0c3')
    address=k.VirtualAlloc(None,len(raw),0x3000,0x04)
    assert address
    try:
        c.memmove(address,raw,len(raw))
        previous=c.c_ulong()
        assert k.VirtualProtect(address,len(raw),0x20,c.byref(previous))
        assert k.FlushInstructionCache(c.c_void_p(-1),address,len(raw))
        sample=c.CFUNCTYPE(c.c_ulonglong)(address)
        values=[]
        for _ in range(256):
            packed=sample()
            seconds,nanos=packed>>32,packed&0xffffffff
            assert nanos<1000000000 and nanos%1000000==0,(seconds,nanos)
            values.append(seconds*1000+nanos//1000000)
        assert all(base-spread<=v<=base+spread for v in values),values
        assert len(set(values))>1 if spread else set(values)=={base}
        results.append([base,spread,min(values),max(values)])
    finally:
        assert k.VirtualFree(address,0,0x8000)
print(json.dumps(results))
'''
        result = subprocess.run([sys.executable,'-B','-X','utf8','-c',script],
                                cwd=Path(__file__).resolve().parents[1],capture_output=True,
                                text=True,encoding='utf-8',timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(json.loads(result.stdout)),6)
