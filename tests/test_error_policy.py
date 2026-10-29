"""Execute our classifier in a child, with guard pages at String boundaries."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class ErrorPolicyTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows x64 emitter')
    def test_precise_fields_and_bounded_reads(self):
        script=r'''
import ctypes as c
import json
from controller.native_errors import error_policy,AZURE_RESOURCE_MESSAGE as AZURE
from controller.core import profile
k=c.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong,c.c_ulong];k.VirtualAlloc.restype=c.c_void_p
k.VirtualProtect.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong,c.POINTER(c.c_ulong)]
k.VirtualFree.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong]
k.FlushInstructionCache.argtypes=[c.c_void_p,c.c_void_p,c.c_size_t]
buffers=[]
def allocate(raw,protection=0x20):
    address=k.VirtualAlloc(None,len(raw),0x3000,0x04);assert address
    buffers.append(address);c.memmove(address,raw,len(raw));old=c.c_ulong()
    assert k.VirtualProtect(address,len(raw),protection,c.byref(old))
    assert k.FlushInstructionCache(c.c_void_p(-1),address,len(raw))
    return address
def compile(terminal):
    # Model the proven prefix's ABI, with its terminal bit set/clear.
    prefix=bytes.fromhex('baffffffff')+bytes([0xf9 if terminal else 0xf8])
    body=error_policy(dict(prefix=prefix,invalid_request=dict(tag=99,pointer=16,length=24)),profile(3,'.125'))
    # Win64 stack home area + pack Duration's RAX/EDX after helper returns.
    wrapper=bytes.fromhex('4883ec28e80c00000048c1e0204809d04883c428c3')
    return c.CFUNCTYPE(c.c_ulonglong,c.c_void_p)(allocate(wrapper+body))
terminal=compile(True);native_retry=compile(False)
def record(message='',code=None):
    return json.dumps({'error':{'message':message,'code':code}}).encode()
positive=[record(AZURE),record(AZURE+' [trace_id=local]'),record('bad response status code 400','invalid_encrypted_content'),
          b'{"error": {"code" \r\n:\t "invalid_encrypted_content"}}']
negative=[b'',record('bad response status code 400'),record('invalid_encrypted_content','invalid_parameter'),
          record('example: "code":"invalid_encrypted_content"'),record(AZURE+'x'),
          record('', 'invalid_encrypted_content_extra'),record('example '+AZURE),b'{"message":"short"}',
          b'"code" : ',b'"code" : "invalid_encrypted_content']
# A real inaccessible page immediately follows each native String. Prefixes
# of positive strings test every truncation, including whitespace and quotes.
region=k.VirtualAlloc(None,8192,0x3000,0x04);assert region;buffers.append(region)
old=c.c_ulong();assert k.VirtualProtect(region+4096,4096,1,c.byref(old))
def invoke(raw,tag=99):
    start=region+4096-len(raw)
    c.memmove(start,raw,len(raw))
    error=(c.c_ulonglong*4)(tag,len(raw),start,len(raw))
    return terminal(c.addressof(error))&0xffffffff
try:
    for raw in positive:assert invoke(raw)==125000000,raw
    for raw in negative:assert invoke(raw)==0xffffffff,raw
    for raw in positive:
        for end in range(len(raw)+1):invoke(raw[:end])
    # Non-target variants must not dereference bogus String fields.
    invalid=(c.c_ulonglong*4)(100,0,1,0xffffffffffffffff)
    assert terminal(c.addressof(invalid))&0xffffffff==0xffffffff
    assert native_retry(c.addressof(invalid))&0xffffffff==125000000
finally:
    for address in buffers:assert k.VirtualFree(address,0,0x8000)
print('classifier guard-page checks passed')
'''
        result=subprocess.run([sys.executable,'-B','-X','utf8','-c',script],
                              cwd=Path(__file__).resolve().parents[1],capture_output=True,
                              text=True,encoding='utf-8',timeout=20,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
