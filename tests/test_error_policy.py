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
import struct
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
def compile_returned(nanos):
    body=error_policy(dict(returned_classifier={'deadline_only_tags':[37]},none_value=0xffffffff,
                          error_reload=bytes.fromhex('4889c9'),
                          invalid_request=dict(tag=99,tag_offset=0,pointer=16,length=24)),profile(3,'.125'))
    # Return the helper's ZF in bit 32 and EDX in bits 0..31. The patched
    # caller retains its JE/JNE, so a correct Duration with stale flags fails.
    after=bytes.fromhex('0f94c10fb6c948c1e12089d04809c84883c428c3')
    wrapper=bytes.fromhex('4883ec28ba')+struct.pack('<I',nanos)
    wrapper+=b'\xe8'+struct.pack('<i',len(after))+after
    return c.CFUNCTYPE(c.c_ulonglong,c.c_void_p)(allocate(wrapper+body))
returned=compile_returned(0xffffffff)
returned_retry=compile_returned(1234)

def compile_returned_jump(nanos):
    # Short native CMP+Jcc sites jump to a leaf instead of adding a CALL with
    # no native home space. Exercise both direct native exits in a real child.
    address=k.VirtualAlloc(None,16384,0x3000,0x04);assert address;buffers.append(address)
    body=error_policy(dict(returned_classifier={'deadline_only_tags':[37]},none_value=0xffffffff,
                          error_reload=bytes.fromhex('4889c9'),policy_present=address+32,policy_absent=address+48,
                          invalid_request=dict(tag=99,tag_offset=0,pointer=16,length=24)),
                      profile(3,'.125'),address=address+80)
    start=bytes.fromhex('ba')+struct.pack('<I',nanos)+bytes.fromhex('e9')+struct.pack('<i',70)
    present=bytes.fromhex('89d0c3')
    absent=bytes.fromhex('48b800000000010000004809d0c3')
    raw=start.ljust(32,b'\xcc')+present
    raw=raw.ljust(48,b'\xcc')+absent
    raw=raw.ljust(80,b'\xcc')+body
    c.memmove(address,raw,len(raw));old=c.c_ulong()
    assert k.VirtualProtect(address,16384,0x20,c.byref(old))
    assert k.FlushInstructionCache(c.c_void_p(-1),address,len(raw))
    return c.CFUNCTYPE(c.c_ulonglong,c.c_void_p)(address)
jump_returned=compile_returned_jump(0xffffffff)
jump_retry=compile_returned_jump(1234)
def record(message='',code=None):
    return json.dumps({'error':{'message':message,'code':code}}).encode()
positive=[record(AZURE),record(AZURE+' [trace_id=local]'),record('bad response status code 400','invalid_encrypted_content'),
          b'{"error": {"code" \r\n:\t "invalid_encrypted_content"}}']
# Keep the reported gateway response independent of the emitter's constants.
reported=('OpenAI Responses bad request: The requested item was created under a different *** OpenAI resource. '
          'Use the same resource that created the item to access it. [hub-] [trace_id=local]')
wrapped='OpenAI Responses bad request: '
masked=AZURE.replace('Azure','***')
positive += [record(reported),record(masked),record(wrapped+AZURE),record(wrapped+masked)]
negative=[b'',record('bad response status code 400'),record('invalid_encrypted_content','invalid_parameter'),
          record('example: "code":"invalid_encrypted_content"'),record(AZURE+'x'),
          record('', 'invalid_encrypted_content_extra'),record('example '+AZURE),b'{"message":"short"}',
          b'"code" : ',b'"code" : "invalid_encrypted_content']
negative += [record(wrapped+'bad response status code 400'),record('example '+masked),
             record('example '+reported),record(wrapped+'example '+masked),
             record(masked.replace('***','****')),record(masked.replace('***','***x')),
             record(wrapped+masked+'x'),record(wrapped+masked.replace('same resource','another resource')),
             record(wrapped+wrapped+masked),record('example: "message":"'+masked+'"')]
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
    for terminal in (terminal,returned,jump_returned):
        for raw in positive:assert invoke(raw)==125000000,raw
        for raw in negative:assert invoke(raw)==0xffffffff,raw
        for raw in positive:
            for end in range(len(raw)+1):invoke(raw[:end])
    # Non-target variants must not dereference bogus String fields.
    invalid=(c.c_ulonglong*4)(100,0,1,0xffffffffffffffff)
    assert terminal(c.addressof(invalid))&0xffffffff==0xffffffff
    assert native_retry(c.addressof(invalid))&0xffffffff==125000000
    assert returned(c.addressof(invalid))==0x1ffffffff  # None and ZF=1.
    assert returned_retry(c.addressof(invalid))==125000000  # Some and ZF=0.
    assert jump_returned(c.addressof(invalid))==0x1ffffffff
    assert jump_retry(c.addressof(invalid))==125000000
    invalid[0]=37
    assert returned(c.addressof(invalid))==125000000  # Deadline-only native arm.
    assert jump_returned(c.addressof(invalid))==125000000
finally:
    for address in buffers:assert k.VirtualFree(address,0,0x8000)
print('classifier guard-page checks passed')
'''
        result=subprocess.run([sys.executable,'-B','-X','utf8','-c',script],
                              cwd=Path(__file__).resolve().parents[1],capture_output=True,
                              text=True,encoding='utf-8',timeout=20,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
