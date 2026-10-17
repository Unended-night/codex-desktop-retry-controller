"""Locate a verified x64 instruction family by structure, never file offsets.

Recognized instructions, function boundaries, branch destinations, data-flow
offsets and model/SSE string references must agree. Behavioral verification is
a separate mandatory gate in Manager; this module alone never grants approval.
"""
import bisect
import copy
import hashlib
from pathlib import Path
import re
import struct
import sys
import threading


_analysis_lock = threading.Lock()
_analysis_key = None
_analysis_result = None


def _mapped_va(pe, base, offset):
    rva = pe.get_rva_from_offset(offset)
    if rva is None:
        raise ValueError('file offset is outside mapped PE sections')
    return base + rva


def _file_address_map(pe, length):
    """Map file offsets without repeatedly walking PE section metadata."""
    base = pe.OPTIONAL_HEADER.ImageBase
    regions = sorted((s.PointerToRawData,
                      min(length, s.PointerToRawData + s.SizeOfRawData),
                      base + s.VirtualAddress) for s in pe.sections if s.SizeOfRawData)
    headers = min(pe.OPTIONAL_HEADER.SizeOfHeaders, length)
    previous = headers
    for start, end, _ in regions:
        if start < previous or end <= start:
            raise ValueError('overlapping or invalid mapped PE sections')
        previous = end
    starts = [r[0] for r in regions]

    def address(offset):
        index = bisect.bisect_right(starts, offset) - 1
        if index >= 0:
            start, end, va = regions[index]
            if start <= offset < end:
                return va + offset - start
        if 0 <= offset < headers:
            return base + offset
        raise ValueError('file offset is outside mapped PE sections')

    return address


def locate(data, error):
    """Reuse successful analysis of identical bytes, never behavioral approval.

    Retain one small result rather than the executable or decoded functions.
    Every call hashes all input bytes; changed files and failures are reanalyzed.
    Callers receive independent results so parameter generation cannot poison it.
    """
    global _analysis_key, _analysis_result
    if not isinstance(data, bytes):
        data = bytes(data)
    key = hashlib.sha256(data).digest()
    with _analysis_lock:
        if key != _analysis_key:
            result = _locate(data, error)
            _analysis_result = copy.deepcopy(result)
            _analysis_key = key
        return copy.deepcopy(_analysis_result)


def _locate(data, error):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research/.deps'))
    try:
        import capstone
        import pefile
    except ImportError as exc:
        raise error('缺少随工具提供的 capstone/pefile 结构检测依赖，无法验证兼容性。') from exc
    try:
        pe = pefile.PE(data=data, fast_load=True)
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
            raise ValueError('requires Windows x64 PE')
        base = pe.OPTIONAL_HEADER.ImageBase
        # Map raw sections once. Call-graph queries otherwise ask pefile to
        # normalize every section for each possible relative-call byte.
        va = _file_address_map(pe, len(data))
        section = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.pdata')
        functions = list(struct.iter_unpack('<III', data[section.PointerToRawData:section.PointerToRawData+section.Misc_VirtualSize]))
        starts = [f[0] for f in functions]
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        decoded_index, decoded_result = None, None
        reference_results = {}
        def off(va):
            return pe.get_offset_from_rva(va-base)
        def function(offset):
            nonlocal decoded_index, decoded_result
            address=va(offset)-base
            index=bisect.bisect_right(starts,address)-1
            if index < 0: raise ValueError('missing function')
            a,z,_=functions[index]
            if not a<=address<z: raise ValueError('outside function')
            if index == decoded_index:
                return decoded_result
            instructions=list(cs.disasm(data[off(base+a):off(base+z-1)+1],base+a))
            if not instructions or instructions[-1].address+instructions[-1].size != base+z:
                raise ValueError('incomplete instruction decoding')
            decoded_index, decoded_result = index, ((base+a,base+z),instructions)
            return decoded_result
        def refs(instructions, needle):
            key = (instructions[0].address, needle)
            if key in reference_results:
                return reference_results[key]
            for i in instructions:
                for op in i.operands:
                    if op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base)=='rip':
                        try:
                            at=off(i.address+i.size+op.mem.disp)
                            if data[at:at+len(needle)]==needle:
                                reference_results[key] = True
                                return True
                        except (ValueError,pefile.PEFormatError): pass
            reference_results[key] = False
            return False
        def unique(pattern, start=0, end=None, label='instruction'):
            hits=list(re.finditer(pattern,data[start:end],re.S))
            if len(hits)!=1: raise ValueError(f'{label}: expected one pattern, found {len(hits)}')
            return start+hits[0].start()
        families = {
            'v2': rb'\x49\xb8\xf3\xec\x7f\xd6\x47\x00\x00\x00\x49\x0f\xa3\xc0\x0f\x83',
            'v3': rb'\x4c\x89\xf8\x48\xba\x00\x00\x00\x00\x00\x00\x00\x80\x48\x31\xd0\x4d\x85\xff\xba\x0d\x00\x00\x00\x48\x0f\x49\xc2\x48\xba\xe3\xd9\xff\xac\x8f\x00\x00\x00\x48\x0f\xa3\xc2\x73.',
        }
        candidates=[(name,m.start()+(28 if name=='v3' else 0))
                    for name,pat in families.items() for m in re.finditer(pat,data,re.S)]
        if not candidates:
            from .native_v4 import locate_outlined
            return locate_outlined(data, function, off, va, refs, cs)
        if len(candidates)!=1:
            raise ValueError(f'model error classifier: expected one pattern, found {len(candidates)}')
        family,classify=candidates[0]
        bounds, ins=function(classify)
        boundaries={i.address for i in ins}
        if not refs(ins,b'stream connection failed; waiting to retry'):
            raise ValueError('missing model retry string reference')
        if family=='v3':
            from .native_v3 import outer_sites
            s=outer_sites(data,classify,bounds,unique,off,va)
        else:
            policy=off(va(classify)+20+struct.unpack_from('<i',data,classify+16)[0])
            if not re.fullmatch(rb'\x8b\x82....\x3d\x00\xca\x9a\x3b\x75.\xe8....\x90\x81\xfa\x00\xca\x9a\x3b\x0f\x85....',data[policy:policy+31],re.S):
                raise ValueError('retry duration branch changed')
            resume=va(policy)+31+struct.unpack_from('<i',data,policy+27)[0]
            resume_off=off(resume)
            if not re.fullmatch(rb'\x49\x89\xf7\x48\x8b\xbd....\x48\x89\x87....\x89\x97....\x48\x8b\x87....\x8b\x8f....\x48\x89\x87....\x89\x8f....',data[resume_off:resume_off+49],re.S):
                raise ValueError('retry duration stores changed')
            deadline=resume_off+30
            server_nanos=struct.unpack_from('<I',data,policy+2)[0]
            if (server_nanos != struct.unpack_from('<I',data,deadline+2)[0]
                    or server_nanos != struct.unpack_from('<I',data,resume_off+26)[0]+8):
                raise ValueError('server deadline fields disagree')
            connection=resume_off+49
            count_site=unique(rb'\x48\x8b\x87....\x48\x8b\x08\x48\x3b\x8f....\x0f\x83....\x4c\x8b\x8f....\x4c\x89\x08\x48\x8b\x87....\x48\x8b\x8f....\x8b\x97....',off(bounds[0]),off(bounds[1]-1)+1,label='outer budget')
            budget=struct.unpack_from('<I',data,count_site+13)[0]
            if budget!=struct.unpack_from('<I',data,count_site+36)[0]:
                raise ValueError('budget load does not match comparison')
            if (struct.unpack_from('<I',data,resume_off+13)[0] != struct.unpack_from('<I',data,count_site+43)[0]
                    or struct.unpack_from('<I',data,resume_off+19)[0] != struct.unpack_from('<I',data,count_site+49)[0]):
                raise ValueError('duration loads do not match stores')
            if data[connection:connection+3] != b'\x48\x8b\x85': raise ValueError('connection branch changed')
            s=dict(policy=policy,policy_size=31,resume=resume,deadline=deadline,deadline_size=6,
                   connection=connection,connection_size=7,count_site=count_site,budget=budget,
                   policy_prefix=b'\x48\xc7\x82',classify_prefix=b'\x49\xb8',mask=0x47d67fecf3,rate_bit=28)
        ranges=[(classify,10),(s['policy'],s['policy_size']),
                (s['deadline'],s['deadline_size']),(s['connection'],s['connection_size'])]
        for start,size in ranges:
            if va(start) not in boundaries or va(start+size) not in boundaries:
                raise ValueError('patch splits an instruction')
        if s['resume'] not in boundaries or va(s['count_site']) not in boundaries:
            raise ValueError('branch outside retry function')
        # No other original branch may land inside an overwritten range.
        for i in ins:
            if i.group(capstone.CS_GRP_JUMP) and i.operands[0].type==capstone.CS_OP_IMM:
                dest=i.operands[0].imm
                for start,size in ranges:
                    if va(start)<dest<va(start+size): raise ValueError('branch into patch interior')
        http_candidates=[]
        pattern=rb'\x4c\x3b\xbb....\x0f\x83....\x48\x89\xf1\x48\x83\xe9\x04\xb8\x01\x00\x00\x00\x48\x0f\x43\xc1\x8d\x48\xfd\x83\xf9\x03'
        for hit in re.finditer(pattern,data,re.S):
            http_bounds,http_ins=function(hit.start())
            if refs(http_ins,b'text/event-stream') and refs(http_ins,b'httprequeststreamsamplingremote_compaction_v2codex.retry'):
                http_boundaries={i.address for i in http_ins}
                target=va(hit.start())+13+struct.unpack_from('<i',data,hit.start()+9)[0]
                if va(hit.start()) not in http_boundaries or target not in http_boundaries:
                    raise ValueError('HTTP instruction alignment')
                if not http_bounds[0]<=target<http_bounds[1]: raise ValueError('HTTP branch outside function')
                http_candidates.append(hit.start())
        if len(http_candidates)!=1: raise ValueError('model HTTP budget not unique')
        return dict(s,family='responses-sampling-x64-'+family,classify=classify,
                    policy_va=va(s['policy']),connection_va=va(s['connection']),
                    bounded=va(s['count_site']),http=http_candidates[0])
    except (ValueError,IndexError,KeyError,StopIteration,struct.error,pefile.PEFormatError) as exc:
        raise error(f'当前引擎不符合已验证的重试结构：{exc}。未修改程序。') from exc


def replacements(data,p,error):
    s=locate(data,error)
    if s['family']=='responses-sampling-x64-outlined':
        from .native_v4 import replacements as outlined_replacements
        return outlined_replacements(s,p)
    policy=s['policy_prefix']+struct.pack('<I',s['budget'])+struct.pack('<I',p['max_retries'])
    policy+=b'\xb8'+struct.pack('<I',p['interval_ms']//1000)+b'\xba'+struct.pack('<I',p['interval_ms']%1000*1000000)
    policy+=b'\xe9'+struct.pack('<i',s['resume']-(s['policy_va']+len(policy)+5))
    return [(s['classify'],10,s['classify_prefix']+struct.pack('<Q',s['mask'] & ~(1<<s['rate_bit'])),'generic_429_retry'),
            (s['policy'],s['policy_size'],policy,'model_outer_policy'),
            (s['deadline'],s['deadline_size'],b'\xb9'+struct.pack('<I',1000000000),'ignore_server_deadline'),
            (s['connection'],s['connection_size'],b'\xe9'+struct.pack('<i',s['bounded']-s['connection_va']-5),'bounded_connection_retry'),
            (s['http'],7,bytes.fromhex('4d39ff'),'model_http_budget')]
