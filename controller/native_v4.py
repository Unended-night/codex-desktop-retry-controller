"""Outlined retry policy: derive fields and branches from decoded instructions.

No version, file address, state displacement or terminal mask is hard-coded.
Keep the engine's classifier and replace its delay at this call site only.
The shared helper and its Windows unwind information remain untouched.
Every new build still requires the loopback behavior suite before publication.
"""
import re
import struct

SENTINEL = 1_000_000_000


def reg(op, name):
    return op.type == 1 and op.reg == name


def mem(op, base=None, disp=None):
    return (op.type == 3 and not op.mem.index
            and (base is None or op.mem.base == base)
            and (disp is None or op.mem.disp == disp))


def only(values, label):
    if len(values) != 1:
        raise ValueError(f'outlined {label}: expected one, found {len(values)}')
    return values[0]


def classifier(ins):
    """Return a relocatable prefix ending at the native terminal-mask BT."""
    import capstone.x86_const as x
    # This helper uses the Windows x64 RCX(error), RDX(attempt) ABI.
    if ins[0].mnemonic != 'sub' or ins[0].op_str.split(',')[0] != 'rsp':
        raise ValueError('outlined helper prologue')
    end = next((n for n, i in enumerate(ins[:20]) if i.mnemonic == 'bt'), None)
    if end is None:
        raise ValueError('outlined helper classifier missing')
    prefix = ins[1:end+1]
    volatile = {x.X86_REG_RAX,x.X86_REG_EAX,x.X86_REG_RCX,x.X86_REG_ECX,
                x.X86_REG_RDX,x.X86_REG_EDX,x.X86_REG_R8,x.X86_REG_R8D,
                x.X86_REG_R9,x.X86_REG_R9D,x.X86_REG_R10,x.X86_REG_R10D,
                x.X86_REG_R11,x.X86_REG_R11D}
    for i in prefix:
        if i.mnemonic not in ('mov','movabs','xor','test','cmovs','cmovns','bt'):
            raise ValueError('non-relocatable classifier instruction')
        for op in i.operands:
            if op.type == 3 and not mem(op,x.X86_REG_RCX,0):
                raise ValueError('classifier reads outside error tag')
        if any(r not in volatile and r != x.X86_REG_EFLAGS for r in i.regs_access()[1]):
            raise ValueError('classifier modifies nonvolatile register')
    constants = {op.imm & ((1<<64)-1) for i in prefix for op in i.operands if op.type == 2}
    if not {1<<63,13,SENTINEL} <= constants:
        raise ValueError('tag normalization or duration sentinel missing')
    if not any(i.mnemonic in ('cmovs','cmovns') for i in prefix):
        raise ValueError('tag normalization missing')
    if not any(i.mnemonic=='mov' and reg(i.operands[0],x.X86_REG_EDX)
               and i.operands[1].type==2 and i.operands[1].imm==SENTINEL for i in prefix):
        raise ValueError('terminal result is not None duration')
    jump, epilogue, ret = ins[end+1:end+4]
    if (jump.mnemonic != 'jae' or jump.operands[0].type != 2
            or epilogue.mnemonic != 'add' or epilogue.op_str != ins[0].op_str
            or ret.mnemonic != 'ret' or jump.operands[0].imm != ret.address+ret.size):
        raise ValueError('terminal classifier control flow changed')
    return b''.join(bytes(i.bytes) for i in prefix)


def safe_ranges(ins, ranges, data, off):
    """Check boundaries, direct incoming edges and local relative jump tables."""
    boundaries = {i.address for i in ins} | {ins[-1].address+ins[-1].size}
    for a,z in ranges:
        if a not in boundaries or z not in boundaries:
            raise ValueError('outlined patch splits an instruction')
    def check(source, target):
        for a,z in ranges:
            if not a <= source < z and a < target < z:
                raise ValueError('branch into outlined patch interior')
    for n,i in enumerate(ins):
        if (i.mnemonic.startswith('j') or i.mnemonic=='call') and i.operands[0].type==2:
            check(i.address,i.operands[0].imm)
        if i.mnemonic=='lea' and len(i.operands)==2 and i.operands[1].type==3:
            op=i.operands[1]
            if i.reg_name(op.mem.base)!='rip':
                continue
            following=ins[n+1:n+5]
            if not any(j.mnemonic=='movsxd' for j in following):
                continue
            table=i.address+i.size+op.mem.disp
            for index in range(256):
                try:
                    target=table+struct.unpack_from('<i',data,off(table)+index*4)[0]
                except (ValueError,struct.error):
                    break
                if target not in boundaries:
                    break
                check(i.address,target)


def outer(ins, call_index, helper, data, off):
    import capstone.x86_const as x
    call=ins[call_index]
    before=ins[call_index-2]
    # An outlined standalone sampling loop saves the next attempt in its state
    # immediately before passing the error. Inlined wrappers use stack spills.
    if not (before.mnemonic=='mov' and mem(before.operands[0])
            and reg(before.operands[1],x.X86_REG_RDX)):
        raise ValueError('missing next-attempt state store')
    state=before.operands[0].mem.base
    if state in (x.X86_REG_RBP,x.X86_REG_RSP):
        raise ValueError('stack spill is not sampling state')
    next_attempt=before.operands[0].mem.disp
    n=call_index+1
    while ins[n].mnemonic=='nop': n+=1
    compare,jump=ins[n:n+2]
    if not (compare.mnemonic=='cmp' and reg(compare.operands[0],x.X86_REG_EDX)
            and compare.operands[1].type==2 and compare.operands[1].imm==SENTINEL
            and jump.mnemonic=='jne' and jump.operands[0].type==2):
        raise ValueError('duration option branch changed')
    addresses={i.address:k for k,i in enumerate(ins)}
    resume=addresses[jump.operands[0].imm]
    reload=ins[resume]
    if not (reload.mnemonic=='mov' and reload.operands[0].type==1
            and mem(reload.operands[1],x.X86_REG_RBP)):
        raise ValueError('state reload changed')
    resumed=reload.operands[0].reg
    slot=reload.operands[1].mem.disp
    if not any(i.mnemonic=='mov' and reg(i.operands[0],state)
               and mem(i.operands[1],x.X86_REG_RBP,slot) for i in ins[max(0,call_index-30):call_index]):
        raise ValueError('state reload disagrees')
    stores=ins[resume+1:resume+7]
    ssec,snano,lsec,lnano,dsec,dnano=stores
    for i,register,load in [(ssec,x.X86_REG_RAX,False),(snano,x.X86_REG_EDX,False),
                            (lsec,x.X86_REG_RAX,True),(lnano,x.X86_REG_ECX,True),
                            (dsec,x.X86_REG_RAX,False),(dnano,x.X86_REG_ECX,False)]:
        a,b=i.operands if not load else reversed(i.operands)
        if i.mnemonic!='mov' or not mem(a,resumed) or not reg(b,register):
            raise ValueError('duration field flow changed')
    if any(a.operands[index].mem.disp+8 != b.operands[index].mem.disp
           for a,b,index in [(ssec,snano,0),(lsec,lnano,1),(dsec,dnano,0)]):
        raise ValueError('duration field pair disagrees')
    connection=ins[resume+7]
    if not (connection.mnemonic=='mov' and reg(connection.operands[0],x.X86_REG_RAX)
            and mem(connection.operands[1],resumed)):
        raise ValueError('connection path changed')
    counts=[]
    for k in range(resume+8,len(ins)-15):
        a,b,c,d,e=ins[k:k+5]
        if (a.mnemonic=='mov' and reg(a.operands[0],x.X86_REG_RAX) and mem(a.operands[1],resumed)
                and b.mnemonic=='mov' and reg(b.operands[0],x.X86_REG_RCX) and mem(b.operands[1],x.X86_REG_RAX,0)
                and c.mnemonic=='cmp' and reg(c.operands[0],x.X86_REG_RCX) and mem(c.operands[1],resumed)
                and d.mnemonic=='jae' and d.operands[0].type==2
                and e.mnemonic=='mov' and mem(e.operands[1],resumed,next_attempt)):
            counts.append(k)
    k=only(counts,'bounded budget')
    bounded=ins[k]
    budget=ins[k+2].operands[1].mem.disp
    write=ins[k+5]
    if not (write.mnemonic=='mov' and mem(write.operands[0],x.X86_REG_RAX,0)
            and write.operands[1].type==1 and ins[k+4].operands[0].type==1
            and write.operands[1].reg==ins[k+4].operands[0].reg):
        raise ValueError('attempt counter write disagrees')
    tail=ins[k+5:k+18]
    for field in [budget,connection.operands[1].mem.disp,ssec.operands[0].mem.disp,snano.operands[0].mem.disp]:
        if not any(i.mnemonic=='mov' and mem(i.operands[1],resumed,field) for i in tail):
            raise ValueError('bounded path fields disagree')
    # Override the source of the unique state initialization, preserving the
    # existing store and register width. No extra stack or nonvolatile writes.
    initial=[]
    for j,i in enumerate(ins[:call_index]):
        if i.mnemonic=='mov' and mem(i.operands[0],state,budget) and reg(i.operands[1],x.X86_REG_RAX):
            for source in ins[max(0,j-2):j]:
                if source.mnemonic=='mov' and reg(source.operands[0],x.X86_REG_RAX) and mem(source.operands[1],state):
                    initial.append(source)
    init=only(initial,'budget initialization')
    if init.size<5 or lnano.size<5 or call.size!=5:
        raise ValueError('insufficient instruction space')
    if not 100 <= bounded.address-connection.address <= 1024:
        raise ValueError('unexpected connection block size')
    if not any(i.mnemonic=='je' and i.operands[0].type==2 and i.operands[0].imm==bounded.address
               for i in ins[resume+7:k]):
        raise ValueError('missing bounded connection edge')
    ranges=[(call.address,call.address+call.size),(init.address,init.address+init.size),
            (lnano.address,lnano.address+lnano.size),(connection.address,bounded.address)]
    safe_ranges(ins,ranges,data,off)
    return dict(call=call.address,continuation=call.address+call.size,
                init=init.address,init_size=init.size,deadline=lnano.address,deadline_size=lnano.size,
                connection=connection.address,bounded=bounded.address,prefix=helper)


def locate_outlined(data, function, off, va, refs, cs):
    candidates=[]
    # A cheap scan narrows decoding to calls returning an Option<Duration>.
    pattern=rb'\xe8....\x90?\x81\xfa\x00\xca\x9a\x3b(?:\x75.|\x0f\x85....)'
    for match in re.finditer(pattern,data,re.S):
        try:
            _,ins=function(match.start())
            n=next(n for n,i in enumerate(ins) if i.address==va(match.start()) and i.mnemonic=='call')
            if not refs(ins,b'stream connection failed; waiting to retry'): continue
            target=ins[n].operands[0].imm
            bounds,helper=function(off(target))
            if target!=bounds[0]: continue
            candidates.append(outer(ins,n,classifier(helper),data,off))
        except (ValueError,KeyError,IndexError,StopIteration):
            continue
    result=only(candidates,'sampling policy')
    http=[]
    pattern=rb'\x4c\x3b\xbb....\x0f\x83....\x48\x89\xf1\x48\x83\xe9\x04\xb8\x01\x00\x00\x00\x48\x0f\x43\xc1\x8d\x48\xfd\x83\xf9\x03'
    for match in re.finditer(pattern,data,re.S):
        bounds,ins=function(match.start())
        if refs(ins,b'text/event-stream') and refs(ins,b'httprequeststreamsampling'):
            address=va(match.start())
            target=address+13+struct.unpack_from('<i',data,match.start()+9)[0]
            if target not in {i.address for i in ins} or not bounds[0]<=target<bounds[1]:
                raise ValueError('HTTP branch outside model function')
            safe_ranges(ins,[(address,address+7)],data,off)
            http.append(address)
    result['http']=only(http,'model HTTP budget')
    result['family']='responses-sampling-x64-outlined'
    result['offsets']={k:off(result[k]) for k in ('call','init','deadline','connection','http')}
    return result


def jmp(source,target,opcode=b'\xe9'):
    return opcode+struct.pack('<i',target-source-len(opcode)-4)


def replacements(s,p):
    cave=s['connection']
    code=jmp(cave,s['bounded'])
    code+=s['prefix']
    code+=jmp(cave+len(code),s['continuation'],b'\x0f\x82')  # native terminal bit: return None
    code+=b'\xb8'+struct.pack('<I',p['interval_ms']//1000)+b'\xba'+struct.pack('<I',p['interval_ms']%1000*1_000_000)
    code+=jmp(cave+len(code),s['continuation'])
    offsets=s['offsets']
    return [(offsets['call'],5,jmp(s['call'],cave+5),'model_outer_policy'),
            (offsets['connection'],s['bounded']-cave,code,'bounded_connection_and_native_classifier'),
            (offsets['init'],s['init_size'],b'\xb8'+struct.pack('<I',p['max_retries']),'model_outer_budget'),
            (offsets['deadline'],s['deadline_size'],b'\xb9'+struct.pack('<I',SENTINEL),'ignore_server_deadline'),
            (offsets['http'],7,bytes.fromhex('4d39ff'),'model_http_budget')]
