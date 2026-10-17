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
    return (op.type == 3 and not op.mem.segment and not op.mem.index
            and (base is None or op.mem.base == base)
            and (disp is None or op.mem.disp == disp))


def only(values, label):
    if len(values) != 1:
        raise ValueError(f'outlined {label}: expected one, found {len(values)}')
    return values[0]


def classifier_flow(prefix):
    """Prove BT uses the normalized error tag and returns the None sentinel.

    Track volatile register aliases so enum numbering and register allocation
    can change without accepting an unrelated constant or stale flag source.
    """
    registers = {'rcx': ('error-pointer',), 'rdx': ('attempt',)}
    sign = None

    def name(i, op):
        if op.type != 1 or op.size not in (4, 8):
            raise ValueError('classifier requires a full volatile register')
        value = i.reg_name(op.reg)
        aliases = {'eax':'rax', 'ecx':'rcx', 'edx':'rdx'}
        value = aliases.get(value, value.removesuffix('d'))
        if value not in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
            raise ValueError('classifier modifies nonvolatile register')
        return value

    def read(i, op):
        if op.type == 2:
            return ('constant', op.imm & ((1 << (op.size * 8)) - 1))
        if op.type == 3:
            if (op.size != 8 or op.mem.segment or i.reg_name(op.mem.base) != 'rcx'
                    or op.mem.index or op.mem.disp or registers.get('rcx') != ('error-pointer',)):
                raise ValueError('classifier reads outside error tag')
            return ('tag',)
        value = registers.get(name(i, op))
        if value is None:
            raise ValueError('classifier reads undefined register')
        if op.size == 4:
            return (('constant', value[1] & 0xffffffff) if value[0] == 'constant'
                    else ('low32', value))
        return value

    for i in prefix:
        a, b = i.operands
        if i.mnemonic == 'bt':
            mask, index = read(i, a), read(i, b)
            if (a.size != 8 or b.size != 8 or mask[0] != 'constant'
                    or index[:3] != ('select-sign', ('tag',), ('untagged',))
                    or index[3][0] != 'constant' or not 0 <= index[3][1] < 64):
                raise ValueError('terminal mask is not indexed by normalized error tag')
            if registers.get('rdx') != ('constant', SENTINEL):
                raise ValueError('terminal result is not None duration')
            continue
        if i.mnemonic == 'test':
            left, right = read(i, a), read(i, b)
            sign = left if a.size == b.size == 8 and left == right else None
            continue
        target = name(i, a)  # Memory writes and partial register writes are refused.
        value = read(i, b)
        if i.mnemonic == 'xor':
            left = read(i, a)
            if a.size == b.size == 8 and {left, value} == {('tag',), ('constant', 1 << 63)}:
                value = ('untagged',)
            elif left == value:
                value = ('constant', 0)
            else:
                raise ValueError('unrecognized classifier normalization')
            sign = value
        elif i.mnemonic in ('cmovs', 'cmovns'):
            if a.size != 8 or b.size != 8 or sign is None:
                raise ValueError('tag normalization has no matching sign test')
            previous = read(i, a)
            negative, positive = ((value, previous) if i.mnemonic == 'cmovs' else (previous, value))
            value = ('select-sign', sign, negative, positive)
        elif i.mnemonic not in ('mov', 'movabs'):
            raise ValueError('non-relocatable classifier instruction')
        registers[target] = value


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
    classifier_flow(prefix)
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


def http_budget(ins, index, data, off):
    """Prove the inner HTTP gate from counter, state and error-tag flow.

    Register allocation and state displacements are derived from operands. The
    cheap byte scan in locate_outlined is only a candidate finder.
    """
    import capstone.x86_const as x
    if index < 1 or index + 9 > len(ins):
        raise ValueError('HTTP gate is incomplete')
    load, compare, exhausted, copy, subtract, default, select, adjust, limit, reject = ins[index-1:index+9]
    # Include every subregister: a write to EDI/DI/DIL also destroys RDI's
    # counter value, even though Capstone reports a different register ID.
    names = [('RAX','EAX','AX','AL','AH'), ('RBX','EBX','BX','BL','BH'),
             ('RCX','ECX','CX','CL','CH'), ('RDX','EDX','DX','DL','DH'),
             ('RSI','ESI','SI','SIL'), ('RDI','EDI','DI','DIL'),
             ('RBP','EBP','BP','BPL'), ('RSP','ESP','SP','SPL')]
    names += [(f'R{n}',f'R{n}D',f'R{n}W',f'R{n}B') for n in range(8,16)]
    families = {getattr(x,'X86_REG_'+group[0]):
                tuple(getattr(x,'X86_REG_'+name) for name in group) for group in names}
    def writes(i, register):
        return bool(set(i.regs_access()[1]).intersection(families[register]))
    def overlaps(a, b):
        return a < b + 8 and b < a + 8
    nonvolatile = {x.X86_REG_RBX, x.X86_REG_RSI, x.X86_REG_RDI,
                   x.X86_REG_R12, x.X86_REG_R13, x.X86_REG_R14, x.X86_REG_R15}
    if not (load.mnemonic == 'mov' and load.operands[0].type == 1
            and load.operands[0].size == 8 and mem(load.operands[1])
            and load.operands[1].size == 8):
        raise ValueError('HTTP attempt load changed')
    counter, state = load.operands[0].reg, load.operands[1].mem.base
    attempt = load.operands[1].mem.disp
    if counter not in nonvolatile or state not in nonvolatile or counter == state:
        raise ValueError('HTTP state/counter must survive calls')
    if not (compare.mnemonic == 'cmp' and reg(compare.operands[0], counter)
            and compare.operands[0].size == 8 and mem(compare.operands[1], state)
            and compare.operands[1].size == 8 and not overlaps(compare.operands[1].mem.disp, attempt)
            and exhausted.mnemonic == 'jae' and exhausted.operands[0].type == 2):
        raise ValueError('HTTP budget fields disagree')
    boundaries = {i.address for i in ins}
    if exhausted.operands[0].imm not in boundaries or exhausted.operands[0].imm <= reject.address:
        raise ValueError('HTTP exhausted branch outside error path')

    # Preserve the native tag classification after the budget gate. Its SUB
    # flags must feed CMOVAE directly; MOV does not modify those flags.
    if not (copy.mnemonic == 'mov' and all(o.type == 1 and o.size == 8 for o in copy.operands)
            and subtract.mnemonic == 'sub' and reg(subtract.operands[0], copy.operands[0].reg)
            and subtract.operands[0].size == 8 and subtract.operands[1].type == 2
            and subtract.operands[1].imm == 4
            and default.mnemonic == 'mov' and default.operands[0].type == 1
            and default.operands[0].size == 4 and default.operands[1].type == 2
            and default.operands[1].imm == 1
            and select.mnemonic == 'cmovae' and all(o.type == 1 and o.size == 8 for o in select.operands)
            and reg(select.operands[1], copy.operands[0].reg)):
        raise ValueError('HTTP error normalization changed')
    # Capstone supplies the architectural 32-bit alias without relying on a
    # register's spelling (including esi/edi and extended register names).
    aliases = {register: group[1] for register,group in families.items()}
    selected = select.operands[0].reg
    if not (aliases.get(selected) == default.operands[0].reg
            and selected != copy.operands[0].reg
            and adjust.mnemonic == 'lea' and adjust.operands[0].type == 1
            and adjust.operands[0].size == 4 and mem(adjust.operands[1], selected, -3)
            and limit.mnemonic == 'cmp' and reg(limit.operands[0], adjust.operands[0].reg)
            and limit.operands[0].size == 4 and limit.operands[1].type == 2
            and limit.operands[1].imm == 3
            and reject.mnemonic == 'jae' and reject.operands[0].type == 2
            and reject.operands[0].imm in boundaries and reject.operands[0].imm > reject.address):
        raise ValueError('HTTP error range changed')
    if any(writes(i, state) or writes(i, counter) for i in ins[index+2:index+9]):
        raise ValueError('HTTP normalization overwrites retry state/counter')

    # The tag must come from this same state, directly or via LEA + load.
    tag = copy.operands[1].reg
    previous = ins[max(0,index-7):index-1]
    if tag not in families or tag in (state, counter):
        raise ValueError('HTTP error tag aliases retry state/counter')
    source = next((n for n in range(len(previous)-1,-1,-1)
                   if writes(previous[n],tag)), None)
    if source is None:
        raise ValueError('HTTP error tag source missing')
    tagload = previous[source]
    if not (tagload.mnemonic == 'mov' and reg(tagload.operands[0],tag)
            and tagload.operands[0].size == 8 and mem(tagload.operands[1])
            and tagload.operands[1].size == 8):
        raise ValueError('HTTP error tag source changed')
    field = tagload.operands[1]
    tag_field = field.mem.disp
    origin = source
    if field.mem.base != state:
        pointer = previous[source-1] if source else None
        if not (pointer and pointer.mnemonic == 'lea' and reg(pointer.operands[0],field.mem.base)
                and pointer.operands[0].size == 8
                and mem(pointer.operands[1],state) and field.mem.disp == 0):
            raise ValueError('HTTP error tag is not from retry state')
        tag_field = pointer.operands[1].mem.disp
        origin -= 1
    if any(overlaps(tag_field, f) for f in (attempt,compare.operands[1].mem.disp)):
        raise ValueError('HTTP tag overlaps retry budget/attempt')
    if any(writes(i,state) for i in previous[origin:]):
        raise ValueError('HTTP retry state overwritten')
    # Volatile tags cannot survive a call; the retry state is nonvolatile.
    if any(i.mnemonic == 'call' for i in previous[source+1:]) and tag not in nonvolatile:
        raise ValueError('HTTP error tag clobbered by call')

    # On fallthrough the same counter is incremented and persisted for the
    # delay calculation. Calls may occur, but cannot clobber these registers.
    tail = ins[index+9:index+41]
    increment = next((n for n,i in enumerate(tail) if writes(i,counter)), None)
    if increment is None:
        raise ValueError('HTTP next-attempt increment missing')
    if any(i.mnemonic in ('jmp','ret','retf','int3','ud2') for i in tail[:increment]):
        raise ValueError('HTTP fallthrough does not reach next attempt')
    inc = tail[increment]
    store = tail[increment+1] if increment+1 < len(tail) else None
    if not (inc.mnemonic == 'inc' and reg(inc.operands[0],counter)
            and inc.operands[0].size == 8 and store and store.mnemonic == 'mov'
            and mem(store.operands[0],state) and store.operands[0].size == 8
            and reg(store.operands[1],counter)
            and not any(overlaps(store.operands[0].mem.disp,f)
                        for f in (attempt,compare.operands[1].mem.disp,tag_field))
            and not any(writes(i,state) for i in tail[:increment+1])):
        raise ValueError('HTTP next-attempt state disagrees')
    safe_ranges(ins,[(compare.address,compare.address+compare.size)],data,off)
    return dict(http=compare.address,http_size=compare.size)


def responses_transport(data, entry, function, off, va, refs):
    """Require Responses callers, allowing one outlined instrumentation layer.

    Newer builds outline HTTP retry separately from sampling telemetry. The
    retry helper must have a direct model caller. An extra wrapper is accepted
    only when that model caller also calls it, and all its decoded callers
    build Responses requests. Unknown callers, tail calls and address-taking
    fail closed. This bounded call graph supplements mandatory behavior tests;
    it is not a general whole-program indirect-call analysis.
    """
    def model(ins):
        return refs(ins,b'/responses') and refs(ins,b'$failed to encode responses request: ')

    def callers(target):
        if struct.pack('<Q',target) in data:
            raise ValueError('HTTP transport has an indirect function pointer')
        result=[]
        # Include address-taking LEAs and tail jumps so they cannot silently
        # disappear from the call graph. File offsets need not share a section.
        pattern=rb'[\xe8\xe9]|[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'
        for match in re.finditer(pattern,data):
            at=match.start()
            size=5 if len(match[0])==1 else 7
            if at+size>len(data):
                continue
            try:
                address=va(at)
                if address+size+struct.unpack_from('<i',data,at+size-4)[0]!=target:
                    continue
                bounds,ins=function(at)
                call=next(i for i in ins if i.address==address)
            except (ValueError,IndexError,KeyError,StopIteration):
                continue
            if call.mnemonic=='lea' and call.size==size:
                raise ValueError('HTTP transport address is taken')
            if (call.mnemonic in ('call','jmp') and call.operands[0].type==2
                    and call.operands[0].imm==target):
                if call.mnemonic!='call':
                    raise ValueError('HTTP transport has an unproven tail caller')
                result.append((bounds[0],call.address,ins))
        if not result:
            raise ValueError('HTTP transport has no decoded callers')
        return result

    incoming=callers(entry)
    direct=[c for c in incoming if model(c[2])]
    # A unique direct model function anchors any instrumentation wrapper.
    root=only(sorted({c[0] for c in direct}),'Responses HTTP model caller')
    for wrapper,_,ins in incoming:
        if wrapper==root:
            continue
        parents=callers(wrapper)
        if (wrapper==entry or not any(p[0]==root for p in parents)
                or any(not model(p[2]) or p[0] in (entry,wrapper) for p in parents)):
            raise ValueError('HTTP wrapper has an unproven Responses caller')
    return direct[0][1]


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
    outlined_http=[]
    pattern=rb'[\x48-\x4f]\x83[\xe8-\xef]\x04[\x40-\x41]?[\xb8-\xbf]\x01\x00\x00\x00[\x48-\x4f]\x0f\x43[\xc0-\xff]'
    for match in re.finditer(pattern,data,re.S):
        try:
            bounds,ins=function(match.start())
            legacy=refs(ins,b'httprequeststreamsampling')
            outlined=refs(ins,b'requestcodex.retry')
            if not (refs(ins,b'text/event-stream') and (legacy or outlined)):
                continue
            n=next(n for n,i in enumerate(ins) if i.address==va(match.start()))
            if n<4: continue
            site=http_budget(ins,n-3,data,off)
            if outlined:
                outlined_http.append((bounds[0],site))
            else:
                http.append(site)
        except (ValueError,KeyError,IndexError,StopIteration):
            continue
    if outlined_http:
        entry,site=only(outlined_http,'outlined model HTTP budget')
        responses_transport(data,entry,function,off,va,refs)
        result.update(site)
    else:
        result.update(only(http,'model HTTP budget'))
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
            (offsets['http'],s.get('http_size',7),bytes.fromhex('39c0'),'model_http_budget')]
