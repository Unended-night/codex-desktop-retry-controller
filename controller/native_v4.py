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


def register_families():
    """Architectural aliases, including partial writes to a live register."""
    import capstone.x86_const as x
    names = [('RAX','EAX','AX','AL','AH'), ('RBX','EBX','BX','BL','BH'),
             ('RCX','ECX','CX','CL','CH'), ('RDX','EDX','DX','DL','DH'),
             ('RSI','ESI','SI','SIL'), ('RDI','EDI','DI','DIL'),
             ('RBP','EBP','BP','BPL'), ('RSP','ESP','SP','SPL')]
    names += [(f'R{n}',f'R{n}D',f'R{n}W',f'R{n}B') for n in range(8,16)]
    return {getattr(x,'X86_REG_'+group[0]):
            tuple(getattr(x,'X86_REG_'+name) for name in group) for group in names}


def classifier_flow(prefix, none_value=SENTINEL):
    """Prove BT uses the normalized error tag and returns the None sentinel.

    Track volatile register aliases so enum numbering and register allocation
    can change without accepting an unrelated constant or stale flag source.
    """
    registers = {'rcx': ('error-pointer',), 'rdx': ('attempt',)}
    sign = None
    classification = None

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
            if registers.get('rdx') != ('constant', none_value):
                raise ValueError('terminal result is not None duration')
            classification = dict(mask=mask[1], default_tag=index[3][1])
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
    return classification


def classifier(ins, none_value=SENTINEL):
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
    classifier_flow(prefix, none_value)
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


def duration_branch(ins, call_index):
    """Derive the Option discriminant and both successors at the call site.

    A nanosecond value is below 1e9; None must be outside that range. Its
    encoding is a compiler choice, not the numeric limit of Duration itself.
    The classifier must independently return this same value on its None path.
    """
    import capstone.x86_const as x
    n = call_index + 1
    while ins[n].mnemonic == 'nop':
        n += 1
    compare, jump = ins[n:n+2]
    if not (compare.mnemonic == 'cmp' and reg(compare.operands[0], x.X86_REG_EDX)
            and compare.operands[1].type == 2
            and jump.mnemonic in ('je', 'jne') and jump.operands[0].type == 2):
        raise ValueError('duration option branch changed')
    none_value = compare.operands[1].imm & 0xffffffff
    if none_value < SENTINEL:
        raise ValueError('None discriminant overlaps valid nanoseconds')
    taken, fallthrough = jump.operands[0].imm, jump.address + jump.size
    present, absent = (taken, fallthrough) if jump.mnemonic == 'jne' else (fallthrough, taken)
    boundaries = {i.address for i in ins}
    if present == absent or present not in boundaries or absent not in boundaries:
        raise ValueError('duration option successors are not distinct instruction boundaries')
    return none_value, present, absent


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
    none_value, present, absent = duration_branch(ins, call_index)
    # Recheck the relocatable prefix against the caller. Direct users of outer
    # must not accidentally combine a classifier from a different ABI.
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    prefix = list(decoder.disasm(helper, 0))
    if not prefix or sum(i.size for i in prefix) != len(helper) or prefix[-1].mnemonic != 'bt':
        raise ValueError('incomplete classifier prefix')
    classifier_flow(prefix, none_value)
    addresses={i.address:k for k,i in enumerate(ins)}
    resume=addresses[present]
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
    # Block scheduling may put the None/cleanup branch between the connection
    # exception and bounded retry blocks. Leave that live block untouched.
    connection_end = absent if connection.address < absent < bounded.address else bounded.address
    # Scheduling can move the bounded call's R8(error) reload into the skipped
    # connection block. Replay only a stack load proven to be the same error
    # passed to the classifier; copying the classifier alone clobbers R8.
    families = register_families()
    def writes(i, register):
        return bool(set(i.regs_access()[1]).intersection(families[register]))
    setup = ins[k:k+18]
    first_call = next((n for n,i in enumerate(setup) if i.mnemonic=='call'),len(setup))
    skipped = ins[resume+7:addresses[connection_end]]
    reloads = [(n,i) for n,i in enumerate(skipped) if i.mnemonic=='mov'
               and reg(i.operands[0],x.X86_REG_R8) and i.operands[0].size==8
               and mem(i.operands[1],x.X86_REG_RBP) and i.operands[1].size==8]
    bounded_reload = b''
    if reloads and not any(writes(i,x.X86_REG_R8) for i in setup[:first_call]):
        n,reload = only(reloads,'bounded error reload')
        bridge = next((j for j in range(n+1,len(skipped)) if skipped[j].mnemonic=='je'
                       and skipped[j].operands[0].type==2
                       and skipped[j].operands[0].imm==bounded.address),None)
        argument = ins[call_index-1]
        if not (bridge is not None and argument.mnemonic=='mov'
                and reg(argument.operands[0],x.X86_REG_RCX)
                and argument.operands[1].type==1 and argument.operands[1].size==8
                and not any(writes(i,x.X86_REG_R8) or i.mnemonic=='call' for i in skipped[n+1:bridge])):
            raise ValueError('bounded error argument flow changed')
        error = argument.operands[1].reg
        source = next((i for i in reversed(ins[max(0,call_index-30):call_index-1])
                       if writes(i,error)),None)
        if not (source and source.mnemonic=='mov' and reg(source.operands[0],error)
                and source.operands[0].size==8
                and mem(source.operands[1],x.X86_REG_RBP,reload.operands[1].mem.disp)
                and source.operands[1].size==8):
            raise ValueError('bounded error reload disagrees with classifier argument')
        bounded_reload = bytes(reload.bytes)
    ranges=[(call.address,call.address+call.size),(init.address,init.address+init.size),
            (lnano.address,lnano.address+lnano.size),(connection.address,connection_end)]
    safe_ranges(ins,ranges,data,off)
    return dict(call=call.address,continuation=call.address+call.size,
                init=init.address,init_size=init.size,deadline=lnano.address,deadline_size=lnano.size,
                connection=connection.address,connection_end=connection_end,
                bounded=bounded.address,bounded_reload=bounded_reload,
                prefix=helper,none_value=none_value)


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
    families = register_families()
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
    if (counter not in nonvolatile or state not in families
            or state in (x.X86_REG_RBP, x.X86_REG_RSP, counter)):
        raise ValueError('HTTP counter must survive calls and use distinct state')
    if not (compare.mnemonic == 'cmp' and reg(compare.operands[0], counter)
            and compare.operands[0].size == 8 and mem(compare.operands[1], state)
            and compare.operands[1].size == 8 and not overlaps(compare.operands[1].mem.disp, attempt)
            and exhausted.mnemonic == 'jae' and exhausted.operands[0].type == 2):
        raise ValueError('HTTP budget fields disagree')
    boundaries = {i.address for i in ins}
    if exhausted.operands[0].imm not in boundaries or exhausted.operands[0].imm <= reject.address:
        raise ValueError('HTTP exhausted branch outside error path')

    # Preserve the native tag classification after the budget gate. Its SUB
    # flags must feed the signed/unsigned conditional move directly; MOV does
    # not modify those flags. Both native classifications remain untouched.
    if not (copy.mnemonic == 'mov' and all(o.type == 1 and o.size == 8 for o in copy.operands)
            and subtract.mnemonic == 'sub' and reg(subtract.operands[0], copy.operands[0].reg)
            and subtract.operands[0].size == 8 and subtract.operands[1].type == 2
            and 0 < subtract.operands[1].imm <= 0x7fffffff
            and default.mnemonic == 'mov' and default.operands[0].type == 1
            and default.operands[0].size == 4 and default.operands[1].type == 2
            and 0 <= default.operands[1].imm <= 0xffffffff
            and select.mnemonic in ('cmovae', 'cmovge') and all(o.type == 1 and o.size == 8 for o in select.operands)
            and reg(select.operands[1], copy.operands[0].reg)):
        raise ValueError('HTTP error normalization changed')
    # Capstone supplies the architectural 32-bit alias without relying on a
    # register's spelling (including esi/edi and extended register names).
    aliases = {register: group[1] for register,group in families.items()}
    selected = select.operands[0].reg
    if not (aliases.get(selected) == default.operands[0].reg
            and selected != copy.operands[0].reg
            and adjust.mnemonic == 'lea' and adjust.operands[0].type == 1
            and adjust.operands[0].size == 4 and mem(adjust.operands[1], selected)
            and -0x7fffffff <= adjust.operands[1].mem.disp < 0
            and limit.mnemonic == 'cmp' and reg(limit.operands[0], adjust.operands[0].reg)
            and limit.operands[0].size == 4 and limit.operands[1].type == 2
            and 0 < limit.operands[1].imm <= 0x7fffffff
            and ((default.operands[1].imm + adjust.operands[1].mem.disp) & 0xffffffff)
                >= limit.operands[1].imm
            and reject.mnemonic == 'jae' and reject.operands[0].type == 2
            and reject.operands[0].imm in boundaries and reject.operands[0].imm > reject.address):
        raise ValueError('HTTP error range changed')
    if any(writes(i, counter) for i in ins[index+2:index+9]):
        raise ValueError('HTTP normalization overwrites retry counter')

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
    if any(i.mnemonic == 'call' for i in previous[source+1:]) and tag not in nonvolatile:
        raise ValueError('HTTP error tag clobbered by call')

    # On fallthrough the same counter is incremented and persisted for the
    # delay calculation. The state pointer may be copied or reloaded meanwhile.
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
            and mem(store.operands[0]) and store.operands[0].size == 8
            and reg(store.operands[1],counter)
            and not any(overlaps(store.operands[0].mem.disp,f)
                        for f in (attempt,compare.operands[1].mem.disp,tag_field))):
        raise ValueError('HTTP next-attempt state disagrees')

    # Track the object's identity, not a register's lifetime. A compiler may
    # reuse the budget's volatile base for classification and reload the object
    # from its frame slot into a nonvolatile register before the next call.
    # Only full-width copies and a proven, unchanged frame slot preserve it.
    begin = max(0,index-7) + origin
    producer = next((n for n in range(begin-1,max(-1,begin-13),-1)
                     if writes(ins[n],state) or ins[n].mnemonic == 'call'
                     or ins[n].mnemonic.startswith('j')),None)
    spill = None
    if producer is not None:
        i = ins[producer]
        if (i.mnemonic == 'mov' and reg(i.operands[0],state) and i.operands[0].size == 8
                and mem(i.operands[1]) and i.operands[1].size == 8
                and i.operands[1].mem.base in (x.X86_REG_RBP,x.X86_REG_RSP)):
            spill = (i.operands[1].mem.base,i.operands[1].mem.disp)
            begin = producer + 1
    live = {state}
    for i in ins[begin:index+9+increment+1]:
        if i.address == compare.address and state not in live:
            raise ValueError('HTTP budget state lost before comparison')
        # This bounded proof follows fallthrough with outward conditional exits.
        # Internal edges could bypass a reload or merge different state values.
        if (i.mnemonic in ('jmp','ret','retf','int3','ud2')
                or (i.mnemonic.startswith('j') and
                    (i.operands[0].type != 2 or i.operands[0].imm <= store.address))):
            raise ValueError('HTTP state flow has an unproven branch')
        value = None
        if (i.mnemonic == 'mov' and i.operands[0].type == 1 and i.operands[0].size == 8
                and i.operands[1].size == 8):
            src = i.operands[1]
            if ((src.type == 1 and src.reg in live)
                    or (spill is not None and mem(src,*spill))):
                value = i.operands[0].reg
        if spill is not None:
            frame, displacement = spill
            # Do not assume a slot survives frame changes, overlapping stores,
            # escaped frame addresses or the Windows x64 call scratch area.
            if ((i.mnemonic != 'call' and writes(i,frame))
                    or any(o.type == 3 and o.mem.base == frame and
                           (not mem(o,frame) or (o.access & 2 and
                            o.mem.disp < displacement+8 and displacement < o.mem.disp+o.size))
                           for o in i.operands)
                    or (i.mnemonic == 'lea' and i.operands[1].type == 3
                        and i.operands[1].mem.base == frame)
                    or (i.mnemonic == 'mov' and i.operands[1].type == 1
                        and i.operands[1].reg in families[frame])
                    or (i.mnemonic == 'call' and frame == x.X86_REG_RSP and displacement < 32)):
                spill = None
        live = {r for r in live if not writes(i,r)}
        if i.mnemonic == 'call':
            live.intersection_update(nonvolatile)
        if value is not None:
            live.add(value)
    if store.operands[0].mem.base not in live:
        raise ValueError('HTTP next-attempt state provenance lost')
    safe_ranges(ins,[(compare.address,compare.address+compare.size)],data,off)
    return dict(http=compare.address,http_size=compare.size)


def protocol_slice(ins, needle, data, off):
    """Find a literal pointer/length pair, rather than a log containing a path.

    A Rust string slice stores a pointer followed by its byte length. Neither
    the state base register nor the field offset is prescribed here.
    """
    for n, i in enumerate(ins[:-2]):
        if not (i.mnemonic == 'lea' and len(i.operands) == 2
                and i.operands[0].type == 1 and i.operands[0].size == 8
                and mem(i.operands[1]) and i.reg_name(i.operands[1].mem.base) == 'rip'):
            continue
        try:
            at = off(i.address + i.size + i.operands[1].mem.disp)
        except (ValueError, IndexError, KeyError):
            continue
        if data[at:at+len(needle)] != needle:
            continue
        pointer, length = ins[n+1:n+3]
        if not (pointer.mnemonic == length.mnemonic == 'mov'
                and len(pointer.operands) == len(length.operands) == 2):
            continue
        dst, src = pointer.operands
        count_dst, count = length.operands
        if (mem(dst) and dst.size == 8 and src.type == 1 and src.size == 8
                and src.reg == i.operands[0].reg and dst.mem.base != src.reg
                and mem(count_dst, dst.mem.base, dst.mem.disp + 8) and count_dst.size == 8
                and count.type == 2 and count.imm == len(needle)):
            return True
    return False


class ResponsesCallGraph:
    """Bounded caller proof using the Responses protocol, without log names.

    Every decoded caller must lead to a Responses request builder. Wrappers
    must also be connected to a common model caller; disconnected lookalikes,
    cycles, tail calls and address-taking are refused. This is a finite direct
    call analysis, not a proof about arbitrary indirect calls.
    """
    MAX_WRAPPERS = 4
    MAX_FUNCTIONS = 64

    def __init__(self, data, function, off, va, refs, reference_candidates=None):
        self.data, self.function, self.off, self.va = data, function, off, va
        self.reference_candidates = reference_candidates
        self.incoming = {}
        self.models = {}

    def model(self, ins):
        entry = ins[0].address
        if entry not in self.models:
            self.models[entry] = protocol_slice(ins, b'/responses', self.data, self.off)
        return self.models[entry]

    def callers(self, target):
        if target in self.incoming:
            return self.incoming[target]
        data, function, va = self.data, self.function, self.va
        if struct.pack('<Q',target) in data:
            raise ValueError('HTTP transport has an indirect function pointer')
        result=[]
        # Include address-taking LEAs and tail jumps so they cannot silently
        # disappear from the call graph. File offsets need not share a section.
        pattern=rb'[\xe8\xe9]|[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'
        candidates = (self.reference_candidates(target) if self.reference_candidates else
                      ((m.start(), 5 if len(m[0]) == 1 else 7) for m in re.finditer(pattern,data)))
        for at, size in candidates:
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
        self.incoming[target] = result
        return result

    def prove(self, entry):
        edges, roots, wrappers = {}, {}, set()
        visits = 0

        def walk(target, path):
            nonlocal visits
            visits += 1
            if target in path:
                raise ValueError('HTTP wrapper call graph has a cycle')
            if len(path) > self.MAX_WRAPPERS:
                raise ValueError('HTTP wrapper call graph exceeds supported depth')
            if visits > self.MAX_FUNCTIONS:
                raise ValueError('HTTP wrapper call graph exceeds supported size')
            for caller, site, ins in self.callers(target):
                if caller == entry or caller in path:
                    raise ValueError('HTTP wrapper call graph has a cycle')
                edges.setdefault(caller, set()).add(target)
                if self.model(ins):
                    roots.setdefault(caller, []).append(site)
                else:
                    wrappers.add(caller)
                    walk(caller, path + (target,))

        walk(entry, ())
        direct = {c[0] for c in self.callers(entry) if self.model(c[2])}
        root = only(sorted(direct or roots), 'Responses HTTP model caller')
        reachable, pending = set(), [root]
        while pending:
            node = pending.pop()
            if node not in reachable:
                reachable.add(node)
                pending.extend(edges.get(node, ()))
        if not wrappers.issubset(reachable):
            raise ValueError('HTTP wrapper has an unproven Responses caller')
        return min(roots[root])


def responses_transport(data, entry, function, off, va, refs):
    return ResponsesCallGraph(data, function, off, va, refs).prove(entry)


def locate_outlined(data, function, off, va, refs, cs, *, has_reference=None, reference_candidates=None):
    candidates=[]
    # A cheap scan narrows decoding to calls returning an Option<Duration>.
    pattern=(rb'\xe8....(?:\x90|\x66\x90|\x0f\x1f\x00|\x0f\x1f\x40.){0,4}'
             rb'(?:\x81\xfa....|\x83\xfa.)(?:[\x74\x75].|\x0f[\x84\x85]....)')
    for match in re.finditer(pattern,data,re.S):
        try:
            _,ins=function(match.start())
            n=next(n for n,i in enumerate(ins) if i.address==va(match.start()) and i.mnemonic=='call')
            none_value, _, _ = duration_branch(ins, n)
            target=ins[n].operands[0].imm
            bounds,helper=function(off(target))
            if target!=bounds[0]: continue
            candidates.append(outer(ins,n,classifier(helper,none_value),data,off))
        except (ValueError,KeyError,IndexError,StopIteration):
            continue
    result=only(candidates,'sampling policy')
    http={}
    graph=ResponsesCallGraph(data,function,off,va,refs,reference_candidates)
    # SUB r64, imm8/imm32; MOV r32, imm32; CMOVAE/CMOVGE r64, r64. The
    # constants are enum inputs, not identities of a particular release.
    pattern=(rb'[\x48-\x4f](?:\x83[\xe8-\xef].|\x81[\xe8-\xef]....|\x2d....)'
             rb'[\x40-\x41]?[\xb8-\xbf]....[\x48-\x4f]\x0f[\x43\x4d][\xc0-\xff]')
    for match in re.finditer(pattern,data,re.S):
        try:
            if has_reference is not None and not has_reference(match.start(), b'text/event-stream'):
                continue
            bounds,ins=function(match.start())
            if not refs(ins,b'text/event-stream'):
                continue
            n=next(n for n,i in enumerate(ins) if i.address==va(match.start()))
            if n<4: continue
            site=http_budget(ins,n-3,data,off)
        except (ValueError,KeyError,IndexError,StopIteration):
            continue
        # A structurally valid SSE retry loop with unproven callers cannot
        # silently be ignored in favour of a different, easier candidate.
        graph.prove(bounds[0])
        http[site['http']]=dict(site,offset=off(site['http']))
    if not http:
        raise ValueError('outlined model HTTP budget: no proven Responses gate')
    # Releases may keep several Responses implementations side by side. Apply
    # the same inner-budget policy to every proven model gate, without choosing
    # a release-specific telemetry name as the active implementation.
    result['http_sites']=[http[k] for k in sorted(http)]
    result.update(result['http_sites'][0])
    result['family']='responses-sampling-x64-outlined'
    result['offsets']={k:off(result[k]) for k in ('call','init','deadline','connection','http')}
    return result


def jmp(source,target,opcode=b'\xe9'):
    return opcode+struct.pack('<i',target-source-len(opcode)-4)


def delay_code(p):
    """Return Duration in RAX/EDX, using only caller-clobbered registers.

    TSC timing mixed into a 32-bit value supplies non-cryptographic jitter.
    No state, stack, external call or shared helper is changed. Milliseconds
    are chosen inclusively then split, so jitter can safely cross a second.
    """
    spread = p.get('jitter_ms', 0)
    if not spread:
        return b'\xb8'+struct.pack('<I',p['interval_ms']//1000)+b'\xba'+struct.pack('<I',p['interval_ms']%1000*1_000_000)
    code = bytes.fromhex('0f3131d0')  # RDTSC; XOR EAX, EDX.
    code += b'\x69\xc0'+struct.pack('<I',0x45d9f3b)
    code += bytes.fromhex('89c2c1ea1031d031d241b9')+struct.pack('<I',2*spread+1)
    code += bytes.fromhex('41f7f18d82')+struct.pack('<I',p['interval_ms']-spread)
    code += bytes.fromhex('31d241b9')
    code += struct.pack('<I',1000)+bytes.fromhex('41f7f169d2')+struct.pack('<I',1_000_000)
    return code


def replacements(s,p):
    cave=s['connection']
    code=s.get('bounded_reload',b'')
    code+=jmp(cave+len(code),s['bounded'])
    classifier_entry=cave+len(code)
    code+=s['prefix']
    code+=jmp(cave+len(code),s['continuation'],b'\x0f\x82')  # native terminal bit: return None
    code+=delay_code(p)
    code+=jmp(cave+len(code),s['continuation'])
    offsets=s['offsets']
    patches=[(offsets['call'],5,jmp(s['call'],classifier_entry),'model_outer_policy'),
            (offsets['connection'],s.get('connection_end',s['bounded'])-cave,code,'bounded_connection_and_native_classifier'),
            (offsets['init'],s['init_size'],b'\xb8'+struct.pack('<I',p['max_retries']),'model_outer_budget'),
            (offsets['deadline'],s['deadline_size'],b'\xb9'+struct.pack('<I',s.get('none_value',SENTINEL)),'ignore_server_deadline')]
    sites=s.get('http_sites',[dict(offset=offsets['http'],http_size=s.get('http_size',7))])
    for n,site in enumerate(sites):
        label='model_http_budget' if len(sites)==1 else f'model_http_budget_{n+1}'
        patches.append((site['offset'],site['http_size'],bytes.fromhex('39c0'),label))
    return patches
