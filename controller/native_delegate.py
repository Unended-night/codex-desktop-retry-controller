"""Sampling gates whose native policy returns a separately classified kind.

Follow the report call's counter/Duration/error arguments back to the state.
Some optimized copies retain pointers to the budget in frame slots; prove the
address producer rather than requiring a particular register or displacement.
"""
from .native_v4 import duration_branch, field_address, mem, only, reg, safe_ranges


def state_role(ins, at, register, slot):
    """A full state reload/save with no intervening register destruction."""
    from .native_v4 import register_families
    import capstone.x86_const as x
    aliases = register_families()[register]
    for i in reversed(ins[:at]):
        if (i.mnemonic == 'mov' and mem(i.operands[0], x.X86_REG_RBP, slot)
                and i.operands[1].type == 1 and i.operands[1].reg == register
                and i.operands[0].size == i.operands[1].size == 8):
            return True
        if (i.mnemonic == 'call' and register in (x.X86_REG_RAX,x.X86_REG_RCX,x.X86_REG_RDX,
                                                 x.X86_REG_R8,x.X86_REG_R9,x.X86_REG_R10,x.X86_REG_R11)):
            return False
        if any(o.type == 3 and o.mem.base == x.X86_REG_RBP and o.mem.disp == slot and o.access & 2 for o in i.operands):
            return False
        if set(i.regs_access()[1]).intersection(aliases):
            return (i.mnemonic == 'mov' and reg(i.operands[0], register)
                    and mem(i.operands[1], x.X86_REG_RBP, slot)
                    and i.operands[0].size == i.operands[1].size == 8)
    return False


def field_pointer(ins, frame_slot, field, state_slot):
    import capstone.x86_const as x
    from .native_v4 import register_families
    families = register_families()
    found = []
    for n, i in enumerate(ins):
        if not (i.mnemonic == 'mov' and mem(i.operands[0], x.X86_REG_RBP, frame_slot)
                and i.operands[0].size == 8 and i.operands[1].type == 1 and i.operands[1].size == 8):
            continue
        register = i.operands[1].reg
        producer = next(((k, p) for k, p in reversed(list(enumerate(ins[max(0, n-20):n], max(0, n-20))))
                         if set(p.regs_access()[1]).intersection(families[register])), None)
        if producer is None:
            raise ValueError('unproven budget pointer store')
        k, p = producer
        proven = False
        if p.mnemonic == 'lea' and reg(p.operands[0],register) and mem(p.operands[1],disp=field):
            state = p.operands[1].mem.base
            proven = state_role(ins,k,state,state_slot)
            # Optimized poll prologues can materialize all field pointers before
            # saving their common state in the frame. Follow the straight-line
            # source until that save, stopping at branches or register writes.
            if not proven:
                for following in ins[k+1:]:
                    if (following.mnemonic=='mov' and mem(following.operands[0],x.X86_REG_RBP,state_slot)
                            and reg(following.operands[1],state) and following.operands[1].size==8):
                        proven=True
                        break
                    if (following.mnemonic.startswith('j') or following.mnemonic in ('call','ret')
                            or set(following.regs_access()[1]).intersection(families[state])):
                        break
        if not proven:
            raise ValueError('budget pointer does not address the same state field')
        found.append(i.address)
    if not found:
        raise ValueError('missing budget pointer producer')


def clear_byte(register, field):
    import struct
    names = ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
    base = names.index(register)
    code = (bytes([0x41]) if base >= 8 else b'') + bytes([0xc6, 0x80 | (base & 7)])
    if base & 7 == 4:
        code += b'\x24'
    return code + struct.pack('<iB', field, 0)


def sampling(ins, call_index, helper, data, off):
    import capstone.x86_const as x
    call = ins[call_index]
    before, argument = ins[call_index-2:call_index]
    if not (before.mnemonic == 'mov' and mem(before.operands[0])
            and reg(before.operands[1], x.X86_REG_RDX)
            and before.operands[0].mem.base not in (x.X86_REG_RBP, x.X86_REG_RSP)):
        raise ValueError('missing next-attempt state store')
    if not (argument.mnemonic == 'mov' and reg(argument.operands[0], x.X86_REG_RCX)
            and mem(argument.operands[1], x.X86_REG_RBP) and argument.operands[1].size == 8):
        raise ValueError('delegated sampling error argument changed')
    next_attempt = before.operands[0].mem.disp
    none_value, present, absent = duration_branch(ins, call_index)
    if none_value != helper['none_value']:
        raise ValueError('delegated None disagrees with sampling caller')
    indices = {i.address:k for k, i in enumerate(ins)}
    resume = indices[present]
    reload = ins[resume]
    if not (reload.mnemonic == 'mov' and reload.operands[0].type == 1
            and reload.operands[0].size == 8 and mem(reload.operands[1], x.X86_REG_RBP)):
        raise ValueError('delegated sampling state reload changed')
    state, slot = reload.operands[0].reg, reload.operands[1].mem.disp
    if not state_role(ins, call_index, before.operands[0].mem.base, slot):
        raise ValueError('delegated sampling state source disagrees')
    cursor, stores = resume+1, []
    while len(stores) < 6:
        i = ins[cursor]
        if not field_address(i, state, next_attempt):
            stores.append(i)
        cursor += 1
    ssec, snano, lsec, lnano, dsec, dnano = stores
    for i, register, load in ((ssec,x.X86_REG_RAX,False),(snano,x.X86_REG_EDX,False),
                              (lsec,x.X86_REG_RAX,True),(lnano,x.X86_REG_ECX,True),
                              (dsec,x.X86_REG_RAX,False),(dnano,x.X86_REG_ECX,False)):
        a, b = reversed(i.operands) if load else i.operands
        if not (i.mnemonic == 'mov' and mem(a, state) and reg(b, register)):
            raise ValueError('delegated duration field flow changed')
    if any(a.operands[k].mem.disp+8 != b.operands[k].mem.disp
           for a,b,k in ((ssec,snano,0),(lsec,lnano,1),(dsec,dnano,0))):
        raise ValueError('delegated duration pair disagrees')
    connection = ins[cursor]
    if not (connection.mnemonic == 'mov' and reg(connection.operands[0],x.X86_REG_RAX)
            and mem(connection.operands[1],state)):
        raise ValueError('delegated connection entry changed')

    candidates = []
    for k in range(cursor+1, len(ins)-18):
        load_next, write = ins[k:k+2]
        if not (load_next.mnemonic == 'mov' and reg(load_next.operands[0],x.X86_REG_R9)
                and mem(load_next.operands[1],disp=next_attempt)
                and write.mnemonic == 'mov' and mem(write.operands[0],x.X86_REG_RAX,0)
                and reg(write.operands[1],x.X86_REG_R9)):
            continue
        compare, exhausted = ins[k-2:k]
        if not (compare.mnemonic == 'cmp' and reg(compare.operands[0],x.X86_REG_RCX)
                and compare.operands[1].type == 3 and compare.operands[1].size == 8
                and exhausted.mnemonic == 'jae' and exhausted.operands[0].type == 2):
            continue
        bounded_state = load_next.operands[1].mem.base
        tail = ins[k+2:k+18]
        reporter_index = next((n for n,i in enumerate(tail) if i.mnemonic == 'call'), None)
        if reporter_index is None or tail[reporter_index].operands[0].type != 2:
            continue
        setup = tail[:reporter_index]
        budget_loads = [i for i in setup if i.mnemonic == 'mov'
                        and reg(i.operands[0],x.X86_REG_RAX) and mem(i.operands[1],bounded_state)]
        if len(budget_loads) != 1:
            continue
        budget = budget_loads[0].operands[1].mem.disp
        for register, field in ((x.X86_REG_RDX,connection.operands[1].mem.disp),
                                (x.X86_REG_R8,ssec.operands[0].mem.disp),
                                (x.X86_REG_R10D,snano.operands[0].mem.disp)):
            if not any(i.mnemonic == 'mov' and reg(i.operands[0],register)
                       and mem(i.operands[1],bounded_state,field) for i in setup):
                break
        else:
            error_reload = setup[-1]
            if not (error_reload.mnemonic == 'mov' and reg(error_reload.operands[0],x.X86_REG_R8)
                    and mem(error_reload.operands[1],x.X86_REG_RBP,argument.operands[1].mem.disp)):
                continue
            count_index = k-3
            if not mem(compare.operands[1],bounded_state,budget):
                pointer = ins[k-3]
                if not (mem(compare.operands[1],x.X86_REG_RDX,0)
                        and pointer.mnemonic == 'mov' and reg(pointer.operands[0],x.X86_REG_RDX)
                        and mem(pointer.operands[1],x.X86_REG_RBP)):
                    continue
                field_pointer(ins, pointer.operands[1].mem.disp, budget, slot)
                count_index -= 1
            count = ins[count_index]
            if not (count.mnemonic == 'mov' and reg(count.operands[0],x.X86_REG_RCX)
                    and mem(count.operands[1],x.X86_REG_RAX,0)):
                continue
            counter = next((i for i in reversed(ins[cursor:count_index]) if i.mnemonic == 'mov'
                            and reg(i.operands[0],x.X86_REG_RAX) and mem(i.operands[1],bounded_state)), None)
            state_load = next((i for i in reversed(ins[resume:count_index]) if i.mnemonic == 'mov'
                               and reg(i.operands[0],bounded_state) and mem(i.operands[1],x.X86_REG_RBP,slot)),None)
            if counter is None or state_load is None:
                continue
            candidates.append((count_index, bounded_state, budget, counter, state_load, tail[reporter_index]))
    count_index, bounded_state, budget, counter, state_load, reporter = only(candidates,'delegated bounded gate')
    bounded = ins[count_index]
    if not 100 <= bounded.address-connection.address <= 2048:
        raise ValueError('delegated connection range changed')
    # The native path reaches this gate with both fallback flags false. Replay
    # those values, but never touch the interleaved None arm's error drop flag.
    kinds, fallbacks = [], []
    for k in range(cursor, count_index):
        i = ins[k]
        if i.mnemonic == 'sete' and mem(i.operands[0]) and i.operands[0].size == 1:
            prior = ins[k-2:k]
            cmp_kind = prior[0] if prior[-1].mnemonic == 'mov' else prior[-1]
            if (cmp_kind.mnemonic == 'cmp' and reg(cmp_kind.operands[0],x.X86_REG_AL)
                    and cmp_kind.operands[1].type == 2
                    and state_role(ins,k,i.operands[0].mem.base,slot)):
                call_before = next((j for j in reversed(ins[max(cursor,k-7):k]) if j.mnemonic == 'call'),None)
                if call_before and call_before.operands[0].type == 2 and call_before.operands[0].imm == helper['delegate']:
                    kinds.append(i.operands[0].mem.disp)
        if i.mnemonic == 'jae':
            zero = ins[k+1]
            if (zero.mnemonic == 'mov' and mem(zero.operands[0]) and zero.operands[0].size == 1
                    and zero.operands[1].type == 2 and zero.operands[1].imm == 0
                    and state_role(ins,k+1,zero.operands[0].mem.base,slot)):
                fallbacks.append(zero.operands[0].mem.disp)
    kind = only(list(set(kinds)), 'delegated connection-kind flag')
    fallback = only(list(set(fallbacks)), 'delegated fallback flag')
    fields = [(budget,8),(next_attempt,8),(counter.operands[1].mem.disp,8),
              (connection.operands[1].mem.disp,8),(kind,1),(fallback,1)]
    fields += [(a.operands[k].mem.disp,8 if n%2==0 else 4)
               for n,(a,k) in enumerate(((ssec,0),(snano,0),(lsec,1),(lnano,1),(dsec,0),(dnano,0)))]
    if any(a < b+bs and b < a+size for n,(a,size) in enumerate(fields) for b,bs in fields[n+1:]):
        raise ValueError('overlapping delegated state fields')
    policy_index = call_index+1
    while ins[policy_index].mnemonic == 'nop':
        policy_index += 1
    policy, branch = ins[policy_index:policy_index+2]
    size = branch.address+branch.size-policy.address
    if size < 5 or connection.size < 5 or lsec.address+lsec.size != lnano.address:
        raise ValueError('insufficient delegated redirect space')
    ranges = [(policy.address,policy.address+size), (connection.address,connection.address+connection.size),
              (lsec.address,lnano.address+lnano.size)]
    safe_ranges(ins,ranges,data,off)
    state_name = reload.reg_name(state)
    # A nonvolatile error pointer may be loaded before the first connection
    # branch and remain live after the report call. Replay that exact frame
    # load; do not rely on the report call's separate R8 reload to restore it.
    error_prefix=b''
    nonvolatile={x.X86_REG_RBX,x.X86_REG_RSI,x.X86_REG_RDI,x.X86_REG_R12,
                 x.X86_REG_R13,x.X86_REG_R14,x.X86_REG_R15}
    for i in ins[cursor:count_index]:
        if i.mnemonic.startswith('j') or i.mnemonic=='call':break
        if (i.mnemonic=='mov' and i.operands[0].type==1 and i.operands[0].size==8
                and i.operands[0].reg in nonvolatile and i.operands[0].reg!=state):
            if not mem(i.operands[1],x.X86_REG_RBP,argument.operands[1].mem.disp):
                raise ValueError('unproven live nonvolatile connection value')
            error_prefix+=bytes(i.bytes)
    prefix = error_prefix+clear_byte(state_name,kind)+clear_byte(state_name,fallback)+bytes(state_load.bytes)+bytes(counter.bytes)
    return dict(call=call.address, helper=call.operands[0].imm, reporter=reporter.operands[0].imm,
                continuation=call.address+call.size, prefix=b'', none_value=none_value,
                deadline=lsec.address, deadline_size=lnano.address+lnano.size-lsec.address,
                connection=connection.address, connection_end=connection.address+connection.size,
                bounded=bounded.address, bounded_reload=prefix, budget_field=budget, state_register=state_name,
                returned_classifier=helper, policy=policy.address, policy_size=size,
                policy_present=present, policy_absent=absent, error_reload=bytes(argument.bytes))
