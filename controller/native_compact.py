"""Derive local-compaction budgets and backoff calls, including post-turn."""
import re
import struct

from .native_v4 import mem, only, reg, register_families, safe_ranges


def compact_sites(ins, call_index, data, off):
    import capstone.x86_const as x
    call=ins[call_index]
    pointer,increment,store=ins[call_index-3:call_index]
    gate_start=call_index-6
    state_reload=None
    if ins[call_index-4].mnemonic=='mov':
        state_reload=ins[call_index-4]
        gate_start-=1
    load,compare,exhausted=ins[gate_start:gate_start+3]
    if not (load.mnemonic=='mov' and reg(load.operands[0],x.X86_REG_RCX)
            and mem(load.operands[1]) and load.operands[1].size==8):
        raise ValueError('compaction attempt load')
    state=load.operands[1].mem.base
    attempt=load.operands[1].mem.disp
    pointer_state=state
    if state_reload is not None:
        if not (state_reload.operands[0].type==1 and state_reload.operands[0].size==8
                and mem(state_reload.operands[1],x.X86_REG_RBP) and state_reload.operands[1].size==8
                and state_reload.operands[0].reg!=x.X86_REG_RCX):
            raise ValueError('compaction pointer state reload')
        pointer_state=state_reload.operands[0].reg
    if not (compare.mnemonic=='cmp' and reg(compare.operands[0],x.X86_REG_RCX)
            and mem(compare.operands[1],state) and compare.operands[1].size==8
            and exhausted.mnemonic=='jae' and exhausted.operands[0].type==2
            and pointer.mnemonic=='lea' and pointer.operands[0].type==1
            and mem(pointer.operands[1],pointer_state,attempt)
            and increment.mnemonic=='inc' and reg(increment.operands[0],x.X86_REG_RCX)
            and store.mnemonic=='mov' and mem(store.operands[0],pointer.operands[0].reg,0)
            and reg(store.operands[1],x.X86_REG_RCX)):
        raise ValueError('compaction budget/increment relationship')
    budget=compare.operands[1].mem.disp
    if abs(attempt-budget)<8:
        raise ValueError('overlapping compaction counters')
    n=call_index+1
    while ins[n].mnemonic=='nop':n+=1
    reload,reference,seconds,nanos=ins[n:n+4]
    if not (reload.mnemonic=='mov' and reload.operands[0].type==1
            and mem(reload.operands[1],x.X86_REG_RBP)):
        raise ValueError('compaction state reload')
    resumed=reload.operands[0].reg
    slot=reload.operands[1].mem.disp
    if not (reference.mnemonic=='lea' and reg(reference.operands[0],x.X86_REG_RCX)
            and mem(reference.operands[1],resumed,budget)
            and seconds.mnemonic=='mov' and mem(seconds.operands[0],resumed)
            and reg(seconds.operands[1],x.X86_REG_RAX)
            and nanos.mnemonic=='mov' and mem(nanos.operands[0],resumed,seconds.operands[0].mem.disp+8)
            and reg(nanos.operands[1],x.X86_REG_EDX)):
        raise ValueError('compaction Duration stores')
    # The same saved async state must feed the gate and initialization.
    aliases=register_families()[state]
    source=next((i for i in reversed(ins[:gate_start])
                 if set(aliases).intersection(i.regs_access()[1])),None)
    if not (source and source.mnemonic=='mov' and reg(source.operands[0],state)
            and mem(source.operands[1],x.X86_REG_RBP,slot)):
        raise ValueError('compaction counter state source')
    if state_reload is not None and not mem(state_reload.operands[1],x.X86_REG_RBP,slot):
        raise ValueError('compaction pointer reload disagrees with counter state')
    initial=[]
    for k,i in enumerate(ins[:gate_start]):
        if not (k>=4 and i.mnemonic=='mov' and mem(i.operands[0],x.X86_REG_RCX,budget)
                and reg(i.operands[1],x.X86_REG_RAX)):
            continue
        default,select,state_load=ins[k-3:k]
        zero=ins[k+1]
        if (default.mnemonic=='mov' and reg(default.operands[0],x.X86_REG_EAX)
                and default.operands[1].type==2
                and select.mnemonic=='cmovne' and reg(select.operands[0],x.X86_REG_RAX)
                and reg(select.operands[1],x.X86_REG_RDX)
                and state_load.mnemonic=='mov' and reg(state_load.operands[0],x.X86_REG_RCX)
                and mem(state_load.operands[1],x.X86_REG_RBP,slot)
                and zero.mnemonic=='mov' and mem(zero.operands[0],x.X86_REG_RCX,attempt)
                and zero.operands[1].type==2 and zero.operands[1].imm==0):
            initial.append((default,state_load.address-default.address))
    init,size=only(initial,'compaction budget initialization')
    if size<5 or call.size!=5:
        raise ValueError('compaction patch space')
    if exhausted.operands[0].imm not in {i.address for i in ins}:
        raise ValueError('compaction exhaustion outside function')
    if load.address <= exhausted.operands[0].imm < nanos.address+nanos.size:
        raise ValueError('compaction exhaustion enters retry body')
    safe_ranges(ins,[(init.address,init.address+size),(call.address,call.address+call.size)],data,off)
    return dict(init=off(init.address),init_size=size,call=call.address,call_offset=off(call.address))


def returned_compact_sites(ins, call_index, data, off, classification):
    """Compaction now calls the same native Option<Duration> classifier."""
    import capstone.x86_const as x
    from .native_v4 import duration_branch
    call=ins[call_index]
    increment,store,error_arg,attempt_arg=ins[call_index-4:call_index]
    nonvolatile={x.X86_REG_RBX,x.X86_REG_RSI,x.X86_REG_RDI,
                 x.X86_REG_R12,x.X86_REG_R13,x.X86_REG_R14,x.X86_REG_R15}
    if not (increment.mnemonic=='inc' and increment.operands[0].type==1
            and increment.operands[0].size==8 and increment.operands[0].reg in nonvolatile
            and store.mnemonic=='mov' and mem(store.operands[0]) and store.operands[0].size==8
            and reg(store.operands[1],increment.operands[0].reg)
            and error_arg.mnemonic=='mov' and reg(error_arg.operands[0],x.X86_REG_RCX)
            and error_arg.operands[1].type==1 and error_arg.operands[1].reg in nonvolatile
            and attempt_arg.mnemonic=='mov' and reg(attempt_arg.operands[0],x.X86_REG_RDX)
            and reg(attempt_arg.operands[1],increment.operands[0].reg)):
        raise ValueError('compaction classifier arguments changed')
    counter=increment.operands[0].reg
    state=store.operands[0].mem.base
    attempt=store.operands[0].mem.disp
    error_reg=error_arg.operands[1].reg
    if state not in nonvolatile or len({counter,state,error_reg})!=3:
        raise ValueError('compaction state/error/counter aliases')
    gates=[]
    for k in range(max(0,call_index-20),call_index-5):
        load,compare=ins[k:k+2]
        if (load.mnemonic=='mov' and reg(load.operands[0],counter) and mem(load.operands[1],state,attempt)
                and compare.mnemonic=='cmp' and reg(compare.operands[0],counter)
                and mem(compare.operands[1],state) and compare.operands[1].size==8):
            n=k+2
            if ins[n].mnemonic=='mov' and ins[n].operands[0].type==3 and ins[n].operands[0].size==1:
                n+=1  # A flag-neutral async-state byte store.
            jump=ins[n]
            if jump.mnemonic=='jae' and jump.operands[0].type==2:
                gates.append((k,n,compare.operands[1].mem.disp,jump.operands[0].imm))
    gate,branch,budget,exhausted=only(gates,'compaction classifier budget')
    families=register_families()
    # Native memcpy constructs the exact error passed to the classifier.
    pointer,size,copy_arg,copy_call=ins[call_index-8:call_index-4]
    if not (pointer.mnemonic=='lea' and reg(pointer.operands[0],error_reg) and mem(pointer.operands[1],state)
            and size.mnemonic=='mov' and reg(size.operands[0],x.X86_REG_R8D) and size.operands[1].type==2
            and copy_arg.mnemonic=='mov' and reg(copy_arg.operands[0],x.X86_REG_RCX) and reg(copy_arg.operands[1],error_reg)
            and copy_call.mnemonic=='call' and copy_call.operands[0].type==2):
        raise ValueError('compaction classifier error source changed')
    for i in ins[branch+1:call_index-8]:
        if (i.mnemonic!='mov' or not mem(i.operands[0],state) or i.operands[0].size!=1
                or any(i.operands[0].mem.disp<f+8 and f<i.operands[0].mem.disp+1 for f in (attempt,budget))):
            raise ValueError('compaction gate fallthrough changed')
    none_value,present,absent=duration_branch(ins,call_index)
    if classification['none_value']!=none_value:
        raise ValueError('compaction classifier None disagrees with caller')
    addresses={i.address:n for n,i in enumerate(ins)}
    n=addresses[present]
    reload,attempt_ref,budget_ref,seconds,nanos,lsec,lnano,dsec,dnano=ins[n:n+9]
    if not (reload.mnemonic=='mov' and reload.operands[0].type==1 and reload.operands[0].size==8
            and mem(reload.operands[1],x.X86_REG_RBP) and reload.operands[1].size==8):
        raise ValueError('compaction returned state reload')
    resumed=reload.operands[0].reg
    slot=reload.operands[1].mem.disp
    source=next((i for i in reversed(ins[:gate]) if set(families[state]).intersection(i.regs_access()[1])),None)
    if not (source and source.mnemonic=='mov' and reg(source.operands[0],state)
            and mem(source.operands[1],x.X86_REG_RBP,slot)):
        raise ValueError('compaction returned state disagrees')
    for ref,register,field in [(attempt_ref,x.X86_REG_RCX,attempt),(budget_ref,x.X86_REG_R8,budget)]:
        if not (ref.mnemonic=='lea' and reg(ref.operands[0],register) and mem(ref.operands[1],resumed,field)):
            raise ValueError('compaction returned counter references')
    for i,register,load in [(seconds,x.X86_REG_RAX,False),(nanos,x.X86_REG_EDX,False),
                            (lsec,x.X86_REG_RAX,True),(lnano,x.X86_REG_EDX,True),
                            (dsec,x.X86_REG_RAX,False),(dnano,x.X86_REG_EDX,False)]:
        a,b=i.operands if not load else reversed(i.operands)
        if i.mnemonic!='mov' or not mem(a,resumed) or not reg(b,register):
            raise ValueError('compaction returned Duration flow')
    if any(a.operands[index].mem.disp+8!=b.operands[index].mem.disp
           for a,b,index in [(seconds,nanos,0),(lsec,lnano,1),(dsec,dnano,0)]):
        raise ValueError('compaction returned Duration pair')
    if lsec.operands[1].mem.disp!=pointer.operands[1].mem.disp:
        raise ValueError('compaction deadline/error source disagrees')
    fields=[(attempt,8),(budget,8),(seconds.operands[0].mem.disp,12),
            (lsec.operands[1].mem.disp,12),(dsec.operands[0].mem.disp,12)]
    if any(a<b+bs and b<a+size for n,(a,size) in enumerate(fields) for b,bs in fields[n+1:]):
        raise ValueError('overlapping compaction classifier fields')
    initial=[]
    for k,i in enumerate(ins[:gate]):
        if k<3 or not (i.mnemonic=='mov' and mem(i.operands[0],x.X86_REG_RCX,budget) and reg(i.operands[1],x.X86_REG_RAX)):
            continue
        default,select,state_load=ins[k-3:k]
        zero=ins[k+1]
        if (default.mnemonic=='mov' and reg(default.operands[0],x.X86_REG_EAX) and default.operands[1].type==2
                and select.mnemonic=='cmovne' and reg(select.operands[0],x.X86_REG_RAX) and reg(select.operands[1],x.X86_REG_RDX)
                and state_load.mnemonic=='mov' and reg(state_load.operands[0],x.X86_REG_RCX) and mem(state_load.operands[1],x.X86_REG_RBP,slot)
                and zero.mnemonic=='mov' and mem(zero.operands[0],x.X86_REG_RCX,attempt)
                and zero.operands[1].type==2 and zero.operands[1].imm==0):
            initial.append((default,state_load.address-default.address))
    init,init_size=only(initial,'compaction classifier initialization')
    policy=ins[call_index+1]
    while policy.mnemonic=='nop':policy=ins[addresses[policy.address]+1]
    if min(init_size,policy.size,lnano.size)<5 or exhausted not in addresses or ins[gate].address<=exhausted<dnano.address+dnano.size:
        raise ValueError('compaction classifier patch/exit boundary')
    safe_ranges(ins,[(init.address,init.address+init_size),(policy.address,policy.address+policy.size),
                     (lnano.address,lnano.address+lnano.size)],data,off)
    return dict(init=off(init.address),init_size=init_size,call=call.address,
                policy=policy.address,policy_offset=off(policy.address),policy_size=policy.size,
                deadline=off(lnano.address),deadline_size=lnano.size,error_reload=bytes(error_arg.bytes),
                none_value=none_value,returned_classifier=classification)


def locate_compaction(data,s,function,off,va,reference_candidates=None):
    call=s['call']
    helper=call+5+struct.unpack_from('<i',data,off(call)+1)[0]
    _,body=function(off(helper))
    backoffs={i.operands[0].imm for i in body if i.mnemonic=='call' and i.operands[0].type==2}
    results={}
    # RCX is the attempt argument under Windows x64. The bytes only narrow
    # candidates; the state, counter, Duration and same-helper checks prove it.
    if 'returned_classifier' in s:
        candidates=(at for at,size in reference_candidates(helper) if size==5 and data[at]==0xe8)
        backoffs={helper}
    else:
        candidates=(m.end()-1 for m in re.finditer(rb'\x48\xff\xc1[\x48-\x4f]\x89.{1,6}?\xe8',data,re.S))
    for at in candidates:
        target=va(at)+5+struct.unpack_from('<i',data,at+1)[0]
        if target not in backoffs:
            continue
        try:
            _,ins=function(at)
            n=next(n for n,i in enumerate(ins) if i.address==va(at) and i.mnemonic=='call')
            if 'returned_classifier' in s:
                sites=returned_compact_sites(ins,n,data,off,s['returned_classifier'])
            else:
                sites=compact_sites(ins,n,data,off)
        except (ValueError,KeyError,IndexError,StopIteration):
            continue
        # Both compaction implementations have the history-shrinking branch.
        # Its diagnostic is a supplementary scope anchor; counter/state/Duration
        # flow and the shared backoff target above prove the actual patch sites.
        # Rust's formatting representation prefixes this literal with a length.
        prompt=b'Context window exceeded while compacting; removing oldest history item.'
        purpose=False
        for i in ins:
            for operand in i.operands:
                if operand.type==3 and i.reg_name(operand.mem.base)=='rip':
                    target=off(i.address+i.size+operand.mem.disp)
                    if prompt in data[target:target+len(prompt)+8]:
                        purpose=True
        if not purpose:
            raise ValueError('unproven compaction request purpose')
        results[sites['call']]=sites
    if not results:
        raise ValueError('no local compaction loop')
    return [results[key] for key in sorted(results)]
