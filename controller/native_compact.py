"""Derive local-compaction budgets and backoff calls, including post-turn."""
import re
import struct

from .native_v4 import mem, only, reg, safe_ranges


def compact_sites(ins, call_index, data, off):
    import capstone.x86_const as x
    call=ins[call_index]
    load,compare,exhausted,pointer,increment,store=ins[call_index-6:call_index]
    if not (load.mnemonic=='mov' and reg(load.operands[0],x.X86_REG_RCX)
            and mem(load.operands[1]) and load.operands[1].size==8):
        raise ValueError('compaction attempt load')
    state=load.operands[1].mem.base
    attempt=load.operands[1].mem.disp
    if not (compare.mnemonic=='cmp' and reg(compare.operands[0],x.X86_REG_RCX)
            and mem(compare.operands[1],state) and compare.operands[1].size==8
            and exhausted.mnemonic=='jae' and exhausted.operands[0].type==2
            and pointer.mnemonic=='lea' and pointer.operands[0].type==1
            and mem(pointer.operands[1],state,attempt)
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
    source=next((i for i in reversed(ins[:call_index-6])
                 if state in i.regs_access()[1]),None)
    if not (source and source.mnemonic=='mov' and reg(source.operands[0],state)
            and mem(source.operands[1],x.X86_REG_RBP,slot)):
        raise ValueError('compaction counter state source')
    initial=[]
    for k,i in enumerate(ins[:call_index-6]):
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


def locate_compaction(data,s,function,off,va):
    call=s['call']
    helper=call+5+struct.unpack_from('<i',data,off(call)+1)[0]
    _,body=function(off(helper))
    backoffs={i.operands[0].imm for i in body if i.mnemonic=='call' and i.operands[0].type==2}
    results={}
    # RCX is the attempt argument under Windows x64. The bytes only narrow
    # candidates; the state, counter, Duration and same-helper checks prove it.
    for m in re.finditer(rb'\x48\xff\xc1[\x48-\x4f]\x89.{1,6}?\xe8',data,re.S):
        at=m.end()-1
        target=va(at)+5+struct.unpack_from('<i',data,at+1)[0]
        if target not in backoffs:
            continue
        try:
            _,ins=function(at)
            n=next(n for n,i in enumerate(ins) if i.address==va(at) and i.mnemonic=='call')
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
