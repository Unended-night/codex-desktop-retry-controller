"""Keep the native classifier; adjust its returned Option<Duration> in a leaf.

Byte-tag dispatch is proved against the enum's Debug formatter. No version,
enum number, field offset or terminal bitmap is assumed by this family.
"""
import struct

from .native_v4 import mem, only, reg, register_families


def byte_dispatch(ins, data, off):
    import capstone.x86_const as x
    families = register_families()
    objects = {x.X86_REG_RCX}
    for n, i in enumerate(ins[:24]):
        if (i.mnemonic == 'movzx' and i.operands[0].type == 1
                and i.operands[0].size == 4 and mem(i.operands[1])
                and i.operands[1].mem.base in objects and i.operands[1].size == 1):
            tag = next(full for full, aliases in families.items() if i.operands[0].reg in aliases)
            k = n + 1
            if ins[k].mnemonic == 'mov' and reg(ins[k].operands[0], x.X86_REG_EDX):
                k += 1  # The retry helper presets None before dispatch.
            a, b, c, d = ins[k:k+4]
            if not (a.mnemonic == 'lea' and a.operands[0].type == 1
                    and a.operands[0].size == 8 and mem(a.operands[1], x.X86_REG_RIP)
                    and a.operands[0].reg != tag
                    and b.mnemonic == 'movsxd' and reg(b.operands[0], tag)
                    and b.operands[1].type == 3 and b.operands[1].size == 4
                    and b.operands[1].mem.base == a.operands[0].reg
                    and b.operands[1].mem.index == tag and b.operands[1].mem.scale == 4
                    and not b.operands[1].mem.disp and not b.operands[1].mem.segment
                    and c.mnemonic == 'add' and reg(c.operands[0], tag)
                    and reg(c.operands[1], a.operands[0].reg)
                    and d.mnemonic == 'jmp' and reg(d.operands[0], tag)):
                raise ValueError('byte error dispatch table flow changed')
            table = a.address+a.size+a.operands[1].mem.disp
            boundaries = {j.address for j in ins}
            targets = []
            for index in range(256):
                target = table+struct.unpack_from('<i', data, off(table)+4*index)[0]
                if target not in boundaries:
                    break
                targets.append(target)
            if len(targets) < 2:
                raise ValueError('byte error dispatch has no bounded table')
            for instruction in ins[n:k+4]:
                for full, aliases in families.items():
                    if set(aliases).intersection(instruction.regs_access()[1]):
                        objects.discard(full)
            if x.X86_REG_RCX not in objects:
                raise ValueError('error object lost through byte dispatch')
            return dict(tag_offset=i.operands[1].mem.disp, targets=targets,
                        tag_index=n, dispatch_end=k+4)
        if i.mnemonic not in ('push', 'sub', 'mov', 'nop'):
            break
        copied = None
        if (i.mnemonic == 'mov' and i.operands[0].type == 1 and i.operands[0].size == 8
                and i.operands[1].type == 1 and i.operands[1].reg in objects):
            copied = i.operands[0].reg
        for full, aliases in families.items():
            if set(aliases).intersection(i.regs_access()[1]):
                objects.discard(full)
        if copied is not None:
            objects.add(copied)
    raise ValueError('missing byte error dispatch')


def returned_classifier(ins, none_value, data, off):
    import capstone.x86_const as x
    dispatch = byte_dispatch(ins, data, off)
    preset = ins[dispatch['tag_index']+1]
    if not (preset.mnemonic == 'mov' and reg(preset.operands[0], x.X86_REG_EDX)
            and preset.operands[1].type == 2 and preset.operands[1].imm & 0xffffffff == none_value):
        raise ValueError('native classifier None return disagrees with caller')
    prologue = ins[:dispatch['tag_index']]
    pushes = [i.operands[0].reg for i in prologue if i.mnemonic == 'push']
    stacks = [i for i in prologue if i.mnemonic == 'sub' and reg(i.operands[0], x.X86_REG_RSP)
              and i.operands[1].type == 2]
    stack = only(stacks, 'native classifier stack allocation').operands[1].imm
    addresses = {i.address:n for n, i in enumerate(ins)}
    terminal = []
    for tag, target in enumerate(dispatch['targets']):
        n = addresses[target]
        body = ins[n:n+len(pushes)+2]
        if (len(body) == len(pushes)+2 and body[0].mnemonic == 'add'
                and reg(body[0].operands[0], x.X86_REG_RSP)
                and body[0].operands[1].type == 2 and body[0].operands[1].imm == stack
                and all(i.mnemonic == 'pop' and reg(i.operands[0], r)
                        for i, r in zip(body[1:-1], reversed(pushes)))
                and body[-1].mnemonic == 'ret'):
            terminal.append(tag)
    if not terminal:
        raise ValueError('native classifier terminal return missing')
    deadline_only=[]
    terminal_targets={dispatch['targets'][tag] for tag in terminal}
    for tag,target in enumerate(dispatch['targets']):
        body=ins[addresses[target]:addresses[target]+7]
        if len(body)!=7:continue
        load,compare,missing,seconds,save_sec,save_nano,jump=body
        if (load.mnemonic=='mov' and reg(load.operands[0],x.X86_REG_R8D) and mem(load.operands[1],x.X86_REG_RCX)
                and compare.mnemonic=='cmp' and reg(compare.operands[0],x.X86_REG_R8D)
                and compare.operands[1].type==2 and compare.operands[1].imm & 0xffffffff==none_value
                and missing.mnemonic=='je' and missing.operands[0].type==2 and missing.operands[0].imm in terminal_targets
                and seconds.mnemonic=='mov' and reg(seconds.operands[0],x.X86_REG_RAX)
                and mem(seconds.operands[1],x.X86_REG_RCX,load.operands[1].mem.disp-8)
                and save_sec.mnemonic=='mov' and mem(save_sec.operands[0],x.X86_REG_RSP)
                and save_sec.operands[0].mem.disp>=32 and reg(save_sec.operands[1],x.X86_REG_RAX)
                and save_nano.mnemonic=='mov' and mem(save_nano.operands[0],x.X86_REG_RSP,save_sec.operands[0].mem.disp+8)
                and reg(save_nano.operands[1],x.X86_REG_R8D)
                and jump.mnemonic=='jmp' and jump.operands[0].type==2 and jump.operands[0].imm in addresses):
            deadline_only.append(tag)
    return dict(tag_offset=dispatch['tag_offset'], targets=dispatch['targets'],
                terminal_tags=terminal,deadline_only_tags=deadline_only,none_value=none_value)


def string_view(data, address, off, cs):
    import capstone.x86_const as x
    body = list(cs.disasm(data[off(address):off(address)+32], address, count=5))
    if len(body) != 5:
        raise ValueError('incomplete String formatter')
    a, b, c, d, e = body
    if not (a.mnemonic == 'mov' and reg(a.operands[0], x.X86_REG_R8) and reg(a.operands[1], x.X86_REG_RDX)
            and b.mnemonic == 'mov' and reg(b.operands[0], x.X86_REG_RAX) and mem(b.operands[1], x.X86_REG_RCX, 0)
            and c.mnemonic == 'mov' and reg(c.operands[0], x.X86_REG_RCX) and mem(c.operands[1], x.X86_REG_RAX)
            and d.mnemonic == 'mov' and reg(d.operands[0], x.X86_REG_RDX) and mem(d.operands[1], x.X86_REG_RAX)
            and c.operands[1].size == d.operands[1].size == 8
            and d.operands[1].mem.disp == c.operands[1].mem.disp+8
            and e.mnemonic == 'jmp' and e.operands[0].type == 2):
        raise ValueError('InvalidRequest String view changed')
    return c.operands[1].mem.disp, d.operands[1].mem.disp


def invalid_request_layout(ins, n, data, off, cs, classification):
    import capstone.x86_const as x
    dispatch = byte_dispatch(ins, data, off)
    if dispatch['tag_offset'] != classification['tag_offset'] or len(dispatch['targets']) != len(classification['targets']):
        raise ValueError('Debug enum disagrees with native classifier')
    add, store, receiver, vtable, method = ins[n-5:n]
    length, jump = ins[n+1:n+3]
    if not (add.mnemonic == 'add' and reg(add.operands[0], x.X86_REG_RCX)
            and add.operands[1].type == 2 and 0 < add.operands[1].imm <= 256
            and store.mnemonic == 'mov' and mem(store.operands[0], x.X86_REG_RSP)
            and store.operands[0].mem.disp >= 32 and reg(store.operands[1], x.X86_REG_RCX)
            and receiver.mnemonic == 'mov' and reg(receiver.operands[0], x.X86_REG_RDI)
            and mem(receiver.operands[1], x.X86_REG_RSI, 0)
            and vtable.mnemonic == 'mov' and reg(vtable.operands[0], x.X86_REG_RBX)
            and mem(vtable.operands[1], x.X86_REG_RSI, 8)
            and method.mnemonic == 'mov' and reg(method.operands[0], x.X86_REG_R14)
            and mem(method.operands[1], x.X86_REG_RBX, 24)
            and length.mnemonic == 'mov' and reg(length.operands[0], x.X86_REG_R8D)
            and length.operands[1].type == 2 and length.operands[1].imm == len('InvalidRequest')
            and jump.mnemonic == 'jmp' and jump.operands[0].type == 2):
        raise ValueError('InvalidRequest Debug payload/name flow changed')
    tag = only([tag for tag, target in enumerate(dispatch['targets']) if target == add.address], 'byte InvalidRequest tag')
    if tag not in classification['terminal_tags']:
        raise ValueError('InvalidRequest is not a native terminal arm')
    addresses = {i.address:k for k, i in enumerate(ins)}
    slot = store.operands[0].mem.disp
    pending, visited, views = [addresses[jump.operands[0].imm]], set(), []
    # Follow both ordinary/alternate Debug formatting paths. The saved payload
    # must survive until an &String formatter receives that exact stack slot.
    while pending:
        k = pending.pop()
        if k in visited:
            continue
        if len(visited) >= 160 or k >= len(ins):
            raise ValueError('InvalidRequest formatter traversal exceeded boundary')
        visited.add(k)
        i = ins[k]
        if (i.mnemonic == 'lea' and reg(i.operands[0], x.X86_REG_RCX)
                and mem(i.operands[1], x.X86_REG_RSP, slot)):
            argument, call = ins[k+1:k+3]
            if (reg(argument.operands[0], x.X86_REG_RDX)
                    and ((argument.mnemonic == 'mov' and reg(argument.operands[1], x.X86_REG_RSI))
                         or (argument.mnemonic == 'lea' and mem(argument.operands[1], x.X86_REG_RSP)
                             and argument.operands[1].mem.disp >= 32 and argument.operands[1].mem.disp != slot))
                    and call.mnemonic == 'call' and call.operands[0].type == 2):
                views.append(string_view(data, call.operands[0].imm, off, cs))
                continue
            raise ValueError('unproven InvalidRequest payload use')
        if any(o.type == 3 and o.mem.base == x.X86_REG_RSP and o.access & 2
               and o.mem.disp < slot+8 and slot < o.mem.disp+o.size for o in i.operands):
            raise ValueError('InvalidRequest payload slot overwritten')
        if i.mnemonic in ('ret', 'pop', 'int3') or (i.mnemonic == 'add' and reg(i.operands[0], x.X86_REG_RSP)):
            continue
        if i.mnemonic.startswith('j'):
            if i.operands[0].type != 2 or i.operands[0].imm not in addresses:
                raise ValueError('InvalidRequest formatter branch outside function')
            pending.append(addresses[i.operands[0].imm])
            if i.mnemonic == 'jmp':
                continue
        pending.append(k+1)
    pointer, length = only(list(set(views)), 'InvalidRequest String formatter')
    return dict(tag=tag, tag_offset=classification['tag_offset'], tag_size=1,
                pointer=add.operands[1].imm+pointer, length=add.operands[1].imm+length)
