"""Narrow recoverable InvalidRequest cases, with a proven native String view."""
import re
import struct

from .native_extension import Code
from .native_v4 import classifier_flow, delay_code, mem, only, reg, register_families

AZURE_RESOURCE_MESSAGE = ('The requested item was created under a different Azure OpenAI resource. '
                          'Use the same resource that created the item to access it.')
ENCRYPTED_CONTENT_CODE = 'invalid_encrypted_content'


def debug_dispatch_source(ins, stop, normalized, tag_register):
    """Follow the dispatch entry, including a separately formatted special tag.

    Register allocation and placement of the niche constant may change. Only
    a JNE comparing the original tag with a niche variant can bypass a Debug
    arm; calls, other branches and lost tag/object provenance are refused.
    """
    import capstone.x86_const as x
    families=register_families()
    aliases={alias:full for full,group in families.items() for alias in group}
    values={x.X86_REG_RCX:('object',)}
    addresses={i.address:n for n,i in enumerate(ins)}
    compare=None
    bypass=None
    n=0
    visits=set()
    def read(op):
        if op.type==2:
            return ('constant',op.imm & ((1<<(op.size*8))-1))
        if op.type==1 and op.size==8:
            return values.get(aliases.get(op.reg))
        if (op.type==3 and op.size==8 and mem(op,disp=0)
                and values.get(op.mem.base)==('object',)):
            return ('tag',)
        return None
    while n<stop:
        if n in visits:
            raise ValueError('error dispatch entry cycle')
        visits.add(n)
        i=ins[n]
        if i.mnemonic.startswith('j'):
            if not (i.mnemonic=='jne' and i.operands[0].type==2 and compare is not None
                    and bypass is None and 1<<63 <= compare < (1<<63)+64):
                raise ValueError('error dispatch entry changed')
            bypass=compare-(1<<63)
            n=addresses.get(i.operands[0].imm,len(ins))
            continue
        if i.mnemonic in ('call','ret'):
            raise ValueError('error dispatch entry changed')
        value=None
        if i.mnemonic in ('mov','movabs') and len(i.operands)==2:
            value=read(i.operands[1])
        elif i.mnemonic=='lea' and mem(i.operands[1]):
            source=values.get(i.operands[1].mem.base)
            if source is not None and source[0]=='constant':
                value=('constant',(source[1]+i.operands[1].mem.disp)&((1<<64)-1))
        writes=i.regs_access()[1]
        if x.X86_REG_EFLAGS in writes:
            compare=None
        if i.mnemonic=='cmp':
            pair=[read(o) for o in i.operands]
            if ('tag',) in pair:
                other=pair[1-pair.index(('tag',))]
                if other is not None and other[0]=='constant':compare=other[1]
        for register in writes:
            values.pop(aliases.get(register),None)
        if (value is not None and i.operands[0].type==1 and i.operands[0].size in (4,8)
                and (i.operands[0].size==8 or value[0]=='constant')):
            values[aliases.get(i.operands[0].reg)]=value
        n+=1
    if not (n==stop and values.get(normalized)==('constant',1<<63)
            and values.get(tag_register)==('tag',) and values.get(x.X86_REG_RDI)==('object',)):
        raise ValueError('error object/tag source changed')
    return bypass


def invalid_request_layout(ins, name_index, data, off, function, classification):
    """Use the enum's own Debug arm and its &String formatter to derive fields.

    The variant name is a semantic candidate anchor, not an assumed numeric tag.
    Require the same niche normalization as the retry classifier, invert its
    checked jump table, and follow the concrete formatter's pointer/length loads.
    """
    import capstone.x86_const as x
    n = name_index
    add, argument, vtable, store = ins[n-4:n]
    if not (add.mnemonic=='add' and reg(add.operands[0],x.X86_REG_RDI)
            and add.operands[1].type==2 and 0 < add.operands[1].imm <= 32
            and argument.mnemonic=='mov' and mem(argument.operands[0],x.X86_REG_RSP)
            and reg(argument.operands[1],x.X86_REG_RDI)
            and vtable.mnemonic=='lea' and reg(vtable.operands[0],x.X86_REG_RAX)
            and mem(vtable.operands[1],x.X86_REG_RIP)
            and store.mnemonic=='mov' and mem(store.operands[0],x.X86_REG_RSP,0x20)
            and reg(store.operands[1],x.X86_REG_RAX)):
        raise ValueError('InvalidRequest debug payload changed')
    addresses = {i.address:k for k,i in enumerate(ins)}
    at = n+1
    for _ in range(8):
        i = ins[at]
        if i.mnemonic=='jmp' and i.operands[0].type==2:
            at = addresses[i.operands[0].imm]
            continue
        if i.mnemonic=='mov' and reg(i.operands[0],x.X86_REG_R8D):
            if i.operands[1].type!=2 or i.operands[1].imm!=len('InvalidRequest'):
                raise ValueError('InvalidRequest name length changed')
            break
        if i.mnemonic!='lea':
            raise ValueError('InvalidRequest name argument changed')
        at += 1
    else:
        raise ValueError('InvalidRequest name length not proven')
    tables=[]
    for k in range(n-7):
        a,b,c,d,e,f,g,h=ins[k:k+8]
        if not (a.mnemonic=='xor' and all(o.type==1 and o.size==8 for o in a.operands)):
            continue
        normalized,tag_register=(o.reg for o in a.operands)
        aliases=register_families()
        if (normalized!=tag_register
                and b.mnemonic=='test' and all(reg(o,tag_register) and o.size==8 for o in b.operands)
                and c.mnemonic=='mov' and reg(c.operands[0],aliases[tag_register][1])
                and c.operands[1].type==2 and c.operands[1].imm==classification['default_tag']
                and d.mnemonic=='cmovs' and reg(d.operands[0],tag_register) and reg(d.operands[1],normalized)
                and e.mnemonic=='lea' and reg(e.operands[0],normalized) and mem(e.operands[1],x.X86_REG_RIP)
                and f.mnemonic=='movsxd' and reg(f.operands[0],tag_register)
                and f.operands[1].type==3 and f.operands[1].mem.base==normalized
                and f.operands[1].mem.index==tag_register and f.operands[1].mem.scale==4
                and f.operands[1].mem.disp==0
                and g.mnemonic=='add' and reg(g.operands[0],tag_register) and reg(g.operands[1],normalized)
                and h.mnemonic=='jmp' and reg(h.operands[0],tag_register)):
            bypass=debug_dispatch_source(ins,k,normalized,tag_register)
            tables.append((k,e.address+e.size+e.operands[1].mem.disp,bypass))
    k,table,bypass_tag=only(tables,'InvalidRequest dispatch')
    tags=[]
    for index in range(64):
        target=table+struct.unpack_from('<i',data,off(table)+index*4)[0]
        if target not in addresses:
            break
        if target==add.address:
            tags.append(index)
    tag=only(tags,'InvalidRequest variant tag')
    if tag in (classification['default_tag'],bypass_tag) or not classification['mask'] & (1<<tag):
        raise ValueError('InvalidRequest does not agree with native terminal classifier')
    vt=vtable.address+vtable.size+vtable.operands[1].mem.disp
    drop,size,alignment,formatter=struct.unpack_from('<QQQQ',data,off(vt))
    if (drop,size,alignment)!=(0,8,8):
        raise ValueError('InvalidRequest payload is not a reference formatter')
    # This stackless tail wrapper legitimately has no .pdata unwind record.
    import capstone
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    decoder.detail=True
    body=list(decoder.disasm(data[off(formatter):off(formatter)+32],formatter,count=5))
    if len(body)!=5:
        raise ValueError('InvalidRequest String formatter changed')
    a,b,c,d,e=body
    if not (a.mnemonic=='mov' and reg(a.operands[0],x.X86_REG_R8) and reg(a.operands[1],x.X86_REG_RDX)
            and b.mnemonic=='mov' and reg(b.operands[0],x.X86_REG_RAX) and mem(b.operands[1],x.X86_REG_RCX,0)
            and c.mnemonic=='mov' and reg(c.operands[0],x.X86_REG_RCX) and mem(c.operands[1],x.X86_REG_RAX)
            and d.mnemonic=='mov' and reg(d.operands[0],x.X86_REG_RDX) and mem(d.operands[1],x.X86_REG_RAX)
            and c.operands[1].size==d.operands[1].size==8
            and d.operands[1].mem.disp==c.operands[1].mem.disp+8
            and e.mnemonic=='jmp' and e.operands[0].type==2):
        raise ValueError('InvalidRequest string slice is not proven')
    return dict(tag=(1<<63)|tag,pointer=add.operands[1].imm+c.operands[1].mem.disp,
                length=add.operands[1].imm+d.operands[1].mem.disp)


def name_references(data, regions, targets):
    """Find all candidate LEA RDX,[RIP+rel32] name arguments in one pass.

    The Debug-arm proof already requires this ABI argument. Search only its
    three-byte opcode, retaining overlapping operands and block boundaries;
    exact target checks and full instruction decoding still follow.
    """
    references={target:[] for target in targets}
    pattern=re.compile(rb'[\x48-\x4b]\x8d\x15')
    for start,end,address in regions:
        for match in pattern.finditer(data,start,end):
            at=match.start()
            if at+7>end:
                continue
            target=address+at-start+7+struct.unpack_from('<i',data,at+3)[0]
            if target in references:
                references[target].append(at)
    return references


def locate_invalid_request(data, s, function, off, va, cs, regions):
    prefix=list(cs.disasm(s['prefix'],0))
    classification=classifier_flow(prefix,s['none_value'])
    if any('rcx' in [i.reg_name(r) for r in i.regs_access()[1]] for i in prefix):
        raise ValueError('retry classifier no longer preserves error pointer')
    results=[]
    # Rust may pool names directly next to other printable literals. The exact
    # slice length and enum/formatter flow below, not a trailing byte, prove
    # that this is the InvalidRequest variant rather than an SDK name prefix.
    targets={va(match.start()) for match in re.finditer(rb'InvalidRequest',data)}
    for offsets in name_references(data,regions,targets).values():
        for at in offsets:
            try:
                _,ins=function(at)
                n=next(n for n,i in enumerate(ins) if i.address==va(at)
                       and i.mnemonic=='lea' and i.reg_name(i.operands[0].reg)=='rdx')
                result=invalid_request_layout(ins,n,data,off,function,classification)
            except (ValueError,KeyError,IndexError,StopIteration,struct.error):
                continue
            if result not in results:
                results.append(result)
    return only(results,'InvalidRequest layout')


def error_policy(s, p):
    """Leaf helper: preserve native classification, then check two JSON fields.

    Never calls another function or touches the stack/nonvolatile registers.
    Every byte comparison is bounded by the native String's end pointer.
    """
    c=Code()
    c.emit(s['prefix'])
    c.relative('0f83','delay')  # Native nonterminal result.
    c.emit('48b8');c.emit(struct.pack('<Q',s['invalid_request']['tag']))
    c.emit('483901');c.relative('0f85','return')
    for index,(key,value) in enumerate([(b'"code"',b'"'+ENCRYPTED_CONTENT_CODE.encode()+b'"'),
                                      (b'"message"',b'"'+AZURE_RESOURCE_MESSAGE.encode())]):
        name=f'field{index}'
        next_field=f'field{index+1}' if index==0 else 'return'
        c.label(name)
        c.emit('4c8b91');c.emit(struct.pack('<i',s['invalid_request']['pointer']))
        c.emit('4c8b99');c.emit(struct.pack('<i',s['invalid_request']['length']))
        c.emit('4d01d3')  # R10 cursor, R11 end.
        c.label(name+'scan')
        c.emit('4d89d0')  # R8 candidate cursor.
        def literal(text,fail):
            c.emit('498d80');c.emit(struct.pack('<i',len(text)))
            c.emit('4c39d8');c.relative('0f87',fail)
            for offset in range(0,len(text),8):
                chunk=text[offset:offset+8]
                if len(chunk)==8:
                    c.emit('48b8');c.emit(chunk)
                    c.emit('493980');c.emit(struct.pack('<i',offset))
                    c.relative('0f85',fail)
                else:
                    for j,byte in enumerate(chunk,offset):
                        c.emit('4180b8');c.emit(struct.pack('<i',j)+bytes([byte]))
                        c.relative('0f85',fail)
            c.emit('4981c0');c.emit(struct.pack('<i',len(text)))
        # Insufficient bytes for the key ends this field's scan.
        c.emit('498d82');c.emit(struct.pack('<i',len(key)))
        c.emit('4c39d8');c.relative('0f87',next_field)
        literal(key,name+'advance')
        def whitespace(label):
            c.label(label)
            c.emit('4d39d8');c.relative('0f83',name+'advance')
            c.emit('410fb600')
            for byte in (32,9,10,13):
                c.emit(bytes([0x3c,byte]));c.relative('0f84',label+'step')
            c.relative('e9',label+'done')
            c.label(label+'step');c.emit('49ffc0');c.relative('e9',label)
            c.label(label+'done')
        whitespace(name+'ws1')
        literal(b':',name+'advance')
        whitespace(name+'ws2')
        literal(value,name+'advance')
        if index==1:
            c.emit('4d39d8');c.relative('0f83',name+'advance')
            c.emit('41803822');c.relative('0f84','delay')
            c.emit('41803820');c.relative('0f85',name+'advance')
        c.relative('e9','delay')
        c.label(name+'advance');c.emit('49ffc2');c.relative('e9',name+'scan')
    c.label('return');c.emit('c3')
    c.label('delay');c.emit(delay_code(p));c.emit('c3')
    return c.finish()
