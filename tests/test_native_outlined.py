"""Real instruction fragments: relocation, field drift and unsafe mutations."""
import json
from pathlib import Path
import struct
import random
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'research/.deps'))
import capstone
from controller.native import _file_address_map, _mapped_va, _relative_reference_candidates
from controller.native_v4 import (classifier, duration_branch, http_budget, locate_outlined, outer,
                                  protocol_slice, replacements, responses_transport, safe_ranges)
from controller import native


class AnalysisCacheTests(unittest.TestCase):
    def setUp(self):
        self.key = patch.object(native, '_analysis_key', None)
        self.result = patch.object(native, '_analysis_result', None)
        self.key.start()
        self.result.start()
        self.addCleanup(self.key.stop)
        self.addCleanup(self.result.stop)

    def test_identical_content_reuses_analysis_without_retaining_caller_mutations(self):
        with patch.object(native, '_locate', return_value={'offsets': {'http': 7}}) as analyze:
            first = native.locate(b'original', ValueError)
            first['offsets']['http'] = 99
            second = native.locate(bytes(bytearray(b'original')), RuntimeError)
        self.assertEqual(second, {'offsets': {'http': 7}})
        self.assertEqual(analyze.call_count, 1)

    def test_changed_bytes_are_reanalyzed_even_at_the_same_size(self):
        with patch.object(native, '_locate', side_effect=[{'http': 7}, {'http': 8}]) as analyze:
            self.assertEqual(native.locate(b'original', ValueError), {'http': 7})
            self.assertEqual(native.locate(b'originaL', ValueError), {'http': 8})
        self.assertEqual(analyze.call_count, 2)

    def test_failed_analysis_is_not_cached_or_replaced_with_previous_success(self):
        with patch.object(native, '_locate', side_effect=[{'http': 7}, ValueError('changed structure'), {'http': 8}]) as analyze:
            native.locate(b'original', ValueError)
            with self.assertRaisesRegex(ValueError, 'changed structure'):
                native.locate(b'changed!', ValueError)
            self.assertEqual(native.locate(b'changed!', ValueError), {'http': 8})
        self.assertEqual(analyze.call_count, 3)


class FileAddressTests(unittest.TestCase):
    def test_relative_reference_prefilter_matches_full_scan_across_blocks_and_sections(self):
        base=0x140000000
        data=bytearray(random.Random(42).randbytes(0x34000))
        regions=[(0,0x18000,base),(0x1c000,len(data),base+0x90000)]
        def address(at):
            return next(va+at-start for start,end,va in regions if start<=at<end)
        targets=[base-0x10000,base+0x10100,base+0x90030,base+0x80000000]
        for target in targets:
            for at,opcode in [(0x20,b'\xe8'),(0xfffe,b'\xe9'),(0x10013,b'\x48\x8d\x05'),
                              (0x1c008,b'\xe8'),(0x2bffd,b'\x4c\x8d\x1d')]:
                displacement=target-address(at)-len(opcode)-4
                if -0x80000000<=displacement<=0x7fffffff:
                    data[at:at+len(opcode)+4]=opcode+struct.pack('<i',displacement)
            def reaches(at,size):
                try:
                    return address(at)+size+struct.unpack_from('<i',data,at+size-4)[0]==target
                except (StopIteration,struct.error):
                    return False
            expected={(m.start(),5 if len(m[0])==1 else 7) for m in
                      re.finditer(rb'[\xe8\xe9]|[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',data)
                      if reaches(m.start(),5 if len(m[0])==1 else 7)}
            actual={(at,size) for at,size in _relative_reference_candidates(data,regions,target) if reaches(at,size)}
            self.assertEqual(actual,expected)

    def image(self, sections):
        return SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x140000000,SizeOfHeaders=0x200),
            sections=[SimpleNamespace(PointerToRawData=start,SizeOfRawData=size,
                                      VirtualAddress=rva) for start,size,rva in sections])

    def test_section_mapping_handles_headers_gaps_and_different_rva_deltas(self):
        address=_file_address_map(self.image([(0x600,0x200,0x5000),(0x200,0x200,0x1000)]),0x900)
        for at,expected in ((0x80,0x80),(0x200,0x1000),(0x3ff,0x11ff),(0x600,0x5000),(0x7ff,0x51ff)):
            self.assertEqual(address(at),0x140000000+expected)
        for at in (-1,0x400,0x800,0x900):
            with self.subTest(at=at),self.assertRaises(ValueError):
                address(at)

    def test_overlapping_or_empty_sections_are_refused(self):
        for sections in ([(0x100,0x200,0x1000)],[(0x200,0x300,0x1000),(0x400,0x100,0x4000)],
                         [(0x1000,0x100,0x1000)]):
            with self.subTest(sections=sections),self.assertRaises(ValueError):
                _file_address_map(self.image(sections),0x900)


class OutlinedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads((ROOT/'tests/fixtures/outlined-retry.json').read_text(encoding='utf-8'))

    def decode(self,data,address):
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        cs.detail=True
        return list(cs.disasm(data,address))

    def test_unmapped_pe_offsets_are_rejected_as_structure_mismatches(self):
        class PE:
            def __init__(self, rva):
                self.rva=rva

            def get_rva_from_offset(self, offset):
                return self.rva

        self.assertEqual(_mapped_va(PE(0x1234),0x140000000,0x80),0x140001234)
        with self.assertRaisesRegex(ValueError,'outside mapped PE sections'):
            _mapped_va(PE(None),0x140000000,0x80)

    def layout(self,shift=0,mutate=None):
        f=self.fixture
        data=bytearray.fromhex(f['outer']['hex'])
        address=f['outer']['va']+shift
        instructions=self.decode(data,address)
        if mutate:
            mutate(data,instructions,address)
            instructions=self.decode(data,address)
        call=next(n for n,i in enumerate(instructions) if i.mnemonic=='call'
                  and i.operands[0].imm==f['helper']['va']+shift)
        helper=classifier(self.decode(bytes.fromhex(f['helper']['hex']),f['helper']['va']))
        def off(va):
            if not address<=va<address+len(data): raise ValueError('outside fixture')
            return va-address
        return outer(instructions,call,helper,data,off),instructions,data,off

    def test_address_relocation_preserves_fields_and_relative_patches(self):
        original=self.layout()[0]
        shifted=self.layout(0x12340000)[0]
        for name in ('call','init','connection','bounded','deadline','continuation'):
            self.assertEqual(shifted[name]-original[name],0x12340000)
        def plan(s):
            s=dict(s,offsets={k:s[k]-s['init'] for k in ('call','init','connection','deadline','http')})
            return replacements(s,dict(max_retries=20,interval_ms=1000))
        self.assertEqual(plan(dict(original,http=original['init']-100)),
                         plan(dict(shifted,http=shifted['init']-100)))

    def test_consistent_state_field_changes_are_supported(self):
        def change(data,ins,address):
            for i in ins:
                if i.disp_size==4 and any(op.type==3 and i.reg_name(op.mem.base) in ('r13','r15') for op in i.operands):
                    struct.pack_into('<i',data,i.address-address+i.disp_offset,i.disp+0x40)
        self.assertEqual(self.layout()[0],self.layout(mutate=change)[0])

    def test_resumed_state_register_allocation_can_change(self):
        def change(data,ins,address):
            for i in ins:
                if any(op.type==3 and i.reg_name(op.mem.base)=='r15' for op in i.operands):
                    at=i.address-address+i.modrm_offset
                    data[at]=(data[at]&0xf8)|6  # r15 memory base -> r14
                if (i.mnemonic=='mov' and i.operands[0].type==1
                        and i.reg_name(i.operands[0].reg)=='r15' and i.operands[1].type==3):
                    at=i.address-address+i.modrm_offset
                    data[at]=(data[at]&0xc7)|(6<<3)
        self.assertEqual(self.layout()[0],self.layout(mutate=change)[0])

    def test_changed_terminal_mask_is_retained_without_known_enum_bits(self):
        raw=bytes.fromhex(self.fixture['helper']['hex'])
        for mask in (0x8f8cf7d9e3,0x8f8cf7d9e3 ^ (1<<20)):
            data=raw.replace(struct.pack('<Q',0x8f8cf7d9e3),struct.pack('<Q',mask))
            prefix=classifier(self.decode(data,self.fixture['helper']['va']))
            self.assertIn(struct.pack('<Q',mask),prefix)

    def test_classifier_rejects_stack_reads_and_nonvolatile_writes(self):
        raw=bytes.fromhex(self.fixture['helper']['hex'])
        for changed in (raw.replace(bytes.fromhex('4889d0'),bytes.fromhex('4889d3'),1),
                        raw.replace(bytes.fromhex('488b11'),bytes.fromhex('488b1424'),1)):
            with self.assertRaises(ValueError):
                classifier(self.decode(changed,self.fixture['helper']['va']))

    def test_mismatched_delay_field_is_rejected(self):
        def change(data,ins,address):
            i=next(i for i in ins if i.mnemonic=='mov' and i.op_str=='dword ptr [r15 + 0x228], edx')
            struct.pack_into('<i',data,i.address-address+i.disp_offset,0x229)
        with self.assertRaises(ValueError): self.layout(mutate=change)

    def test_external_branch_into_repurposed_connection_block_is_rejected(self):
        s,ins,data,off=self.layout()
        start=ins[0].address-5
        branch=b'\xe9'+struct.pack('<i',s['connection']+10-start-5)
        with self.assertRaisesRegex(ValueError,'branch into'):
            safe_ranges(self.decode(branch,start)+ins,[(s['connection'],s['bounded'])],data,off)

    def helper(self, fallback=14, mask=0x123456789ab):
        # Synthetic classifier; enum fallback and terminal mask are inputs.
        return (bytes.fromhex('4883ec384889d0488b1149b900000000000000804931d1')
                + bytes.fromhex('4885d241b8') + struct.pack('<I',fallback)
                + bytes.fromhex('4d0f48c1ba00ca9a3b49b9') + struct.pack('<Q',mask)
                + bytes.fromhex('4d0fa3c173054883c438c390'))

    def test_classifier_accepts_changed_enum_and_register_allocation(self):
        for fallback in (0,13,14,63):
            for mask in (0x123456789ab,0xabcdef123456):
                with self.subTest(fallback=fallback,mask=mask):
                    data=self.helper(fallback,mask)
                    prefix=classifier(self.decode(data,0x1000))
                    self.assertIn(struct.pack('<Q',mask),prefix)

    def test_duration_none_encoding_and_branch_direction_come_from_the_caller(self):
        for none_value in (1_000_000_000, 0xffffffff, 0xfffffffe):
            for jump in (b'\x74', b'\x75'):
                for compare in (b'\x81\xfa'+struct.pack('<I',none_value),
                                b'\x83\xfa'+bytes([none_value & 255])):
                    if len(compare)==3 and none_value==1_000_000_000:
                        continue
                    raw=b'\xe8\0\0\0\0\x90'+compare+jump+b'\x01\x90\xc3'
                    ins=self.decode(raw,0x1000)
                    expected=(ins[-2].address,ins[-1].address)
                    if jump==b'\x75':
                        expected=expected[::-1]
                    with self.subTest(none_value=none_value,jump=jump,compare=compare):
                        self.assertEqual(duration_branch(ins,0),(none_value,*expected))
                        helper=self.helper().replace(bytes.fromhex('ba00ca9a3b'),b'\xba'+struct.pack('<I',none_value))
                        classifier(self.decode(helper,0x2000),none_value)
                        if none_value!=1_000_000_000:
                            with self.assertRaisesRegex(ValueError,'None duration'):
                                classifier(self.decode(self.helper(),0x2000),none_value)

    def test_duration_branch_refuses_valid_nanoseconds_and_invalid_successors(self):
        for raw in (bytes.fromhex('e80000000083fa01740190c3'),
                    bytes.fromhex('e80000000083faff740290c3'),
                    bytes.fromhex('e80000000083faff750090c3'),
                    bytes.fromhex('e80000000083faff720190c3')):
            with self.subTest(raw=raw.hex()),self.assertRaises(ValueError):
                duration_branch(self.decode(raw,0x1000),0)

    def test_outer_preserves_none_cleanup_between_connection_and_budget_blocks(self):
        # Invented layout: a JE None branch skips over the live retry block.
        # The cleanup block has an incoming edge and cannot become code space.
        address=0x5000
        for none_value in (1_000_000_000,0xffffffff):
            data=bytearray()
            labels={}
            jumps=[]
            def emit(raw):
                data.extend(bytes.fromhex(raw))
            def jump(opcode,target):
                emit(opcode)
                jumps.append((len(data),target))
                data.extend(b'\0'*4)
            emit('498b8508000000498985100000004c8b6d20488b7528')
            emit('498955304889f1')
            call_address=address+len(data)
            data.extend(b'\xe8'+struct.pack('<i',0x3000-call_address-5))
            data.extend(b'\x90\x81\xfa'+struct.pack('<I',none_value))
            jump('0f84','absent')
            emit('4c8b7d204989474041895748498b4750418b8f58000000')
            emit('4989476041894f68498b47204885c04c8b4528')
            jump('0f84','bounded')
            jump('e9','bounded')
            data.extend(b'\x90'*128)
            labels['absent']=address+len(data)
            emit('41c6477000c3')
            labels['bounded']=address+len(data)
            emit('498b4708488b08493b4f10')
            jump('0f83','end')
            emit('4d8b4f304c8908498b4710498b4720498b4740418b4f48')
            data.extend(b'\x90'*18)
            labels['end']=address+len(data)
            emit('c3')
            for at,target in jumps:
                struct.pack_into('<i',data,at,labels[target]-address-at-4)
            helper=self.helper().replace(bytes.fromhex('ba00ca9a3b'),b'\xba'+struct.pack('<I',none_value))
            prefix=classifier(self.decode(helper,0x3000),none_value)
            ins=self.decode(data,address)
            call=next(n for n,i in enumerate(ins) if i.address==call_address)
            sites=outer(ins,call,prefix,data,lambda va:va-address)
            self.assertEqual(sites['connection_end'],labels['absent'])
            self.assertGreater(sites['bounded'],sites['connection_end'])
            self.assertEqual(sites['bounded_reload'],bytes.fromhex('4c8b4528'))
            sites.update(http=labels['end'],http_size=3)
            sites['offsets']={k:sites[k]-address for k in ('call','init','deadline','connection','http')}
            patches=replacements(sites,dict(max_retries=30,interval_ms=1000))
            trampoline=self.decode(patches[1][2],sites['connection'])
            self.assertEqual(trampoline[0].op_str,'r8, qword ptr [rbp + 0x28]')
            self.assertEqual(trampoline[1].operands[0].imm,sites['bounded'])
            redirect=self.decode(patches[0][2],sites['call'])[0]
            self.assertEqual(redirect.operands[0].imm,trampoline[2].address)
            before=bytes(data)
            for at,size,new,_ in patches[:-1]:
                self.assertLessEqual(len(new),size)
                data[at:at+size]=new+b'\x90'*(size-len(new))
            self.assertEqual(data[labels['absent']-address:labels['bounded']-address],
                             before[labels['absent']-address:labels['bounded']-address])
            self.assertEqual(patches[3][2],b'\xb9'+struct.pack('<I',none_value))
            for before_hex,after_hex in (('4c8b4528','4c8b4530'),
                                         ('4885c04c8b4528','4c8b45284531c0'),
                                         ('488b7528','9031f690')):
                changed=before.replace(bytes.fromhex(before_hex),bytes.fromhex(after_hex),1)
                self.assertEqual(len(changed),len(before))
                changed_ins=self.decode(changed,address)
                changed_call=next(n for n,i in enumerate(changed_ins) if i.address==call_address)
                with self.assertRaisesRegex(ValueError,'bounded error'):
                    outer(changed_ins,changed_call,prefix,changed,lambda va:va-address)
            wrong_prefix=classifier(self.decode(self.helper(),0x3000))
            if none_value!=1_000_000_000:
                with self.assertRaisesRegex(ValueError,'None duration'):
                    outer(ins,call,wrong_prefix,before,lambda va:va-address)

    def test_classifier_rejects_unproven_tag_flags_mask_and_sentinel(self):
        raw=self.helper()
        changes=[('4885d2','4885c0'),  # Sign flags from attempt instead of tag.
                 ('4d0f48c1','4d0f48c0'),  # Selects its fallback, not untagged error.
                 ('4d0fa3c1','4d0fa3c0'),  # BT operand is not the mask.
                 ('ba00ca9a3b','ba01ca9a3b'),
                 ('488b11','488b12'),  # Wrong pointer provenance.
                 ('4931d1','4131d1'),  # Truncates the tag normalization.
                 ('41b80e000000','41b840000000'),  # Out-of-range fallback.
                 ('488b11','65488b11')]
        for before,after in changes:
            with self.subTest(change=after), self.assertRaises(ValueError):
                classifier(self.decode(raw.replace(bytes.fromhex(before),bytes.fromhex(after),1),0x1000))

    def http_fragment(self, indirect=True):
        # Small invented state layout, branch destinations and call target.
        tag='498d5720488b1a' if indirect else '498b5f20'
        return bytes.fromhex(tag+'4883fb0c7400'
            '498b7f10493b7f087300'  # Counter, budget, exhausted.
            '4889d94883e904b801000000480f43c18d48fd83f9037300'
            'e80000000048ffc749897f30c3')

    def http_layout(self, raw=None, address=0x2000):
        data=bytearray(raw if raw is not None else self.http_fragment())
        ins=self.decode(data,address)
        compare=next(n for n,i in enumerate(ins) if i.mnemonic=='cmp' and i.operands[1].type==3)
        # All synthetic conditional exits target the final RET.
        for i in ins:
            if i.mnemonic in ('je','jae'):
                data[i.address-address+i.size-1]=ins[-1].address-i.address-i.size
        ins=self.decode(data,address)
        off=lambda va:va-address
        return http_budget(ins,compare,data,off),ins,data,off

    def test_http_gate_accepts_direct_indirect_and_relocated_state(self):
        for indirect in (False,True):
            raw=self.http_fragment(indirect)
            for address in (0x2000,0x12342000):
                with self.subTest(indirect=indirect,address=address):
                    result,ins,_,_=self.http_layout(raw,address)
                    cmp=next(i for i in ins if i.address==result['http'])
                    self.assertEqual(result['http_size'],cmp.size)
                    # Moving every state field together preserves their relation.
                    shifted=bytearray(raw)
                    for i in self.decode(raw,address):
                        if i.disp_size and any(o.type==3 and i.reg_name(o.mem.base)=='r15' for o in i.operands):
                            shifted[i.address-address+i.disp_offset]+=0x10
                    self.assertEqual(result,self.http_layout(shifted,address)[0])

    def test_http_gate_accepts_register_reallocation(self):
        raw=self.http_fragment(False)
        variants=[raw.replace(bytes.fromhex('4889d94883e904b801000000480f43c18d48fd83f903'),
                              bytes.fromhex('4989d84983e804ba01000000490f43d08d4afd83f903')),
                  raw.replace(bytes.fromhex('b801000000480f43c18d48fd'),
                              bytes.fromhex('be01000000480f43f18d4efd')),
                  raw.replace(bytes.fromhex('498b7f10493b7f08'),bytes.fromhex('498b7710493b7708'))
                     .replace(bytes.fromhex('48ffc749897f30'),bytes.fromhex('48ffc649897730')),
                  raw.replace(bytes.fromhex('498b5f20'),bytes.fromhex('498b5e20'))
                     .replace(bytes.fromhex('498b7f10493b7f08'),bytes.fromhex('498b7e10493b7e08'))
                     .replace(bytes.fromhex('49897f30'),bytes.fromhex('49897e30'))]
        for raw in variants:
            self.http_layout(raw)

    def test_http_gate_accepts_signed_normalization_with_the_same_field_proof(self):
        for indirect in (False,True):
            raw=self.http_fragment(indirect).replace(bytes.fromhex('480f43c1'),bytes.fromhex('480f4dc1'))
            raw=raw.replace(bytes.fromhex('4883e904'),bytes.fromhex('4883e903'))
            self.http_layout(raw)
            for before,after in (('480f4dc1','480f4cc1'),
                                 ('b801000000480f4dc1','31c0480f4dc1909090'),
                                 ('49897f30','49897e30')):
                with self.subTest(change=after),self.assertRaises(ValueError):
                    self.http_layout(raw.replace(bytes.fromhex(before),bytes.fromhex(after),1))

    def http_reloaded_fragment(self):
        # State starts in RAX, classification reuses RAX, then the same frame
        # slot supplies RSI. R12 is the counter across the intervening call.
        return bytes.fromhex('488b4528488b58204883fb0c7400'
            '4c8b60104c3b60087300'
            '4889d94883e904b801000000480f4dc18d48fd83f9037300'
            '488b7528e80000000049ffc44c896630c3')

    def test_http_gate_tracks_reloaded_state_across_register_and_frame_changes(self):
        raw=self.http_reloaded_fragment()
        variants=[raw,
                  raw.replace(bytes.fromhex('488b4528'),bytes.fromhex('488b4548'))
                     .replace(bytes.fromhex('488b7528'),bytes.fromhex('488b7548')),
                  raw.replace(bytes.fromhex('488b4528'),bytes.fromhex('488b442440'))
                     .replace(bytes.fromhex('488b7528'),bytes.fromhex('488b742440')),
                  raw.replace(bytes.fromhex('488b4528'),bytes.fromhex('4c8b5528'))
                     .replace(bytes.fromhex('488b5820'),bytes.fromhex('498b5a20'))
                     .replace(bytes.fromhex('4c8b60104c3b6008'),bytes.fromhex('4d8b62104d3b6208')),
                  raw.replace(bytes.fromhex('488b7528'),bytes.fromhex('4c8b6d28'))
                     .replace(bytes.fromhex('4c896630'),bytes.fromhex('4d896530')),
                  raw.replace(bytes.fromhex('480f4dc1'),bytes.fromhex('480f43c1'))]
        for variant in variants:
            for address in (0x2000,0x12342000):
                with self.subTest(raw=variant.hex(),address=address):
                    self.http_layout(variant,address)

    def test_http_gate_tracks_full_register_copies_of_state(self):
        raw=self.http_reloaded_fragment()
        # Preserve RAX in R13 before normalization, then copy R13 to RSI.
        raw=raw.replace(bytes.fromhex('4c8b6010'),bytes.fromhex('4989c54c8b6010'))
        raw=raw.replace(bytes.fromhex('488b7528'),bytes.fromhex('4c89ee'))
        self.http_layout(raw)
        with self.assertRaises(ValueError):
            self.http_layout(raw.replace(bytes.fromhex('4c89ee'),bytes.fromhex('4489ee')))

    def test_http_gate_rejects_invalid_reloaded_state_provenance(self):
        raw=self.http_reloaded_fragment()
        changes=[('488b7528','488b7530'),             # Different source slot.
                 ('4c896630','4d896530'),             # Different destination object.
                 ('488b7528','48c7452800000000488b7528'),  # Overwrite source slot.
                 ('488b7528','c6452f00488b7528'),      # Partial slot write.
                 ('488b7528','48c7452400000000488b7528'),  # Overlapping slot write.
                 ('488b7528','40b501488b7528'),        # Partial frame register write.
                 ('488b7528','488d4d28488b7528'),      # Escaping slot address.
                 ('488b7528','4889e9488b7528'),        # Escaping frame pointer.
                 ('49ffc4','40b60149ffc4'),           # Partial final state overwrite.
                 ('488b7528','7504488b7528'),         # Branch can bypass reload.
                 ('4c8b6010','e8000000004c8b6010')]   # RAX lost before budget load.
        for before,after in changes:
            with self.subTest(change=after),self.assertRaises(ValueError):
                self.http_layout(raw.replace(bytes.fromhex(before),bytes.fromhex(after),1))

    def test_http_gate_rejects_volatile_reload_across_call(self):
        raw=self.http_reloaded_fragment().replace(bytes.fromhex('488b7528'),bytes.fromhex('488b4d28'))
        raw=raw.replace(bytes.fromhex('4c896630'),bytes.fromhex('4c896130'))
        with self.assertRaises(ValueError):
            self.http_layout(raw)
        self.http_layout(raw.replace(bytes.fromhex('e800000000'),b''))

    def test_http_gate_checks_stack_slot_survival_across_calls(self):
        raw=self.http_reloaded_fragment()
        raw=raw.replace(bytes.fromhex('488b7528'),bytes.fromhex('e800000000488b7528'))
        self.http_layout(raw)
        for displacement in (0x18,0x40):
            variant=raw.replace(bytes.fromhex('488b4528'),bytes.fromhex('488b4424')+bytes([displacement]))
            variant=variant.replace(bytes.fromhex('488b7528'),bytes.fromhex('488b7424')+bytes([displacement]))
            if displacement < 32:
                with self.assertRaises(ValueError):
                    self.http_layout(variant)
            else:
                self.http_layout(variant)

    def test_http_gate_rejects_alias_clobbers_and_mismatched_fields(self):
        raw=self.http_fragment()
        changes=[('4889d9','4989df'),  # Normalization overwrites state.
                 ('4889d9','4889df'),  # Normalization overwrites counter.
                 ('b801000000480f43c18d48fd','bf01000000480f43f98d4ffd'),  # EDI alias.
                 ('8d48fd83f903','418d7ffd83ff03'),  # Range temp aliases counter.
                 ('4883fb0c','31db'),  # EBX invalidates the loaded error tag.
                 ('4883fb0c','4531ff'),  # R15D invalidates state provenance.
                 ('4883fb0c','41b701'),  # R15B also invalidates state.
                 ('498d5720','498d5710'),  # Tag overlaps attempt.
                 ('498d5720','498d570c'),  # Partial overlap with budget/attempt.
                 ('493b7f08','493b7f10'),  # Budget equals attempt.
                 ('493b7f08','65493b7f08'),  # Segment-based memory access.
                 ('488b1a','65488b1a'),
                 ('488b1a','488b1c0a'),  # Indexed tag load.
                 ('498d5720','498d5620'),  # Tag from different state.
                 ('49897f30','49897e30'),  # Store to different state.
                 ('49897f30','49897f24'),  # Next attempt overlaps tag.
                 ('48ffc7','31ff48ffc7'),  # EDI clobber before increment.
                 ('48ffc7','4531ff48ffc7'),  # R15D clobber before increment.
                 ('48ffc7','40b70148ffc7'),  # DIL partial clobber.
                 ('49897f30','6549897f30'),
                 ('e800000000','c390909090'),  # Unreachable increment.
                 ('8d48fd83f903','4885c9'),  # Similar normalization, unrelated gate.
                 ('83f903','83f900'),  # Empty error range.
                 ('b801000000','b803000000')]  # Fallback enters retry range.
        for before,after in changes:
            with self.subTest(change=after), self.assertRaises(ValueError):
                self.http_layout(raw.replace(bytes.fromhex(before),bytes.fromhex(after),1))

    def test_http_gate_rejects_branch_into_comparison(self):
        result,ins,data,off=self.http_layout()
        source=ins[0].address-5
        jump=b'\xe9'+struct.pack('<i',result['http']+1-source-5)
        compare=next(n for n,i in enumerate(ins) if i.address==result['http'])
        with self.assertRaisesRegex(ValueError,'branch into'):
            http_budget(self.decode(jump,source)+ins,compare+1,data,off)

    def test_http_replacement_supports_comparison_width_and_preserves_branch_flags(self):
        base=self.layout()[0]
        for raw in (self.http_fragment(),self.http_fragment().replace(bytes.fromhex('493b7f08'),bytes.fromhex('493bbf80000000'))):
            gate,_,_,_=self.http_layout(raw)
            sites=dict(base,**gate)
            sites['offsets']={k:sites[k] for k in ('call','init','connection','deadline','http')}
            patch=replacements(sites,dict(max_retries=20,interval_ms=1000))[-1]
            self.assertEqual(patch[1],gate['http_size'])
            self.assertEqual(self.decode(patch[2],0)[0].op_str,'eax, eax')

    def test_http_enum_numbers_and_immediate_width_can_change(self):
        raw=self.http_fragment()
        changed=raw.replace(bytes.fromhex('4883e904b801000000'),
                            bytes.fromhex('4881e909000000b802000000'))
        changed=changed.replace(bytes.fromhex('8d48fd83f903'),bytes.fromhex('8d48fa83f905'))
        for variant in (raw,changed):
            self.http_layout(variant)

    def outlined_image(self, gates=1, unknown_caller=False, missing_endpoint=False,
                       changed_enum=False, duplicate_outer=False, signed_enum=False, reloaded_last=False, optimized=False):
        """Sparse real outer fragment plus synthetic protocol-scoped gates.

        No log, instrumentation or function-name strings exist in this image.
        Mutated instructions are decoded only and are never executed.
        """
        base=0x100000
        data=bytearray()
        functions=[]
        outer_raw=bytearray.fromhex(self.fixture['outer']['hex'])
        original=self.decode(outer_raw,base)
        call=next(i for i in original if i.mnemonic=='call' and
                  i.operands[0].imm==self.fixture['helper']['va']-self.fixture['outer']['va']+base)
        helper_raw=bytes.fromhex(self.fixture['helper']['hex'])
        helper_at=len(outer_raw)+16
        struct.pack_into('<i',outer_raw,call.address-base+1,helper_at-(call.address-base)-5)
        def add(raw):
            at=len(data)
            data.extend(raw)
            functions.append((at,len(raw)))
            data.extend(b'\xcc'*16)
            return at
        add(outer_raw)
        add(helper_raw)
        if duplicate_outer:
            other=bytearray(outer_raw)
            struct.pack_into('<i',other,call.address-base+1,helper_at-len(data)-(call.address-base)-5)
            add(other)
        http=[]
        references=[]
        for number in range(gates):
            raw=self.http_reloaded_fragment() if reloaded_last and number==gates-1 else self.http_fragment()
            if signed_enum:
                raw=raw.replace(bytes.fromhex('480f43c1'),bytes.fromhex('480f4dc1'))
            if changed_enum:
                raw=raw.replace(bytes.fromhex('4883e904b801000000'),
                                bytes.fromhex('4881e909000000b802000000'))
                raw=raw.replace(bytes.fromhex('8d48fd83f903'),bytes.fromhex('8d48fa83f905'))
            # Resolve synthetic conditional exits before adding protocol LEA.
            _,_,raw,_=self.http_layout(raw)
            at=add(b'\x48\x8d\x05'+b'\0'*4+raw)
            references.append((at,7))
            http.append(at)
        root_at=len(data)
        root=b'\x48\x8d\x05'+b'\0'*4
        root+=bytes.fromhex('488944243048c74424380a000000')
        for at in http:
            source=root_at+len(root)
            root+=b'\xe8'+struct.pack('<i',at-source-5)
        add(root+b'\xc3')
        if unknown_caller:
            at=len(data)
            add(b'\xe8'+struct.pack('<i',http[-1]-at-5)+b'\xc3')
        sse_at=len(data)
        data.extend(b'text/event-stream\0')
        endpoint_at=len(data)
        data.extend(b'/unrelated\0' if missing_endpoint else b'/responses\0')
        for at,size in references:
            struct.pack_into('<i',data,at+size-4,sse_at-at-size)
        struct.pack_into('<i',data,root_at+3,endpoint_at-root_at-7)
        def function(at):
            for start,size in functions:
                if start<=at<start+size:
                    return (base+start,base+start+size),self.decode(data[start:start+size],base+start)
            raise ValueError('outside fixture function')
        def refs(ins,needle):
            return any(o.type==3 and i.reg_name(o.mem.base)=='rip' and
                       data[i.address+i.size+o.mem.disp-base:][:len(needle)]==needle
                       for i in ins for o in i.operands)
        options = dict(reference_candidates=lambda target: _relative_reference_candidates(data,[(0,len(data),base)],target),
                       has_reference=lambda at,needle: refs(function(at)[1],needle)) if optimized else {}
        return locate_outlined(data,function,lambda va:va-base,lambda at:base+at,refs,None,**options)

    def test_optimized_locator_preserves_sites_and_unproven_caller_rejection(self):
        self.assertEqual(self.outlined_image(gates=2,reloaded_last=True),
                         self.outlined_image(gates=2,reloaded_last=True,optimized=True))
        for options in (dict(unknown_caller=True),dict(missing_endpoint=True)):
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.outlined_image(gates=2,optimized=True,**options)

    def test_locator_needs_no_log_or_function_names(self):
        for changed_enum in (False,True):
            for signed_enum in (False,True):
                s=self.outlined_image(changed_enum=changed_enum,signed_enum=signed_enum)
                self.assertEqual(len(s['http_sites']),1)
                self.assertEqual(len(replacements(s,dict(max_retries=20,interval_ms=1000))),5)

    def test_locator_handles_multiple_proven_responses_gates(self):
        for signed_enum in (False,True):
            s=self.outlined_image(gates=2,signed_enum=signed_enum)
            patches=replacements(s,dict(max_retries=20,interval_ms=1000))
            self.assertEqual(len(patches),6)
            self.assertEqual({p[0] for p in patches[-2:]},{g['offset'] for g in s['http_sites']})

    def test_locator_includes_reloaded_gate_alongside_stable_gate(self):
        for count in (1,2):
            sites=self.outlined_image(gates=count,reloaded_last=True)
            self.assertEqual(len(sites['http_sites']),count)
            self.assertEqual(len(replacements(sites,dict(max_retries=50,interval_ms=1000))),4+count)

    def test_locator_refuses_unproven_gate_even_when_another_gate_is_valid(self):
        for options in (dict(gates=2,unknown_caller=True),dict(missing_endpoint=True),dict(duplicate_outer=True)):
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.outlined_image(**options)

    def transport_layout(self, shift=0, wrong_marker=False, extra_caller=False, wrong_endpoint=False,
                         wrapper=False, unrelated_parent=False, unlinked=False, wrong_length=False,
                         tail=False, address_taken=False, function_pointer=False):
        base=0x500000+shift
        data=bytearray(b'\xcc'*0x200)
        entry=base+0x180
        endpoint=b'/responses'
        encoding=b'$failed to encode responses request: '
        data[0x100:0x100+len(endpoint)]=b'?'*len(endpoint) if wrong_endpoint else endpoint
        data[0x120:0x120+len(encoding)]=b'?'*len(encoding) if wrong_marker else encoding
        def call(at,target):
            return b'\xe8'+struct.pack('<i',target-at-5)
        def request(at,target):
            code=b'\x48\x8d\x05'+struct.pack('<i',0x100-at-7)
            code+=bytes.fromhex('488944243048c7442438')+struct.pack('<I',11 if wrong_length else 10)
            code+=b'\x48\x8d\x15'+struct.pack('<i',0x120-at-len(code)-7)
            return code+call(at+len(code),target)
        code=request(0x20,0x180)
        if wrapper and not unlinked:
            code+=call(0x20+len(code),0x80)
        code+=b'\xc3'
        data[0x20:0x20+len(code)]=code
        functions=[(0x20,len(code))]
        # A raw CALL byte in a MOVABS immediate has a plausible relative
        # destination but is not a decoded instruction boundary.
        false=b'\x48\xb8\xe8'+struct.pack('<i',0x180-0x67)+b'\0'*3+b'\xc3'
        data[0x60:0x60+len(false)]=false
        functions.append((0x60,len(false)))
        if extra_caller:
            data[0x80:0x86]=b'\xe8'+struct.pack('<i',0x180-0x85)+b'\xc3'
            functions.append((0x80,6))
        if wrapper:
            raw=call(0x80,0x180)+b'\xc3'
            if tail:
                raw=b'\xe9'+raw[1:]
            data[0x80:0x80+len(raw)]=raw
            functions.append((0x80,len(raw)))
            raw=(call(0xa0,0x80) if unrelated_parent else request(0xa0,0x80))+b'\xc3'
            data[0xa0:0xa0+len(raw)]=raw
            functions.append((0xa0,len(raw)))
        if address_taken:
            raw=b'\x48\x8d\x05'+struct.pack('<i',0x180-0xc7)+b'\xc3'
            data[0xc0:0xc0+len(raw)]=raw
            functions.append((0xc0,len(raw)))
        if function_pointer:
            data[0x1c0:0x1c8]=struct.pack('<Q',entry)
        data[-1]=0xe8  # A truncated scan candidate must be ignored.
        def function(at):
            for start,size in functions:
                if start<=at<start+size:
                    return (base+start,base+start+size),self.decode(data[start:start+size],base+start)
            raise ValueError('outside fixture function')
        def refs(ins,needle):
            for i in ins:
                for op in i.operands:
                    if op.type==3 and i.reg_name(op.mem.base)=='rip':
                        at=i.address+i.size+op.mem.disp-base
                        if data[at:at+len(needle)]==needle:
                            return True
            return False
        return responses_transport(data,entry,function,lambda va:va-base,lambda at:base+at,refs)

    def test_outlined_http_requires_responses_caller_and_instruction_alignment(self):
        for shift in (0,0x12340000):
            self.assertEqual(self.transport_layout(shift),0x50003c+shift)

    def test_outlined_http_rejects_unproven_or_shared_request_scope(self):
        for options in (dict(wrong_endpoint=True),dict(wrong_length=True),dict(extra_caller=True),
                        dict(address_taken=True),dict(function_pointer=True)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.transport_layout(**options)

    def test_diagnostic_text_is_not_required_for_protocol_scope(self):
        self.assertEqual(self.transport_layout(wrong_marker=True),0x50003c)

    def test_outlined_http_accepts_wrapper_with_only_proven_model_callers(self):
        for shift in (0,0x12340000):
            self.assertEqual(self.transport_layout(shift,wrapper=True),0x50003c+shift)

    def test_outlined_http_rejects_unknown_or_disconnected_wrapper_callers(self):
        for options in (dict(unrelated_parent=True),dict(unlinked=True),dict(tail=True)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.transport_layout(wrapper=True,**options)

    def transport_chain(self, depth, cycle=False, shared=False):
        base=0x900000
        data=bytearray(b'\xcc'*0x1000)
        functions={}
        entry=0x700
        wrappers=[0x100+n*0x40 for n in range(depth)]
        def add(at,targets,model=False):
            raw=b''
            if model:
                raw=b'\x48\x8d\x05'+struct.pack('<i',0x800-at-7)
                raw+=bytes.fromhex('488944243048c74424380a000000')
            for target in targets:
                raw+=b'\xe8'+struct.pack('<i',target-at-len(raw)-5)
            raw+=b'\xc3'
            data[at:at+len(raw)]=raw
            functions[at]=len(raw)
        add(0x20,[wrappers[0] if wrappers else entry],model=True)
        for n,at in enumerate(wrappers):
            targets=[wrappers[n+1] if n+1<len(wrappers) else entry]
            if cycle and n==len(wrappers)-1:
                targets.append(wrappers[0])
            add(at,targets)
        if shared:
            add(0x600,[wrappers[-1] if wrappers else entry])
        data[0x800:0x80b]=b'/responses\0'
        def function(at):
            for start,size in functions.items():
                if start<=at<start+size:
                    return (base+start,base+start+size),self.decode(data[start:start+size],base+start)
            raise ValueError('outside fixture function')
        def refs(ins,needle):
            return any(o.type==3 and i.reg_name(o.mem.base)=='rip' and
                       data[i.address+i.size+o.mem.disp-base:][:len(needle)]==needle
                       for i in ins for o in i.operands)
        return responses_transport(data,base+entry,function,lambda va:va-base,lambda at:base+at,refs)

    def test_protocol_scope_accepts_bounded_wrapper_chains_without_direct_model_call(self):
        for depth in range(5):
            with self.subTest(depth=depth):
                self.assertEqual(self.transport_chain(depth),0x900035)

    def test_protocol_literal_requires_matching_pointer_and_length_fields(self):
        base=0xa00000
        needle=b'/responses'
        def accepts(stores, suffix=b''):
            code=bytes.fromhex('4c8d15')+struct.pack('<i',0x80-7)+bytes.fromhex(stores)+b'\xc3'
            data=code.ljust(0x80,b'\xcc')+needle+suffix
            return protocol_slice(self.decode(code,base),needle,data,lambda va:va-base)
        # R10 feeds a state field; its length belongs to the next qword.
        self.assertTrue(accepts('4c89935801000048c783600100000a000000'))
        for stores in ('',  # A bare reference may be a log or debug string.
                       '4c89935801000048c783600100000b000000',  # Prefix, wrong length.
                       '4c89935801000048c783680100000a000000',  # Wrong field.
                       '4c89935801000048c787600100000a000000',  # Different state.
                       '4c898b5801000048c783600100000a000000'):  # Different pointer.
            with self.subTest(stores=stores):
                self.assertFalse(accepts(stores,b'/compact'))

    def test_protocol_scope_refuses_cycles_excessive_depth_and_shared_wrappers(self):
        for options in (dict(depth=5),dict(depth=2,cycle=True),dict(depth=2,shared=True)):
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.transport_chain(**options)


if __name__=='__main__': unittest.main()
