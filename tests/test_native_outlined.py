"""Real instruction fragments: relocation, field drift and unsafe mutations."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'research/.deps'))
import capstone
from controller.native_v4 import classifier, outer, replacements, safe_ranges


class OutlinedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads((ROOT/'tests/fixtures/outlined-retry.json').read_text(encoding='utf-8'))

    def decode(self,data,address):
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        cs.detail=True
        return list(cs.disasm(data,address))

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


if __name__=='__main__': unittest.main()
