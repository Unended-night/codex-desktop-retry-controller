"""Regression for native returned policies, byte enums and compacted layouts."""
import copy
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'research/.deps'))
import capstone
from controller.native_return import byte_dispatch, invalid_request_layout, returned_classifier
from controller.native_v4 import outer, safe_ranges
from controller.native_compact import returned_compact_sites


class ReturnedPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads((ROOT/'tests/fixtures/returned-retry.json').read_text(encoding='utf-8'))

    def setUp(self):
        self.chunks=copy.deepcopy(self.fixture['chunks'])
        for c in self.chunks:c['raw']=bytearray.fromhex(c.pop('hex'))
        self.cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        self.cs.detail=True

    def chunk(self,name):
        return next(c for c in self.chunks if c['name']==name)

    def environment(self,delta=0):
        data=bytearray();maps=[]
        for c in self.chunks:
            maps.append((c['address']+delta,len(data),len(c['raw'])))
            data.extend(c['raw'])
        def off(address):
            for base,start,length in maps:
                if base<=address<base+length:return start+address-base
            raise ValueError('outside fixture')
        return data,off

    def body(self,name,delta=0):
        c=self.chunk(name)
        return list(self.cs.disasm(c['raw'],c['address']+delta))

    def helper(self,delta=0):
        data,off=self.environment(delta)
        return returned_classifier(self.body('helper',delta),1_000_000_000,data,off)

    def error(self,delta=0):
        data,off=self.environment(delta)
        ins=self.body('debug',delta)
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['error_name']+delta)
        return invalid_request_layout(ins,n,data,off,self.cs,self.helper(delta))

    def sampling(self,index,delta=0):
        data,off=self.environment(delta)
        ins=self.body(f'sampling{index}',delta)
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['sampling_calls'][index]+delta)
        return outer(ins,n,self.helper(delta),data,off)

    def compact(self,delta=0):
        data,off=self.environment(delta)
        ins=self.body('compact',delta)
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['compact_call']+delta)
        return returned_compact_sites(ins,n,data,off,self.helper(delta))

    def change_displacement(self,name,instruction,value):
        c=self.chunk(name)
        struct.pack_into('<i' if instruction.disp_size==4 else '<b',c['raw'],
                         instruction.address-c['address']+instruction.disp_offset,value)

    def test_real_byte_enum_and_string_fields_relocate(self):
        for delta in (0,0x12340000):
            self.assertEqual(self.error(delta),dict(tag=17,tag_offset=16,tag_size=1,pointer=32,length=40))
            self.assertEqual(self.helper(delta)['deadline_only_tags'],[26,27,37])

    def test_enum_reordering_is_derived_from_both_tables(self):
        for prefix in ('helper-table','debug-table'):
            c=next(c for c in self.chunks if c['name'].startswith(prefix))
            raw=c['raw']
            raw[17*4:18*4],raw[33*4:34*4]=raw[33*4:34*4],raw[17*4:18*4]
        self.assertEqual(self.error()['tag'],33)

    def test_byte_tag_and_string_offsets_can_drift_together(self):
        for name in ('helper','debug'):
            i=next(i for i in self.body(name) if i.mnemonic=='movzx' and i.operands[1].type==3)
            self.change_displacement(name,i,0x14)
        for i in self.body('formatter')[2:4]:
            self.change_displacement('formatter',i,i.disp+8)
        self.assertEqual(self.error(),dict(tag=17,tag_offset=20,tag_size=1,pointer=40,length=48))

    def test_disagreeing_enum_source_and_string_pair_are_refused(self):
        i=next(i for i in self.body('debug') if i.mnemonic=='movzx' and i.operands[1].type==3)
        self.change_displacement('debug',i,0x18)
        with self.assertRaisesRegex(ValueError,'disagrees'):self.error()
        self.setUp()
        i=self.body('formatter')[3]
        self.change_displacement('formatter',i,i.disp+8)
        with self.assertRaisesRegex(ValueError,'String view'):self.error()

    def test_none_preset_must_match_the_caller(self):
        c=self.chunk('helper')
        i=next(i for i in self.body('helper') if i.mnemonic=='mov' and i.op_str.startswith('edx,'))
        struct.pack_into('<I',c['raw'],i.address-c['address']+i.imm_offset,0xffffffff)
        with self.assertRaisesRegex(ValueError,'None return'):self.helper()

    def test_dispatch_cannot_reuse_the_live_error_pointer_for_its_table(self):
        c=self.chunk('debug')
        # A coherent table in RCX still destroys the object used by Debug arms.
        for before,after in [('488d15','488d0d'),('48630482','48630481'),('4801d0','4801c8')]:
            c['raw']=c['raw'].replace(bytes.fromhex(before),bytes.fromhex(after),1)
        with self.assertRaisesRegex(ValueError,'object lost'):self.error()

    def test_compaction_and_sampling_none_encodings_must_agree(self):
        data,off=self.environment()
        helper=self.helper();helper['none_value']=0xffffffff
        for name,at,locate in [('sampling0',self.fixture['sampling_calls'][0],outer),
                               ('compact',self.fixture['compact_call'],returned_compact_sites)]:
            ins=self.body(name);n=next(n for n,i in enumerate(ins) if i.address==at)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'None disagrees'):
                if name=='compact':locate(ins,n,data,off,helper)
                else:locate(ins,n,helper,data,off)

    def test_deadline_only_arm_requires_exact_missing_deadline_flow(self):
        c=self.chunk('helper')
        i=next(i for i in self.body('helper') if i.mnemonic=='je')
        c['raw'][i.address-c['address']]=0x75  # Same target, opposite condition.
        self.assertEqual(self.helper()['deadline_only_tags'],[])

    def test_invalid_request_must_still_be_a_native_terminal_arm(self):
        data,off=self.environment()
        ins=self.body('debug')
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['error_name'])
        helper=self.helper();helper['terminal_tags'].remove(17)
        with self.assertRaisesRegex(ValueError,'terminal arm'):
            invalid_request_layout(ins,n,data,off,self.cs,helper)

    def test_all_sampling_instances_share_reporter_and_keep_native_calls(self):
        for delta in (0,0x100000):
            sites=[self.sampling(n,delta) for n in range(3)]
            self.assertEqual(len({s['reporter'] for s in sites}),1)
            self.assertEqual([s['state_register'] for s in sites],['rbx','r13','r8'])
            for s in sites:
                self.assertGreater(s['policy'],s['call']+4)
                self.assertGreaterEqual(s['deadline_size'],5)
            self.assertEqual(sites[1]['deadline_size'],8)  # Two short disp8 loads.

    def test_volatile_budget_reload_must_use_the_same_frame_slot(self):
        site=self.sampling(2)
        i=next(i for i in self.body('sampling2') if i.address==site['bounded'])
        self.change_displacement('sampling2',i,i.disp+8)
        with self.assertRaisesRegex(ValueError,'bounded budget'):self.sampling(2)

    def test_sampling_error_slot_must_agree_with_reporter(self):
        body=self.body('sampling0')
        n=next(n for n,i in enumerate(body) if i.address==self.fixture['sampling_calls'][0])
        self.change_displacement('sampling0',body[n-1],body[n-1].disp+8)
        with self.assertRaisesRegex(ValueError,'error reload'):self.sampling(0)

    def test_jump_into_second_deadline_load_is_refused(self):
        site=self.sampling(1);body=self.body('sampling1');data,off=self.environment()
        first=next(i for i in body if i.address==site['deadline'])
        target=first.address+first.size
        at=body[0].address-5
        branch=list(self.cs.disasm(b'\xe9'+struct.pack('<i',target-at-5),at))
        with self.assertRaisesRegex(ValueError,'interior'):
            safe_ranges(branch+body,[(site['deadline'],site['deadline']+site['deadline_size'])],data,off)

    def test_compaction_classifier_fields_and_relocation(self):
        original=self.compact()
        shifted=self.compact(0x100000)
        self.assertEqual(shifted['policy']-original['policy'],0x100000)
        self.assertEqual(original['init_size'],9)
        self.assertEqual(original['error_reload'],bytes.fromhex('4c89f9'))

    def test_compaction_rejects_mismatched_deadline_and_counter_fields(self):
        c=self.compact();data,off=self.environment()
        i=next(i for i in self.body('compact') if off(i.address)==c['deadline'])
        self.change_displacement('compact',i,i.disp+8)
        with self.assertRaisesRegex(ValueError,'Duration pair'):self.compact()
        self.setUp()
        body=self.body('compact')
        n=next(n for n,i in enumerate(body) if i.address==self.fixture['compact_call'])
        i=body[n-3]
        self.change_displacement('compact',i,i.disp+8)
        with self.assertRaisesRegex(ValueError,'budget'):self.compact()
