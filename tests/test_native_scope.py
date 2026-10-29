"""Native fragments prove error fields and compaction counters without addresses."""
import json
import random
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'research/.deps'))
import capstone
from controller.native_errors import invalid_request_layout, name_references
from controller.native_compact import compact_sites
from controller.native_extension import layout,section_patches


class ScopeStructureTests(unittest.TestCase):
    def setUp(self):
        self.fixture=json.loads((ROOT/'tests/fixtures/retry-scope.json').read_text())
        self.chunks={c['name']:dict(c,raw=bytes.fromhex(c['hex'])) for c in self.fixture['chunks']}
        self.cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);self.cs.detail=True

    def environment(self,delta=0):
        data=bytearray();maps=[]
        for c in self.chunks.values():
            maps.append((c['address']+delta,len(data),len(c['raw'])))
            data.extend(c['raw'])
        def off(address):
            return next(start+address-base for base,start,length in maps if base<=address<base+length)
        if delta:
            vt=off(self.chunks['vtable']['address']+delta)+24
            struct.pack_into('<Q',data,vt,struct.unpack_from('<Q',data,vt)[0]+delta)
        return data,off

    def error_layout(self,delta=0,classification=None):
        data,off=self.environment(delta)
        c=self.chunks['error'];ins=list(self.cs.disasm(c['raw'],c['address']+delta))
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['error_name']+delta)
        return invalid_request_layout(ins,n,data,off,None,classification or self.fixture['classification'])

    def test_error_layout_relocates_and_derives_tag_and_string_fields(self):
        for delta in (0,0x100000):
            self.assertEqual(self.error_layout(delta),dict(tag=(1<<63)|15,pointer=16,length=24))
        # Move the enum arm in its dispatch table: no production constant may
        # assign InvalidRequest a fixed tag.
        c=self.chunks['table'];raw=bytearray(c['raw'])
        raw[15*4:16*4],raw[16*4:17*4]=raw[16*4:17*4],raw[15*4:16*4]
        c['raw']=bytes(raw)
        classification=dict(self.fixture['classification'])
        classification['mask']|=1<<16
        self.assertEqual(self.error_layout(classification=classification)['tag'],(1<<63)|16)

    def test_string_field_drift_is_derived_and_inconsistent_pair_refused(self):
        c=self.chunks['formatter'];raw=bytearray(c['raw'])
        ins=list(self.cs.disasm(raw,c['address'],count=5))
        for i in ins[2:4]:
            raw[i.address-c['address']+i.disp_offset]+=8
        c['raw']=bytes(raw)
        self.assertEqual(self.error_layout()['pointer'],24)
        self.assertEqual(self.error_layout()['length'],32)
        raw[ins[3].address-c['address']+ins[3].disp_offset]+=8
        c['raw']=bytes(raw)
        with self.assertRaisesRegex(ValueError,'slice'):
            self.error_layout()

    def test_wrong_classifier_or_vtable_is_refused(self):
        with self.assertRaises(ValueError):
            self.error_layout(classification=dict(self.fixture['classification'],default_tag=12))
        c=self.chunks['vtable'];raw=bytearray(c['raw']);raw[8]=16;c['raw']=bytes(raw)
        with self.assertRaisesRegex(ValueError,'reference formatter'):
            self.error_layout()

    def compact(self,raw=None,delta=0):
        c=self.chunks['compact'];raw=c['raw'] if raw is None else raw
        ins=list(self.cs.disasm(raw,c['address']+delta))
        n=next(n for n,i in enumerate(ins) if i.address==self.fixture['compact_call']+delta)
        return compact_sites(ins,n,raw,lambda address:address-c['address']-delta),ins,n

    def test_compaction_relocation_and_counter_integrity(self):
        a,ins,n=self.compact();b,_,_=self.compact(delta=0x100000)
        self.assertEqual(a['init'],b['init']);self.assertEqual(a['call_offset'],b['call_offset'])
        c=self.chunks['compact'];raw=bytearray(c['raw']);i=ins[n-5]
        raw[i.address-c['address']+i.disp_offset]^=8
        with self.assertRaises(ValueError):self.compact(raw)
        raw=bytearray(c['raw']);i=ins[n-4]
        raw[i.address-c['address']+i.imm_offset: i.address-c['address']+i.imm_offset+i.imm_size]=bytes(i.imm_size)
        with self.assertRaises(ValueError):self.compact(raw)


class NameReferenceTests(unittest.TestCase):
    def test_batched_scan_matches_exhaustive_scan_with_overlaps_and_section_boundaries(self):
        data=bytearray(random.Random(12).randbytes(0x22000))
        regions=[(0,0x12000,0x140000000),(0x14000,len(data),0x141000000)]
        targets={0x13ffff000,0x141012345,0x140500000,0x145000000}
        for n,at in enumerate((5,0xfffe,0x11002,0x14000,0x15001,len(data)-7)):
            start,end,address=next(r for r in regions if r[0]<=at<r[1])
            target=sorted(targets)[n%len(targets)]
            data[at:at+7]=bytes([0x48+n%4,0x8d,0x15])+struct.pack('<i',target-address-at+start-7)
        # A prefix may also occur inside another candidate's displacement.
        at=0x200;data[at:at+10]=bytes.fromhex('488d15488d1500000000')
        for pos in (at,at+3):
            targets.add(regions[0][2]+pos+7+struct.unpack_from('<i',data,pos+3)[0])
        # A truncated instruction at the executable section boundary is invalid,
        # even if bytes in the adjacent non-executable gap complete its target.
        at=0x12000-4
        data[at:at+7]=b'\x48\x8d\x15'+struct.pack('<i',0x140500000-regions[0][2]-at-7)
        expected={target:[] for target in targets}
        for start,end,address in regions:
            for at in range(start,end-6):
                if 0x48<=data[at]<=0x4b and data[at+1:at+3]==b'\x8d\x15':
                    target=address+at-start+7+struct.unpack_from('<i',data,at+3)[0]
                    if target in expected:expected[target].append(at)
        self.assertEqual(name_references(data,regions,targets),expected)
        self.assertIn(0x200,expected[regions[0][2]+0x207+struct.unpack_from('<i',data,0x203)[0]])


class SectionTests(unittest.TestCase):
    def pe(self):
        return SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(SectionAlignment=4096,FileAlignment=512,SizeOfHeaders=512,
                ImageBase=0x140000000,SizeOfCode=512,get_field_absolute_offset=lambda k:{'SizeOfImage':200,'SizeOfCode':148}[k]),
            FILE_HEADER=SimpleNamespace(NumberOfSections=1,get_field_absolute_offset=lambda k:126),
            sections=[SimpleNamespace(VirtualAddress=4096,Misc_VirtualSize=400,SizeOfRawData=512,
                                     PointerToRawData=512,get_file_offset=lambda:256)])

    def test_appended_section_has_rx_permissions_and_aligned_locations(self):
        data=bytes(1057);s=layout(data,self.pe());patches=section_patches(s,b'\xc3')
        self.assertEqual(s['raw']%512,0);self.assertEqual(s['rva']%4096,0)
        header=next(p[2] for p in patches if p[3]=='retry_section_header')
        self.assertEqual(struct.unpack_from('<I',header,36)[0],0x60000020)
        tail=patches[-1];self.assertEqual(tail[0],len(data))
        self.assertEqual(tail[2][s['raw']-len(data)],0xc3)
        self.assertEqual((tail[0]+tail[1])%512,0)

    def test_occupied_header_and_invalid_alignment_are_refused(self):
        data=bytearray(1057);data[296]=1
        with self.assertRaises(ValueError):layout(data,self.pe())
        pe=self.pe();pe.OPTIONAL_HEADER.FileAlignment=3
        with self.assertRaises(ValueError):layout(bytes(1057),pe)
