"""Semantic regressions for split kind/Duration policies; no fixture execution."""
import copy
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'research/.deps'))
import capstone
from controller.native_return import delegated_classifier, direct_invalid_request_layout
from controller.native_v4 import outer, locate_outlined
from controller.native_compact import returned_compact_sites, locate_compaction
from controller.native_errors import error_policy


class DelegatedPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT/'tests/fixtures/delegated-retry.json').read_text(encoding='utf-8'))

    def setUp(self):
        self.chunks = copy.deepcopy(self.fixture['chunks'])
        for chunk in self.chunks:
            chunk['raw'] = bytearray.fromhex(chunk.pop('hex'))
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs.detail = True

    def chunk(self, name):
        return next(c for c in self.chunks if c['name'] == name)

    def body(self, name, delta=0):
        chunk = self.chunk(name)
        return list(self.cs.disasm(chunk['raw'], chunk['address']+delta))

    def environment(self, delta=0):
        data = bytearray()
        maps = []
        for chunk in self.chunks:
            raw = bytearray(chunk['raw'])
            if chunk['name'] == 'string-vtable':
                struct.pack_into('<Q', raw, 24, struct.unpack_from('<Q', raw, 24)[0]+delta)
            maps.append((chunk['address']+delta, len(data), len(raw), chunk))
            data.extend(raw)
        def off(address):
            for base, start, size, _ in maps:
                if base <= address < base+size:
                    return start+address-base
            raise ValueError('outside fixture')
        def va(offset):
            for base, start, size, _ in maps:
                if start <= offset < start+size:
                    return base+offset-start
            raise ValueError('outside fixture')
        def function(offset):
            for base, start, size, chunk in maps:
                if start <= offset < start+size and chunk.get('function'):
                    return (base, base+size), self.body(chunk['name'], delta)
            raise ValueError('outside fixture function')
        return data, off, va, function

    def helper(self, delta=0, none=0xffffffff):
        data, off, _, function = self.environment(delta)
        return delegated_classifier(self.body('helper', delta), none, data, off, function)

    def error(self, delta=0):
        data, off, _, _ = self.environment(delta)
        body = self.body('debug', delta)
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['error_name']+delta)
        return direct_invalid_request_layout(body, index, data, off, self.cs, self.helper(delta))

    def sampling(self, number, delta=0):
        data, off, _, _ = self.environment(delta)
        body = self.body(f'sampling{number}', delta)
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['sampling_calls'][number]+delta)
        return outer(body, index, self.helper(delta), data, off)

    def compact(self, number, delta=0):
        data, off, _, _ = self.environment(delta)
        body = self.body(f'compact{number}', delta)
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['compact_calls'][number]+delta)
        return returned_compact_sites(body, index, data, off, self.helper(delta))

    def displacement(self, name, instruction, value):
        chunk = self.chunk(name)
        struct.pack_into('<i' if instruction.disp_size == 4 else '<b', chunk['raw'],
                         instruction.address-chunk['address']+instruction.disp_offset, value)

    def immediate(self, name, instruction, value):
        chunk = self.chunk(name)
        struct.pack_into({1:'<B',4:'<I',8:'<Q'}[instruction.imm_size], chunk['raw'],
                         instruction.address-chunk['address']+instruction.imm_offset, value)

    def test_split_policy_and_direct_debug_relocate_together(self):
        for delta in (0, 0x12340000):
            helper = self.helper(delta)
            self.assertTrue(helper['delegated'])
            self.assertEqual(len(helper['targets']), 51)
            self.assertEqual(self.error(delta), dict(tag=18, tag_offset=16, tag_size=1, pointer=32, length=40))
            sites = [self.sampling(n, delta) for n in range(4)]
            self.assertEqual(len({s['reporter'] for s in sites}), 1)
            self.assertEqual(len({s['helper'] for s in sites}), 1)
            for site in sites+[self.compact(n, delta) for n in range(3)]:
                self.assertGreater(site['policy'], site['call'])
                self.assertGreaterEqual(site['policy_size'], 5)
                self.assertNotEqual(site['policy_present'], site['policy_absent'])

    def test_reordered_enum_tags_are_derived_from_both_tables(self):
        for prefix in ('delegate-table-', 'debug-table-'):
            raw = next(c['raw'] for c in self.chunks if c['name'].startswith(prefix))
            raw[18*4:19*4], raw[33*4:34*4] = raw[33*4:34*4], raw[18*4:19*4]
        self.assertEqual(self.error()['tag'], 33)

    def test_tag_and_string_field_drift_is_not_a_version_identity(self):
        for name in ('delegate', 'debug'):
            tag = next(i for i in self.body(name) if i.mnemonic == 'movzx' and i.operands[1].type == 3)
            self.displacement(name, tag, 20)
        for item in self.body('formatter')[2:4]:
            self.displacement('formatter', item, item.disp+8)
        self.assertEqual(self.error(), dict(tag=18, tag_offset=20, tag_size=1, pointer=40, length=48))

    def test_none_value_must_agree_with_native_helper_and_callers(self):
        with self.assertRaisesRegex(ValueError, 'flow|None'):
            self.helper(none=1_000_000_000)
        data, off, _, _ = self.environment()
        helper = self.helper()
        helper['none_value'] = 1_000_000_000
        for name, call in [('sampling0', self.fixture['sampling_calls'][0]),
                           ('compact0', self.fixture['compact_calls'][0])]:
            body = self.body(name)
            index = next(n for n, i in enumerate(body) if i.address == call)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'None disagrees'):
                if name.startswith('sampling'):
                    outer(body, index, helper, data, off)
                else:
                    returned_compact_sites(body, index, data, off, helper)

    def test_deadline_sources_must_be_the_same_error_object(self):
        loads = [i for i in self.body('helper') if i.mnemonic == 'mov' and i.op_str.startswith('eax, dword ptr')]
        self.assertEqual(len(loads), 2)
        self.displacement('helper', loads[1], loads[1].disp+8)
        with self.assertRaisesRegex(ValueError, 'deadline source'):
            self.helper()

    def test_argument_registers_cannot_alias(self):
        raw = self.chunk('helper')['raw']
        self.assertIn(bytes.fromhex('4889ce'), raw)  # saved error RSI
        raw[:] = raw.replace(bytes.fromhex('4889ce'), bytes.fromhex('4889d6'), 1)
        with self.assertRaisesRegex(ValueError, 'arguments'):
            self.helper()

    def test_frame_budget_address_must_match_its_reported_state_field(self):
        site = self.sampling(2)
        producer = next(i for i in self.body('sampling2') if i.mnemonic == 'lea' and i.disp == site['budget_field'])
        self.displacement('sampling2', producer, producer.disp+8)
        with self.assertRaisesRegex(ValueError, 'budget pointer'):
            self.sampling(2)

    def test_sampling_error_reload_and_reporter_must_agree(self):
        body = self.body('sampling0')
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['sampling_calls'][0])
        self.displacement('sampling0', body[index-1], body[index-1].disp+8)
        with self.assertRaisesRegex(ValueError, 'bounded gate|nonvolatile'):
            self.sampling(0)

    def test_live_nonvolatile_error_reload_is_replayed_and_checked(self):
        found = False
        for number in range(4):
            site = self.sampling(number)
            body = self.body(f'sampling{number}')
            begin = next(n for n, i in enumerate(body) if i.address == site['connection'])
            for item in body[begin:]:
                if item.mnemonic.startswith('j') or item.mnemonic == 'call':
                    break
                if (item.mnemonic == 'mov' and item.op_str.startswith('r13, qword ptr [rbp')
                        and bytes(item.bytes) in site['bounded_reload']):
                    found = True
                    self.displacement(f'sampling{number}', item, item.disp+8)
                    with self.assertRaisesRegex(ValueError, 'nonvolatile'):
                        self.sampling(number)
                    break
            if found:
                break
        self.assertTrue(found, 'fixture must cover the live nonvolatile error pointer')

    def test_direct_debug_vtable_and_name_length_are_proven(self):
        self.chunk('string-vtable')['raw'][8] = 16
        with self.assertRaisesRegex(ValueError, 'borrowed String'):
            self.error()
        self.setUp()
        body = self.body('debug')
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['error_name'])
        target = body[index+1].operands[0].imm
        index = next(n for n, i in enumerate(body) if i.address == target)
        item = body[index+1]
        self.immediate('debug', item, 13)
        with self.assertRaisesRegex(ValueError, 'slice/payload'):
            self.error()

    def test_debug_tag_offset_must_match_the_kind_classifier(self):
        item = next(i for i in self.body('debug') if i.mnemonic == 'movzx' and i.operands[1].type == 3)
        self.displacement('debug', item, item.disp+4)
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            self.error()

    def test_short_compare_redirect_is_a_stackless_leaf_with_both_native_exits(self):
        for site in [self.sampling(0), self.compact(0), self.compact(1), self.compact(2)]:
            origin = 0x150000000
            code = error_policy(dict(site, invalid_request=self.error()),
                                dict(max_retries=3, interval_ms=125), address=origin)
            body = list(self.cs.disasm(code, origin))
            self.assertEqual(sum(i.size for i in body), len(code))
            self.assertFalse(any(i.mnemonic in ('call','push','pop','ret') for i in body))
            external = {i.operands[0].imm for i in body if i.mnemonic.startswith('j')
                        and i.operands[0].type == 2 and not origin <= i.operands[0].imm < origin+len(code)}
            self.assertEqual(external, {site['policy_present'], site['policy_absent']})

    def test_scheduled_nonvolatile_reload_stays_before_the_compaction_patch(self):
        site = self.compact(2)
        body = self.body('compact2')
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['compact_calls'][2])
        reload = body[index+2]
        self.assertEqual(reload.mnemonic, 'mov')
        self.assertEqual(reload.address+reload.size, site['policy'])
        raw = self.chunk('compact2')['raw']
        at = reload.address-self.chunk('compact2')['address']
        self.assertEqual(raw[at:at+3], bytes.fromhex('4c8ba5'))
        raw[at:at+3] = bytes.fromhex('488b95')  # RDX would destroy the returned discriminant.
        with self.assertRaisesRegex(ValueError, 'duration option branch'):
            self.compact(2)

    def test_recognized_compaction_cannot_be_silently_omitted(self):
        # One damaged instance must reject the complete adaptation, even while
        # the other instance still matches and would pass a superficial count.
        body = self.body('compact1')
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['compact_calls'][1])
        self.displacement('compact1', body[index-3], body[index-3].disp+8)
        data, off, va, function = self.environment()
        entry = dict(call=self.fixture['sampling_calls'][0], returned_classifier=self.helper())
        refs = lambda target: [(off(call), 5) for call in self.fixture['compact_calls']]
        with self.assertRaisesRegex(ValueError, 'unproven local compaction instance'):
            locate_compaction(data, entry, function, off, va, refs)

    def test_recognized_sampling_cannot_be_silently_omitted(self):
        body = self.body('sampling3')
        index = next(n for n, i in enumerate(body) if i.address == self.fixture['sampling_calls'][3])
        self.displacement('sampling3', body[index-1], body[index-1].disp+8)
        data, off, va, function = self.environment()
        with self.assertRaisesRegex(ValueError, 'unproven delegated sampling instance'):
            locate_outlined(data, function, off, va, lambda *args: [], self.cs)
