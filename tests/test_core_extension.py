"""Appended native sections remain reversible, including interrupted writes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller.core import (Manager, ControllerError, b64, patched_bytes,
                             profile, recover_baseline, sha)


class ExtendedJournalTests(unittest.TestCase):
    original = b'MZ codex-app-server99.12.3 fixture\0HEAD'

    def plan(self, data, p):
        tail = bytes([p['max_retries']])*p['interval_ms']
        return [dict(offset=len(data)-4,before=b64(b'HEAD'),after=b64(b'EDIT'),label='header'),
                dict(offset=len(data),before=b64(bytes(len(tail))),after=b64(tail),label='append')]

    def test_every_partial_append_restores_exact_original_length_and_hash(self):
        slots=self.plan(self.original,profile(3,'.009'))
        target=patched_bytes(self.original,slots)
        journal=dict(format=2,size=len(target),base_size=len(self.original),
                     base_sha256=sha(self.original),slots=slots)
        for length in range(len(self.original),len(target)+1):
            self.assertEqual(recover_baseline(target[:length],journal),self.original)
        self.assertEqual(recover_baseline(self.original,journal),self.original)
        for damaged in (target[:-1]+b'X',target+b'X',target[:len(self.original)-1]):
            with self.assertRaises(ControllerError):
                recover_baseline(damaged,journal)

    def test_real_manager_reconfigures_growing_and_shrinking_sections_and_restores(self):
        with tempfile.TemporaryDirectory() as folder,patch('controller.core.build_plan',side_effect=self.plan):
            path=Path(folder)/'engine.exe'
            path.write_bytes(self.original)
            manager=Manager(Path(folder)/'tool',verify_writes=False)
            try:
                for count,size in [(2,8),(3,32),(4,5)]:
                    settings=profile(count,size,unit='ms')
                    manager.apply(path,settings)
                    journal=manager.read_journal(path)
                    self.assertEqual(journal['format'],2)
                    self.assertEqual(recover_baseline(path.read_bytes(),journal),self.original)
                    self.assertEqual(path.read_bytes()[len(self.original):len(self.original)+size],bytes([count])*size)
                    self.assertFalse(manager.apply(path,settings)['changed'])
                # A crash after writing headers and only part of the append.
                with path.open('r+b') as stream:
                    stream.truncate(len(self.original)+2)
                manager.restore(path)
                self.assertEqual(path.read_bytes(),self.original)
                self.assertFalse(manager.restore(path)['changed'])
                manager.apply(path,profile(2,8,unit='ms'))
                with path.open('r+b') as stream:
                    stream.seek(-1,2);stream.write(b'X')
                damaged=path.read_bytes()
                with self.assertRaises(ControllerError):
                    manager.restore(path)
                self.assertEqual(path.read_bytes(),damaged)
            finally:
                manager.close()

    def test_unknown_append_base_and_gap_are_rejected(self):
        for offset,before in [(len(self.original)+1,b'\0'),(len(self.original),b'X')]:
            with self.assertRaises(ControllerError):
                patched_bytes(self.original,[dict(offset=offset,before=b64(before),after=b64(b'A'))])
