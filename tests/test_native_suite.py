"""Acceptance scheduling uses immutable images and preserves every gate."""
import contextlib
import logging
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from controller.core import Manager, ControllerError, ROOT, b64, profile, sha
from controller import native_suite as suite
from controller.verification import verify, cache_path

sys.path.insert(0,str(ROOT/'research'))
import probe_retries


class NativeSuiteTests(unittest.TestCase):
    data = b'MZ codex-app-server99.12.3 fixture\0'+bytes(24)+b'end'

    def plan(self, data, p):
        return [dict(offset=len(data)-27+8*i,before=b64(bytes(4)),after=b64(struct.pack('<I',value)),label=str(i))
                for i,value in enumerate((p['max_retries'],p['interval_ms'],p.get('jitter_ms',0)))]

    def execute(self, fail=False):
        lock = threading.Lock()
        baseline_barrier = threading.Barrier(4,timeout=5)
        active = maximum = 0
        observed = {}
        def probe(exe, retries, **options):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum,active)
            try:
                data = Path(exe).read_bytes()
                count,base,spread = [struct.unpack_from('<I',data,len(data)-27+8*i)[0] for i in range(3)]
                if retries == 0:
                    baseline_barrier.wait()
                    requests = 1 if options['error_status'] == 400 else 2
                else:
                    with lock:
                        observed.setdefault(exe,set()).add((count,base,spread))
                    time.sleep(.005)
                    self.assertEqual(Path(exe).read_bytes(),data)
                    if fail and count == 0:
                        raise RuntimeError('fixture probe failed')
                    requests = count+1
                    from controller.native_errors import AZURE_RESOURCE_MESSAGE
                    retryable400=(options.get('error_code')=='invalid_encrypted_content' or
                                  options.get('error_message','').startswith(AZURE_RESOURCE_MESSAGE))
                    if options.get('error_code') == 'insufficient_quota' or (options.get('error_status') == 400 and not retryable400 and not options.get('compact')):
                        requests = 1
                    if options.get('succeed'):
                        requests = options['stop_after']+1
                delays = [base-spread+2*spread*(i%2) if spread else base for i in range(requests-1)]
                return dict(timed_out=False,requests=requests,exit_code=0 if options.get('succeed') or isinstance(options.get('compact'),str) else 1,
                            intervals_seconds=[v/1000 for v in delays],selected_delays_ms=delays,
                            interface=options.get('interface','exec'),setup_requests=1,setup_compaction_requests=0,
                            compaction_requests=requests,reconnects=[f'Reconnecting... {i}/{count}' for i in range(1,requests)])
            finally:
                with lock:
                    active -= 1
        with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as cleanup:
            owner = Manager(Path(folder))
            cleanup.callback(owner.close)
            cleanup.enter_context(patch('controller.core.build_plan',side_effect=self.plan))
            cleanup.enter_context(patch.object(suite,'build_plan',side_effect=self.plan))
            cleanup.enter_context(patch('controller.verification.build_plan',side_effect=self.plan))
            cleanup.enter_context(patch('controller.native.locate',return_value={'family':'responses-sampling-x64-outlined'}))
            cleanup.enter_context(patch.object(probe_retries,'probe',side_effect=probe))
            if fail:
                with self.assertRaisesRegex(ControllerError,'fixture probe failed'):
                    verify(owner,self.data)
                self.assertFalse(cache_path(owner,self.data).exists())
                self.assertEqual(list((owner.state/'.verification').iterdir()),[])
                report = None
            else:
                report = suite.run_suite(self.data,owner)
        self.assertEqual(active,0)
        self.assertEqual(maximum,4)
        self.assertTrue(all(len(values)==1 for values in observed.values()))
        return report, observed

    def test_parallel_probes_reuse_profiles_and_keep_complete_restoration(self):
        report, observed = self.execute()
        self.assertEqual([c['name'] for c in report['cases']],list(suite.REQUIRED_CASES+suite.JITTER_CASES+suite.SCOPE_CASES))
        self.assertEqual(report['staged_profiles'],11)
        self.assertEqual(len(observed),11)
        self.assertEqual(report['restored_sha256'],sha(self.data))
        self.assertTrue(report['interrupted_write_recovery'] and report['unrelated_change_refused'])

    def test_failed_probe_drains_workers_and_never_creates_approval(self):
        self.execute(fail=True)

    def test_staged_image_must_match_bytes_written_to_disk(self):
        original = Path.write_bytes
        def corrupt(path, data):
            return original(path,data[:-1]+b'X')
        with tempfile.TemporaryDirectory() as folder, patch.object(Path,'write_bytes',corrupt):
            with self.assertRaisesRegex(ControllerError,'写入后校验失败'):
                suite._stage(self.data,Path(folder)/'codex.exe')

    def test_missing_intervals_cannot_pass_case_validation(self):
        def probe(*args,**kwargs):
            return dict(timed_out=False,requests=2,exit_code=1,intervals_seconds=[])
        with self.assertRaisesRegex(AssertionError,'missing request intervals'):
            suite._case(probe,Path('fixture.exe'),'fixture',profile(1,'1'),2,False,{},logging.getLogger('fixture'))
