"""Loopback acceptance suite used for each newly encountered engine build."""
import contextlib
from pathlib import Path
import sys
import tempfile
from .core import Manager, ROOT, SUPPORTED_SHA256, profile, sha, unb64, exclusive_binary, ControllerError

REQUIRED_CASES = ('zero-budget','http-fixed','http-429','quota-terminal','http-529',
                  'http-retry-after','stream-interrupted','stream-server-delay',
                  'connection-failure','success-after-failures','app-server-success',
                  'app-server-budget','whole-seconds','thousand-retries',
                  'http-400-classification','http-401-classification',
                  'http-403-classification','http-404-classification',
                  'millisecond-fixed')
JITTER_CASES = ('jitter-http','jitter-cross-second','jitter-millisecond')


def run_suite(data, owner):
    sys.path.insert(0,str(ROOT/'research'))
    from probe_retries import probe
    work = owner.state / '.verification'
    work.mkdir(parents=True,exist_ok=True)
    from .native import locate
    jitter_supported = (sha(data) != SUPPORTED_SHA256 and
                        locate(data, ControllerError)['family'] == 'responses-sampling-x64-outlined')
    report={'cases':[], 'supports_jitter':jitter_supported}
    with tempfile.TemporaryDirectory(dir=work,prefix='native-') as directory, contextlib.ExitStack() as cleanup:
        path=Path(directory)/'codex.exe'
        path.write_bytes(data)
        manager=Manager(Path(directory)/'tool',verify_writes=False)
        cleanup.callback(manager.close)
        original_classification={}
        for status in (400,401,403,404):
            result=probe(str(path),0,stream_retries=1,error_status=status)
            assert not result['timed_out'] and result['exit_code']==1
            assert result['requests'] in (1,2), f'baseline HTTP {status}: unexpected budget'
            original_classification[status]=result['requests']>1
        def case(name,count,delay,expected,success=False,**kwargs):
            manager.apply(path,profile(count,delay))
            result=probe(str(path),4,stream_retries=5,succeed=success,**kwargs)
            assert not result['timed_out'], f'{name}: timed out'
            assert result['requests']==expected, f"{name}: {result['requests']} requests, expected {expected}"
            assert result['exit_code']==(0 if success else 1), f'{name}: unexpected exit'
            if float(delay):
                assert all(float(delay)-0.04<=t<=float(delay)+0.5 for t in result['intervals_seconds']), f'{name}: interval mismatch'
            # Keep evidence compact; no prompts, credentials or request bodies.
            report['cases'].append(dict(name=name,passed=True,retries=count,interval_seconds=delay,
                                        requests=result['requests'],intervals_seconds=result['intervals_seconds'],
                                        interface=result['interface'],exit_code=result['exit_code']))
            owner.logger.info('Native case passed: %s requests=%s',name,expected)
        case('zero-budget',0,'0.5',1)
        case('http-fixed',3,'0.5',4)
        case('http-429',3,'0.125',4,error_status=429)
        case('quota-terminal',3,'0.125',1,error_status=429,error_code='insufficient_quota')
        case('http-529',2,'0.125',3,error_status=529)
        case('http-retry-after',2,'0.125',3,retry_after=4)
        case('stream-interrupted',3,'0.125',4,mode='stream')
        case('stream-server-delay',2,'0.125',3,mode='stream-rate-limit')
        case('connection-failure',2,'0.125',3,mode='disconnect')
        case('success-after-failures',3,'0.125',3,success=True,stop_after=2)
        case('app-server-success',3,'0.125',3,success=True,stop_after=2,interface='app-server')
        case('app-server-budget',3,'0.125',4,interface='app-server',error_status=429)
        case('whole-seconds',2,'1.25',3)
        case('thousand-retries',1000,'0',1001,stop_after=1100,timeout=90)
        for status,retryable in original_classification.items():
            case(f'http-{status}-classification',2,'0.125',3 if retryable else 1,error_status=status)
            report['cases'][-1]['original_retryable']=retryable
        case('millisecond-fixed',3,'0.001',4)
        jitter_cases = [('jitter-http',100,70,'exec'), ('jitter-cross-second',1000,70,'app-server'),
                        ('jitter-millisecond',5,4,'exec')] if jitter_supported else []
        for name,base,spread,interface in jitter_cases:
            manager.apply(path,profile(8,base,spread,unit='ms'))
            result=probe(str(path),4,stream_retries=5,stop_after=10,interface=interface)
            delays=result['selected_delays_ms']
            assert not result['timed_out'] and result['exit_code']==1 and result['requests']==9, name
            assert len(delays)==8 and all(base-spread<=v<=base+spread for v in delays), f'{name}: chosen wait outside range'
            assert len(set(delays))>1, f'{name}: no observed variation'
            assert all(max(0,wait/1000-.04)<=actual<=wait/1000+.5
                       for wait,actual in zip(delays,result['intervals_seconds'])), f'{name}: interval mismatch'
            report['cases'].append(dict(name=name,passed=True,profile=profile(8,base,spread,unit='ms'),
                                       requests=result['requests'],selected_delays_ms=delays,
                                       intervals_seconds=result['intervals_seconds'],interface=interface))
            owner.logger.info('Native case passed: %s requests=%s',name,result['requests'])
        manager.restore(path)
        assert sha(path.read_bytes())==sha(data),'restore mismatch'
        assert not manager.restore(path)['changed'],'restore is not idempotent'
        manager.apply(path,profile(2,'0.123'))
        manager.restore(path)
        assert sha(path.read_bytes())==sha(data),'second restore mismatch'
        manager.apply(path,profile(2,'0.123'))
        journal=manager.read_journal(path)
        slot=next(x for x in journal['slots'] if x['before']!=x['after'])
        with exclusive_binary(path) as stream:
            stream.seek(slot['offset'])
            stream.write(unb64(slot['before']))
        assert manager.inspect(path)['status']=='interrupted','partial write not detected'
        manager.restore(path)
        assert sha(path.read_bytes())==sha(data),'partial-write restore mismatch'
        manager.apply(path,profile(2,'0.123'))
        with exclusive_binary(path) as stream:
            stream.seek(-1,2)
            last=stream.read(1)
            stream.seek(-1,2)
            stream.write(bytes([last[0]^1]))
        changed_hash=sha(path.read_bytes())
        try:
            manager.restore(path)
        except ControllerError:
            pass
        else:
            raise AssertionError('unrelated modification overwritten')
        assert sha(path.read_bytes())==changed_hash,'failed restore modified file'
        with exclusive_binary(path) as stream:
            stream.seek(-1,2)
            stream.write(last)
        manager.restore(path)
        assert sha(path.read_bytes())==sha(data),'final restore mismatch'
        report['interrupted_write_recovery']=True
        report['unrelated_change_refused']=True
        report['restored_sha256']=sha(path.read_bytes())
    return report
