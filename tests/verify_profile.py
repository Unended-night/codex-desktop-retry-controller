"""Supplemental acceptance for White's 15 retries / 5 seconds on a copy."""
import contextlib
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller.core import Manager, ROOT, atomic_json, detect_installation, now, profile, sha
from controller.verification import cached, cache_path
sys.path.insert(0,str(ROOT/'research'))
from probe_retries import probe


def main():
    owner=Manager()
    installed=detect_installation()
    original=installed.read_bytes()
    config=Path.home()/'.codex/config.toml'
    config_hash=sha(config.read_bytes())
    try:
        data,_=owner.baseline(installed,original)
        approval=cached(owner,data)
        assert approval is not None,'Run full native verification first'
        report=dict(version=approval['version'],base_sha256=sha(data),
                    recipe_sha256=approval['recipe_sha256'],cases=[])
        with tempfile.TemporaryDirectory(dir=owner.state/'.verification',prefix='profile-') as directory, contextlib.ExitStack() as cleanup:
            directory=Path(directory)
            exe=directory/'codex.exe'
            exe.write_bytes(data)
            manager=Manager(directory/'tool')
            cleanup.callback(manager.close)
            atomic_json(cache_path(manager,data),approval)
            baseline_responses={}
            for status in (400,401,403):
                result=probe(str(exe),0,stream_retries=3,error_status=status)
                assert not result['timed_out'] and result['exit_code']==1,result
                baseline_responses[status]=result['requests']
            manager.apply(exe,profile(15,'5'))
            result=probe(str(exe),4,stream_retries=5,error_status=429,stop_after=20,timeout=110)
            assert not result['timed_out'] and result['exit_code']==1
            assert result['requests']==16,result['requests']
            assert all(4.96<=v<=5.5 for v in result['intervals_seconds']),result['intervals_seconds']
            report['cases'].append(dict(name='15-retries-5-seconds',passed=True,requests=result['requests'],intervals_seconds=result['intervals_seconds']))
            print('15 retries / 5 seconds passed',flush=True)
            manager.apply(exe,profile(3,'0.125'))
            for status in (400,401,403):
                result=probe(str(exe),4,stream_retries=5,error_status=status)
                assert not result['timed_out'] and result['exit_code']==1,result
                assert result['requests']==baseline_responses[status],result
                report['cases'].append(dict(name=f'http-{status}-baseline-parity',passed=True,
                                            requests=result['requests'],baseline_requests=baseline_responses[status]))
            manager.restore(exe)
            assert sha(exe.read_bytes())==sha(data)
            report['restored_sha256']=sha(data)
        assert sha(installed.read_bytes())==sha(original)
        assert sha(config.read_bytes())==config_hash
        report.update(passed=True,installed_unchanged=True,config_unchanged=True,verified_at=now())
        atomic_json(ROOT/'logs/profile-verification-current.json',report)
        print('Profile, HTTP baseline parity, restoration and installed/config hashes passed',flush=True)
    finally:
        owner.close()
        assert sha(installed.read_bytes())==sha(original)
        assert sha(config.read_bytes())==config_hash


if __name__=='__main__':main()
