"""Exercise the normal write gate with an approved build on a disposable copy."""
import contextlib
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller.core import Manager, ROOT, atomic_json, detect_installation, profile, sha
from controller.verification import cached, cache_path


def main():
    owner=Manager()
    installed=detect_installation()
    before=sha(installed.read_bytes())
    try:
        data,_=owner.baseline(installed,installed.read_bytes())
        approval=cached(owner,data)
        assert approval is not None,'Run full native verification first'
        with tempfile.TemporaryDirectory(dir=owner.state/'.verification',prefix='approved-') as directory, contextlib.ExitStack() as cleanup:
            directory=Path(directory)
            exe=directory/'test.exe'
            exe.write_bytes(data)
            manager=Manager(directory/'tool')
            cleanup.callback(manager.close)
            atomic_json(cache_path(manager,data),approval)
            result=manager.apply(exe,profile(7,'0.25'))
            status=manager.inspect(exe)
            assert status['verified'] and status['status']=='custom'
            assert status['profile']==profile(7,'0.25')
            assert result['version']==approval['version']
            manager.restore(exe)
            assert sha(exe.read_bytes())==sha(data)
        assert sha(installed.read_bytes())==before
        installed_status=owner.inspect(installed)
        report=dict(passed=True,normal_write_gate=True,cache_reused=True,restored=True,
                    installed_unchanged=True,installed_sha256=before,
                    version=installed_status['version'],installed_status=installed_status['status'],
                    installed_profile=installed_status['profile'],verified=installed_status['verified'])
        atomic_json(ROOT/'logs/acceptance.json',report)
        print(json.dumps(report))
    finally:owner.close()


if __name__=='__main__':main()
