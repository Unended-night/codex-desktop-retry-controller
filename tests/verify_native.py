"""Verify the current desktop build on a temporary copy, including restoration."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller.core import Manager, detect_installation, sha
from controller.verification import cache_path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--force',action='store_true',help='忽略已有缓存，重新完整验证')
    args=parser.parse_args()
    manager=Manager()
    installed=detect_installation()
    before=sha(installed.read_bytes())
    try:
        baseline,_=manager.baseline(installed,installed.read_bytes())
        if args.force:
            cache_path(manager,baseline).unlink(missing_ok=True)
        report=manager.verify(installed)
        print(json.dumps(dict(version=report['version'],passed=report['passed'],
                              cases=len(report['cases']),installed_unchanged=sha(installed.read_bytes())==before)))
    finally:
        manager.close()
        assert sha(installed.read_bytes())==before,'Installed executable changed'


if __name__=='__main__':
    main()
