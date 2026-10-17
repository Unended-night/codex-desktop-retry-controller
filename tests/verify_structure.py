"""Read-only structural regression against the installed build; no execution."""
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller.core import Manager, ROOT, ControllerError, build_plan, detect_installation, version_of
from controller.native import locate


def main():
    manager=Manager()
    try:
        path=detect_installation()
        data,_=manager.baseline(path,path.read_bytes())
        settings={'max_retries':3,'interval_ms':125}
        plan=build_plan(data,settings)
        changed=data.replace(b'codex-app-server'+version_of(data).encode(),b'codex-app-server9.999.9')
        # This replacement has equal length for the currently installed version.
        if len(changed)==len(data):
            assert build_plan(changed,settings)==plan,'version-only change rejected'
        # Insert a raw-file page; keep all virtual addresses unchanged.
        moved=bytearray(data)
        pe=struct.unpack_from('<I',moved,60)[0]
        count=struct.unpack_from('<H',moved,pe+6)[0]
        first=pe+24+struct.unpack_from('<H',moved,pe+20)[0]
        raw=[struct.unpack_from('<I',moved,first+i*40+20)[0] for i in range(count)]
        insertion=min(x for x in raw if x)
        for i,at in enumerate(raw):
            if at:struct.pack_into('<I',moved,first+i*40+20,at+512)
        moved[insertion:insertion]=b'\0'*512
        actual=build_plan(bytes(moved),settings)
        assert len(actual)==len(plan)
        for old,new in zip(plan,actual):
            assert new['offset']==old['offset']+512
            assert {k:v for k,v in old.items() if k!='offset'}=={k:v for k,v in new.items() if k!='offset'}
        for slot in plan:
            changed=bytearray(data)
            changed[slot['offset']]=0xcc
            try:build_plan(bytes(changed),settings)
            except ControllerError:pass
            else:raise AssertionError('changed opcode accepted: '+slot['label'])
        sites=locate(data,ControllerError)
        rejected=[]
        if sites['family']=='responses-sampling-x64-v3':
            resume=sites['policy']+sites['resume']-sites['policy_va']
            # Keep opcodes intact: independently corrupt the paired data fields.
            mutations={
                'state-base':resume+3,
                'budget-field':sites['count_site']+15,
                'duration-seconds':resume+11,
                'duration-nanos':resume+19,
                'server-deadline':sites['deadline']+4,
                'connection-state':sites['connection']+4,
                'classifier-target':sites['classify']+15,
                'resume-target':sites['policy']+27,
                'error-mask':sites['classify']+2,
            }
            for name,offset in mutations.items():
                changed=bytearray(data)
                changed[offset]^=1
                try:build_plan(bytes(changed),settings)
                except ControllerError:rejected.append(name)
                else:raise AssertionError('changed control/data flow accepted: '+name)
        report=dict(passed=True,version=version_of(data),raw_offset_relocation=True,
                    changed_opcodes_rejected=len(plan),flow_mutations_rejected=rejected,
                    family=sites['family'],execution='none; structural fixtures only')
        (ROOT/'logs/structural-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report))
    finally:manager.close()


if __name__=='__main__':main()
