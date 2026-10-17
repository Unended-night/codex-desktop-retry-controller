"""Exercise the same pythonw -> worker path as the shortcut, in an isolated root."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controller.core import Manager, atomic_json, profile
from controller.verification import cached, cache_path
from desktop_runtime import DesktopManager, config_path
import desktop_trial as launcher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pythonw-worker', type=Path)
    args = parser.parse_args()
    if args.pythonw_worker:
        manager = DesktopManager(args.pythonw_worker, config=args.pythonw_worker / 'test-config.toml')
        try:
            result = manager.apply(profile(2, '.25'))
            atomic_json(args.pythonw_worker / 'gui-result.json', result)
        except Exception as exc:
            atomic_json(args.pythonw_worker / 'gui-result.json', {'error': str(exc)})
            raise
        finally:
            manager.close()
        return
    resources = launcher.installed_resources()
    pointer = ROOT / 'state/desktop-trial.json'
    active = Path(json.loads(pointer.read_text(encoding='utf-8'))['runtime']) / 'codex.exe'
    protected = [config_path(), pointer, active, resources / 'codex.exe']
    before = {str(p): launcher.digest(p) for p in protected}
    workspace = ROOT / 'logs/integration-runs'
    workspace.mkdir(exist_ok=True)
    target = Path(tempfile.mkdtemp(prefix='desktop-', dir=workspace))
    try:
        run_case(target, resources, protected, before)
    finally:
        atomic_json(target / 'completed.json', {'finished': True})


def run_case(target, resources, protected, before):
    config = target / 'test-config.toml'
    # This is not passed to sandbox probes: preparation must allow user-owned
    # settings while continuing to test the same isolated unelevated fixture.
    config.write_text('sandbox_mode="read-only"\napproval_policy="on-request"\n[windows]\nsandbox="elevated"\n', encoding='utf-8')
    isolated_config_before = config.read_bytes()
    owner, isolated = Manager(ROOT), Manager(target)
    try:
        data = (resources / 'codex.exe').read_bytes()
        approval = cached(owner, data)
        assert approval is not None, 'Run native verification first'
        atomic_json(cache_path(isolated, data), approval)
    finally:
        owner.close(); isolated.close()
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    with (target / 'pythonw.log').open('w', encoding='utf-8') as log:
        process = subprocess.run([str(pythonw), '-B', '-X', 'utf8', str(Path(__file__).resolve()),
                                  '--pythonw-worker', str(target)], stdout=log, stderr=log,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    result = json.loads((target / 'gui-result.json').read_text(encoding='utf-8'))
    assert process.returncode == 0 and 'error' not in result, result
    selected = launcher.get_selection(target, resources=resources, config_path=config)
    assert selected['mode'] == 'custom-trial', selected
    assert selected['profile'] == profile(2, '.25'), selected
    assert config.read_bytes() == isolated_config_before
    assert selected['config_notes']
    selected_engine = selected['engine']
    configuration_cases = []
    variants = {
        'provider-and-model': 'model_provider="switched"\nmodel="fixture-model"\n[model_providers.switched]\nbase_url="http://127.0.0.1:9/v1"\n[windows]\nsandbox="unelevated"',
        'whitespace-and-comments': '# updated by provider switcher\n\n[windows]\nsandbox = "unelevated"\n',
        'permissions-and-profiles': 'profile="custom"\n[profiles.custom]\nsandbox_mode="read-only"\n[permissions.custom]\nnetwork=true',
        'websocket': 'model_provider="switched"\n[model_providers.switched]\nsupports_websockets=true',
        'incomplete-config': 'model_provider = "unfinished',
    }
    for name, contents in variants.items():
        config.write_text(contents, encoding='utf-8')
        selection = launcher.get_selection(target, resources=resources, config_path=config)
        assert selection['mode'] == 'custom-trial' and selection['engine'] == selected_engine, selection
        assert config.read_text(encoding='utf-8') == contents
        configuration_cases.append(dict(name=name, mode=selection['mode']))
    config.unlink()
    assert launcher.get_selection(target, resources=resources, config_path=config)['engine'] == selected_engine
    configuration_cases.append(dict(name='missing-config', mode='custom-trial'))
    other_config = target / 'other-home/config.toml'
    other_config.parent.mkdir()
    other_config.write_text('[windows]\nsandbox="unelevated"', encoding='utf-8')
    assert launcher.get_selection(target, resources=resources, config_path=other_config)['engine'] == selected_engine
    configuration_cases.append(dict(name='changed-config-home', mode='custom-trial'))
    report = json.loads(Path(result['validation']).read_text(encoding='utf-8'))
    manager = DesktopManager(target, config=config)
    try:
        manager.restore()
        assert launcher.get_selection(target, resources=resources, config_path=config)['mode'] == 'official'
    finally:
        manager.close()
    after = {str(p): launcher.digest(p) for p in protected}
    assert before == after, 'Protected files changed'
    summary = dict(passed=True, pythonw_worker=True, root=str(target), retry=report['retry'],
                   configuration_cases=configuration_cases, user_config_unchanged_by_publish=True,
                   sandbox_cases=sum(len(m['cases']) for m in report['comparisons']),
                   same_launcher_restore=True, protected_unchanged=before == after,
                   validation=result['validation'], before=before, after=after)
    atomic_json(ROOT / 'logs/desktop-integration-verification.json', summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    if '--pythonw-worker' in sys.argv:
        main()
    else:
        # Keep main-root maintenance out until the isolated run is finished.
        from desktop_runtime import operation_lock
        from desktop_storage import best_effort
        with operation_lock(ROOT):
            try:
                main()
            finally:
                best_effort(ROOT)
