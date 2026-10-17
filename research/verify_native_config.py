"""Verify retry alternatives without patching the installed engine or user config.

All model requests go to a loopback fake Responses server. Only test-owned
app-server processes are started/stopped, with temporary CODEX_HOME directories.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from verify_reported_rate_limit import MESSAGE, replay


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    exe = Path(sys.argv[1]).resolve(strict=True)
    config = Path.home() / '.codex' / 'config.toml'
    before = {str(p): digest(p) for p in (exe, config)}
    report = {
        'executable': str(exe),
        'version': subprocess.check_output([str(exe), '--version'], text=True, encoding='utf-8').strip(),
        'before_sha256': before,
        'scope': 'Unmodified native app-server, isolated configuration, simulated loopback SSE; not a desktop UI restart or live provider test.',
        'cases': [],
    }
    cases = [
        ('native-5-exhausted', 5, None, MESSAGE, 30),
        ('native-8-exhausted', 8, None, MESSAGE, 80),
        ('native-25-recover-after-2', 25, 2, MESSAGE, 30),
        ('native-server-advice-4s', 8, 2, MESSAGE + ' Please try again in 4s.', 30),
    ]
    with tempfile.TemporaryDirectory(prefix='codex-native-config-research-') as temporary:
        for name, count, stop, message, timeout in cases:
            result = replay(exe, Path(temporary) / name, stop, stream_retries=count, message=message, timeout=timeout)
            expected = stop + 1 if stop is not None else count + 1
            assert not result['timed_out'] and result['exact_error_seen'], result
            assert result['requests'] == expected, result
            assert result['turn_exit_code'] == (0 if stop is not None else 1), result
            assert result['reconnects'] == [f'Reconnecting... {i}/{count}' for i in range(1, expected)], result
            intervals = result['intervals_seconds']
            if name == 'native-server-advice-4s':
                assert all(3.9 <= value <= 5 for value in intervals), result
            else:
                # Allow transport/scheduler overhead while checking native exponential backoff.
                assert all(0.2 * 2**i * 0.85 <= value <= 0.2 * 2**i * 1.15 + 0.5
                           for i, value in enumerate(intervals)), result
            report['cases'].append(dict(name=name, stream_max_retries=count, passed=True, **result))
            print(json.dumps({'name': name, 'requests': result['requests'], 'intervals': intervals,
                              'reconnects': result['reconnects'], 'passed': True}, ensure_ascii=False), flush=True)
    report['after_sha256'] = {str(p): digest(p) for p in (exe, config)}
    assert report['after_sha256'] == before, 'Installed engine or real config changed during test'
    report['installed_engine_and_real_config_unchanged'] = True
    report['passed'] = True
    output = ROOT / 'logs' / 'native-config-alternatives.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(str(output), flush=True)


if __name__ == '__main__':
    main()
