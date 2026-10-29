"""Build-specific behavioral approval. Cached approval never contains patches."""
import json
import threading
from .core import ROOT, ControllerError, atomic_json, build_plan, now, sha, unb64, version_of

_mutex = threading.Lock()


def recipe_id():
    paths = sorted((ROOT / 'controller').glob('*.py'))
    paths += [ROOT / 'research' / n for n in ('probe_retries.py', 'appserver_probe.py')]
    return sha(b''.join(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes() for p in paths))


def cache_path(manager, data):
    return manager.state / 'compatibility' / (sha(data) + '.json')


def cached(manager, data):
    from .native_suite import REQUIRED_CASES, JITTER_CASES, SCOPE_CASES
    try:
        report = json.loads(cache_path(manager,data).read_text(encoding='utf-8'))
        required = set(REQUIRED_CASES) | (set(JITTER_CASES) if report.get('supports_jitter') is True else set())
        if report.get('supports_retry_scope') is True:
            required.update(SCOPE_CASES)
        if (report.get('format') == 1 and report.get('passed') is True
                and report.get('recipe_sha256') == recipe_id()
                and report.get('base_sha256') == sha(data)
                and report.get('restored_sha256') == sha(data)
                and report.get('interrupted_write_recovery') is True
                and report.get('unrelated_change_refused') is True
                and {c.get('name') for c in report['cases'] if c.get('passed') is True} == required):
            return report
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        pass
    return None


def verify(manager, data):
    with _mutex:
        existing = cached(manager,data)
        if existing is not None:
            return existing
        from .native_suite import run_suite
        plan = build_plan(data, {'max_retries':1000,'interval_ms':500})
        verified_recipe = recipe_id()
        manager.logger.info('Native verification started version=%s sha=%s',version_of(data),sha(data))
        try:
            report = run_suite(data, manager)
        except Exception as exc:
            manager.logger.exception('Native compatibility verification failed')
            raise ControllerError(f'临时副本行为验证未通过，未修改安装程序：{exc}') from exc
        if recipe_id() != verified_recipe:
            raise ControllerError('验证期间控制器规则发生变化，请重新验证。')
        report.update(format=1,passed=True,version=version_of(data),base_sha256=sha(data),
                      recipe_sha256=verified_recipe,verified_at=now(),
                      undo_bytes=sum(len(unb64(p['before'])) for p in plan))
        atomic_json(cache_path(manager,data),report)
        if cached(manager,data) is None:
            raise ControllerError('行为验证报告不完整，未批准应用。')
        atomic_json(manager.logs/'native-verification-current.json',report)
        manager.logger.info('Native verification passed sha=%s',sha(data))
        return report
