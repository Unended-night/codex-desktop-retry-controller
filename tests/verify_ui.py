"""Tk smoke checks: display/version/button states only; never applies patches."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:pass
    loader=importlib.machinery.SourceFileLoader('controller_ui',str(ROOT/'app.pyw'))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    app=module.App()
    app.withdraw()
    for task in app.tk.call('after','info'):
        app.after_cancel(task)
    try:
        status=dict(path=str(ROOT/'fixture.exe'),version='99.12.3',status='custom',
                    profile={'max_retries':25,'interval_ms':1000}, enabled=True,
                    current_text='当前运行：25 次 / 1 秒', next_text='下次启动：2 次 / 0.25 秒（待重启）',
                    selected={'engine':str(ROOT/'runtime/fixture/codex.exe')},
                    compatible=True,verified=False,can_restore=True,reason='fixture')
        app.show_status(status)
        assert '99.12.3' in app.current.get()
        assert str(app.apply_button['state'])=='normal'
        assert app.max_retries.get()=='25' and app.interval.get()=='1000'
        assert not app.http_enabled.get() and str(app.http_entry['state'])=='disabled'
        app.show_status(dict(status,profile=dict(max_retries=300,interval_ms=1500,jitter_ms=500,http_timeout_ms=300000)))
        assert app.http_enabled.get() and app.http_timeout.get()=='300'
        assert str(app.http_entry['state'])=='normal'
        with patch.object(app,'_run') as dispatch, patch.object(app.manager,'apply') as apply:
            app.apply()
            dispatch.call_args.args[1]()
            assert apply.call_args.args[0]['http_timeout_ms']==300000
            dispatch.reset_mock()
            app.http_timeout.set('不是数字')
            app.apply()
            assert '有效的 HTTP' in app.notice.get()
            dispatch.assert_not_called()
        app.show_status(status)
        app.jitter.set('70')
        assert '930～1070 毫秒' in app.wait_preview.get()
        app.unit.set('秒'); app._unit_changed()
        assert app.interval.get()=='1' and app.jitter.get()=='0.07'
        app.unit.set('毫秒'); app._unit_changed()
        assert app.interval.get()=='1000' and app.jitter.get()=='70'
        app.show_status(dict(status,profile=dict(max_retries=25,interval_ms=1000,jitter_ms=50)))
        assert app.jitter.get()=='50' and '950～1050 毫秒' in app.wait_preview.get()
        assert '2 次 / 0.25 秒' in app.next_start.get()
        app.show_status(dict(status, reason='范围提示（不拦截启动）：当前 Windows 沙盒组合尚未验证'))
        assert str(app.apply_button['state'])=='normal'
        assert str(app.verify_button['state'])=='normal'
        app.show_status(dict(status,compatible=False,status='incompatible'))
        assert '99.12.3' in app.current.get()
        assert str(app.apply_button['state'])=='normal'
        app.retry_enabled.set(False);app.http_enabled.set(True);app.http_timeout.set('120');app._mode_changed()
        assert str(app.count_entry['state'])=='disabled' and str(app.http_entry['state'])=='normal'
        assert '不等于禁止重试' in app.wait_preview.get()
        with patch.object(app,'_run') as dispatch, patch.object(app.manager,'apply') as apply:
            app.max_retries.set('invalid inactive input')
            app.apply();dispatch.call_args.args[1]()
            saved=apply.call_args.args[0]
            assert saved['retry_enabled'] is False and saved['http_timeout_ms']==120000
            assert saved['max_retries']==25
        app.show_status(dict(status,profile=dict(max_retries=300,interval_ms=1500,jitter_ms=500,http_timeout_ms=120000),
            features={'retry':{'state':'ready'},'http_timeout':{'state':'unavailable'}},
            reason='HTTP 超时未启用；自定义重试已验收，设置已保留。'))
        assert app.retry_enabled.get() and app.http_enabled.get() and app.http_timeout.get()=='120'
        assert '待适配' in app.feature_status.get() and '已保留' in app.feature_status.get()
        assert str(app.restore_button['state'])=='normal'
        assert str(app.cleanup_button['text']) == '清空历史副本'
        assert str(app.cleanup_button['state']) == 'normal'
        assert str(app.recover_button['text']) == '清理控制器进程'
        app.busy = True
        app._permissions()
        assert str(app.recover_button['state']) == 'normal'
        app.recovering = True
        app._permissions()
        assert str(app.recover_button['state']) == 'disabled'
        app.busy = app.recovering = False
        app._permissions()
        app.processes_recovered(dict(recovered=True, stopped=[{'pid': 42}]))
        assert '操作锁已释放' in app.notice.get()
        app.processes_recovered(dict(recovered=False, stopped=[], remaining=[42]))
        assert '仍有进程或锁未释放' in app.notice.get()
        app.cleaned(dict(reclaimed_bytes=1024**2, keep_history=False, retained=[{}], skipped=[]))
        assert '保留 1 份' in app.notice.get()
        app.cleaned(dict(reclaimed_bytes=0, keep_history=False, retained=[{}, {}], skipped=[]))
        assert '保留 2 份' in app.notice.get()
        app.mode.set('default');app._mode_changed()
        assert str(app.apply_button['state'])=='normal'
        app.mode.set('custom');app._mode_changed()
        assert str(app.apply_button['state'])=='normal'
        app.show_status(dict(status, enabled=False, status='default'))
        assert app.mode.get()=='default' and str(app.count_entry['state'])=='disabled'
        app.refresh=lambda:None
        app.changed(dict(action='restore',changed=True,version='99.12.4'))
        assert '正常退出' in app.notice.get()
        app.update_idletasks()
        report=dict(passed=True,actual_version_display=True,incompatible_native_can_save_timeout=True,
                    restore_always_enabled=True,current_and_next_separate=True,
                    saved_values_loaded=True,millisecond_units_and_jitter_preview=True,manual_history_clear_display=True,
                    optional_http_timeout_saved_and_validated=True,
                    independent_switches_and_partial_status=True,inactive_invalid_retry_does_not_block_timeout=True,
                    process_recovery_available_while_busy=True,
                    window_size=[app.winfo_width(),app.winfo_height()])
        (ROOT/'logs/ui-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report))
    finally:
        app.manager.close()
        app.destroy()


if __name__=='__main__':main()
