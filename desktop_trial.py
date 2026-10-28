"""Guarded, opt-in desktop launcher for the sandbox-tested retry runtime.

No installation writes, global environment changes, sandbox setup, or process
termination. Changed builds are revalidated automatically before fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from controller.core import ControllerError

ROOT = Path(__file__).resolve().parent


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()


def installed_resources():
    """Resolve the user's registered package, not an arbitrary old copied app."""
    import winreg
    key=r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'
    candidates=[]
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key) as packages:
        for i in range(winreg.QueryInfoKey(packages)[0]):
            name=winreg.EnumKey(packages,i)
            match=re.fullmatch(r'OpenAI\.Codex_(\d+\.\d+\.\d+\.\d+)_x64__2p2nqsd0c76g0',name)
            if not match:continue
            with winreg.OpenKey(packages,name) as package:
                location=Path(winreg.QueryValueEx(package,'PackageRootFolder')[0])
            resources=location/'app/resources'
            if (resources.parent/'ChatGPT.exe').is_file():
                candidates.append((tuple(map(int,match[1].split('.'))),resources))
    if not candidates:raise RuntimeError('没有找到当前用户注册的 Codex 桌面安装。请使用原官方入口。')
    return max(candidates,key=lambda item:item[0])[1]


def selection(resources, runtime, manifest, config_path, expected_recipe):
    """Pure validation: neither writes files nor starts applications."""
    official=resources/'codex.exe'
    fallback=dict(mode='official',engine=str(official),desktop=str(resources.parent/'ChatGPT.exe'))
    def reject(reason):return dict(fallback,reason=reason)
    try:
        if manifest.get('activation')!='app-server-tested-desktop-trial':
            return reject('副本没有通过试用验收。')
        if resources.resolve()!=Path(manifest['resources']).resolve():
            return reject('官方桌面已更新，尚未验收新版本副本。')
        if digest(resources.parent/'ChatGPT.exe')!=manifest['desktop_sha256'] or digest(resources/'app.asar')!=manifest['app_asar_sha256']:
            return reject('官方桌面构建发生变化。')
        if manifest['recipe_sha256']!=expected_recipe:
            return reject('控制器规则已变化，需要重新验收。')
        required={'codex.exe','codex-code-mode-host.exe','codex-command-runner.exe','codex-windows-sandbox-setup.exe','rg.exe'}
        if set(manifest['official_files'])!=required or set(manifest['runtime_files'])!=required:
            return reject('组件清单不完整。')
        for name in required:
            if digest(resources/name)!=manifest['official_files'][name]:
                return reject('官方引擎或辅助程序已更新。')
            if digest(runtime/name)!=manifest['runtime_files'][name]:
                return reject('副本或辅助程序被修改，需要重新验收。')
        if digest(runtime/'validation.json')!=manifest['validation_sha256']:
            return reject('验证报告缺失或发生变化。')
        validation=json.loads((runtime/'validation.json').read_text(encoding='utf-8'))
        if not validation.get('trial_eligible'):
            return reject('验证报告没有批准试用。')
        from controller.core import validate_profile, profile_label
        p = validate_profile(manifest['profile'])
        if manifest.get('format', 1) in (2, 3):
            from desktop_validation import rules_id, receipt_valid
            if manifest.get('desktop_rules_sha256') != rules_id() or not receipt_valid(validation, manifest):
                return reject('桌面验证规则或参数验收记录不匹配，请在控制器重新验证。')
        elif manifest.get('format', 1) != 1:
            return reject('副本记录格式不受支持。')
        desktop_status=('首次桌面引擎选择已确认' if manifest.get('desktop_launch_confirmed_at')
                        else '首次桌面引擎选择待确认')
        from desktop_validation import configuration_notes
        return dict(mode='custom-trial',engine=str(runtime/'codex.exe'),desktop=fallback['desktop'],
                    config_notes=configuration_notes(config_path),
                    profile=p, reason=profile_label(p)+'；app-server 与 unelevated 沙盒对照已通过；'+desktop_status+'。')
    except (OSError,ValueError,KeyError,TypeError,AttributeError,ControllerError):
        return reject('副本文件或记录不可用。')


def launch_environment(base, selected):
    env=dict(base)
    # Electron inherits this from some terminal hosts; leaving it set starts Node.
    env.pop('ELECTRON_RUN_AS_NODE',None)
    env.pop('CODEX_CLI_PATH',None)
    if selected['mode']=='custom-trial':env['CODEX_CLI_PATH']=selected['engine']
    return env


def process_snapshot():
    script="""[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();
@(Get-CimInstance Win32_Process -Filter \"Name = 'ChatGPT.exe' OR Name = 'codex.exe'\" |
Select-Object ProcessId,ParentProcessId,ExecutablePath) | ConvertTo-Json -Compress"""
    result=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),
        '-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,encoding='utf-8',
        errors='replace',timeout=20,creationflags=subprocess.CREATE_NO_WINDOW,check=True)
    items=json.loads(result.stdout) if result.stdout.strip() else []
    return items if isinstance(items,list) else [items]


def running_desktops(processes):
    return [p for p in processes if Path(p.get('ExecutablePath') or '').name.lower()=='chatgpt.exe'
            and 'openai.codex_' in (p.get('ExecutablePath') or '').lower()]


def save_status(name, status):
    from controller.core import atomic_json, now
    atomic_json(ROOT/'logs'/name,dict(time=now(),**status))


def taskbar(operation, **arguments):
    """Shell decoration must never block engine selection or a desktop launch."""
    try:
        import desktop_shell
        return getattr(desktop_shell, operation)(**arguments)
    except Exception as exc:
        save_status('taskbar-error.json', dict(operation=operation, error=str(exc)))
        return None


def message(title, text):
    import tkinter as tk
    from tkinter import ttk
    # A visible, owned top-level is discoverable in the task switcher. Informational
    # notices also expire so an overlooked window cannot leave a launcher behind.
    window = tk.Tk()
    window.title(title)
    window.resizable(False, False)
    body = ttk.Frame(window, padding=22)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text=text, wraplength=470).pack(anchor='w')
    ttk.Label(body, text='此提示将在 15 秒后自动关闭。').pack(anchor='w', pady=(14, 10))
    ttk.Button(body, text='确定', command=window.destroy).pack(anchor='e')
    window.protocol('WM_DELETE_WINDOW', window.destroy)
    window.update_idletasks()
    window.geometry(f'+{max(0, (window.winfo_screenwidth()-window.winfo_width())//2)}'
                    f'+{max(0, (window.winfo_screenheight()-window.winfo_height())//2)}')
    window.attributes('-topmost', True)
    window.lift()
    window.after(1000, lambda: window.attributes('-topmost', False))
    window.after(15000, window.destroy)
    try:
        window.mainloop()
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


def automatic_update(manager):
    """Show launch progress while the hidden console worker owns validation."""
    import queue
    import threading
    import tkinter as tk
    from tkinter import ttk
    window=tk.Tk()
    window.title('Codex 更新适配')
    window.resizable(False,False)
    ttk.Label(window,text='正在为新版准备已保存的重试设置…',padding=(24,18)).pack()
    ttk.Label(window,text='首次验收可能需要数分钟，完成后自动启动。',padding=(24,0)).pack()
    progress=ttk.Progressbar(window,mode='indeterminate',length=340)
    progress.pack(padx=24,pady=18);progress.start(12)
    window.protocol('WM_DELETE_WINDOW',window.iconify)
    output=queue.Queue()
    result=[]
    def work():
        try: output.put((manager._worker('auto'),None))
        except Exception as exc: output.put((None,exc))
    def poll():
        try: result.append(output.get_nowait())
        except queue.Empty: window.after(100,poll)
        else: window.quit()
    threading.Thread(target=work,daemon=False).start()
    window.after(100,poll)
    try: window.mainloop()
    finally:
        progress.stop()
        window.destroy()
    value,error=result[0]
    if error: raise error
    return value


def get_selection(root=ROOT, *, resources=None, config_path=None):
    from controller.verification import recipe_id
    resources=resources or installed_resources()
    try:
        pointer=json.loads((root/'state/desktop-trial.json').read_text(encoding='utf-8'))
        if pointer.get('enabled', True) is False:
            return dict(mode='official',engine=str(resources/'codex.exe'),
                        desktop=str(resources.parent/'ChatGPT.exe'),reason='已在控制器选择官方默认。')
        runtime=Path(pointer['runtime']).resolve(strict=True)
        runtime.relative_to((root/'runtime').resolve())
        manifest=json.loads((runtime/'manifest.json').read_text(encoding='utf-8'))
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        return dict(mode='official',engine=str(resources/'codex.exe'),
                    desktop=str(resources.parent/'ChatGPT.exe'),reason='没有可用的试用副本。')
    config_path=config_path or Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))/'config.toml'
    return selection(resources,runtime,manifest,config_path,recipe_id())


def _main(argv=None, automatic=None, *, notifications=None):
    def notify(title, text):
        if notifications is None:
            message(title, text)
        else:
            notifications.append((title, text))
    parser=argparse.ArgumentParser(description='Codex 自定义重试桌面试用入口')
    parser.add_argument('--check',action='store_true',help='只检查选择和更新保护，不启动桌面')
    parser.add_argument('--official',action='store_true',help='使用当前官方引擎启动')
    args=parser.parse_args(argv)
    selected=get_selection()
    if args.official:
        resources=installed_resources()
        selected.update(mode='official',engine=str(resources/'codex.exe'),reason='使用官方默认入口。')
    processes=process_snapshot()
    existing=running_desktops(processes)
    status=dict(**selected,already_running=bool(existing),running_desktop_pids=[p['ProcessId'] for p in existing])
    save_status('desktop-launch-check.json',status)
    if args.check:
        print(json.dumps(status,ensure_ascii=False,indent=2));return 0
    if existing:
        notify('Codex 已经在运行','请先正常退出 Codex 桌面，再点击这个入口。\n当前进程保持运行；没有切换引擎。')
        return 2
    if selected['mode']=='official' and not args.official:
        detail=(automatic or {}).get('reason') or selected['reason']
        notify('使用官方引擎',detail+'\n本次使用官方桌面，自定义重试暂未启用；已保存参数保留。')
    if not args.official:
        taskbar('prepare')
    env=launch_environment(os.environ,selected)
    process=subprocess.Popen([selected['desktop']],cwd=str(Path(selected['desktop']).parent),env=env)
    save_status('desktop-last-launch.json',dict(**status,launcher_child_pid=process.pid,forced_official=args.official))
    if not args.official:
        taskbar('start_watch', pid=process.pid, desktop=selected['desktop'])
    # Read-only startup observation; no restart, automatic repair or setup.
    before={p['ProcessId'] for p in processes}
    deadline=time.monotonic()+25
    observed=[]
    observation_error=None
    try:
        while time.monotonic()<deadline:
            time.sleep(2)
            snapshot=process_snapshot()
            fresh_desktops={p['ProcessId'] for p in running_desktops(snapshot) if p['ProcessId'] not in before}
            observed=[p for p in snapshot if p['ProcessId'] not in before and p['ParentProcessId'] in fresh_desktops
                      and Path(p.get('ExecutablePath') or '').name.lower()=='codex.exe']
            if observed:break
    except Exception as exc:
        # Launch already happened; never misreport a monitoring failure as failure to start.
        observation_error=str(exc)
    selected_seen=any(Path(p['ExecutablePath']).resolve()==Path(selected['engine']).resolve() for p in observed)
    save_status('desktop-launch-observation.json',dict(**selected,selected_engine_seen=selected_seen,
                processes=observed,observation_error=observation_error,
                scope='Executable selection only; not a sandbox or account-feature test.'))
    if selected['mode']=='custom-trial' and not selected_seen:
        notify('试用入口需要检查','未确认桌面选中了自定义引擎。\n请查看 Codex/logs/desktop-launch-observation.json；不要把本次启动当作已生效。')
    return 0


def main(argv=None):
    # The console worker owns the lock during tests. Reacquire it for selection
    # and spawn afterwards, including a fresh process/build check.
    from desktop_runtime import operation_lock, read_pointer, DesktopManager
    arguments = sys.argv[1:] if argv is None else argv
    if '--check' in arguments:
        return _main(argv)
    automatic = None
    if not arguments:
        pointer = read_pointer(ROOT)
        if (pointer.get('enabled', True) is not False and pointer.get('runtime')
                and get_selection()['mode'] != 'custom-trial'
                and not running_desktops(process_snapshot())):
            manager = DesktopManager(ROOT)
            try:
                automatic = automatic_update(manager)
            except Exception as exc:
                automatic = dict(reason='自动验收未完成：'+str(exc))
                save_status('automatic-update-error.json', automatic)
            finally:
                manager.close()
    notifications = []
    with operation_lock(ROOT, '启动并确认桌面引擎'):
        result = _main(argv, automatic, notifications=notifications)
        if result == 0 and '--check' not in arguments:
            from desktop_storage import best_effort
            best_effort(ROOT)
    # Informational windows must never hold the operation lock while waiting for
    # input. Keep the bounded startup observation above locked to protect its copy.
    for title, text in notifications:
        message(title, text)
    return result


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        save_status('desktop-launch-error.json',{'error':str(exc)})
        if '--check' in sys.argv:raise
        message('Codex 试用入口未启动',str(exc)+'\n请使用原来的官方入口。')
