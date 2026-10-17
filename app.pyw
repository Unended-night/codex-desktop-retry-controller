"""Desktop UI. Importing this file never modifies Codex 桌面版."""
from __future__ import annotations

import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from decimal import Decimal

from controller.core import ControllerError, Manager, profile
from desktop_runtime import DesktopManager


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Codex 桌面版 · 重试控制器")
        self.geometry("820x720")
        self.minsize(730, 660)
        self.configure(bg="#f3f1ed")
        self.manager = DesktopManager()
        self.path: Path | None = None
        self.busy = False
        self.recovering = False
        self.operation_id = 0
        self.cancel_active = None
        self.detected = {}
        self.version = "未识别"
        self.jobs = queue.Queue()
        self.max_retries = tk.StringVar(value="25")
        self.interval = tk.StringVar(value="1")
        self.mode = tk.StringVar(value="custom")
        self.current = tk.StringVar(value="正在检测安装…")
        self.next_start = tk.StringVar(value="")
        self.location = tk.StringVar(value="")
        self.notice = tk.StringVar(value="打开时只检测。保存设置将验证新副本，通过后更新自定义启动入口。")
        self.widgets = []
        self._build()
        self.after(100, self._poll)
        self.after(150, self.refresh)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def _build(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f1ed")
        style.configure("TLabel", background="#f3f1ed", foreground="#242825", font=("Microsoft YaHei UI", 10))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 24, "bold"))
        style.configure("Muted.TLabel", foreground="#626b66", font=("Microsoft YaHei UI", 9))
        style.configure("TButton", font=("Microsoft YaHei UI", 10), padding=(13, 8))
        style.configure("Accent.TButton", background="#28564a", foreground="white")
        style.map("Accent.TButton", background=[("active", "#346f5e"), ("disabled", "#a9b5af")])
        style.configure("TRadiobutton", background="#f3f1ed", font=("Microsoft YaHei UI", 10))
        style.configure("TEntry", padding=8, font=("Microsoft YaHei UI", 12))
        body = ttk.Frame(self, padding=(30, 24))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="CODEX DESKTOP  /  LOCAL CONTROL", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(body, text="重试，由你设定。", style="Title.TLabel").pack(anchor="w", pady=(6, 6))
        ttk.Label(body, text="为自定义启动入口配置重试次数与等待间隔，随时切回官方默认。",
                  wraplength=740).pack(anchor="w")
        ttk.Separator(body).pack(fill="x", pady=18)
        status = ttk.Frame(body)
        status.pack(fill="x")
        self._button(status, "重新检测", self.refresh).pack(side="right")
        self._button(status, "启动 Codex", self.launch).pack(side="right", padx=(0, 8))
        ttk.Label(status, textvariable=self.current, wraplength=490, font=("Microsoft YaHei UI", 11, "bold")).pack(side="left", fill="x", expand=True)
        ttk.Label(body, textvariable=self.next_start, wraplength=735).pack(anchor="w", pady=(8, 0))
        ttk.Label(body, textvariable=self.location, style="Muted.TLabel", wraplength=735).pack(anchor="w", pady=(8, 12))
        modes = ttk.Frame(body)
        modes.pack(fill="x", pady=(0, 16))
        for title, value in [("自定义固定间隔", "custom"), ("官方默认", "default")]:
            radio = ttk.Radiobutton(modes, text=title, variable=self.mode, value=value, command=self._mode_changed)
            radio.pack(side="left", padx=(0, 26))
            self.widgets.append(radio)
        fields = ttk.Frame(body)
        fields.pack(fill="x")
        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(1, weight=1)
        ttk.Label(fields, text="最多重试次数").grid(row=0, column=0, sticky="w")
        ttk.Label(fields, text="失败后的等待间隔（秒）").grid(row=0, column=1, sticky="w")
        self.count_entry = ttk.Entry(fields, textvariable=self.max_retries, width=20)
        self.delay_entry = ttk.Entry(fields, textvariable=self.interval, width=20)
        self.count_entry.grid(row=1, column=0, sticky="ew", padx=(0, 18), pady=6)
        self.delay_entry.grid(row=1, column=1, sticky="ew", pady=6)
        self.widgets.extend((self.count_entry, self.delay_entry))
        ttk.Label(fields, text="0～1,000,000；0 表示不重试", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Label(fields, text="0～60 秒；0 表示不主动等待", style="Muted.TLabel").grid(row=2, column=1, sticky="w")
        ttk.Label(body, text="次数不含首次请求；间隔不含请求耗时。可以保持 Codex 运行并保存设置。\n保存成功后，正常退出 Codex，再从自定义重试入口或上方按钮启动。",
                  style="Muted.TLabel", wraplength=735).pack(anchor="w", pady=(16, 14))
        actions = ttk.Frame(body)
        actions.pack(fill="x")
        self.apply_button = self._button(actions, "保存到启动入口", self.apply, "Accent.TButton")
        self.apply_button.pack(side="left")
        self.restore_button = self._button(actions, "恢复官方默认", self.restore)
        self.restore_button.pack(side="left", padx=10)
        self.verify_button = self._button(actions, "重新验证已存设置", self.verify)
        self.verify_button.pack(side="left")
        self._button(actions, "查看日志", lambda: os.startfile(self.manager.logs)).pack(side="right")
        maintenance = ttk.Frame(body)
        maintenance.pack(fill="x", pady=(10, 0))
        self.cleanup_button = self._button(maintenance, "清空历史副本", self.cleanup)
        self.cleanup_button.pack(side="left")
        ttk.Label(maintenance, text="自动保留 1 个历史版本；手动清空历史，保留运行中和待生效副本。",
                  style="Muted.TLabel", wraplength=560).pack(side="left", padx=12)
        recovery = ttk.Frame(body)
        recovery.pack(fill="x", pady=(8, 0))
        self.recover_button = self._button(recovery, "清理控制器进程", self.recover_processes)
        self.recover_button.pack(side="left")
        ttk.Label(recovery, text="取消启动、保存和验证任务并释放锁；保留 Codex 与控制器窗口。",
                  style="Muted.TLabel", wraplength=540).pack(side="left", padx=12)
        ttk.Label(body, textvariable=self.notice, wraplength=735).pack(anchor="w", pady=(16, 8))
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 10))
        ttk.Label(body, text="最近操作", style="Muted.TLabel").pack(anchor="w")
        self.history = tk.Text(body, height=5, bg="#e9ece7", fg="#35423b", relief="flat",
                               font=("Microsoft YaHei UI", 9), padx=10, pady=8, state="disabled", wrap="word")
        self.history.pack(fill="both", expand=True, pady=(6, 0))
        ttk.Label(body, text="更新后自动适配并验收 · 沿用已保存参数 · 不修改 config.toml",
                  style="Muted.TLabel").pack(anchor="w", pady=(10, 0))
        self.update_idletasks()
        # Tk font sizes scale with Windows DPI; fixed pixel heights otherwise
        # clip the history and footer at 150% / 200% display scaling.
        width = min(max(820, body.winfo_reqwidth() + 20), self.winfo_screenwidth() - 100)
        height = min(max(720, body.winfo_reqheight() + 70), self.winfo_screenheight() - 100)
        self.geometry(f"{width}x{height}")
        self.minsize(min(width, 820), height)

    def _button(self, parent, title, command, style="TButton"):
        widget = ttk.Button(parent, text=title, command=command, style=style)
        self.widgets.append(widget)
        return widget

    def _mode_changed(self):
        state = "normal" if self.mode.get() == "custom" and not self.busy else "disabled"
        self.count_entry.configure(state=state)
        self.delay_entry.configure(state=state)
        self._permissions()

    def _permissions(self):
        compatible = self.detected.get("compatible", False)
        ready = not self.busy and compatible
        self.apply_button.configure(state="normal" if ready or (not self.busy and self.mode.get() == "default") else "disabled")
        self.restore_button.configure(state="normal" if not self.busy else "disabled")
        self.verify_button.configure(state="normal" if ready else "disabled")
        self.recover_button.configure(state="disabled" if self.recovering else "normal")

    def _record(self, text):
        self.history.configure(state="normal")
        self.history.insert("end", text + "\n")
        self.history.see("end")
        self.history.configure(state="disabled")

    def _run(self, description, work, done, *, recovery=False):
        if (self.busy and not recovery) or self.recovering:
            return
        if recovery and self.cancel_active is not None:
            self.cancel_active.set()
        self.operation_id += 1
        operation_id = self.operation_id
        cancel = threading.Event()
        self.cancel_active = cancel
        self.recovering = recovery
        self.busy = True
        self.notice.set(description)
        for widget in self.widgets:
            widget.configure(state="disabled")
        self.recover_button.configure(state="disabled" if recovery else "normal")
        self.progress.start(12)

        def worker():
            try:
                with self.manager.cancellable(cancel):
                    result = work()
                self.jobs.put((operation_id, done, result, None))
            except Exception as exc:
                self.jobs.put((operation_id, done, None, str(exc)))
        threading.Thread(target=worker, daemon=False).start()

    def _poll(self):
        try:
            operation_id, done, result, error = self.jobs.get_nowait()
        except queue.Empty:
            pass
        else:
            # A cancelled worker may finish after recovery. Its stale callback
            # must not reset the UI or start a follow-up operation.
            if operation_id != self.operation_id:
                self.after(100, self._poll)
                return
            self.busy = False
            self.recovering = False
            self.cancel_active = None
            self.progress.stop()
            for widget in self.widgets:
                widget.configure(state="normal")
            self._mode_changed()
            if error:
                if done == self.show_status:
                    self.detected = {}
                    self._permissions()
                    self.current.set("检测未通过 · 请查看下方说明")
                self.notice.set("操作未完成：" + error)
                self._record("未完成 · " + error)
                self.manager.logger.error("UI operation failed: %s", error)
            else:
                done(result)
        self.after(100, self._poll)

    def show_status(self, result):
        self.path = Path(result["path"])
        self.location.set("下次引擎：" + result['selected']['engine'])
        self.detected = result
        self.version = result["version"]
        self.current.set(f"安装 v{self.version} · {result['current_text']}")
        self.next_start.set(result['next_text'])
        p = result['profile']
        self.max_retries.set(str(p['max_retries']))
        self.interval.set(str(Decimal(p['interval_ms']) / 1000))
        self.mode.set('custom' if result['enabled'] else 'default')
        self._mode_changed()
        self._record(f"检测完成 · {self.current.get()}")
        self.notice.set(result.get("reason") or "可保存设置；将在下次从自定义入口启动时生效。")

    def refresh(self):
        self._run("正在检测官方版本、当前进程与下次启动设置…", self.manager.inspect, self.show_status)

    def launch(self):
        self._run("正在打开自定义启动入口…", self.manager.launch,
                  lambda result: self.notice.set("入口已打开。若 Codex 仍在运行，会提示先正常退出。"))

    def apply(self):
        if self.mode.get() == "default":
            self.restore()
            return
        if self.path is None:
            self.notice.set("请先检测 Codex 桌面安装。")
            return
        try:
            p = profile(self.max_retries.get(), self.interval.get())
        except ControllerError as exc:
            self.notice.set(str(exc))
            return
        self._run("正在制作新副本并验证重试和沙盒，可能需要数分钟；当前进程保持运行…", lambda: self.manager.apply(p), self.changed)

    def verify(self):
        if self.path is not None:
            self._run("正在按已保存参数重新验收并启用新副本；不采用输入框未保存的数值…",
                      self.manager.verify, self.changed)

    def restore(self):
        self._run("正在将下次启动切回官方默认…", self.manager.restore, self.changed)

    def cleanup(self):
        self._run("正在清空未使用的历史副本；运行中和下次启动所需副本保留…",
                  self.manager.cleanup, self.cleaned)

    def cleaned(self, result):
        text = f"清理完成：释放 {result['reclaimed_bytes'] / 1024**2:.1f} MiB"
        if result.get('keep_history') is False:
            text += f"；保留 {len(result.get('retained', []))} 份运行中或下次启动所需副本"
        if result.get('skipped'):
            text += f"；{len(result['skipped'])} 项暂未处理，详情见 logs/storage-cleanup.json"
        self._record(text)
        self.notice.set(text)

    def recover_processes(self):
        self._run("正在取消控制器任务、清理测试子进程并检查操作锁…",
                  self.manager.recover_processes, self.processes_recovered, recovery=True)

    def processes_recovered(self, result):
        count = len(result.get('stopped', []))
        if result.get('recovered'):
            text = f"进程清理完成：结束 {count} 个任务进程，操作锁已释放，可以重新保存或验证。"
        else:
            text = f"已结束 {count} 个任务进程，仍有进程或锁未释放；详情见 logs/process-recovery.json。"
        self._record(text)
        self.notice.set(text)

    def changed(self, result):
        if result.get('cleanup'):
            self.cleaned(result['cleanup'])
        self.version = result.get("version", self.version)
        title = ("下次启动已切回官方默认" if result["action"] == "restore" else
                 "设置未变化，已复用有效副本" if result.get('reused') else "新副本已验收并保存到启动入口")
        if not result["changed"]:
            title += "（原本已处于此状态）"
        self._record(title + "；当前运行保持不变。")
        self.notice.set(title + "。正常退出后从自定义入口启动生效。")
        self.refresh()

    def close(self):
        if self.busy:
            self.notice.set("正在处理文件，请等待本次操作完成后关闭窗口。")
            return
        self.manager.close()
        self.destroy()


if __name__ == "__main__":
    try:
        # Keep widgets crisp at Windows scaling factors above 100%.
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    try:
        App().mainloop()
    except Exception as exc:
        Manager().logger.exception("GUI startup failed")
        messagebox.showerror("启动失败", f"{exc}\n详细信息已写入 logs/controller.log。")
