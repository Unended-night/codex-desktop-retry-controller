# 运行所需的探测与验收脚本

此目录虽然叫 research，其中部分脚本已经成为正式运行依赖，不能整体删除。

| 文件 | 用途 |
|---|---|
| `probe_retries.py` | 回环模拟 API、临时配置和真实引擎重试探测；完整原生套件依赖 |
| `appserver_probe.py` | 通过临时 app-server stdio 协议进行桌面请求探测 |
| `debug_probe.py` | 仅调试自己启动的临时子进程；供探测脚本的可选调试分支使用 |
| `verify_desktop_runtime.py` | 发布时调用的参数与 unelevated 沙盒对照函数 |
| `verify_native_config.py` | 独立临时配置探测的手工辅助工具 |

Python 依赖通过根目录的 `requirements.txt` 安装。代码为兼容旧部署仍会查找本地 `.deps/`，但公开仓库不捆绑该目录，正常 Python site-packages 同样可用。

原始抓取、反汇编全文、旧补丁实验、临时 `.work/`、探测 JSON 和本机供应商诊断不公开。公开的指令回归夹具位于 `tests/fixtures/outlined-retry.json`，仅作为结构识别测试输入，不是可执行程序。

这些脚本不是统一的一键兼容性入口：部分脚本的 `main()` 仍含历史安装布局假设。普通使用请从根目录的 `desktop_runtime.py` / `desktop_trial.py` 进入；维护者调用前先检查参数和前提，详见[测试说明](../tests/README.md)。
