# Codex Desktop Retry Controller

为 Windows 上的 Codex 桌面版提供中文重试控制器：设置模型请求的最多重试次数、毫秒级等待和随机扰动，通过独立、经过验收的引擎副本启动。官方安装与用户配置保持原样。

这是社区工具，与 OpenAI 无隶属关系。仓库只分发控制器源码；使用者需要自行安装官方 Codex 桌面版。

> **兼容性状态（2026-10-29）：桌面包 `26.1023.6123.0` / 引擎 `0.165.0-alpha.1.2` 已通过完整验收。** 包括 22 项原生请求场景及撤销恢复；100 次 / 2000 ms 固定等待、隔离目录中的 50 次 / 1000 ± 70 ms 随机等待，各通过参数验收和六项 unelevated 沙盒对照。结论绑定实际文件与规则摘要，不保证任意未来构建；已验证范围见[兼容性说明](docs/COMPATIBILITY.md)。设置成功后须正常退出 Codex，再从自定义入口启动，才会使用新副本。

## 能做什么

- 最多重试 **0～1,000,000 次**，不含首次请求；0 表示不重试。
- 等待支持 **秒／毫秒**切换，精度为 **1 毫秒**；不含请求本身的耗时。
- 可配置对称随机扰动，例如 **1000 ± 70 毫秒**，每次失败后选择 **930～1070 毫秒**等待；扰动为 0 时保持固定等待，整个范围须在 0～60 秒内。
- 独立副本制作、行为验收、启动指针原子切换，以及恢复官方默认。
- 官方桌面更新后沿用保存参数，尝试适配新构建；失败时保留参数并允许官方启动。
- 自动保留当前副本与一代历史，保护运行中的副本；提供历史清理和控制器进程恢复。
- 管理自定义启动快捷方式的稳定图标与任务栏关联。

当前拆分函数规则按错误分类数据流、预算字段、分支和 Responses 调用关系定位，已去掉内部函数名、遥测名及诊断文字依赖，并支持有限包装链和多个通过范围检查的 HTTP 实现。本轮支持 HTTP 状态指针经完整寄存器复制或同一未被改写的栈槽恢复，分类过程可复用原状态寄存器；仍核对调用、分支和计数写回关系。这样可减少重命名与有限布局变化带来的失效；ABI 或控制流重构仍可能需要适配，历史精确规则也保留原有约束。详见[后续版本预期](docs/COMPATIBILITY.md#后续版本的预期)。

作用范围是模型采样的 **HTTP / Responses / SSE** 重试。它不提高服务端额度，也不缩短服务器返回错误前的等待。WebSocket、远程主机和所有后台请求没有完整验收，不能当作全局网络重试开关。

## 环境与安装

| 项目 | 要求与边界 |
|---|---|
| 系统 | Windows x64，当前用户已注册安装的官方 Codex 桌面包 |
| Python | 3.10+，64 位，包含 tkinter；同目录需要 `python.exe`，快捷方式建议使用 `pythonw.exe` |
| Python 依赖 | `requirements.txt` 中的 capstone、pefile；Python 3.10 另安装 tomli |
| 其他平台 | 未支持 macOS、Linux、WSL、Windows ARM64 或独立终端 CLI |
| 引擎版本 | 每个构建须通过结构识别及行为验收，不能仅凭版本号判断兼容 |
| 磁盘空间 | 一代完整副本通常数百 MB；自动保留两代，验证期间需要额外临时空间 |

从 PowerShell 执行；以下 `python` 应指向同一个 Python 安装或虚拟环境：

```powershell
git clone https://github.com/Unended-night/codex-desktop-retry-controller.git
Set-Location .\codex-desktop-retry-controller
python -m pip install -r requirements.txt
python -m tkinter
python -B -X utf8 desktop_runtime.py status
```

`python -m tkinter` 用于确认界面依赖，关闭测试窗口后继续。缺少 tkinter 时请通过 Python 安装程序补齐；它不是这里的 pip 依赖。程序不自动下载 Python 依赖或官方引擎。

## 使用

1. 运行 `python -B -X utf8 app.pyw`，或双击 **启动控制器.cmd**。后者要求所需的 `pythonw.exe` 已在 PATH 中；有多个 Python 安装时应确认它与安装依赖的解释器一致。本轮完整回归使用直接 Python 解释器，虚拟环境的验证限制见兼容性说明。
2. 查看“当前运行”和“下次启动”，输入次数、基础等待和随机扰动，点击 **保存到启动入口**。例如时间单位选“毫秒”，基础等待填 `1000`、随机扰动填 `70`，界面会预览 `930～1070 毫秒`。切换单位会换算输入值。新副本只有在验收通过后才生效；当前已运行的 Codex 不会被替换。
3. 正常退出 Codex，再点击控制器的 **启动 Codex**，或从下述“自定义重试”快捷方式启动。重新检测以确认实际运行的引擎与参数。
4. **恢复官方默认**让同一启动入口下次使用官方引擎，保留最后保存的参数；不会自动重新启用自定义。
5. **重新验证已存设置**按最后保存的参数重新制作并验收副本，成功后重新启用自定义。输入框里尚未保存的修改不参与。

首次打开控制器只检测。结构不兼容时不能保存自定义副本，应使用官方入口并等待规则适配。未设置过自定义参数时，先在兼容构建上完成首次保存；自动更新适配用于后续已启用的自定义入口。

1 毫秒是参数精度，不代表 Windows 能保证 1 毫秒准时发起请求；系统调度和请求耗时可能使实测间隔更长。等待从失败处理后开始，不是所有成功请求之间的全局限速。随机扰动目前仅在支持的拆分函数结构上启用，旧精确结构继续支持固定等待。

## 两种快捷方式

| 入口 | 目标脚本 | 用途 |
|---|---|---|
| Codex 重试控制器 | `app.pyw` | 打开设置界面 |
| Codex 自定义重试 | `desktop_trial.py` | 检查设置与收据，启动合适的桌面引擎 |
| 官方 Codex | 官方安装入口 | 使用官方引擎 |

**设置界面与真正的启动入口是两个快捷方式。** 创建方法、项目迁移、图标修复与任务栏固定步骤见[快捷方式说明](docs/SHORTCUTS.md)。`.lnk` 含本机绝对路径，因此不随源码分发。

自定义入口使用项目内稳定的 `assets/codex.ico`，缺失或损坏时从当前官方安装提取恢复。官方图标不随公开仓库分发。控制器使用自身原有图标；官方更新和历史副本清理不需要改快捷方式的版本路径。

## 更新与工作原理

启动器从当前用户注册信息定位官方桌面包，通过进程级 `CODEX_CLI_PATH` 选择经过验收的独立引擎副本，不覆写 WindowsApps 中的正式安装。每次启动检查构建、组件、规则与收据；需要新副本时先验收，再原子切换启动指针。

- **官方 Codex 更新**：已启用的自定义入口自动尝试适配并沿用参数。失败则保留指针与参数，本次使用官方引擎；同一构建、规则和参数的自动失败冷却 6 小时。手动保存或重新验证可立即重试。
- **控制器源码更新**：本项目没有自动下载更新器。在项目目录执行 `git pull`；依赖声明变化时重新安装依赖。规则变化会使旧收据失效，之后须重新验收。
- **正在运行的 Codex**：保存设置和更新适配不热替换当前进程。正常退出后从自定义入口重新启动。

详细流程见[原理说明](docs/ARCHITECTURE.md)，更新和维护要求见[维护说明](docs/MAINTENANCE.md)。

检测会核对完整文件和规则摘要，已有有效行为批准时省去重复反汇编。本机实测状态检测约 **3.5 秒**，相同参数重复保存约 **2.4 秒**；已有批准后，更换参数并制作、验收副本约 **75 秒**。首次新规则下完整验收并发布约 **6 分 28 秒**，仍需覆盖所有原生场景、实际参数及沙盒对照；时间受引擎大小、请求等待和机器负载影响。

## 常用命令与恢复

在项目根目录执行：

```powershell
python -B -X utf8 desktop_runtime.py status
python -B -X utf8 desktop_trial.py --check
python -B -X utf8 desktop_runtime.py apply --retries 20 --interval 1
python -B -X utf8 desktop_runtime.py apply --retries 20 --interval-ms 1000 --jitter-ms 70
python -B -X utf8 desktop_runtime.py verify
python -B -X utf8 desktop_runtime.py restore
python -B -X utf8 desktop_trial.py --official
python -B -X utf8 desktop_runtime.py cleanup --dry-run
python -B -X utf8 desktop_runtime.py recover --dry-run
```

`status` / `--check` 不制作副本、不切换入口、不修复快捷方式；仍可能记录检查日志。`apply` / `verify` 需要当前构建兼容。`cleanup` 去掉 `--dry-run` 后清空可删除历史，保留运行中和下次启动所需的副本；自动清理则额外保留一代历史。

保存或验证卡住时，可用界面的 **清理控制器进程**；按钮在后台任务忙碌时仍可用。它只处理核实属于本项目的启动器、验证任务及子进程，保护真实 Codex 桌面和聊天引擎，并实际检查锁能否重新获取。不要删除锁文件来假装解锁。命令行实际恢复为 `python -B -X utf8 desktop_runtime.py recover`。

## 文件与验证

| 路径 | 内容 |
|---|---|
| `app.pyw` | 中文 tkinter 控制器 |
| `desktop_runtime.py`、`desktop_trial.py` | 副本管理与桌面启动选择 |
| `desktop_validation.py`、`desktop_storage.py`、`desktop_processes.py` | 验收、存储和进程恢复 |
| `desktop_shell.py`、`windows_shell.py` | 自定义快捷方式与窗口任务栏关联 |
| `controller/` | 指令结构识别、可撤销补丁与原生验收套件 |
| `research/` | 精选的运行及验收依赖，不能整体删除 |
| `tests/` | 单元回归、指令夹具与手工集成验收工具 |
| `runtime/`、`state/`、`logs/` | 本机生成的副本、状态与诊断，不进入 Git |

```powershell
python -B -X utf8 -m unittest discover -s tests -p "test_*.py" -v
```

单元测试不等于当前引擎已兼容；真实原生与沙盒验收有各自前提，见[测试说明](tests/README.md)。公开文件范围和首次发布检查见[发布说明](docs/PUBLICATION.md)。
