# 快捷方式、图标与任务栏

## 两个入口分别做什么

| 名称 | 目标程序 | 参数 |
|---|---|---|
| Codex 重试控制器 | 所选 Python 的 `pythonw.exe` | `-B -X utf8 "<项目目录>\app.pyw"` |
| Codex 自定义重试 | 同一 Python 的 `pythonw.exe` | `-B -X utf8 "<项目目录>\desktop_trial.py"` |

两者的“起始位置”均为项目目录。控制器用于保存设置；真正启动带自定义重试的 Codex，应使用第二个入口或控制器的“启动 Codex”按钮。官方入口继续可用。需要显式使用官方引擎时可运行：

```powershell
python -B -X utf8 desktop_trial.py --official
```

保存设置不会替换已运行的 Codex。需要正常退出桌面，再通过自定义入口重新启动；已有桌面运行时，启动器不会结束它来强行切换引擎。

## 创建桌面入口

`.lnk` 包含本机 Python 和项目的绝对路径，因此请在每台机器上创建，不要从 GitHub 复制别人机器的快捷方式。

可以在 Windows“新建快捷方式”中按上表填写，或在项目根目录运行以下 PowerShell。代码将使用当前 `python` 对应的 `pythonw.exe`，只创建不存在的桌面入口；已有同名入口保留：

```powershell
$projectRoot = (Get-Location).Path
$pythonExe = (& python -B -X utf8 -c 'import sys; print(sys.executable)').Trim()
if ($LASTEXITCODE -ne 0) { throw '无法定位所选 Python。' }
$pythonwExe = Join-Path (Split-Path $pythonExe -Parent) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonwExe -PathType Leaf)) {
    throw '同目录未找到 pythonw.exe，请检查 Python 安装。'
}
foreach ($script in @('app.pyw', 'desktop_trial.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $script) -PathType Leaf)) {
        throw '请先切换到项目根目录。'
    }
}
$desktopDir = [Environment]::GetFolderPath('Desktop')
$shell = New-Object -ComObject WScript.Shell
$entries = @(
    @{ Name = 'Codex重试控制器.lnk'; Script = 'app.pyw' },
    @{ Name = 'Codex自定义重试.lnk'; Script = 'desktop_trial.py' }
)
foreach ($entry in $entries) {
    $linkPath = Join-Path $desktopDir $entry.Name
    if (Test-Path -LiteralPath $linkPath) {
        Write-Host "保留已有入口：$linkPath"
        continue
    }
    $link = $shell.CreateShortcut($linkPath)
    $link.TargetPath = $pythonwExe
    $link.Arguments = '-B -X utf8 "' + (Join-Path $projectRoot $entry.Script) + '"'
    $link.WorkingDirectory = $projectRoot
    $link.Description = $entry.Name
    $link.Save()
}
& $pythonExe -B -X utf8 desktop_shell.py repair
```

最后一行维护自定义入口的稳定图标、开始菜单和任务栏关联；不启动 Codex，不保存重试参数，也不修改控制器图标。此前没有启动记录时，返回的“未附加运行桌面”说明正常，快捷方式仍可完成修复。该操作要求当前用户已正确安装官方桌面包，以便首次提取图标。

若把这段中文代码保存为 `.ps1` 并使用 Windows PowerShell 5.1，建议保存为 UTF-8 with BOM，避免中文路径或名称被错误解码。直接粘贴到 PowerShell 终端执行不涉及脚本文件编码检测。

## 固定图标与开始菜单

- 自定义入口的图标固定为项目的 `assets/codex.ico`，不引用带版本号的 WindowsApps 路径，也不引用会被清理的 runtime 目录。
- 公开仓库不分发官方 ICO；正常自定义启动或 `desktop_shell.py repair` 会在图标缺失/损坏时从当前官方包的 `icon-chatgpt.ico` 恢复。有效图标保留，损坏图标先备份。
- 控制器保留原图标；不要为了统一外观把它也设成 Codex 图标。
- 个人开始菜单中维护“Codex自定义重试”入口，使用固定应用标识 `White.Codex.CustomRetry`。这是现有协议标识，不是需要修改的用户名占位符。
- 开始菜单同名入口若指向无关程序，会报告冲突并保留该入口。先核对和自行处理冲突，再修复。

普通自定义启动会自动维护关联。需要固定到任务栏时，先启动并确认是自定义入口，再从已修复的开始菜单入口或对应窗口固定。旧版固定项仍关联错误时可取消旧固定项，再重新固定；不需要删除 Explorer 图标缓存或重启 Explorer。

## 运行窗口如何关联

`desktop_shell.py` / `windows_shell.py` 把本次自定义启动的窗口关联到上述固定标识、启动命令和图标。一个隐藏 Python 辅助进程跟踪本次桌面进程的新窗口，按 PID、可执行文件和创建时间核对身份；同一桌面进程去重，桌面退出后辅助进程退出。

该辅助进程不属于引擎副本，也不增加历史副本数量。显式官方启动和控制器窗口排除。任务栏维护失败仅记日志，不成为引擎启动的阻断条件。

## 修复与迁移

```powershell
# 修复本项目自定义快捷方式及已核实的运行窗口关联
python -B -X utf8 desktop_shell.py repair

# 仅修复识别出的自定义启动快捷方式图标
powershell -NoProfile -File .\repair_shortcut_icons.ps1
```

第二个脚本扫描桌面、个人开始菜单和任务栏快捷方式，只更新指向本项目启动脚本的图标，保留启动目标、参数、起始位置和快捷键；不建立完整窗口关联。备份和报告分别保存在 `logs/taskbar-repair/`、`logs/shortcut-icon-repair/`，这些文件留在本机。

移动项目或 Python 后需要重新创建快捷方式。新项目路径的修复不能保证识别仍指向旧路径的入口，请核对旧入口后更新或删除再创建。跨机器迁移推荐重新克隆、安装依赖、创建入口并重新验收，不复制旧启动指针或批准缓存。

官方 Codex 正常更新不需要人工改快捷方式的版本路径。控制器源码 `git pull` 更新时路径不变，通常也不需要重建入口；如升级 Python 或移动虚拟环境则需要重新创建。
