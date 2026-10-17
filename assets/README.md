# 本机图标目录

公开仓库只包含此说明，不分发官方图标文件。首次正常自定义启动或运行 `python -B -X utf8 desktop_shell.py repair` 时，会从当前用户安装的官方 Codex 包中提取 `icon-chatgpt.ico`，保存为此处的 `codex.ico`。

自定义 Codex 入口和窗口使用这个稳定路径，不引用带版本号的 WindowsApps 或可被清理的 runtime 路径。有效图标保留，缺失或损坏时恢复；损坏图标先备份到本机日志目录。控制器工具继续使用原图标。

本机备份/迁移时可保留此目录；新的克隆无需预先获得 ICO。图标被 Git 忽略。快捷方式、任务栏关联和修复步骤见[快捷方式说明](../docs/SHORTCUTS.md)。
