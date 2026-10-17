# Restore icons without binding shortcuts to a versioned WindowsApps/runtime path.
[CmdletBinding()]
param([string[]]$ShortcutDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()
$projectRoot = $PSScriptRoot
$iconDirectory = Join-Path $projectRoot 'assets'
$stableIcon = Join-Path $iconDirectory 'codex.ico'

# The installed app is only an initial source. Keep the local icon on updates.
if (-not (Test-Path -LiteralPath $stableIcon -PathType Leaf)) {
    $registryRoot = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'
    $sources = @(foreach ($package in Get-ChildItem -LiteralPath $registryRoot) {
        if ($package.PSChildName -match '^OpenAI\.Codex_(\d+\.\d+\.\d+\.\d+)_x64__2p2nqsd0c76g0$') {
            $packageVersion = [version]$Matches[1]
            $packageFolder = $package.GetValue('PackageRootFolder')
            if ($packageFolder) {
                $sourceIcon = Join-Path $packageFolder 'app\resources\icon-chatgpt.ico'
                if (Test-Path -LiteralPath $sourceIcon -PathType Leaf) {
                    [pscustomobject]@{Version=$packageVersion; Path=$sourceIcon}
                }
            }
        }
    })
    $latest = $sources | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $latest) { throw 'No installed Codex icon found. Restore assets/codex.ico from the project backup.' }
    New-Item -ItemType Directory -Path $iconDirectory -Force | Out-Null
    # WindowsApps can carry encryption metadata that Copy-Item cannot transfer.
    # Copy the icon bytes only; the project file needs no package attributes.
    [System.IO.File]::WriteAllBytes($stableIcon, [System.IO.File]::ReadAllBytes($latest.Path))
}

Add-Type -AssemblyName System.Drawing
$iconCheck = [System.Drawing.Icon]::new($stableIcon)
$iconCheck.Dispose()

if (-not $ShortcutDirectory) {
    $ShortcutDirectory = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('Programs'),
        (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
    )
}
$shortcuts = @(foreach ($directory in $ShortcutDirectory) {
    if (Test-Path -LiteralPath $directory -PathType Container) {
        Get-ChildItem -LiteralPath $directory -Filter '*.lnk' -File -Recurse
    }
}) | Sort-Object FullName -Unique
# Only the custom Codex launcher uses this icon; preserve the controller's icon.
$managedScripts = @('desktop_trial.py') | ForEach-Object { Join-Path $projectRoot $_ }
$shell = New-Object -ComObject WScript.Shell
$backupDirectory = Join-Path $projectRoot ('logs\shortcut-icon-repair\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$records = [System.Collections.Generic.List[object]]::new()
$changedPaths = [System.Collections.Generic.List[string]]::new()
$newLocation = $stableIcon + ',0'

foreach ($file in $shortcuts) {
    $link = $shell.CreateShortcut($file.FullName)
    $managed = $false
    foreach ($script in $managedScripts) {
        $argumentPattern = '(?:^|\s)"?' + [regex]::Escape($script) + '"?(?=\s|$)'
        if ($link.TargetPath -ieq $script -or $link.Arguments -imatch $argumentPattern) { $managed = $true }
    }
    if (-not $managed) { continue }
    $before = [ordered]@{}
    foreach ($field in @('TargetPath','Arguments','WorkingDirectory','Description','WindowStyle','Hotkey')) {
        $before[$field] = $link.$field
    }
    $oldLocation = $link.IconLocation
    $changed = $oldLocation -ine $newLocation
    $backup = $null
    if ($changed) {
        New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
        $backup = Join-Path $backupDirectory ($records.Count.ToString('D3') + '-' + $file.Name)
        Copy-Item -LiteralPath $file.FullName -Destination $backup
        try {
            $link.IconLocation = $newLocation
            $link.Save()
            $check = $shell.CreateShortcut($file.FullName)
            foreach ($field in $before.Keys) {
                if ($check.$field -cne $before[$field]) { throw "Unexpected shortcut change: $field" }
            }
            if ($check.IconLocation -ine $newLocation) { throw 'Shortcut icon write did not persist.' }
        } catch {
            Copy-Item -LiteralPath $backup -Destination $file.FullName -Force
            throw
        }
        $changedPaths.Add($file.FullName)
    }
    $records.Add([pscustomobject]@{path=$file.FullName; changed=$changed; previous_icon=$oldLocation;
        icon=$newLocation; launch_properties_preserved=$true; backup=$backup})
}

# Notify Explorer; do not stop it or delete its icon cache.
if ($changedPaths.Count) {
    if (-not ('CodexShortcutIconNotify' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CodexShortcutIconNotify {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
    public static extern void SHChangeNotify(uint eventId, uint flags, string path, IntPtr unused);
}
'@
    }
    foreach ($path in $changedPaths) {
        [CodexShortcutIconNotify]::SHChangeNotify(0x2000, 0x2005, $path, [IntPtr]::Zero)
    }
    $report = [ordered]@{icon=$stableIcon; changed=$changedPaths.Count; shortcuts=@($records.ToArray())}
    $json = $report | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText((Join-Path $backupDirectory 'report.json'), $json, [System.Text.UTF8Encoding]::new($false))
}
[pscustomobject]@{icon=$stableIcon; matched=$records.Count; changed=$changedPaths.Count; shortcuts=@($records.ToArray())} |
    ConvertTo-Json -Depth 6
