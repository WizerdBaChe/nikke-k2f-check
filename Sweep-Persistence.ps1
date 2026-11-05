<#
.SYNOPSIS
  Read-only sweep for anything an operator could have planted with the K2F RAT's `exec` command,
  for people who cannot reinstall Windows.
.DESCRIPTION
  The known K2F persistence is the Chrome COM hijack (checked by Check-K2F.ps1). But the RAT can run
  arbitrary shell commands, so this sweep lists generic autostart points and new unsigned executables
  created since -Since, and highlights anything created inside the agent's active windows
  (read from the launcher debug.log when -InstallPath is given).
  Nothing is changed. Items are leads to review, not verdicts: a hit is "look at this", not "malware".
.PARAMETER Since
  Start of the review window. Default 2026-09-27 (first CDN tampering).
.PARAMETER InstallPath
  Launcher install root (NIKKE or Delta Force Garena); used only to read agent start times from debug.log.
.PARAMETER WindowHours
  How long after each agent start counts as "active window". Default 8.
#>
[CmdletBinding()]
param(
  [datetime]$Since = '2026-09-27',
  [string]$InstallPath,
  [int]$WindowHours = 8,
  [string]$ReportPath
)

$ErrorActionPreference = 'SilentlyContinue'
$items = New-Object System.Collections.ArrayList
$sigCache = @{}

$userWritable = @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, $env:ProgramData, "$env:PUBLIC", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents") |
  Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

function Test-UserWritable([string]$p) {
  if (-not $p) { return $false }
  foreach ($u in $userWritable) { if ($p.StartsWith($u, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
  return $false
}
function Get-Signer([string]$p) {
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return 'missing' }
  if ($sigCache.ContainsKey($p)) { return $sigCache[$p] }
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $r = if ($s.Status -eq 'Valid' -and $s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^CN=("[^"]+"|[^,]+).*', '$1').Trim('"') } else { "unsigned($($s.Status))" }
  $sigCache[$p] = $r; return $r
}
# Pull the executable path out of a command line.
function Get-ExePath([string]$cmd) {
  if (-not $cmd) { return $null }
  $cmd = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($cmd -match '^"([^"]+)"') { return $matches[1] }
  if ($cmd -match '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|lua|scr|com))\b') { return $matches[1] }
  return ($cmd -split '\s+')[0]
}

# ---------- active windows from debug.log ----------
$windows = @()
if ($InstallPath) {
  # intl_service (NIKKE) or service (Delta Force Garena), as in Check-K2F.ps1.
  $dbg = Get-ChildItem $InstallPath -Recurse -Force -Filter debug.log | Where-Object { $_.DirectoryName -match '\\(intl_service|service)$' } | Select-Object -First 1
  if ($dbg) {
    # The agent lives inside the launcher's web view, so it is active only while the launcher runs.
    # Window = agent start .. last debug.log line of that launcher session (gap > 1 h ends a session),
    # plus 30 min margin; capped at -WindowHours.
    # Log lines carry no year. The file's last write is the newest line, so a line from a later month than
    # that belongs to the previous year (a log spanning New Year).
    $lastWrite = $dbg.LastWriteTime
    $stamps = foreach ($line in (Get-Content -LiteralPath $dbg.FullName)) {
      if ($line -match '^\[(\d{2})(\d{2})/(\d{2})(\d{2})(\d{2})') {
        $year = if ([int]$matches[1] -gt $lastWrite.Month) { $lastWrite.Year - 1 } else { $lastWrite.Year }
        try { $t = Get-Date -Year $year -Month $matches[1] -Day $matches[2] -Hour $matches[3] -Minute $matches[4] -Second $matches[5] -Millisecond 0 } catch { continue }
        [pscustomobject]@{ T = $t; Agent = ($line -like '*agent started as*') }
      }
    }
    for ($i = 0; $i -lt $stamps.Count; $i++) {
      if (-not $stamps[$i].Agent) { continue }
      $start = $stamps[$i].T; $last = $start
      for ($j = $i + 1; $j -lt $stamps.Count; $j++) {
        if (($stamps[$j].T - $last).TotalHours -gt 1) { break }
        $last = $stamps[$j].T
      }
      $end = $last.AddMinutes(30); if ($end -gt $start.AddHours($WindowHours)) { $end = $start.AddHours($WindowHours) }
      $windows += [pscustomobject]@{ Start = $start; End = $end }
    }
  }
}
function Test-InWindow([datetime]$t) { foreach ($w in $windows) { if ($t -ge $w.Start -and $t -le $w.End) { return $true } }; return $false }

function Add-Item([string]$Kind, [string]$Name, [string]$Target, [Nullable[datetime]]$When, [string]$Why) {
  $exe = Get-ExePath $Target
  $signer = if ($exe) { Get-Signer $exe } else { '' }
  $score = 0
  if ($signer -like 'unsigned*' -or $signer -eq 'missing') { $score++ }
  if (Test-UserWritable $exe) { $score++ }
  if ($When -and $When -ge $Since) { $score++ }
  $inWin = [bool]($When -and (Test-InWindow $When))
  if ($inWin) { $score += 2 }
  [void]$items.Add([pscustomobject]@{
    Score = $score; InWindow = $inWin; Kind = $Kind; Name = $Name; Target = $Target
    Signer = $signer; When = $(if ($When) { $When.ToString('yyyy-MM-dd HH:mm') } else { '' }); Why = $Why })
}

# ---------- 1. Run keys ----------
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
  $props = Get-ItemProperty $k
  if (-not $props) { continue }
  foreach ($p in $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
    if ($k -like '*NT\CurrentVersion\Windows' -and $p.Name -notin 'Load', 'Run') { continue }
    if (-not $p.Value) { continue }
    Add-Item 'Run key' "$($k -replace '^HK(CU|LM):\\Software\\','')\$($p.Name)" "$($p.Value)" $null 'autostart at logon'
  }
}
# Winlogon shell / userinit tampering
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { Add-Item 'Winlogon' 'Shell' $wl.Shell $null 'Shell is not explorer.exe' }
if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Add-Item 'Winlogon' 'Userinit' $wl.Userinit $null 'Userinit has extra entries' }
$wlu = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wlu.Shell) { Add-Item 'Winlogon' 'HKCU Shell' $wlu.Shell $null 'per-user Shell override' }

# ---------- 2. Startup folders ----------
foreach ($d in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
  foreach ($f in Get-ChildItem $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' }) {
    $target = $f.FullName
    if ($f.Extension -eq '.lnk') { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath }
    Add-Item 'Startup folder' $f.Name $target $f.CreationTime 'runs at logon'
  }
}

# ---------- 3. Scheduled tasks ----------
foreach ($t in Get-ScheduledTask) {
  $reg = $null; if ($t.Date) { [datetime]::TryParse($t.Date, [ref]$reg) | Out-Null }
  foreach ($a in $t.Actions | Where-Object { $_.Execute }) {
    $exe = [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"'))
    $isNew = $reg -and $reg -ge $Since
    if ($t.TaskPath -like '\Microsoft\*' -and -not $isNew -and -not (Test-UserWritable $exe)) { continue }
    Add-Item 'Scheduled task' "$($t.TaskPath)$($t.TaskName)" "`"$exe`" $($a.Arguments)" $reg 'scheduled execution'
  }
}

# ---------- 4. Services with non-system binaries ----------
foreach ($s in Get-CimInstance Win32_Service) {
  $exe = Get-ExePath $s.PathName
  if (-not $exe -or $exe -match '^C:\\Windows\\') { continue }
  $sig = Get-Signer $exe
  if ($sig -like 'unsigned*' -or $sig -eq 'missing' -or (Test-UserWritable $exe)) {
    $ct = (Get-Item -LiteralPath $exe -Force).CreationTime
    Add-Item 'Service' "$($s.Name) ($($s.StartMode))" $s.PathName $ct 'service binary outside Windows, unsigned or user-writable'
  }
}

# ---------- 5. WMI event subscriptions ----------
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer) {
  Add-Item 'WMI consumer' $c.Name "$($c.CommandLineTemplate)" $null 'WMI permanent event consumer (rare on home PCs)'
}
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer) {
  Add-Item 'WMI consumer' $c.Name "script:$($c.ScriptingEngine)" $null 'WMI script consumer (rare on home PCs)'
}

# ---------- 6. Per-user COM hijacks (InprocServer32 in user-writable paths) ----------
foreach ($k in Get-ChildItem 'HKCU:\Software\Classes\CLSID' -Force) {
  $ip = Join-Path $k.PSPath 'InprocServer32'
  if (-not (Test-Path $ip)) { continue }
  $dll = [Environment]::ExpandEnvironmentVariables(((Get-ItemProperty $ip).'(default)' -as [string]))
  if (-not $dll) { continue }
  $sig = Get-Signer $dll
  if ((Test-UserWritable $dll) -and ($sig -like 'unsigned*' -or $sig -eq 'missing')) {
    Add-Item 'COM hijack (HKCU)' $k.PSChildName $dll (Get-Item -LiteralPath $dll -Force).CreationTime 'per-user COM server, unsigned, user-writable path'
  }
}

# ---------- 7. IFEO debuggers ----------
foreach ($k in Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
  $d = (Get-ItemProperty $k.PSPath).Debugger
  if ($d) { Add-Item 'IFEO debugger' $k.PSChildName $d $null 'program launch is redirected' }
}

# ---------- 8. Browser extensions installed in the window ----------
foreach ($root in "$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data") {
  foreach ($ext in Get-ChildItem $root -Directory -Force | Where-Object { $_.Name -match '^(Default|Profile \d+)$' } | ForEach-Object { Get-ChildItem (Join-Path $_.FullName 'Extensions') -Directory -Force }) {
    if ($ext.CreationTime -lt $Since) { continue }
    $mf = Get-ChildItem $ext.FullName -Recurse -Filter manifest.json -Force | Select-Object -First 1
    $nm = if ($mf) { ((Get-Content $mf.FullName -Raw) | ConvertFrom-Json).name } else { '' }
    [void]$items.Add([pscustomobject]@{ Score = $(if (Test-InWindow $ext.CreationTime) { 3 } else { 1 }); InWindow = (Test-InWindow $ext.CreationTime); Kind = 'Browser extension'
      Name = "$($ext.Name) $nm"; Target = $ext.FullName; Signer = ''; When = $ext.CreationTime.ToString('yyyy-MM-dd HH:mm'); Why = 'extension added since window start' })
  }
}

# ---------- 9. New unsigned executables / scripts in user-writable places ----------
$exts = '.exe', '.dll', '.scr', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.lua', '.hta'
# Fast walk: .NET enumeration, prune cache-type folders, filter by extension before touching timestamps.
$skip = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
'node_modules', 'site-packages', '.git', 'Code Cache', 'Service Worker', 'GPUCache', '__pycache__', 'Cache', 'Cache_Data',
'CacheStorage', 'IndexedDB', 'blob_storage', 'WebCache', 'INetCache', 'Packages', 'pip', 'npm-cache', 'conda', 'pkgs',
'.venv', 'venv', 'Microsoft\Windows\Explorer', 'ShaderCache', 'DXCache', 'NVIDIA', 'CrashDumps' | ForEach-Object { [void]$skip.Add($_) }
$extSet = [Collections.Generic.HashSet[string]]::new([string[]]$exts, [StringComparer]::OrdinalIgnoreCase)
function Find-NewFiles([string]$root, [int]$maxDepth = 7) {
  $stack = New-Object System.Collections.Stack
  $stack.Push(@($root, 0))
  while ($stack.Count) {
    $cur, $depth = $stack.Pop()
    try { $di = [IO.DirectoryInfo]::new($cur) } catch { continue }
    if ($di.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    try {
      foreach ($fi in $di.EnumerateFiles()) {
        if ($extSet.Contains($fi.Extension) -and $fi.CreationTime -ge $Since) { $fi }
      }
      if ($depth -lt $maxDepth) {
        foreach ($sub in $di.EnumerateDirectories()) { if (-not $skip.Contains($sub.Name)) { $stack.Push(@($sub.FullName, ($depth + 1))) } }
      }
    } catch {}
  }
}
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($d in ($userWritable | Sort-Object -Unique)) {
  Find-NewFiles $d |
    ForEach-Object {
      $inWin = Test-InWindow $_.CreationTime
      $isBin = $_.Extension -in '.exe', '.dll', '.scr'
      if (-not $inWin -and -not $isBin) { return }    # outside the window, only binaries are worth listing
      $sig = if ($isBin) { Get-Signer $_.FullName } else { 'script' }
      if ($isBin -and $sig -notlike 'unsigned*') { return }   # validly signed binaries are not leads
      if (-not $seen.Add($_.FullName)) { return }             # nested roots (TEMP sits inside LOCALAPPDATA)
      [void]$items.Add([pscustomobject]@{ Score = $(if ($inWin) { 3 } else { 1 }) + $(if ($sig -like 'unsigned*') { 1 } else { 0 }); InWindow = $inWin; Kind = 'New file'
        Name = $_.Name; Target = $_.FullName; Signer = $sig; When = $_.CreationTime.ToString('yyyy-MM-dd HH:mm'); Why = 'created since window start in a user-writable folder' })
    }
}

# ---------- 10. Accounts and remote access ----------
foreach ($u in Get-LocalUser | Where-Object { $_.Enabled }) {
  if ($u.PasswordLastSet -and $u.PasswordLastSet -ge $Since) { Add-Item 'Local account' $u.Name '' $u.PasswordLastSet 'enabled account with password set since window start' }
}
foreach ($f in "$env:USERPROFILE\.ssh\authorized_keys", "$env:ProgramData\ssh\administrators_authorized_keys") {
  $fi = Get-Item -LiteralPath $f -Force
  if ($fi -and $fi.LastWriteTime -ge $Since) { Add-Item 'SSH authorized_keys' $fi.Name $fi.FullName $fi.LastWriteTime 'remote login key list changed' }
}
$rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
if ($rdp -eq 0) { Add-Item 'Remote Desktop' 'RDP enabled' '' $null 'Remote Desktop is accepting connections (fine if you enabled it)' }

# ---------- report ----------
$sorted = $items | Sort-Object @{ e = 'Score'; Descending = $true }, When
Write-Host ''
if ($windows) {
  Write-Host '木馬活動時段（從 agent started 到那次啟動器最後一筆紀錄 +30 分鐘）：'
  $windows | ForEach-Object { Write-Host "  $($_.Start.ToString('yyyy-MM-dd HH:mm')) ~ $($_.End.ToString('HH:mm'))" }
} else { Write-Host '沒有提供 -InstallPath，無法標出木馬活動時段；只用 -Since 篩選。' -ForegroundColor DarkGray }
Write-Host ''
$hi = @($sorted | Where-Object { $_.InWindow -or $_.Score -ge 3 })
$lo = @($sorted | Where-Object { -not ($_.InWindow -or $_.Score -ge 3) })
if ($hi) {
  Write-Host "優先檢視（$($hi.Count) 項：在木馬活動時段內出現，或同時是新的 + 未簽章 + 放在使用者可寫位置）" -ForegroundColor Red
  $hi | ForEach-Object { Write-Host ("  [{0}] {1}  {2}" -f $_.Kind, $_.Name, $_.When) -ForegroundColor Red; Write-Host "      $($_.Target)  <$($_.Signer)>  $($_.Why)" -ForegroundColor DarkGray }
} else { Write-Host '優先檢視：沒有項目。' -ForegroundColor Green }
Write-Host ''
Write-Host "其他自動啟動項與新檔案（$($lo.Count) 項，大多是正常軟體，看一眼認不認得即可）："
$lo | Where-Object Kind -ne 'New file' | ForEach-Object { Write-Host ("  [{0}] {1}  {2}  <{3}>" -f $_.Kind, $_.Name, $_.Target, $_.Signer) }
$newFiles = @($lo | Where-Object Kind -eq 'New file')
if ($newFiles) {
  Write-Host "  [New file] 未簽章的新程式檔，依資料夾合併（$($newFiles.Count) 個）："
  $newFiles | Group-Object { Split-Path $_.Target } | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("    {0,4} 個  {1}  （例：{2}）" -f $_.Count, $_.Name, $_.Group[0].Name) }
}
Write-Host ''
Write-Host '這份掃描只列線索，不做判定。認不得的項目：先用 Microsoft 的 Autoruns 看細節，再上傳 VirusTotal 查。' -ForegroundColor Yellow
# Offline scan advice: Start-MpWDOScan reboots into the Defender scan, which does nothing when Defender is not the
# active antivirus or the recovery environment (WinRE) is off, and may ask for the BitLocker recovery key.
$avMode = ''; try { $avMode = [string](Get-MpComputerStatus -ErrorAction Stop).AMRunningMode } catch {}
$winre = ''; try { $winre = [string]([xml](Get-Content "$env:SystemRoot\System32\Recovery\ReAgent.xml" -Raw -ErrorAction Stop)).WindowsRE.InstallState.state } catch {}
$bitlocker = ''; try { $bitlocker = [string](Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus } catch {}   # needs an elevated window
Write-Host '接著建議跑 Defender 完整掃描：Start-MpScan -ScanType FullScan' -ForegroundColor Yellow
if ($avMode -and $avMode -ne 'Normal') {
  Write-Host "  Defender 目前不是主要防毒（模式：$avMode），離線掃描不會執行；請用你正在用的防毒軟體做一次完整掃描。" -ForegroundColor Yellow
} elseif ($winre -eq '0') {
  Write-Host '  這台電腦的 Windows 復原環境（WinRE）已關閉，離線掃描無法執行；做完整掃描就好。' -ForegroundColor Yellow
} elseif ($bitlocker -eq 'On') {
  Write-Host '  系統碟開了 BitLocker，離線掃描重開機時可能要求復原金鑰。手邊有金鑰再跑 Start-MpWDOScan，沒有就只做完整掃描。' -ForegroundColor Yellow
} else {
  Write-Host '  再加一次離線掃描（會重開機、約 15 分鐘，先存檔）：Start-MpWDOScan' -ForegroundColor Yellow
  if (-not $bitlocker) { Write-Host '  沒辦法確認 BitLocker 狀態（要系統管理員視窗）。有開 BitLocker 或「裝置加密」的話，先備好復原金鑰。' -ForegroundColor DarkGray }
}
if ($ReportPath) { $sorted | ConvertTo-Json -Depth 3 | Out-File -LiteralPath $ReportPath -Encoding utf8; Write-Host "報告：$ReportPath" }
