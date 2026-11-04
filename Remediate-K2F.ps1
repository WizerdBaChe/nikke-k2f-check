<#
.SYNOPSIS
  Contain the NIKKE launcher K2F malware. Dry-run by default; -Apply to act.
.DESCRIPTION
  Nothing is deleted: every artifact is MOVED into a quarantine folder (evidence kept,
  DLLs renamed so they cannot load). Order follows the published removal sequence:
    1. stop launcher processes
    2. export + remove the HKCU COM hijack key, 64- and 32-bit views (never the HKLM one: that is Windows' wpc.dll)
    3. quarantine PlatformExperienceHelper\<64-hex> folders of Chrome and the other Chromium browsers,
       for every readable user profile (locked until reboot -> re-run after reboot)
    4. quarantine launcher web cache tbs_cache (holds tampered JS + agent state), TEMP k2f* files,
       for every readable user profile, and copy the launcher logs as evidence. NIKKE caches always;
       other launchers' caches (e.g. Delta Force Garena) only when they contain an insightjs / k2f indicator
    5. block insightjs domains + C2 IP in hosts / firewall (needs an elevated window)
  Run in YOUR OWN PowerShell window. Credential rotation is NOT something a script can do.
.PARAMETER Apply
  Actually perform the steps. Without it the script only prints what it would do.
.PARAMETER Quarantine
  Quarantine root. Default %USERPROFILE%\nikke-k2f-quarantine-<timestamp>.
.PARAMETER UsersRoot
  Folder holding the other user profiles (default C:\Users). Used by tests.
#>
[CmdletBinding()]
param(
  [switch]$Apply,
  [string]$InstallPath,
  [string]$Quarantine = (Join-Path $env:USERPROFILE ("nikke-k2f-quarantine-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
  [string]$UsersRoot = "$env:SystemDrive\Users"
)

# User profiles: current user + every readable profile under -UsersRoot.
# Same logic as Check-K2F.ps1 section 0a; change both together.
$profiles = @([pscustomobject]@{ Name = $env:USERNAME; Roaming = $env:APPDATA; Local = $env:LOCALAPPDATA; Temp = $env:TEMP; Current = $true })
foreach ($u in Get-ChildItem -LiteralPath $UsersRoot -Directory -Force -ErrorAction SilentlyContinue) {
  if ($u.Name -in 'Public', 'Default', 'Default User', 'All Users') { continue }
  if ($u.FullName.TrimEnd('\') -ieq "$env:USERPROFILE".TrimEnd('\')) { continue }
  $loc = Join-Path $u.FullName 'AppData\Local'
  if (-not (Test-Path -LiteralPath $loc -ErrorAction SilentlyContinue)) { continue }
  $profiles += [pscustomobject]@{ Name = $u.Name; Roaming = (Join-Path $u.FullName 'AppData\Roaming'); Local = $loc; Temp = (Join-Path $loc 'Temp'); Current = $false }
}

# Launcher web-view data folders, same rule as Check-K2F.ps1: nikke_launcher* by name, or any folder holding a tbs_cache.
$dataDirs = @($profiles | ForEach-Object {
  Get-ChildItem -LiteralPath $_.Roaming -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'nikke_launcher*' -or (Test-Path -LiteralPath (Join-Path $_.FullName 'tbs_cache')) }
})
# The launcher folder under a root: the root itself or root\launcher, holding intl_service (NIKKE) or service\debug.log (Delta Force Garena).
function Resolve-LauncherDir([string]$r) {
  if (-not $r) { return $null }
  $r = $r.TrimEnd('\')
  foreach ($c in $r, "$r\launcher") { if ((Test-Path "$c\intl_service") -or (Test-Path "$c\service\debug.log")) { return $c } }
  return $null
}

# Find the install the same way Check-K2F.ps1 does when -InstallPath is not given.
if (-not $InstallPath) {
  $cands = @()
  foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'NIKKE|Delta Force' -and $_.InstallLocation } | ForEach-Object { $cands += $_.InstallLocation.TrimEnd('\') }
  }
  # Launcher URL protocol icon and url_protocol.reg, as in Check-K2F.ps1.
  $exeRx = '[A-Za-z]:\\[^"\r\n]*?\\nikke_launcher[^"\\\r\n]*\.exe'
  foreach ($p in 'nikkelauncher', 'nikkelauncherhmt') {
    $v = [string](Get-ItemProperty "HKCU:\Software\Classes\$p\DefaultIcon" -ErrorAction SilentlyContinue).'(default)'
    if ($v -match $exeRx) { $cands += (Split-Path $matches[0] -Parent) }
  }
  $regExeRx = '[A-Za-z]:\\[^"\r\n]*?\\[^"\\\r\n]*launcher[^"\\\r\n]*\.exe'
  foreach ($A in $dataDirs) {
    foreach ($rf in (Join-Path $A.FullName 'url_protocol.reg'), "$($A.FullName).reg") {
      $t = Get-Content -LiteralPath $rf -Raw -ErrorAction SilentlyContinue
      if ($t) { foreach ($m in [regex]::Matches(($t -replace '\\\\', '\'), $regExeRx)) { $cands += (Split-Path $m.Value -Parent) } }
    }
  }
  if (-not @($cands | Where-Object { Resolve-LauncherDir $_ })) {
    foreach ($d in (Get-PSDrive -PSProvider FileSystem).Root) { foreach ($g in "$d*NIKKE*", "$d*\*NIKKE*", "$d*\*\*NIKKE*", "$d*Delta Force*", "$d*\*Delta Force*", "$d*\*\*Delta Force*") { Get-Item $g -Force -ErrorAction SilentlyContinue | Where-Object PSIsContainer | ForEach-Object { $cands += $_.FullName } } }
  }
  $InstallPath = $cands | Where-Object { Resolve-LauncherDir $_ } | Select-Object -First 1
  if (-not $InstallPath) { Write-Host '找不到啟動器安裝資料夾，請用 -InstallPath 指定（例：-InstallPath D:\NIKKE）。啟動器紀錄的證據備份會略過。' -ForegroundColor Yellow; $InstallPath = '' }
}

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$pending = New-Object System.Collections.ArrayList

function Step([string]$Msg) { Write-Host ''; Write-Host "== $Msg" -ForegroundColor Cyan }
function Do-It([string]$Desc, [scriptblock]$Action) {
  if ($Apply) {
    try { & $Action; Write-Host "  [done] $Desc" -ForegroundColor Green }
    catch { Write-Host "  [fail] $Desc -- $($_.Exception.Message)" -ForegroundColor Red; [void]$pending.Add($Desc) }
  } else { Write-Host "  [would] $Desc" -ForegroundColor Yellow }
}
function Ensure-Dir([string]$p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

if (-not $Apply) { Write-Host '試跑模式 (dry-run)：只列出會做的事。確認後加 -Apply 再跑一次。' -ForegroundColor Yellow }
Write-Host "隔離區：$Quarantine"

$L = if (-not $InstallPath) { '' } elseif (Resolve-LauncherDir $InstallPath) { Resolve-LauncherDir $InstallPath } else { $InstallPath.TrimEnd('\') }

# 1. processes
Step '1. 結束啟動器程序'
$procs = @()
# Never match on an empty or drive-root prefix: StartsWith('') is true for every process.
if ($L -and $L.Length -gt 3) {
  $procs += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($L + '\', [StringComparison]::OrdinalIgnoreCase) })
}
$procs += @(Get-Process -Name tbs_browser, INTLWebViewHelper, intl_service, nikke_launcher, nikke_launcher_hmt, df_garena_launcher -ErrorAction SilentlyContinue)
$procs = $procs | Sort-Object Id -Unique
if ($procs) { foreach ($p in $procs) { Do-It "停止 $($p.Name) (PID $($p.Id))" { Stop-Process -Id $p.Id -Force } } } else { Write-Host '  沒有執行中的啟動器程序' }

# 2. HKCU COM hijack
Step '2. 移除 HKCU COM 劫持登錄項'
$clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$foundKey = $false
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {   # 64-bit and 32-bit registry views
  $key = "HKCU\Software\Classes\$view\$clsid"
  if (-not (Test-Path "HKCU:\Software\Classes\$view\$clsid")) { continue }
  $foundKey = $true
  $regFile = Join-Path $Quarantine ('hkcu-' + ($view -replace '\\', '-').ToLower() + '.reg')
  Do-It "匯出 $key 到隔離區" { Ensure-Dir $Quarantine; & reg.exe export $key $regFile /y | Out-Null; if ($LASTEXITCODE) { throw "reg export exit $LASTEXITCODE" } }
  Do-It "刪除登錄項 $key（HKLM 同名項是 Windows 正常的，不動）" { Remove-Item "HKCU:\Software\Classes\$view\$clsid" -Recurse -Force -ErrorAction Stop }
}
# Generic variant: other HKCU CLSIDs whose in-process server sits where the known dll sits.
# Same logic in Check-K2F.ps1 (Get-SuspectComServer); change both together.
function Get-SuspectComServer([string]$Path) {
  if (-not $Path) { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
  $dir = Split-Path $p -Parent
  if ((Split-Path $dir -Leaf) -match '^[0-9a-fA-F]{64}$' -and (Split-Path (Split-Path $dir -Parent) -Leaf) -eq 'PlatformExperienceHelper') {
    return 'PlatformExperienceHelper\<64 碼> 資料夾'
  }
  if ($p -notlike '*\User Data\*') { return $null }
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return '瀏覽器 User Data 底下（檔案已不在）' }
  $sig = Get-AuthenticodeSignature -LiteralPath $p
  if ($sig.Status -eq 'Valid') { return $null }
  return '瀏覽器 User Data 底下、沒有有效簽章'
}
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {
  foreach ($k in Get-ChildItem "HKCU:\Software\Classes\$view" -Force) {
    if ($k.PSChildName -ieq $clsid) { continue }
    $v = [string](Get-ItemProperty (Join-Path $k.PSPath 'InprocServer32')).'(default)'
    $why = Get-SuspectComServer $v
    if (-not $why) { continue }
    $foundKey = $true
    $key = "HKCU\Software\Classes\$view\$($k.PSChildName)"
    $regFile = Join-Path $Quarantine ('hkcu-' + ($view -replace '\\', '-').ToLower() + '-' + $k.PSChildName.Trim('{}') + '.reg')
    Do-It "匯出疑似變種 $key（dll 在$why）到隔離區" { Ensure-Dir $Quarantine; & reg.exe export $key $regFile /y | Out-Null; if ($LASTEXITCODE) { throw "reg export exit $LASTEXITCODE" } }
    Do-It "刪除登錄項 $key" { Remove-Item "HKCU:\Software\Classes\$view\$($k.PSChildName)" -Recurse -Force -ErrorAction Stop }
    # Step 3 moves only platform_experience_helper.dll* inside PlatformExperienceHelper\<64-hex>; any other target is moved here.
    $dll = [Environment]::ExpandEnvironmentVariables($v.Trim('"'))
    if ((Test-Path -LiteralPath $dll -PathType Leaf) -and $dll -notmatch '\\PlatformExperienceHelper\\[0-9a-fA-F]{64}\\platform_experience_helper\.dll[^\\]*$') {
      $dest = Join-Path $Quarantine ('com-dll\' + $k.PSChildName.Trim('{}') + '-' + (Split-Path $dll -Leaf) + '.quarantined')
      Do-It "隔離 $dll" { Ensure-Dir (Split-Path $dest); Move-Item -LiteralPath $dll -Destination $dest -Force -ErrorAction Stop }
    }
  }
}
if (-not $foundKey) { Write-Host '  沒有這個登錄項' }
if (@($profiles | Where-Object { -not $_.Current }).Count) { Write-Host '  其他使用者的登錄要用該帳號登入再跑一次。' -ForegroundColor DarkGray }

# 3. browser DLL (Chrome documented; other Chromium browsers inferred, see docs/FACTS.md)
Step '3. 隔離瀏覽器常駐 dll'
$bad = @()
foreach ($pf in $profiles) {
  $browserRoots = @(
    @{ Name = 'chrome'; Path = "$($pf.Local)\Google\Chrome\User Data" }, @{ Name = 'chrome-beta'; Path = "$($pf.Local)\Google\Chrome Beta\User Data" },
    @{ Name = 'chrome-sxs'; Path = "$($pf.Local)\Google\Chrome SxS\User Data" }, @{ Name = 'edge'; Path = "$($pf.Local)\Microsoft\Edge\User Data" },
    @{ Name = 'brave'; Path = "$($pf.Local)\BraveSoftware\Brave-Browser\User Data" }, @{ Name = 'vivaldi'; Path = "$($pf.Local)\Vivaldi\User Data" },
    @{ Name = 'chromium'; Path = "$($pf.Local)\Chromium\User Data" }, @{ Name = 'opera'; Path = "$($pf.Roaming)\Opera Software\Opera Stable" },
    @{ Name = 'opera-gx'; Path = "$($pf.Roaming)\Opera Software\Opera GX Stable" })
  foreach ($br in $browserRoots) {
    $peh = Join-Path $br.Path 'PlatformExperienceHelper'
    foreach ($d in Get-ChildItem -LiteralPath $peh -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' }) {
      $dlls = @(Get-ChildItem -LiteralPath $d.FullName -Filter 'platform_experience_helper.dll*' -Force -ErrorAction SilentlyContinue)
      if (-not $dlls) { continue }
      # Same exclusion as Check-K2F.ps1: a folder whose dlls are all validly signed by Google or Microsoft is left alone.
      $trusted = @($dlls | Where-Object { $s = Get-AuthenticodeSignature -LiteralPath $_.FullName; $s.Status -eq 'Valid' -and "$($s.SignerCertificate.Subject)" -match 'O=(Google LLC|Microsoft Corporation)' })
      if ($trusted.Count -eq $dlls.Count) { continue }
      $bad += [pscustomobject]@{ Dir = $d; Tag = "$($pf.Name)-$($br.Name)" }
    }
  }
}
if ($bad) {
  foreach ($b in $bad) {
    $d = $b.Dir; $tag = $b.Tag
    Do-It "移動 $($d.FullName) 到隔離區（dll 改名 .quarantined）" {
      $dst = Join-Path $Quarantine "peh\$tag\$($d.Name)"; Ensure-Dir (Split-Path $dst)
      Move-Item -LiteralPath $d.FullName -Destination $dst -Force -ErrorAction Stop
      Get-ChildItem $dst -Recurse -File | Where-Object { $_.Extension -match 'dll|old' } | ForEach-Object { Rename-Item $_.FullName ($_.Name + '.quarantined') }
    }
  }
  if ($Apply -and $pending) { Write-Host '  dll 可能被瀏覽器鎖住：完成第 2 步後重新開機，再跑一次本腳本。' -ForegroundColor Yellow }
} else { Write-Host '  沒有 64 碼子資料夾（PlatformExperienceHelper 本身是 Chrome 正常元件，不動）' }

# 4. launcher cache, logs, temp
Step '4. 隔離啟動器快取與暫存檔，保留紀錄當證據'
# NIKKE caches are always moved (they held the tampered JS). Other launchers' caches are moved only when they
# carry an indicator, since no public sample shows K2F there (docs/FACTS.md, other games).
$cacheNeedles = 'insightjs', 'k2f.agent.state'
function Test-CacheHit([string]$dir) {
  foreach ($f in Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -le 64MB }) {
    try { $s = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($f.FullName)) } catch { continue }
    foreach ($n in $cacheNeedles) {
      $wide = ($n.ToCharArray() | ForEach-Object { "$_`0" }) -join ''
      if ($s.IndexOf($n, [StringComparison]::Ordinal) -ge 0 -or $s.IndexOf($wide, [StringComparison]::Ordinal) -ge 0) { return $true }
    }
  }
  return $false
}
foreach ($pf in $profiles) {
  foreach ($A in @($dataDirs | Where-Object { $_.FullName.StartsWith($pf.Roaming.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) })) {
    $tbs = Join-Path $A.FullName 'tbs_cache'
    if (-not (Test-Path -LiteralPath $tbs)) { continue }
    if ($A.Name -notlike 'nikke_launcher*' -and -not (Test-CacheHit $tbs)) { Write-Host "  $tbs 沒有木馬痕跡，不動" -ForegroundColor DarkGray; continue }
    $name = if ($pf.Current) { $A.Name } else { "$($pf.Name)-$($A.Name)" }
    Do-It "移動 $tbs 到隔離區（啟動器下次開會重建）" {
      $dst = Join-Path $Quarantine "$name-tbs_cache"; Ensure-Dir $Quarantine
      Move-Item -LiteralPath $tbs -Destination $dst -Force -ErrorAction Stop
    }
  }
}
foreach ($src in "$L\intl_service\debug.log", "$L\service\debug.log", "$L\log\tinyget") {
  if ($L -and (Test-Path $src)) { Do-It "複製 $src 到隔離區（原檔保留）" { $dst = Join-Path $Quarantine 'launcher-logs'; Ensure-Dir $dst; Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force -ErrorAction Stop } }
}
$tmp = @($profiles | ForEach-Object { $_.Temp } | Sort-Object -Unique | ForEach-Object { Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue } | Where-Object { $_.Name -like 'k2f-bcreds*' -or $_.Name -like 'k2f_screen*' -or $_.Name -like 'k2f*.lua' })
foreach ($t in $tmp) { Do-It "移動 $($t.FullName) 到隔離區" { $dst = Join-Path $Quarantine 'temp'; Ensure-Dir $dst; Move-Item -LiteralPath $t.FullName -Destination $dst -Force -ErrorAction Stop } }
if (-not $tmp) { Write-Host '  TEMP 沒有 k2f 暫存檔' }

# 5. network block
Step '5. 封鎖惡意網域與 C2 IP'
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
# A host already mapped to any null address (0.0.0.0, 127.0.0.1, ::1, ::) counts as blocked, same rule as Check-K2F.ps1.
$blockedNow = @{}
foreach ($line in (Get-Content $hostsPath -ErrorAction SilentlyContinue)) {
  $tok = @((($line -replace '#.*$', '').Trim() -split '\s+') | Where-Object { $_ })
  if ($tok.Count -ge 2 -and $tok[0] -in '0.0.0.0', '127.0.0.1', '::1', '::') { foreach ($h in $tok[1..($tok.Count - 1)]) { $blockedNow[$h.ToLowerInvariant()] = $true } }
}
$missing = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org', 'www.insightjs.com' | Where-Object { -not $blockedNow[$_] } | ForEach-Object { "0.0.0.0 $_" })
$fwIps = '89.127.233.127', '89.126.250.172'
# The rule counts only when enabled, outbound, block and covering both IPs; otherwise it is rebuilt.
function Test-FwRule {
  $r = Get-NetFirewallRule -DisplayName 'Block K2F C2' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $r) { return $false }
  if ("$($r.Enabled)" -ne 'True' -or "$($r.Direction)" -ne 'Outbound' -or "$($r.Action)" -ne 'Block') { return $false }
  $addr = @(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress)
  return (@($fwIps | Where-Object { $addr -notcontains $_ }).Count -eq 0)
}
$fwOff = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -eq 'False' } | ForEach-Object { $_.Name })
if ($fwOff) { Write-Host "  注意：Windows 防火牆有關閉的設定檔（$($fwOff -join ', ')），封鎖規則在那裡不會生效。到「Windows 安全性 → 防火牆與網路保護」打開。" -ForegroundColor Yellow }
if (-not $isAdmin) {
  Write-Host '  需要「系統管理員」PowerShell 視窗才能改 hosts / 防火牆；這一步略過。' -ForegroundColor Yellow
  [void]$pending.Add('hosts/firewall block (needs admin)')
} else {
  if ($missing) { Do-It "hosts 加入：$($missing -join ', ')" { Add-Content -Path $hostsPath -Value (@('', '# NIKKE K2F malware block') + $missing) -Encoding ascii -ErrorAction Stop; ipconfig /flushdns | Out-Null } } else { Write-Host '  hosts 已封鎖' }
  if (Test-FwRule) { Write-Host '  防火牆規則已存在且內容正確' }
  else {
    Do-It "防火牆封鎖連出 $($fwIps -join ', ')（既有同名規則內容不對的話先移除再重建）" {
      Get-NetFirewallRule -DisplayName 'Block K2F C2' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
      New-NetFirewallRule -DisplayName 'Block K2F C2' -Direction Outbound -Action Block -RemoteAddress $fwIps -ErrorAction Stop | Out-Null
      if (-not (Test-FwRule)) { throw 'rule created but verification failed' }
    }
  }
}

Write-Host ''
if ($pending) { Write-Host "未完成：$($pending -join '; ')" -ForegroundColor Yellow }
Write-Host '腳本做不到的部分：改密碼、撤銷 token/API key、換錢包。請照 README 的清單，用手機或另一台乾淨裝置處理。' -ForegroundColor Red
Write-Host '處理完再跑一次 Check-K2F.ps1 確認。'
