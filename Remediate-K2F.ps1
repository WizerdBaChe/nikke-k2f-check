<#
.SYNOPSIS
  Contain the NIKKE launcher K2F malware. Dry-run by default; -Apply to act.
.DESCRIPTION
  No file is deleted: every file artifact is MOVED into a quarantine folder (evidence kept, DLLs renamed so
  they cannot load). Exceptions: registry keys are deleted after a successful .reg export, hosts gets block
  lines, a wrong firewall rule of our name is removed and rebuilt, launcher processes are stopped.
  Selectors (paths, dll filter, residue names, hosts, firewall) come from K2F-Common.ps1, shared with Check-K2F.ps1.
  Order follows the published removal sequence:
    1. stop launcher processes (by name, plus processes under a RECOGNISED launcher folder only)
    2. export + remove the per-user COM hijack key, 64- and 32-bit views (never the HKLM one: that is Windows' wpc.dll)
    3. quarantine PlatformExperienceHelper\<64-hex> folders of Chrome and the other Chromium browsers,
       for every readable user profile (locked until reboot -> re-run after reboot), and the installer
       residue next to Chrome (platform_experience_helper.dll.old, old-clsid.txt, service_util.dll)
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
.PARAMETER UserSid
  Clean this user's registry (HKU\<SID>) instead of HKCU. Run-K2F.ps1 passes it when the elevated window
  belongs to a different account than the one that started the check.
#>
[CmdletBinding()]
param(
  [switch]$Apply,
  [string]$InstallPath,
  [string]$Quarantine = (Join-Path $env:USERPROFILE ("nikke-k2f-quarantine-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
  [string]$UsersRoot = "$env:SystemDrive\Users",
  [string]$UserSid
)

. (Join-Path $PSScriptRoot 'K2F-Common.ps1')
# User profiles, data folders, the registry hive and install discovery come from K2F-Common.ps1 (same as Check-K2F.ps1).
$pr = Get-K2FProfiles $UsersRoot
$profiles = $pr.Profiles
$hive = Get-K2FUserHive $UserSid
$dataDirs = Get-K2FDataDirs $profiles
if (-not $InstallPath) {
  $InstallPath = @(Get-K2FInstallCandidates $dataDirs $hive) | Where-Object { Resolve-K2FLauncherDir $_ } | Select-Object -First 1
  if (-not $InstallPath) { Write-Host '找不到啟動器安裝資料夾，請用 -InstallPath 指定（例：-InstallPath D:\NIKKE）。啟動器紀錄的證據備份會略過。' -ForegroundColor Yellow; $InstallPath = '' }
}

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$pending = New-Object System.Collections.ArrayList
# Every action, in order, for the one-screen summary at the end (Ok = $null in dry-run).
$plan = New-Object System.Collections.ArrayList

function Step([string]$Msg) { Write-Host ''; Write-Host "== $Msg" -ForegroundColor Cyan }
# $script:LastOk tells the caller whether the last Do-It succeeded ($true in dry-run).
function Do-It([string]$Desc, [scriptblock]$Action) {
  if ($Apply) {
    try { & $Action; $script:LastOk = $true; Write-Host "  [done] $Desc" -ForegroundColor Green; [void]$plan.Add([pscustomobject]@{ Desc = $Desc; Ok = $true }) }
    catch { $script:LastOk = $false; Write-Host "  [fail] $Desc -- $($_.Exception.Message)" -ForegroundColor Red; [void]$pending.Add($Desc); [void]$plan.Add([pscustomobject]@{ Desc = $Desc; Ok = $false }) }
  } else { $script:LastOk = $true; Write-Host "  [would] $Desc" -ForegroundColor Yellow; [void]$plan.Add([pscustomobject]@{ Desc = $Desc; Ok = $null }) }
}
# A registry key is deleted only after its .reg backup was written; otherwise it stays and the run reports it.
function Remove-KeyAfterExport([string]$Key, [string]$PsPath) {
  if (-not $script:LastOk) {
    $d = "略過刪除 $Key（備份 .reg 失敗，登錄項保留不動）"
    Write-Host "  [skip] $d" -ForegroundColor Red; [void]$pending.Add($d); [void]$plan.Add([pscustomobject]@{ Desc = $d; Ok = $false })
    return
  }
  Do-It "刪除登錄項 $Key" { Remove-Item $PsPath -Recurse -Force -ErrorAction Stop }
}
function Ensure-Dir([string]$p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

if (-not $Apply) { Write-Host '試跑模式 (dry-run)：只列出會做的事。確認後加 -Apply 再跑一次。' -ForegroundColor Yellow }
Write-Host "隔離區：$Quarantine"
if ($pr.Skipped.Count) { Write-Host "注意：$($pr.Skipped.Count) 個其他使用者的資料夾讀不到（$($pr.Skipped -join ', ')），這次沒處理；要處理請用「系統管理員」視窗再跑。" -ForegroundColor Yellow }

# Only a recognised launcher folder is used as a kill prefix: a parent folder passed as -InstallPath would
# otherwise end every process under it (rules/privileged-remediation.md, recognised-only selectors).
$L = if ($InstallPath) { Resolve-K2FLauncherDir $InstallPath } else { $null }
if ($InstallPath -and -not $L) { Write-Host "  -InstallPath $InstallPath 底下認不出啟動器（找不到 intl_service 或 service\debug.log）：不依資料夾結束程序，只結束已知名稱的啟動器程序，也不複製紀錄檔。" -ForegroundColor Yellow }

# 1. processes
Step '1. 結束啟動器程序'
$procs = @()
# Never match on an empty or drive-root prefix: StartsWith('') is true for every process.
if ($L -and $L.Length -gt 3) {
  $procs += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($L + '\', [StringComparison]::OrdinalIgnoreCase) })
}
$procs += @(Get-Process -Name $K2F_LauncherProcs -ErrorAction SilentlyContinue)
$procs = $procs | Sort-Object Id -Unique
if ($procs) { foreach ($p in $procs) { Do-It "停止 $($p.Name) (PID $($p.Id))" { Stop-Process -Id $p.Id -Force -ErrorAction Stop } } } else { Write-Host '  沒有執行中的啟動器程序' }

# 2. per-user COM hijack (HKCU, or HKU\<SID> when the elevated window belongs to another account)
$H = $hive.Label
Step "2. 移除 $H COM 劫持登錄項"
$clsid = $K2F_Clsid
$foundKey = $false
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {   # 64-bit and 32-bit registry views
  $key = "$($hive.Reg)\Software\Classes\$view\$clsid"
  if (-not (Test-Path "$($hive.Ps)\Software\Classes\$view\$clsid")) { continue }
  $foundKey = $true
  $regFile = Join-Path $Quarantine ('hkcu-' + ($view -replace '\\', '-').ToLower() + '.reg')
  Do-It "匯出 $key 到隔離區" { Ensure-Dir $Quarantine; & reg.exe export $key $regFile /y | Out-Null; if ($LASTEXITCODE) { throw "reg export exit $LASTEXITCODE" } }
  Remove-KeyAfterExport "$key（HKLM 同名項是 Windows 正常的，不動）" "$($hive.Ps)\Software\Classes\$view\$clsid"
}
# Generic variant: other CLSIDs whose in-process server sits where the known dll sits (Get-SuspectComServer, K2F-Common.ps1).
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {
  foreach ($k in Get-ChildItem "$($hive.Ps)\Software\Classes\$view" -Force -ErrorAction SilentlyContinue) {
    if ($k.PSChildName -ieq $clsid) { continue }
    # Most CLSIDs have no InprocServer32 subkey (LocalServer32/ProgID only); that is normal, not an error.
    $v = [string](Get-ItemProperty (Join-Path $k.PSPath 'InprocServer32') -ErrorAction SilentlyContinue).'(default)'
    $why = Get-SuspectComServer $v
    if (-not $why) { continue }
    $foundKey = $true
    $key = "$($hive.Reg)\Software\Classes\$view\$($k.PSChildName)"
    $regFile = Join-Path $Quarantine ('hkcu-' + ($view -replace '\\', '-').ToLower() + '-' + $k.PSChildName.Trim('{}') + '.reg')
    Do-It "匯出疑似變種 $key（dll 在$why）到隔離區" { Ensure-Dir $Quarantine; & reg.exe export $key $regFile /y | Out-Null; if ($LASTEXITCODE) { throw "reg export exit $LASTEXITCODE" } }
    Remove-KeyAfterExport $key "$($hive.Ps)\Software\Classes\$view\$($k.PSChildName)"
    # Step 3 moves whole PlatformExperienceHelper\<64-hex> folders; any other target is moved here.
    $dll = [Environment]::ExpandEnvironmentVariables($v.Trim('"'))
    if ((Test-Path -LiteralPath $dll -PathType Leaf) -and $dll -notmatch '\\PlatformExperienceHelper\\[0-9a-fA-F]{64}\\[^\\]+$') {
      $dest = Join-Path $Quarantine ('com-dll\' + $k.PSChildName.Trim('{}') + '-' + (Split-Path $dll -Leaf) + '.quarantined')
      Do-It "隔離 $dll" { Ensure-Dir (Split-Path $dest); Move-Item -LiteralPath $dll -Destination $dest -Force -ErrorAction Stop }
    }
  }
}
if (-not $foundKey) { Write-Host '  沒有這個登錄項' }
if (@($profiles | Where-Object { -not $_.Current }).Count) { Write-Host '  其他使用者的登錄要用該帳號登入再跑一次。' -ForegroundColor DarkGray }

# 3. browser DLL (Chrome documented; other Chromium browsers inferred, see docs/FACTS.md)
Step '3. 隔離瀏覽器常駐 dll'
# Same selector as Check-K2F.ps1 (Get-K2FPehDlls: any *.dll* file not validly signed by Google or Microsoft);
# the folder holding such a file is moved whole.
$bad = @()
foreach ($pf in $profiles) {
  $hits = @(Get-K2FPehDlls $pf)
  foreach ($g in ($hits | Group-Object { $_.Dir.FullName })) {
    $bad += [pscustomobject]@{ Dir = $g.Group[0].Dir; Tag = "$($pf.Name)-$($g.Group[0].Tag)" }
  }
}
if ($bad) {
  foreach ($b in $bad) {
    $d = $b.Dir; $tag = $b.Tag
    Do-It "移動 $($d.FullName) 到隔離區（dll 改名 .quarantined）" {
      $dst = Join-Path $Quarantine "peh\$tag\$($d.Name)"; Ensure-Dir (Split-Path $dst)
      Move-Item -LiteralPath $d.FullName -Destination $dst -Force -ErrorAction Stop
      Get-ChildItem -LiteralPath $dst -Recurse -File -Force | Where-Object { $_.Name -like '*.dll*' -or $_.Extension -eq '.old' } | ForEach-Object { Rename-Item -LiteralPath $_.FullName ($_.Name + '.quarantined') -ErrorAction Stop }
    }
  }
  if ($Apply -and $pending) { Write-Host '  dll 可能被瀏覽器鎖住：完成第 2 步後重新開機，再跑一次本腳本。' -ForegroundColor Yellow }
} else { Write-Host '  沒有 64 碼子資料夾（PlatformExperienceHelper 本身是 Chrome 正常元件，不動）' }

# 3b. installer residue next to Chrome (the same files Check-K2F.ps1 reports)
$res = @(Get-K2FResidue $profiles)
foreach ($r in $res) {
  $rel = ($r.FullName -replace '[:\\]', '_')
  Do-It "移動木馬安裝殘留 $($r.FullName) 到隔離區（改名 .quarantined）" { $dst = Join-Path $Quarantine "residue\$rel.quarantined"; Ensure-Dir (Split-Path $dst); Move-Item -LiteralPath $r.FullName -Destination $dst -Force -ErrorAction Stop }
}
if ($res -and -not $isAdmin) { Write-Host '  Chrome 裝在 Program Files 時，殘留檔要「系統管理員」視窗才能搬。' -ForegroundColor Yellow }

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
# Same hosts and firewall rules as Check-K2F.ps1 (K2F-Common.ps1).
$blockedNow = Get-K2FHostsBlocked $hostsPath
$missing = @($K2F_HostsDomains | Where-Object { -not $blockedNow[$_] } | ForEach-Object { "0.0.0.0 $_" })
$fwIps = $K2F_FwIps
$fwOff = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -eq 'False' } | ForEach-Object { $_.Name })
if ($fwOff) { Write-Host "  注意：Windows 防火牆有關閉的設定檔（$($fwOff -join ', ')），封鎖規則在那裡不會生效。到「Windows 安全性 → 防火牆與網路保護」打開。" -ForegroundColor Yellow }
if (-not $isAdmin) {
  Write-Host '  需要「系統管理員」PowerShell 視窗才能改 hosts / 防火牆；這一步略過。' -ForegroundColor Yellow
  [void]$pending.Add('hosts/firewall block (needs admin)')
} else {
  if ($missing) { Do-It "hosts 加入：$($missing -join ', ')" { Add-Content -Path $hostsPath -Value (@('', '# NIKKE K2F malware block') + $missing) -Encoding ascii -ErrorAction Stop; ipconfig /flushdns | Out-Null } } else { Write-Host '  hosts 已封鎖' }
  if (Test-K2FFwRule) { Write-Host '  防火牆規則已存在且內容正確' }
  else {
    Do-It "防火牆封鎖連出 $($fwIps -join ', ')（既有同名規則內容不對的話先移除再重建）" {
      Get-NetFirewallRule -DisplayName $K2F_FwRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
      New-NetFirewallRule -DisplayName $K2F_FwRuleName -Direction Outbound -Action Block -RemoteAddress $fwIps -ErrorAction Stop | Out-Null
      if (-not (Test-K2FFwRule)) { throw 'rule created but verification failed' }
    }
  }
}

# One-screen summary: everything this run would do (dry-run) or did (-Apply), numbered.
Write-Host ''
if (-not $plan.Count) {
  Write-Host '== 總結：沒有要清除或封鎖的東西' -ForegroundColor Green
} else {
  if ($Apply) {
    $okN = @($plan | Where-Object { $_.Ok }).Count
    Write-Host "== 總結：做了 $($plan.Count) 件事，成功 $okN 件，失敗 $($plan.Count - $okN) 件" -ForegroundColor Cyan
  } else {
    Write-Host "== 總結：照這份清單會做 $($plan.Count) 件事（現在都還沒做）" -ForegroundColor Cyan
  }
  $i = 0
  foreach ($p in $plan) {
    $i++
    $mark = if ($p.Ok -eq $true) { '[完成] ' } elseif ($p.Ok -eq $false) { '[失敗] ' } else { '' }
    $color = if ($p.Ok -eq $false) { 'Red' } else { 'White' }
    Write-Host ('  {0,2}. {1}{2}' -f $i, $mark, $p.Desc) -ForegroundColor $color
  }
  Write-Host "  搬走的檔案都在隔離區 $Quarantine，沒有刪除，可以搬回去還原。" -ForegroundColor DarkGray
  Write-Host '  例外（不是「搬走」）：登錄項是先匯出 .reg 再刪除（用 .reg 匯回還原）；hosts 加了封鎖行；防火牆同名規則會移除重建；啟動器程序被結束。' -ForegroundColor DarkGray
  Write-Host '  不會動：遊戲本體、瀏覽器本身、書籤與你的其他檔案。' -ForegroundColor DarkGray
}
Write-Host ''
if ($pending) { Write-Host "未完成：$($pending -join '; ')" -ForegroundColor Yellow }
Write-Host '腳本做不到的部分：改密碼、撤銷 token/API key、換錢包。請照 README 的清單，用手機或另一台乾淨裝置處理。' -ForegroundColor Red
Write-Host '處理完再跑一次 Check-K2F.ps1 確認。'
