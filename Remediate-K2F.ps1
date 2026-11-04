<#
.SYNOPSIS
  Contain the NIKKE launcher K2F malware. Dry-run by default; -Apply to act.
.DESCRIPTION
  Nothing is deleted: every artifact is MOVED into a quarantine folder (evidence kept,
  DLLs renamed so they cannot load). Order follows the published removal sequence:
    1. stop launcher processes
    2. export + remove the HKCU COM hijack key (never the HKLM one: that is Windows' wpc.dll)
    3. quarantine the Chrome PlatformExperienceHelper\<64-hex> folder (locked until reboot -> re-run after reboot)
    4. quarantine launcher web cache tbs_cache (holds tampered JS + agent state), TEMP k2f* files,
       and copy the launcher logs as evidence
    5. block insightjs domains + C2 IP in hosts / firewall (needs an elevated window)
  Run in YOUR OWN PowerShell window. Credential rotation is NOT something a script can do.
.PARAMETER Apply
  Actually perform the steps. Without it the script only prints what it would do.
.PARAMETER Quarantine
  Quarantine root. Default D:\archive\nikke-k2f-quarantine-<timestamp>.
#>
[CmdletBinding()]
param(
  [switch]$Apply,
  [string]$InstallPath,
  [string]$Quarantine = (Join-Path $env:USERPROFILE ("nikke-k2f-quarantine-" + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

# Find the install the same way Check-K2F.ps1 does when -InstallPath is not given.
if (-not $InstallPath) {
  $cands = @()
  foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*NIKKE*' -and $_.InstallLocation } | ForEach-Object { $cands += $_.InstallLocation.TrimEnd('\') }
  }
  if (-not $cands) {
    foreach ($d in (Get-PSDrive -PSProvider FileSystem).Root) { foreach ($g in "$d*NIKKE*", "$d*\*NIKKE*", "$d*\*\*NIKKE*") { Get-Item $g -Force -ErrorAction SilentlyContinue | Where-Object PSIsContainer | ForEach-Object { $cands += $_.FullName } } }
  }
  $InstallPath = $cands | Where-Object { (Test-Path "$_\intl_service") -or (Test-Path "$_\launcher\intl_service") } | Select-Object -First 1
  if (-not $InstallPath) { Write-Host '找不到 NIKKE 安裝資料夾，請用 -InstallPath 指定（例：-InstallPath D:\NIKKE）。啟動器紀錄的證據備份會略過。' -ForegroundColor Yellow; $InstallPath = '' }
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

$L = if (-not $InstallPath) { '' } elseif (Test-Path "$InstallPath\launcher\intl_service") { "$InstallPath\launcher" } else { $InstallPath.TrimEnd('\') }

# 1. processes
Step '1. 結束 NIKKE 啟動器程序'
$procs = @()
# Never match on an empty or drive-root prefix: StartsWith('') is true for every process.
if ($L -and $L.Length -gt 3) {
  $procs += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($L + '\', [StringComparison]::OrdinalIgnoreCase) })
}
$procs += @(Get-Process -Name tbs_browser, INTLWebViewHelper, intl_service, nikke_launcher, nikke_launcher_hmt -ErrorAction SilentlyContinue)
$procs = $procs | Sort-Object Id -Unique
if ($procs) { foreach ($p in $procs) { Do-It "停止 $($p.Name) (PID $($p.Id))" { Stop-Process -Id $p.Id -Force } } } else { Write-Host '  沒有執行中的啟動器程序' }

# 2. HKCU COM hijack
Step '2. 移除 HKCU COM 劫持登錄項'
$clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$key = "HKCU\Software\Classes\CLSID\$clsid"
if (Test-Path "HKCU:\Software\Classes\CLSID\$clsid") {
  Do-It "匯出 $key 到隔離區" { Ensure-Dir $Quarantine; & reg.exe export $key (Join-Path $Quarantine 'hkcu-clsid.reg') /y | Out-Null; if ($LASTEXITCODE) { throw "reg export exit $LASTEXITCODE" } }
  Do-It "刪除登錄項 $key（HKLM 同名項是 Windows 正常的，不動）" { Remove-Item "HKCU:\Software\Classes\CLSID\$clsid" -Recurse -Force -ErrorAction Stop }
} else { Write-Host '  沒有這個登錄項' }

# 3. Chrome DLL
Step '3. 隔離 Chrome 常駐 dll'
$peh = "$env:LOCALAPPDATA\Google\Chrome\User Data\PlatformExperienceHelper"
$bad = @(Get-ChildItem $peh -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' -and (Get-ChildItem $_.FullName -Filter 'platform_experience_helper.dll*' -Force) })
if ($bad) {
  foreach ($d in $bad) {
    Do-It "移動 $($d.FullName) 到隔離區（dll 改名 .quarantined）" {
      $dst = Join-Path $Quarantine "chrome-peh\$($d.Name)"; Ensure-Dir (Split-Path $dst)
      Move-Item -LiteralPath $d.FullName -Destination $dst -Force -ErrorAction Stop
      Get-ChildItem $dst -Recurse -File | Where-Object { $_.Extension -match 'dll|old' } | ForEach-Object { Rename-Item $_.FullName ($_.Name + '.quarantined') }
    }
  }
  if ($Apply -and $pending) { Write-Host '  dll 可能被 chrome.exe 鎖住：完成第 2 步後重新開機，再跑一次本腳本。' -ForegroundColor Yellow }
} else { Write-Host '  沒有 64 碼子資料夾（PlatformExperienceHelper 本身是 Chrome 正常元件，不動）' }

# 4. launcher cache, logs, temp
Step '4. 隔離啟動器快取與暫存檔，保留紀錄當證據'
foreach ($A in Get-ChildItem $env:APPDATA -Directory -Force -Filter 'nikke_launcher*') {
  $tbs = Join-Path $A.FullName 'tbs_cache'
  if (Test-Path $tbs) {
    Do-It "移動 $tbs 到隔離區（啟動器下次開會重建）" {
      $dst = Join-Path $Quarantine "$($A.Name)-tbs_cache"; Ensure-Dir $Quarantine
      Move-Item -LiteralPath $tbs -Destination $dst -Force -ErrorAction Stop
    }
  }
}
foreach ($src in "$L\intl_service\debug.log", "$L\log\tinyget") {
  if ($L -and (Test-Path $src)) { Do-It "複製 $src 到隔離區（原檔保留）" { $dst = Join-Path $Quarantine 'launcher-logs'; Ensure-Dir $dst; Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force -ErrorAction Stop } }
}
$tmp = @(Get-ChildItem $env:TEMP -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'k2f-bcreds*' -or $_.Name -like 'k2f_screen*' -or $_.Name -like 'k2f*.lua' })
foreach ($t in $tmp) { Do-It "移動 $($t.FullName) 到隔離區" { $dst = Join-Path $Quarantine 'temp'; Ensure-Dir $dst; Move-Item -LiteralPath $t.FullName -Destination $dst -Force -ErrorAction Stop } }
if (-not $tmp) { Write-Host '  TEMP 沒有 k2f 暫存檔' }

# 5. network block
Step '5. 封鎖惡意網域與 C2 IP'
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$want = '0.0.0.0 insightjs.com', '0.0.0.0 analytics.insightjs.com', '0.0.0.0 insightjs.org', '0.0.0.0 www.insightjs.com'
$have = Get-Content $hostsPath -ErrorAction SilentlyContinue
$missing = @($want | Where-Object { $have -notcontains $_ })
if (-not $isAdmin) {
  Write-Host '  需要「系統管理員」PowerShell 視窗才能改 hosts / 防火牆；這一步略過。' -ForegroundColor Yellow
  [void]$pending.Add('hosts/firewall block (needs admin)')
} else {
  if ($missing) { Do-It "hosts 加入：$($missing -join ', ')" { Add-Content -Path $hostsPath -Value (@('', '# NIKKE K2F malware block') + $missing) -Encoding ascii -ErrorAction Stop; ipconfig /flushdns | Out-Null } } else { Write-Host '  hosts 已封鎖' }
  if (-not (Get-NetFirewallRule -DisplayName 'Block K2F C2' -ErrorAction SilentlyContinue)) {
    Do-It '防火牆封鎖連出 89.127.233.127, 89.126.250.172' { New-NetFirewallRule -DisplayName 'Block K2F C2' -Direction Outbound -Action Block -RemoteAddress 89.127.233.127, 89.126.250.172 -ErrorAction Stop | Out-Null }
  } else { Write-Host '  防火牆規則已存在' }
}

Write-Host ''
if ($pending) { Write-Host "未完成：$($pending -join '; ')" -ForegroundColor Yellow }
Write-Host '腳本做不到的部分：改密碼、撤銷 token/API key、換錢包。請照 README 的清單，用手機或另一台乾淨裝置處理。' -ForegroundColor Red
Write-Host '處理完再跑一次 Check-K2F.ps1 確認。'
