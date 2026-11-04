<#
.SYNOPSIS
  Read-only detector for the NIKKE PC launcher supply-chain malware (K2F / insightjs, Sep-Nov 2026).
.DESCRIPTION
  Never modifies anything. Uses byte-level search (Select-String misses strings inside
  Chromium leveldb / Code Cache binaries). Sources: MotherSphere gist d6c049a09ba8ac3085c51ee9df24a4e5,
  WormW/nikke_malware_analysis, Bahamut bsn=36390 snA=23304 (NGA tid=47843502).
  Run it in YOUR OWN PowerShell window (not inside a sandboxed app shell): HKCU and
  %LOCALAPPDATA% can be virtualized for packaged apps, which would hide stage-2 artifacts.
  Launcher layouts: NIKKE (launcher\intl_service\debug.log, %APPDATA%\nikke_launcher*) and the Delta Force
  Garena launcher (launcher\service\debug.log, %APPDATA%\df_garena_launcher*). Any %APPDATA% folder holding a
  tbs_cache web view is also scanned, as an inferred extension: no public sample shows K2F outside NIKKE.
.PARAMETER InstallPath
  Launcher install root(s), e.g. D:\NIKKE or "D:\game\Delta Force". Auto-discovered when omitted.
.PARAMETER ReportPath
  Optional JSON report path (secrets redacted).
.PARAMETER UsersRoot
  Folder holding the other user profiles to check (default C:\Users). Profiles you cannot read are skipped.
.PARAMETER HostsPath
  hosts file to read (default the system one). Used by tests.
#>
[CmdletBinding()]
param(
  [string[]]$InstallPath,
  [string]$ReportPath,
  [string]$UsersRoot = "$env:SystemDrive\Users",
  [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
)

$ErrorActionPreference = 'SilentlyContinue'
$Latin1 = [Text.Encoding]::GetEncoding(28591)   # 1 byte -> 1 char, lossless
$findings = New-Object System.Collections.ArrayList
$timeline = New-Object System.Collections.ArrayList
$checked  = New-Object System.Collections.ArrayList

function Add-Finding([string]$Level, [string]$Stage, [string]$What, [string]$Where) {
  [void]$findings.Add([pscustomobject]@{ Level = $Level; Stage = $Stage; What = $What; Where = $Where })
}

# Byte search: returns $true when any needle appears as ASCII or UTF-16LE.
function Test-Bytes([string]$Path, [string[]]$Needles, [long]$MaxBytes = 64MB) {
  $fi = Get-Item -LiteralPath $Path -Force
  if (-not $fi -or $fi.PSIsContainer -or $fi.Length -gt $MaxBytes) { return $false }
  try {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    $buf = New-Object byte[] $fs.Length; [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
  } catch { return $false }
  $s = $Latin1.GetString($buf)
  foreach ($n in $Needles) {
    if ($s.IndexOf($n, [StringComparison]::Ordinal) -ge 0) { return $true }
    $wide = ($n.ToCharArray() | ForEach-Object { "$_`0" }) -join ''
    if ($s.IndexOf($wide, [StringComparison]::Ordinal) -ge 0) { return $true }
  }
  return $false
}

function Read-Latin1([string]$Path) {
  try {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    $buf = New-Object byte[] $fs.Length; [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
    return $Latin1.GetString($buf)
  } catch { return '' }
}

# ---------- 0a. user profiles: current user + every readable profile under -UsersRoot ----------
# Same logic in Remediate-K2F.ps1 (Get-Profiles); change both together.
$profiles = @([pscustomobject]@{ Name = $env:USERNAME; Roaming = $env:APPDATA; Local = $env:LOCALAPPDATA; Temp = $env:TEMP; Current = $true })
foreach ($u in Get-ChildItem -LiteralPath $UsersRoot -Directory -Force) {
  if ($u.Name -in 'Public', 'Default', 'Default User', 'All Users') { continue }
  if ($u.FullName.TrimEnd('\') -ieq "$env:USERPROFILE".TrimEnd('\')) { continue }
  $loc = Join-Path $u.FullName 'AppData\Local'
  if (-not (Test-Path -LiteralPath $loc)) { continue }
  $profiles += [pscustomobject]@{ Name = $u.Name; Roaming = (Join-Path $u.FullName 'AppData\Roaming'); Local = $loc; Temp = (Join-Path $loc 'Temp'); Current = $false }
}

# ---------- 0. locate installs ----------
$roots = @()
if ($InstallPath) { $roots += $InstallPath }
# Launcher URL protocol icon (nikkelauncher, HK/MO/TW: nikkelauncherhmt) and the url_protocol.reg the
# launcher leaves in its data folder; both name the launcher exe (nikke_launcher.exe / nikke_launcher_hmt.exe).
$exeRx = '[A-Za-z]:\\[^"\r\n]*?\\nikke_launcher[^"\\\r\n]*\.exe'
foreach ($p in 'nikkelauncher', 'nikkelauncherhmt') {
  $v = [string](Get-ItemProperty "HKCU:\Software\Classes\$p\DefaultIcon").'(default)'
  if ($v -match $exeRx) { $roots += (Split-Path $matches[0] -Parent) }
}
# Launcher web-view data folders: NIKKE by name, plus any folder holding a tbs_cache (Delta Force Garena:
# df_garena_launcher). The same list feeds section 2.
$dataDirs = @($profiles | ForEach-Object {
  Get-ChildItem -LiteralPath $_.Roaming -Directory -Force | Where-Object { $_.Name -like 'nikke_launcher*' -or (Test-Path -LiteralPath (Join-Path $_.FullName 'tbs_cache')) }
})
# Protocol .reg files name the launcher exe: url_protocol.reg inside the folder (NIKKE) or <folder>.reg beside it (Delta Force).
$regExeRx = '[A-Za-z]:\\[^"\r\n]*?\\[^"\\\r\n]*launcher[^"\\\r\n]*\.exe'
foreach ($A in $dataDirs) {
  foreach ($rf in (Join-Path $A.FullName 'url_protocol.reg'), "$($A.FullName).reg") {
    $t = Get-Content -LiteralPath $rf -Raw
    if ($t) { foreach ($m in [regex]::Matches(($t -replace '\\\\', '\'), $regExeRx)) { $roots += (Split-Path $m.Value -Parent) } }
  }
}
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
  Get-ItemProperty $k | Where-Object { $_.DisplayName -match 'NIKKE|Delta Force' -and $_.InstallLocation } |
    ForEach-Object { $roots += $_.InstallLocation }
}
# A root may be the launcher folder itself or its parent. Recorded paths can be stale (uninstalled),
# so the folder glob runs whenever no root resolves to a launcher, not only when no root was found.
# Log folder: intl_service (NIKKE) or service with a debug.log (Delta Force Garena).
function Resolve-Launchers($rs) {
  $out = @()
  foreach ($r in ($rs | Where-Object { $_ } | Sort-Object -Unique)) {
    $r = $r.TrimEnd('\')
    foreach ($c in $r, "$r\launcher") {
      if ((Test-Path "$c\intl_service") -or (Test-Path "$c\service\debug.log")) { $out += $c; break }
    }
  }
  $out | Sort-Object -Unique
}
$launchers = @(Resolve-Launchers $roots)
if (-not $launchers) {
  foreach ($d in (Get-PSDrive -PSProvider FileSystem).Root) {
    foreach ($g in "$d*NIKKE*", "$d*\*NIKKE*", "$d*\*\*NIKKE*", "$d*Delta Force*", "$d*\*Delta Force*", "$d*\*\*Delta Force*") {
      Get-Item $g -Force | Where-Object PSIsContainer | ForEach-Object { $roots += $_.FullName }
    }
  }
  $launchers = @(Resolve-Launchers $roots)
}

# ---------- 1. stage 1: launcher logs ----------
foreach ($L in $launchers) {
  $dbg = Get-ChildItem $L -Recurse -Force -Filter debug.log | Where-Object { $_.DirectoryName -match '\\(intl_service|service)$' }
  foreach ($f in $dbg) {
    [void]$checked.Add($f.FullName)
    $lines = Get-Content -LiteralPath $f.FullName
    $reg = @($lines | Where-Object { $_ -like '*k2f_chan registered*' })
    $adp = @($lines | Where-Object { $_ -match '"(adopted|resuming) [0-9a-f-]{36}"' })
    $agt = @($lines | Where-Object { $_ -like '*agent started as*' })
    $lua = @($lines | Where-Object { $_ -like '*lua downloaded*' })
    # Do not name this loop variable $l: PowerShell names are case-insensitive and $L holds the launcher path.
    foreach ($line in ($agt + $lua)) {
      if ($line -match '^\[(\d{4})/(\d{6})') {
        $evt = if ($line -like '*agent started as*') { 'agent started' } else { 'payload downloaded' }
        [void]$timeline.Add([pscustomobject]@{ When = "$($matches[1].Substring(0,2))/$($matches[1].Substring(2,2)) $($matches[2].Substring(0,2)):$($matches[2].Substring(2,2)):$($matches[2].Substring(4,2))"; Event = $evt; Key = '' })
      }
    }
    if ($reg -and $agt) {
      Add-Finding 'RED' '1' "debug.log 有 k2f_chan registered + $($adp.Count) 筆 adopted/resuming + $($agt.Count) 筆 agent started（木馬已啟動）" $f.FullName
    } elseif ($reg) {
      Add-Finding 'YELLOW' '1' "debug.log 只有 k2f_chan registered，沒有 agent started（大概率載入失敗，仍建議改密碼）" $f.FullName
    }
  }
  $tg = "$L\log\tinyget"
  if (Test-Path $tg) {
    foreach ($f in Get-ChildItem $tg -File -Force) {
      [void]$checked.Add($f.FullName)
      if (Test-Bytes $f.FullName @('insight.bundle')) { Add-Finding 'RED' '1' '下載紀錄顯示 insight.bundle（木馬本體）曾下載' $f.FullName }
      $head = Read-Latin1 $f.FullName
      if ($head.Length -ge 4 -and $head.Substring(0,4) -eq "$([char]0x1B)LJ$([char]1)") { Add-Finding 'RED' '1' 'LuaJIT bytecode 檔（木馬 payload 本體）仍在' $f.FullName }
      if ($f.Name -like 'k2f*') { Add-Finding 'RED' '1' 'k2f*.lua 木馬檔案' $f.FullName }
    }
  }
}

# ---------- 2. stage 1: launcher web cache (%APPDATA%\nikke_launcher*, other tbs_cache folders) ----------
$agentInfo = $null
# Chromium HSTS keys: base64(SHA-256(DNS wire-format host)). Recomputed 2026-11-04, equal to hamzzi v3.8's constants.
$hstsAnalytics = 'wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw='   # analytics.insightjs.com
$hstsOther = 'JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=', '+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk='   # insightjs.com, insightjs.org
foreach ($A in $dataDirs) {
  # Network records of the launcher web view: which hosts it reached (history, not a live component).
  foreach ($f in Get-ChildItem -LiteralPath $A.FullName -Recurse -File -Force | Where-Object { $_.Name -in 'TransportSecurity', 'Network Persistent State' }) {
    [void]$checked.Add($f.FullName)
    if (Test-Bytes $f.FullName @('analytics.insightjs.com', $hstsAnalytics)) {
      Add-Finding 'RED' '1' "啟動器網路紀錄（$($f.Name)）顯示曾連到木馬本體下載網域 analytics.insightjs.com" $f.FullName
    } elseif (Test-Bytes $f.FullName (@('insightjs') + $hstsOther)) {
      Add-Finding 'YELLOW' '1' "啟動器網路紀錄（$($f.Name)）有 insightjs 網域（有接觸）" $f.FullName
    }
  }
  $ldb = Join-Path $A.FullName 'tbs_cache\Local Storage\leveldb'
  foreach ($f in Get-ChildItem $ldb -File -Force) {
    [void]$checked.Add($f.FullName)
    $s = Read-Latin1 $f.FullName
    if ($s.IndexOf('k2f.agent.state', [StringComparison]::Ordinal) -ge 0) {
      $ms = [regex]::Matches($s, '\{"agent_id":"([0-9a-f-]{36})"[^}]*?"c2s_counter":(\d+)')
      $last = if ($ms.Count) { $ms[$ms.Count - 1] } else { $null }
      if ($last) { $agentInfo = [pscustomobject]@{ AgentId = $last.Groups[1].Value; C2SCounter = [int]$last.Groups[2].Value; Source = $f.FullName } }
      $extra = if ($last) { "（agent_id $($last.Groups[1].Value)，已回報 C2 $($last.Groups[2].Value) 次）" } else { '' }
      Add-Finding 'RED' '1' "啟動器 localStorage 有 k2f.agent.state 木馬狀態$extra" $f.FullName
    }
  }
  $cc = Join-Path $A.FullName 'tbs_cache\Code Cache'
  $hit = Get-ChildItem $cc -Recurse -File -Force | Where-Object { Test-Bytes $_.FullName @('insightjs') } | Select-Object -First 1
  if ($hit) { Add-Finding 'YELLOW' '1' '啟動器 Code Cache 曾編譯攻擊者腳本（有接觸）' $hit.DirectoryName }
  [void]$checked.Add($cc)
  foreach ($n in 'psd.dat', 'last_user.dat') {
    $p = Join-Path $A.FullName $n
    if (Test-Path $p) { Add-Finding 'INFO' '1' "啟動器存了 NIKKE 登入資料（木馬 creds 指令會讀這個），請改 NIKKE 密碼" $p }
  }
}

# ---------- 3. stage 2: Chrome persistence ----------
$clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {   # 64-bit and 32-bit registry views
  $hk = "HKCU:\Software\Classes\$view\$clsid"
  [void]$checked.Add("HKCU\Software\Classes\$view\$clsid")
  if (Test-Path $hk) {
    $v = (Get-ItemProperty "$hk\InprocServer32").'(default)'
    Add-Finding 'RED' '2' "HKCU 有惡意 COM 劫持項目（$view，指向 $(if ($v) { $v } else { '（無 dll 值）' })）" "HKCU\Software\Classes\$view\$clsid"
  }
}
# Generic variant (X, IOCS.md): any other HKCU CLSID whose in-process server sits where the known dll sits.
# Same logic in Remediate-K2F.ps1 (Get-SuspectComServer); change both together.
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
    if ($k.PSChildName -ieq $clsid) { continue }   # reported above
    $v = [string](Get-ItemProperty (Join-Path $k.PSPath 'InprocServer32')).'(default)'
    $why = Get-SuspectComServer $v
    if ($why) { Add-Finding 'RED' '2' "HKCU 有疑似變種的 COM 劫持項目（$view，dll 在$why：$v）" "HKCU\Software\Classes\$view\$($k.PSChildName)" }
  }
}
[void]$checked.Add('HKCU\Software\Classes\CLSID\* (generic)')
# Chrome is the documented target (G, B, H). The other Chromium browsers are checked the same way as an
# inferred extension (hamzzi cleaner v3.8 checks them too; no public sample shows the dll there).
$peHits = @()
foreach ($pf in $profiles) {
  $browserRoots = @(
    @{ Name = 'Chrome'; Path = "$($pf.Local)\Google\Chrome\User Data" }, @{ Name = 'Chrome Beta'; Path = "$($pf.Local)\Google\Chrome Beta\User Data" },
    @{ Name = 'Chrome SxS'; Path = "$($pf.Local)\Google\Chrome SxS\User Data" }, @{ Name = 'Edge'; Path = "$($pf.Local)\Microsoft\Edge\User Data" },
    @{ Name = 'Brave'; Path = "$($pf.Local)\BraveSoftware\Brave-Browser\User Data" }, @{ Name = 'Vivaldi'; Path = "$($pf.Local)\Vivaldi\User Data" },
    @{ Name = 'Chromium'; Path = "$($pf.Local)\Chromium\User Data" }, @{ Name = 'Opera'; Path = "$($pf.Roaming)\Opera Software\Opera Stable" },
    @{ Name = 'Opera GX'; Path = "$($pf.Roaming)\Opera Software\Opera GX Stable" })
  foreach ($br in $browserRoots) {
    $peh = Join-Path $br.Path 'PlatformExperienceHelper'
    if (-not (Test-Path -LiteralPath $peh)) { continue }
    [void]$checked.Add($peh)
    foreach ($d in Get-ChildItem -LiteralPath $peh -Directory -Force | Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' }) {
      foreach ($dll in Get-ChildItem -LiteralPath $d.FullName -File -Force -Filter '*.dll*') {
        $sig = Get-AuthenticodeSignature -LiteralPath $dll.FullName
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'unsigned' }
        $h = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash
        if ($sig.Status -eq 'Valid' -and $signer -match 'O=(Google LLC|Microsoft Corporation)') { continue }
        $who = if ($pf.Current) { '' } else { "使用者 $($pf.Name) 的 " }
        Add-Finding 'RED' '2' "$who$($br.Name) 常駐 dll（簽章：$signer，SHA256 $h）" $dll.FullName
        $peHits += $dll.FullName
      }
    }
  }
}
$appRoots = @("$env:ProgramFiles\Google\Chrome\Application", "${env:ProgramFiles(x86)}\Google\Chrome\Application") + @($profiles | ForEach-Object { "$($_.Local)\Google\Chrome\Application" })
foreach ($app in ($appRoots | Sort-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $app)) { continue }
  # -Path, not -LiteralPath: in PowerShell 5.1 -Include is ignored together with -LiteralPath (every file would match).
  Get-ChildItem -Path $app -Recurse -Force -Include 'platform_experience_helper.dll.old', 'old-clsid.txt', 'service_util.dll' |
    ForEach-Object { Add-Finding 'RED' '2' '木馬安裝殘留檔' $_.FullName }
}
# Any process, not only chrome.exe: the dll is loaded by whatever instantiates the hijacked COM class.
foreach ($p in Get-Process) {
  try {
    $m = $p.Modules | Where-Object { $_.ModuleName -like 'platform_experience_helper*' -and $_.FileName -match '\\[0-9a-fA-F]{64}\\' } | Select-Object -First 1
    if ($m) { Add-Finding 'RED' '2' "$($p.ProcessName) (PID $($p.Id)) 正在載入木馬 dll" $m.FileName }
  } catch {}
}

# ---------- 4. transient / network ----------
foreach ($td in @($profiles | ForEach-Object { $_.Temp } | Sort-Object -Unique)) {
  Get-ChildItem -LiteralPath $td -Force | Where-Object { $_.Name -like 'k2f-bcreds*' -or $_.Name -like 'k2f_screen*' -or $_.Name -like 'k2f*.lua' } |
    ForEach-Object { Add-Finding 'RED' '1' '暫存資料夾有木馬暫存檔（竊取的憑證/截圖）' $_.FullName }
}
$dns = (ipconfig /displaydns) -match 'insightjs'
if ($dns) { Add-Finding 'YELLOW' 'net' 'DNS 快取有 insightjs 網域（近期連線過）' 'ipconfig /displaydns' }
# hosts: a host counts as blocked when any non-comment line maps it to a null address (0.0.0.0, 127.0.0.1, ::1, ::).
$hostsBlocked = @{}
foreach ($line in (Get-Content -LiteralPath $HostsPath)) {
  $tok = @((($line -replace '#.*$', '').Trim() -split '\s+') | Where-Object { $_ })
  if ($tok.Count -ge 2 -and $tok[0] -in '0.0.0.0', '127.0.0.1', '::1', '::') { foreach ($h in $tok[1..($tok.Count - 1)]) { $hostsBlocked[$h.ToLowerInvariant()] = $true } }
}
$hostsMissing = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org' | Where-Object { -not $hostsBlocked[$_] })
$blocked = $hostsMissing.Count -eq 0
# Firewall: a rule counts only if it is enabled, outbound, block, and covers both C2 IPs.
$fwIps = '89.127.233.127', '89.126.250.172'
$fwBlocked = $false
foreach ($r in @(Get-NetFirewallRule -DisplayName 'Block K2F C2', 'NIKKE k2f block' -ErrorAction SilentlyContinue)) {
  if ("$($r.Enabled)" -ne 'True' -or "$($r.Direction)" -ne 'Outbound' -or "$($r.Action)" -ne 'Block') { continue }
  $addr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
  if (@($fwIps | Where-Object { $addr -notcontains $_ }).Count -eq 0) { $fwBlocked = $true }
}
$fwOff = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -eq 'False' } | ForEach-Object { $_.Name })
$running = @(Get-Process | Where-Object { $_.Name -match '^(nikke_launcher|df_garena_launcher|tbs_browser|intl_service|INTLWebViewHelper)' })
if ($running) { Add-Finding 'YELLOW' 'live' "啟動器程序正在執行：$(($running | ForEach-Object Name | Sort-Object -Unique) -join ', ')" 'Get-Process' }
$def = @(Get-MpThreatDetection)

# ---------- report ----------
$tl = @($timeline | ForEach-Object { $_.Key = "$($_.When)|$($_.Event)"; $_ } | Sort-Object Key -Unique | Select-Object When, Event)
$red = @($findings | Where-Object Level -eq 'RED'); $yel = @($findings | Where-Object Level -eq 'YELLOW')
Write-Host ''
Write-Host "已檢查啟動器資料夾：$(if ($launchers) { $launchers -join '; ' } else { '（找不到，請用 -InstallPath 指定）' })"
foreach ($f in $findings) {
  $c = @{ RED = 'Red'; YELLOW = 'Yellow'; INFO = 'Cyan' }[$f.Level]
  Write-Host ("  [{0}] (階段{1}) {2}" -f $f.Level, $f.Stage, $f.What) -ForegroundColor $c
  Write-Host ("        {0}" -f $f.Where) -ForegroundColor DarkGray
}
if ($timeline.Count) {
  Write-Host ''; Write-Host '木馬活動時間線（debug.log，本機時間）：'
  $tl | ForEach-Object { Write-Host "  $($_.When)  $($_.Event)" }
}
Write-Host ''
Write-Host "已檢查使用者資料夾：$($profiles.Count) 個（$(($profiles | ForEach-Object { $_.Name }) -join ', ')）"
if (@($profiles | Where-Object { -not $_.Current }).Count) { Write-Host '  其他使用者的登錄（HKCU）要用該帳號登入再跑一次才查得到。' -ForegroundColor DarkGray }
Write-Host ("hosts 封鎖 insightjs：{0}" -f $(if ($blocked) { '已封鎖' } else { "未封鎖（缺 $($hostsMissing -join ', ')）" }))
Write-Host ("防火牆封鎖 C2 IP：{0}" -f $(if ($fwBlocked) { '已封鎖' } else { '未封鎖（規則不存在、停用，或沒涵蓋兩個 IP）' }))
if ($fwOff) { Write-Host "  注意：Windows 防火牆有關閉的設定檔（$($fwOff -join ', ')），封鎖規則在那裡不會生效。" -ForegroundColor Yellow }
Write-Host ("Defender 偵測紀錄：{0} 筆" -f $def.Count)
Write-Host ''
# Launcher logs are history: they stay after remediation (kept as evidence). Everything else is a live component.
$histRx = '\\(intl_service|service)\\debug\.log$|\\log\\tinyget\\|\\TransportSecurity$|\\Network Persistent State$'
$redLive = @($red | Where-Object { $_.Where -notmatch $histRx })
if ($redLive) {
  Write-Host '【結果：中毒，木馬元件仍在】先用手機改密碼（見 README），再跑 Remediate-K2F.ps1。' -ForegroundColor Red
} elseif ($red) {
  Write-Host '【結果：曾經中毒，目前只剩歷史紀錄】已知的木馬元件都不在了；但被偷的憑證仍有效，換密碼與金鑰才是重點。' -ForegroundColor Red
  Write-Host '  沒辦法重灌的話，再跑 Sweep-Persistence.ps1 找有沒有被另外放進來的東西。' -ForegroundColor Red
} elseif ($yel) {
  Write-Host '【結果：有接觸，未見木馬啟動】建議改 NIKKE 與重要帳號密碼，並清啟動器快取。' -ForegroundColor Yellow
} elseif ($launchers) {
  Write-Host '【結果：沒發現已知痕跡】不代表百分之百安全。' -ForegroundColor Green
} else {
  Write-Host '【結果：沒發現已知痕跡】但找不到啟動器安裝資料夾：已經刪掉遊戲的話，啟動器紀錄也跟著沒了，無法確認以前有沒有中毒。還在的話請用 -InstallPath 指定再跑一次。' -ForegroundColor Green
}
if (-not ($findings | Where-Object Stage -eq '2')) {
  Write-Host '※ 第 2 階段（Chrome 常駐）未見痕跡；但這只在你自己的 PowerShell 視窗執行時才可信。' -ForegroundColor DarkGray
}

if ($ReportPath) {
  [pscustomobject]@{
    GeneratedAt = (Get-Date).ToString('s'); Verdict = $(if ($redLive) { 'infected-live' } elseif ($red) { 'infected-history' } elseif ($yel) { 'contact' } else { 'clean-known' })
    Launchers = $launchers; Findings = $findings; Timeline = $tl
    Agent = $agentInfo; HostsBlocked = $blocked; FirewallBlocked = $fwBlocked; FirewallProfilesOff = $fwOff
    Profiles = @($profiles | ForEach-Object { $_.Name }); DefenderDetections = $def.Count; Checked = $checked
  } | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $ReportPath -Encoding utf8
  Write-Host "報告已寫入：$ReportPath"
}
if ($redLive) { exit 3 } elseif ($red) { exit 2 } elseif ($yel) { exit 1 } else { exit 0 }
