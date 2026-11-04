<#
.SYNOPSIS
  Read-only detector for the NIKKE PC launcher supply-chain malware (K2F / insightjs, Sep-Nov 2026).
.DESCRIPTION
  Never modifies anything. Uses byte-level search (Select-String misses strings inside
  Chromium leveldb / Code Cache binaries). Sources: MotherSphere gist d6c049a09ba8ac3085c51ee9df24a4e5,
  WormW/nikke_malware_analysis, Bahamut bsn=36390 snA=23304 (NGA tid=47843502).
  Run it in YOUR OWN PowerShell window (not inside a sandboxed app shell): HKCU and
  %LOCALAPPDATA% can be virtualized for packaged apps, which would hide stage-2 artifacts.
.PARAMETER InstallPath
  NIKKE install root(s), e.g. D:\game\NIKKE_HMT. Auto-discovered when omitted.
.PARAMETER ReportPath
  Optional JSON report path (secrets redacted).
#>
[CmdletBinding()]
param(
  [string[]]$InstallPath,
  [string]$ReportPath
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

# ---------- 0. locate installs ----------
$roots = @()
if ($InstallPath) { $roots += $InstallPath }
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
  Get-ItemProperty $k | Where-Object { $_.DisplayName -like '*NIKKE*' -and $_.InstallLocation } |
    ForEach-Object { $roots += $_.InstallLocation }
}
if (-not $roots) {
  foreach ($d in (Get-PSDrive -PSProvider FileSystem).Root) {
    foreach ($g in "$d*NIKKE*", "$d*\*NIKKE*", "$d*\*\*NIKKE*") {
      Get-Item $g -Force | Where-Object PSIsContainer | ForEach-Object { $roots += $_.FullName }
    }
  }
}
# A root may be the launcher folder itself or its parent.
$launchers = @()
foreach ($r in ($roots | Sort-Object -Unique)) {
  $r = $r.TrimEnd('\')
  if (Test-Path "$r\intl_service") { $launchers += $r }
  elseif (Test-Path "$r\launcher\intl_service") { $launchers += "$r\launcher" }
}
$launchers = $launchers | Sort-Object -Unique

# ---------- 1. stage 1: launcher logs ----------
foreach ($L in $launchers) {
  $dbg = Get-ChildItem $L -Recurse -Force -Filter debug.log | Where-Object { $_.DirectoryName -match 'intl_service' }
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

# ---------- 2. stage 1: launcher web cache (%APPDATA%\nikke_launcher*) ----------
$agentInfo = $null
foreach ($A in Get-ChildItem $env:APPDATA -Directory -Force -Filter 'nikke_launcher*') {
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
$hk = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
[void]$checked.Add("HKCU\Software\Classes\CLSID\$clsid")
if (Test-Path $hk) {
  $v = (Get-ItemProperty $hk).'(default)'
  Add-Finding 'RED' '2' "HKCU 有惡意 COM 劫持項目（指向 $v）" "HKCU\Software\Classes\CLSID\$clsid"
}
$chromeRoots = @("$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\Google\Chrome Beta\User Data", "$env:LOCALAPPDATA\Google\Chrome SxS\User Data")
foreach ($cr in $chromeRoots) {
  $peh = Join-Path $cr 'PlatformExperienceHelper'
  if (-not (Test-Path $peh)) { continue }
  [void]$checked.Add($peh)
  foreach ($d in Get-ChildItem $peh -Directory -Force | Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' }) {
    foreach ($dll in Get-ChildItem $d.FullName -File -Force -Filter '*.dll*') {
      $sig = Get-AuthenticodeSignature -LiteralPath $dll.FullName
      $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'unsigned' }
      $h = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash
      if ($signer -notmatch 'O=Google LLC') { Add-Finding 'RED' '2' "Chrome 常駐 dll（簽章：$signer，SHA256 $h）" $dll.FullName }
    }
  }
}
foreach ($app in "$env:LOCALAPPDATA\Google\Chrome\Application", "$env:ProgramFiles\Google\Chrome\Application", "${env:ProgramFiles(x86)}\Google\Chrome\Application") {
  if (-not (Test-Path $app)) { continue }
  Get-ChildItem $app -Recurse -Force -Include 'platform_experience_helper.dll.old', 'old-clsid.txt', 'service_util.dll' |
    ForEach-Object { Add-Finding 'RED' '2' '木馬安裝殘留檔' $_.FullName }
}
foreach ($p in Get-Process chrome) {
  try {
    $m = $p.Modules | Where-Object { $_.ModuleName -eq 'platform_experience_helper.dll' -and $_.FileName -match '\\[0-9a-fA-F]{64}\\' } | Select-Object -First 1
    if ($m) { Add-Finding 'RED' '2' "chrome.exe (PID $($p.Id)) 正在載入木馬 dll" $m.FileName; break }
  } catch {}
}

# ---------- 4. transient / network ----------
Get-ChildItem $env:TEMP -Force | Where-Object { $_.Name -like 'k2f-bcreds*' -or $_.Name -like 'k2f_screen*' -or $_.Name -like 'k2f*.lua' } |
  ForEach-Object { Add-Finding 'RED' '1' '暫存資料夾有木馬暫存檔（竊取的憑證/截圖）' $_.FullName }
$dns = (ipconfig /displaydns) -match 'insightjs'
if ($dns) { Add-Finding 'YELLOW' 'net' 'DNS 快取有 insightjs 網域（近期連線過）' 'ipconfig /displaydns' }
$hostsTxt = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw
$blocked = ($hostsTxt -match '0\.0\.0\.0\s+analytics\.insightjs\.com') -and ($hostsTxt -match '0\.0\.0\.0\s+insightjs\.com')
$running = @(Get-Process | Where-Object { $_.Name -match '^(nikke_launcher|tbs_browser|intl_service|INTLWebViewHelper)' })
if ($running) { Add-Finding 'YELLOW' 'live' "NIKKE 啟動器程序正在執行：$(($running | ForEach-Object Name | Sort-Object -Unique) -join ', ')" 'Get-Process' }
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
Write-Host ("hosts 封鎖 insightjs：{0}" -f $(if ($blocked) { '已封鎖' } else { '未封鎖' }))
Write-Host ("Defender 偵測紀錄：{0} 筆" -f $def.Count)
Write-Host ''
# Launcher logs are history: they stay after remediation (kept as evidence). Everything else is a live component.
$histRx = '\\intl_service\\debug\.log$|\\log\\tinyget\\'
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
}
if (-not ($findings | Where-Object Stage -eq '2')) {
  Write-Host '※ 第 2 階段（Chrome 常駐）未見痕跡；但這只在你自己的 PowerShell 視窗執行時才可信。' -ForegroundColor DarkGray
}

if ($ReportPath) {
  [pscustomobject]@{
    GeneratedAt = (Get-Date).ToString('s'); Verdict = $(if ($redLive) { 'infected-live' } elseif ($red) { 'infected-history' } elseif ($yel) { 'contact' } else { 'clean-known' })
    Launchers = $launchers; Findings = $findings; Timeline = $tl
    Agent = $agentInfo; HostsBlocked = $blocked; DefenderDetections = $def.Count; Checked = $checked
  } | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $ReportPath -Encoding utf8
  Write-Host "報告已寫入：$ReportPath"
}
if ($redLive) { exit 3 } elseif ($red) { exit 2 } elseif ($yel) { exit 1 } else { exit 0 }
