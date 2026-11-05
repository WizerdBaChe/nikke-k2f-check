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
.PARAMETER UserSid
  Check this user's registry (HKU\<SID>) instead of HKCU. Run-K2F.ps1 passes it when the elevated window
  belongs to a different account than the one that started the check.
#>
[CmdletBinding()]
param(
  [string[]]$InstallPath,
  [string]$ReportPath,
  [string]$UsersRoot = "$env:SystemDrive\Users",
  [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts",
  [string]$UserSid
)

$ErrorActionPreference = 'SilentlyContinue'
$Latin1 = [Text.Encoding]::GetEncoding(28591)   # 1 byte -> 1 char, lossless
$findings = New-Object System.Collections.ArrayList
$timeline = New-Object System.Collections.ArrayList
$checked  = New-Object System.Collections.ArrayList
# Files that should have been searched but could not be opened (locked, denied) or were over the size cap.
# A clean verdict with any of these is reported as incomplete, never as clean.
$unreadable = New-Object System.Collections.ArrayList

function Add-Finding([string]$Level, [string]$Stage, [string]$What, [string]$Where) {
  [void]$findings.Add([pscustomobject]@{ Level = $Level; Stage = $Stage; What = $What; Where = $Where })
}

# Byte search: returns $true when any needle appears as ASCII or UTF-16LE.
function Test-Bytes([string]$Path, [string[]]$Needles, [long]$MaxBytes = 64MB) {
  $fi = Get-Item -LiteralPath $Path -Force
  if (-not $fi) { [void]$unreadable.Add($Path); return $false }
  if ($fi.PSIsContainer) { return $false }
  if ($fi.Length -gt $MaxBytes) { [void]$unreadable.Add("$Path (over $([int]($MaxBytes / 1MB)) MB)"); return $false }
  try {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    $buf = New-Object byte[] $fs.Length; [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
  } catch { [void]$unreadable.Add($Path); return $false }
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
  } catch { [void]$unreadable.Add($Path); return '' }
}

# ---------- 0a. user profiles: current user + every readable profile under -UsersRoot ----------
. (Join-Path $PSScriptRoot 'K2F-Common.ps1')
$pr = Get-K2FProfiles $UsersRoot
$profiles = $pr.Profiles
$skippedProfiles = @($pr.Skipped)
# Registry of the user being checked: HKCU, or HKU\<SID> when an elevated run checks for another account.
$hive = Get-K2FUserHive $UserSid

# ---------- 0. locate installs ----------
# Install discovery and the data-folder list come from K2F-Common.ps1 (same selectors as Remediate-K2F.ps1).
$dataDirs = Get-K2FDataDirs $profiles
$roots = @(Get-K2FInstallCandidates $dataDirs $hive $InstallPath)
$launchers = @($roots | Where-Object { $_ } | ForEach-Object { Resolve-K2FLauncherDir $_ } | Where-Object { $_ } | Sort-Object -Unique)

# ---------- 1. stage 1: launcher logs ----------
foreach ($L in $launchers) {
  $dbg = Get-ChildItem $L -Recurse -Force -Filter debug.log | Where-Object { $_.DirectoryName -match '\\(intl_service|service)$' }
  foreach ($f in $dbg) {
    [void]$checked.Add($f.FullName)
    $gcErr = $null
    $lines = Get-Content -LiteralPath $f.FullName -ErrorVariable gcErr
    if ($gcErr) { [void]$unreadable.Add($f.FullName) }
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
    $eio = @($lines | Where-Object { $_ -like '*startup failed: EIO*' })
    if ($reg -and $agt) {
      Add-Finding 'RED' '1' "debug.log 有 k2f_chan registered + $($adp.Count) 筆 adopted/resuming + $($agt.Count) 筆 agent started（木馬已啟動）" $f.FullName
    } elseif ($reg) {
      # k2f_chan alone still means the agent was downloaded and ran (G 2026-11-04 23:18 GMT; Level Infinite's
      # Nov 5 notice uses this line as its criterion). Earlier "probably failed to load" reading is superseded.
      $why = if ($eio) { "，並有 $($eio.Count) 筆 startup failed: EIO（使用者名稱含非英文字元時木馬會在這裡出錯，之後做了什麼不知道）" } else { '' }
      Add-Finding 'RED' '1' "debug.log 有 k2f_chan registered，沒有 agent started$why（木馬本體已下載並執行過，照中毒處理）" $f.FullName
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
$clsid = $K2F_Clsid
$H = $hive.Label   # HKCU, or HKU\<SID>
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {   # 64-bit and 32-bit registry views
  $hk = "$($hive.Ps)\Software\Classes\$view\$clsid"
  [void]$checked.Add("$H\Software\Classes\$view\$clsid")
  if (Test-Path $hk) {
    $v = (Get-ItemProperty "$hk\InprocServer32").'(default)'
    Add-Finding 'RED' '2' "$H 有惡意 COM 劫持項目（$view，指向 $(if ($v) { $v } else { '（無 dll 值）' })）" "$H\Software\Classes\$view\$clsid"
  }
}
# Generic variant (X, IOCS.md): any other CLSID whose in-process server sits where the known dll sits
# (Get-SuspectComServer in K2F-Common.ps1, shared with Remediate-K2F.ps1).
foreach ($view in 'CLSID', 'WOW6432Node\CLSID') {
  foreach ($k in Get-ChildItem "$($hive.Ps)\Software\Classes\$view" -Force) {
    if ($k.PSChildName -ieq $clsid) { continue }   # reported above
    $v = [string](Get-ItemProperty (Join-Path $k.PSPath 'InprocServer32')).'(default)'
    $why = Get-SuspectComServer $v
    if ($why) { Add-Finding 'RED' '2' "$H 有疑似變種的 COM 劫持項目（$view，dll 在$why：$v）" "$H\Software\Classes\$view\$($k.PSChildName)" }
  }
}
[void]$checked.Add("$H\Software\Classes\CLSID\* (generic)")
# Chrome is the documented target (G, B, H). The other Chromium browsers are checked the same way as an
# inferred extension (hamzzi cleaner v3.8 checks them too; no public sample shows the dll there).
$peHits = @()
foreach ($pf in $profiles) {
  foreach ($hit in (Get-K2FPehDlls $pf)) {
    [void]$checked.Add($hit.PehRoot)
    $sig = Get-AuthenticodeSignature -LiteralPath $hit.File.FullName
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'unsigned' }
    $h = (Get-FileHash -LiteralPath $hit.File.FullName -Algorithm SHA256).Hash
    $who = if ($pf.Current) { '' } else { "使用者 $($pf.Name) 的 " }
    Add-Finding 'RED' '2' "$who$($hit.Browser) 常駐 dll（簽章：$signer，SHA256 $h）" $hit.File.FullName
    $peHits += $hit.File.FullName
  }
}
foreach ($f in (Get-K2FResidue $profiles)) {
  Add-Finding 'RED' '2' '木馬安裝殘留檔（Remediate-K2F.ps1 會移到隔離區；手動處理的話：先關 Chrome，再刪這個檔案）' $f.FullName
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
# hosts and firewall: same rules as Remediate-K2F.ps1 (K2F-Common.ps1).
$hostsBlocked = Get-K2FHostsBlocked $HostsPath
$hostsMissing = @($K2F_HostsRequired | Where-Object { -not $hostsBlocked[$_] })
$blocked = $hostsMissing.Count -eq 0
$fwBlocked = Test-K2FFwRule
$fwOff = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -eq 'False' } | ForEach-Object { $_.Name })
# A running launcher is normal on a clean machine: information only, it changes no verdict.
$running = @(Get-Process -Name $K2F_LauncherProcs -ErrorAction SilentlyContinue)
if ($running) { Add-Finding 'INFO' 'live' "啟動器程序正在執行：$(($running | ForEach-Object Name | Sort-Object -Unique) -join ', ')（這本身不是中毒痕跡；檢查前先關掉，檔案才讀得到）" 'Get-Process' }
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
if ($skippedProfiles.Count) { Write-Host "  另有 $($skippedProfiles.Count) 個使用者資料夾讀不到、沒檢查（$($skippedProfiles -join ', ')）：要用系統管理員視窗跑才查得到。" -ForegroundColor Yellow }
if ($hive.Label -ne 'HKCU') { Write-Host "  登錄檢查的是 $($hive.Label)（啟動檢查的那個帳號），不是這個系統管理員視窗自己的 HKCU。" -ForegroundColor DarkGray }
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
} elseif ($unreadable.Count) {
  Write-Host "【結果：檢查不完整】讀到的部分沒有已知痕跡，但有 $($unreadable.Count) 個該檢查的檔案讀不到，不能算乾淨。關掉啟動器（或重新開機）後再跑一次。" -ForegroundColor Yellow
} elseif ($launchers) {
  Write-Host '【結果：沒發現已知痕跡】不代表百分之百安全。' -ForegroundColor Green
} else {
  Write-Host '【結果：沒發現已知痕跡】但找不到啟動器安裝資料夾：已經刪掉遊戲的話，啟動器紀錄也跟著沒了，無法確認以前有沒有中毒。還在的話請用 -InstallPath 指定再跑一次。' -ForegroundColor Green
}
if ($unreadable.Count) {
  Write-Host "讀不到的檔案：$($unreadable.Count) 個（被其他程式鎖住、沒有權限，或太大）" -ForegroundColor Yellow
  $unreadable | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
  if ($unreadable.Count -gt 10) { Write-Host "  ……另外 $($unreadable.Count - 10) 個" -ForegroundColor DarkGray }
}
if (-not ($findings | Where-Object Stage -eq '2')) {
  Write-Host '※ 第 2 階段（Chrome 常駐）未見痕跡；但這只在你自己的 PowerShell 視窗執行時才可信。' -ForegroundColor DarkGray
}

if ($ReportPath) {
  [pscustomobject]@{
    GeneratedAt = (Get-Date).ToString('s'); Verdict = $(if ($redLive) { 'infected-live' } elseif ($red) { 'infected-history' } elseif ($yel) { 'contact' } elseif ($unreadable.Count) { 'incomplete' } else { 'clean-known' })
    UnreadableCount = $unreadable.Count; Unreadable = $unreadable
    Launchers = $launchers; Findings = $findings; Timeline = $tl
    Agent = $agentInfo; HostsBlocked = $blocked; FirewallBlocked = $fwBlocked; FirewallProfilesOff = $fwOff
    Profiles = @($profiles | ForEach-Object { $_.Name }); SkippedProfiles = $skippedProfiles; RegistryHive = $hive.Label; DefenderDetections = $def.Count; Checked = $checked
  } | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $ReportPath -Encoding utf8
  Write-Host "報告已寫入：$ReportPath"
}
if ($redLive) { exit 3 } elseif ($red) { exit 2 } elseif ($yel) { exit 1 } elseif ($unreadable.Count) { exit 4 } else { exit 0 }
