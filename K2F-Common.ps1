<#
.SYNOPSIS
  Shared selectors for Check-K2F.ps1 and Remediate-K2F.ps1 (dot-sourced by both, embedded in the one-file build).
.DESCRIPTION
  Every rule the checker and the fixer must judge the same way lives here once: user profiles, launcher data and
  install folders, the registry hive to use, the COM hijack rule, browser roots, the dll filter and signer allowlist,
  stage-2 residue names, hosts domains, firewall rule names and C2 IPs. Change a rule here, never in one script.
  Read-only: nothing in this file changes the system.
#>

$K2F_Clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
# Files inside PlatformExperienceHelper\<64-hex> that count as the stage-2 dll (renamed copies included).
$K2F_PehDllFilter = '*.dll*'
# Leftovers of the dll installer next to Chrome itself (G).
$K2F_ResidueNames = 'platform_experience_helper.dll.old', 'old-clsid.txt', 'service_util.dll'
$K2F_HostsDomains = 'insightjs.com', 'analytics.insightjs.com', 'insightjs.org', 'www.insightjs.com'
# Domains whose absence from hosts counts as "not blocked" (www is added by the fixer but not required).
$K2F_HostsRequired = 'insightjs.com', 'analytics.insightjs.com', 'insightjs.org'
$K2F_FwIps = '89.127.233.127', '89.126.250.172'
$K2F_FwRuleName = 'Block K2F C2'
# Names accepted as an existing block rule (the second one comes from an older community script).
$K2F_FwRuleNames = 'Block K2F C2', 'NIKKE k2f block'
$K2F_LauncherProcs = 'nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google', 'df_garena_launcher', 'tbs_browser', 'intl_service', 'INTLWebViewHelper'

# Current user plus every readable profile under $UsersRoot. Skipped = profiles that exist but cannot be read
# (other users' folders without administrator rights); the caller reports the count.
function Get-K2FProfiles([string]$UsersRoot) {
  $list = @([pscustomobject]@{ Name = $env:USERNAME; Roaming = $env:APPDATA; Local = $env:LOCALAPPDATA; Temp = $env:TEMP; Current = $true })
  $skipped = @()
  foreach ($u in Get-ChildItem -LiteralPath $UsersRoot -Directory -Force -ErrorAction SilentlyContinue) {
    if ($u.Name -in 'Public', 'Default', 'Default User', 'All Users') { continue }
    if ($u.FullName.TrimEnd('\') -ieq "$env:USERPROFILE".TrimEnd('\')) { continue }
    if ($u.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    try { [void](Get-ChildItem -LiteralPath $u.FullName -Force -ErrorAction Stop | Select-Object -First 1) } catch { $skipped += $u.Name; continue }
    $loc = Join-Path $u.FullName 'AppData\Local'
    if (-not (Test-Path -LiteralPath $loc -ErrorAction SilentlyContinue)) { continue }
    $list += [pscustomobject]@{ Name = $u.Name; Roaming = (Join-Path $u.FullName 'AppData\Roaming'); Local = $loc; Temp = (Join-Path $loc 'Temp'); Current = $false }
  }
  [pscustomobject]@{ Profiles = $list; Skipped = $skipped }
}

# Registry hive for the user being checked: HKCU, or HKU\<SID> when an elevated run acts for another account
# (UAC with a different administrator's credentials gives that administrator's HKCU).
function Get-K2FUserHive([string]$UserSid) {
  if (-not $UserSid) { return [pscustomobject]@{ Ps = 'HKCU:'; Reg = 'HKCU'; Label = 'HKCU' } }
  if ($UserSid -notmatch '^S-1-5-21(-\d+){3,}$') { throw "not a user SID: $UserSid" }
  if (-not (Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid")) { throw "registry of $UserSid is not loaded (that user must be signed in)" }
  [pscustomobject]@{ Ps = "Registry::HKEY_USERS\$UserSid"; Reg = "HKU\$UserSid"; Label = "HKU\$UserSid" }
}

# Launcher web-view data folders: nikke_launcher* by name, or any folder holding a tbs_cache.
function Get-K2FDataDirs($Profiles) {
  @($Profiles | ForEach-Object {
    Get-ChildItem -LiteralPath $_.Roaming -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'nikke_launcher*' -or (Test-Path -LiteralPath (Join-Path $_.FullName 'tbs_cache')) }
  })
}

# The launcher folder under a root: the root itself or root\launcher, holding intl_service (NIKKE) or
# service\debug.log (Delta Force Garena). $null when the root is not recognised.
function Resolve-K2FLauncherDir([string]$r) {
  if (-not $r) { return $null }
  $r = $r.TrimEnd('\')
  foreach ($c in $r, "$r\launcher") { if ((Test-Path -LiteralPath "$c\intl_service") -or (Test-Path -LiteralPath "$c\service\debug.log")) { return $c } }
  return $null
}

# Candidate install roots, most specific first; callers keep only those Resolve-K2FLauncherDir recognises.
function Get-K2FInstallCandidates($DataDirs, $Hive, [string[]]$Seed) {
  $c = @($Seed | Where-Object { $_ })
  foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Root) { if (Test-Path -LiteralPath "${d}NIKKE_GOOGLE") { $c += "${d}NIKKE_GOOGLE" } }
  $exeRx = '[A-Za-z]:\\[^"\r\n]*?\\nikke_launcher[^"\\\r\n]*\.exe'
  foreach ($p in 'nikkelauncher', 'nikkelauncherhmt') {
    $v = [string](Get-ItemProperty "$($Hive.Ps)\Software\Classes\$p\DefaultIcon" -ErrorAction SilentlyContinue).'(default)'
    if ($v -match $exeRx) { $c += (Split-Path $matches[0] -Parent) }
  }
  $regExeRx = '[A-Za-z]:\\[^"\r\n]*?\\[^"\\\r\n]*launcher[^"\\\r\n]*\.exe'
  foreach ($A in $DataDirs) {
    foreach ($rf in (Join-Path $A.FullName 'url_protocol.reg'), "$($A.FullName).reg") {
      $t = Get-Content -LiteralPath $rf -Raw -ErrorAction SilentlyContinue
      if ($t) { foreach ($m in [regex]::Matches(($t -replace '\\\\', '\'), $regExeRx)) { $c += (Split-Path $m.Value -Parent) } }
    }
  }
  foreach ($k in "$($Hive.Ps)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'NIKKE|Delta Force' -and $_.InstallLocation } | ForEach-Object { $c += $_.InstallLocation.TrimEnd('\') }
  }
  # Folder search only when nothing recorded resolves (recorded paths can be stale after an uninstall).
  if (-not @($c | Where-Object { Resolve-K2FLauncherDir $_ })) {
    foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Root) {
      foreach ($g in "$d*NIKKE*", "$d*\*NIKKE*", "$d*\*\*NIKKE*", "$d*Delta Force*", "$d*\*Delta Force*", "$d*\*\*Delta Force*") {
        Get-Item $g -Force -ErrorAction SilentlyContinue | Where-Object PSIsContainer | ForEach-Object { $c += $_.FullName }
      }
    }
  }
  $c
}

# Generic COM hijack rule (X, IOCS.md): an in-process server where the known dll sits.
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

# Chrome is the documented target; the other Chromium browsers are an inferred extension (docs/FACTS.md).
function Get-K2FBrowserRoots($Prof) {
  @(
    @{ Name = 'Chrome'; Tag = 'chrome'; Path = "$($Prof.Local)\Google\Chrome\User Data" }, @{ Name = 'Chrome Beta'; Tag = 'chrome-beta'; Path = "$($Prof.Local)\Google\Chrome Beta\User Data" },
    @{ Name = 'Chrome SxS'; Tag = 'chrome-sxs'; Path = "$($Prof.Local)\Google\Chrome SxS\User Data" }, @{ Name = 'Edge'; Tag = 'edge'; Path = "$($Prof.Local)\Microsoft\Edge\User Data" },
    @{ Name = 'Brave'; Tag = 'brave'; Path = "$($Prof.Local)\BraveSoftware\Brave-Browser\User Data" }, @{ Name = 'Vivaldi'; Tag = 'vivaldi'; Path = "$($Prof.Local)\Vivaldi\User Data" },
    @{ Name = 'Chromium'; Tag = 'chromium'; Path = "$($Prof.Local)\Chromium\User Data" }, @{ Name = 'Opera'; Tag = 'opera'; Path = "$($Prof.Roaming)\Opera Software\Opera Stable" },
    @{ Name = 'Opera GX'; Tag = 'opera-gx'; Path = "$($Prof.Roaming)\Opera Software\Opera GX Stable" })
}

# A dll validly signed by Google or Microsoft is never treated as the stage-2 dll.
function Test-K2FTrustedDll([string]$Path) {
  $s = Get-AuthenticodeSignature -LiteralPath $Path
  return ($s.Status -eq 'Valid' -and "$($s.SignerCertificate.Subject)" -match 'O=(Google LLC|Microsoft Corporation)')
}

# Untrusted dll files inside PlatformExperienceHelper\<64-hex> folders of one profile.
function Get-K2FPehDlls($Prof) {
  foreach ($br in (Get-K2FBrowserRoots $Prof)) {
    $peh = Join-Path $br.Path 'PlatformExperienceHelper'
    if (-not (Test-Path -LiteralPath $peh)) { continue }
    foreach ($d in Get-ChildItem -LiteralPath $peh -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' }) {
      foreach ($dll in Get-ChildItem -LiteralPath $d.FullName -File -Force -Filter $K2F_PehDllFilter -ErrorAction SilentlyContinue) {
        if (Test-K2FTrustedDll $dll.FullName) { continue }
        [pscustomobject]@{ Browser = $br.Name; Tag = $br.Tag; Dir = $d; File = $dll; PehRoot = $peh }
      }
    }
  }
}

# Chrome Application folders: machine-wide installs plus each profile's per-user install.
function Get-K2FChromeAppRoots($Profiles) {
  @(@("$env:ProgramFiles\Google\Chrome\Application", "${env:ProgramFiles(x86)}\Google\Chrome\Application") + @($Profiles | ForEach-Object { "$($_.Local)\Google\Chrome\Application" }) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)
}
function Get-K2FResidue($Profiles) {
  # -Path, not -LiteralPath: in PowerShell 5.1 -Include is ignored together with -LiteralPath (every file would match).
  foreach ($app in (Get-K2FChromeAppRoots $Profiles)) { Get-ChildItem -Path $app -Recurse -Force -File -Include $K2F_ResidueNames -ErrorAction SilentlyContinue }
}

# hosts: a host counts as blocked when any non-comment line maps it to a null address (0.0.0.0, 127.0.0.1, ::1, ::).
function Get-K2FHostsBlocked([string]$Path) {
  $b = @{}
  foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
    $tok = @((($line -replace '#.*$', '').Trim() -split '\s+') | Where-Object { $_ })
    if ($tok.Count -ge 2 -and $tok[0] -in '0.0.0.0', '127.0.0.1', '::1', '::') { foreach ($h in $tok[1..($tok.Count - 1)]) { $b[$h.ToLowerInvariant()] = $true } }
  }
  $b
}

# Firewall: a rule counts only if it is enabled, outbound, block, and covers both C2 IPs.
function Test-K2FFwRule {
  foreach ($r in @(Get-NetFirewallRule -DisplayName $K2F_FwRuleNames -ErrorAction SilentlyContinue)) {
    if ("$($r.Enabled)" -ne 'True' -or "$($r.Direction)" -ne 'Outbound' -or "$($r.Action)" -ne 'Block') { continue }
    $addr = @(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress)
    if (@($K2F_FwIps | Where-Object { $addr -notcontains $_ }).Count -eq 0) { return $true }
  }
  return $false
}
