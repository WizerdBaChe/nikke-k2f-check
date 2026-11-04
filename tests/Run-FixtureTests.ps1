<#
.SYNOPSIS
  Fixture tests for Check-K2F.ps1 and Remediate-K2F.ps1. Each check gets a positive and a negative case.
.DESCRIPTION
  Builds fake user profiles, install folders and hosts files under -Root, then runs the scripts in child
  PowerShell processes with APPDATA / LOCALAPPDATA / TEMP pointed at the fixture and asserts on the JSON report.
  Side effects outside -Root (all removed at the end):
    - HKCU\Software\Classes\WOW6432Node\CLSID\{E77CC89B-...} is created for one case (no dll value).
    - one helper powershell.exe loads a copy of C:\Windows\System32\version.dll for the process-module case.
  Not covered: firewall rule creation (needs admin), other users' HKCU, real launcher installs.
  Evidence rung: 0 (example tests); each check has one positive and one negative scenario, not a property.
  Exit code = number of failed assertions.
#>
param([string]$Root = (Join-Path $env:TEMP ('k2f-fixture-' + [guid]::NewGuid().ToString('N').Substring(0, 8))))

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$check = Join-Path $repo 'Check-K2F.ps1'
$remed = Join-Path $repo 'Remediate-K2F.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$hex = 'a' * 64
$clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$wowKey = "HKCU:\Software\Classes\WOW6432Node\CLSID\$clsid"
$script:fail = 0
$script:pass = 0

function Assert([bool]$cond, [string]$name) {
  if ($cond) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green }
  else { $script:fail++; Write-Host "  FAIL  $name" -ForegroundColor Red }
}
function New-Dir([string]$p) { New-Item -ItemType Directory -Force -Path $p | Out-Null; $p }
function New-File([string]$p, [string]$text = 'x') { New-Dir (Split-Path $p) | Out-Null; [IO.File]::WriteAllText($p, $text); $p }

# One case = a fresh fixture tree. Returns paths.
function New-Case([string]$name) {
  $c = Join-Path $Root $name
  $o = [pscustomobject]@{
    Dir = $c
    Roaming = New-Dir "$c\cur\Roaming"; Local = New-Dir "$c\cur\Local"; Temp = New-Dir "$c\cur\Temp"
    Users = New-Dir "$c\users"
    Other = New-Dir "$c\users\other\AppData\Local"
    OtherRoaming = New-Dir "$c\users\other\AppData\Roaming"
    Install = New-Dir "$c\install\launcher\intl_service"
    Hosts = New-File "$c\hosts" "# empty`r`n"
    Report = "$c\report.json"
  }
  New-File "$($o.Install)\debug.log" "[1104/120000.000:INFO] FETCH_LIST suc success`r`n" | Out-Null
  $o
}
function Invoke-Check($case, [switch]$NoInstall) {
  $env:APPDATA = $case.Roaming; $env:LOCALAPPDATA = $case.Local; $env:TEMP = $case.Temp; $env:TMP = $case.Temp
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $check, '-ReportPath', $case.Report)
  # Pass a fixture parameter only when the script declares it, so an older Check-K2F.ps1 can run as the control build.
  if ($checkParams -contains 'UsersRoot') { $a += @('-UsersRoot', $case.Users) }
  if ($checkParams -contains 'HostsPath') { $a += @('-HostsPath', $case.Hosts) }
  if (-not $NoInstall) { $a += @('-InstallPath', (Split-Path (Split-Path $case.Install))) }
  $ErrorActionPreference = 'Continue'   # stderr lines of a native call must not terminate the run
  $out = & $ps @a 2>&1 | Out-String
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  $env:APPDATA = $saved.APPDATA; $env:LOCALAPPDATA = $saved.LOCALAPPDATA; $env:TEMP = $saved.TEMP; $env:TMP = $saved.TMP
  $r = Get-Content -LiteralPath $case.Report -Raw -Encoding UTF8 | ConvertFrom-Json
  [pscustomobject]@{ Code = $code; Report = $r; Out = $out; Findings = @($r.Findings) }
}
function Invoke-Remediate($case, [switch]$Apply) {
  $env:APPDATA = $case.Roaming; $env:LOCALAPPDATA = $case.Local; $env:TEMP = $case.Temp; $env:TMP = $case.Temp
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $remed, '-InstallPath', (Split-Path (Split-Path $case.Install)), '-Quarantine', "$($case.Dir)\quarantine")
  if ($remedParams -contains 'UsersRoot') { $a += @('-UsersRoot', $case.Users) }
  if ($Apply) { $a += '-Apply' }
  $ErrorActionPreference = 'Continue'
  $out = & $ps @a 2>&1 | Out-String
  if ($LASTEXITCODE) { Write-Host "  (Remediate exit $LASTEXITCODE)" -ForegroundColor DarkGray }
  $ErrorActionPreference = 'Stop'
  $env:APPDATA = $saved.APPDATA; $env:LOCALAPPDATA = $saved.LOCALAPPDATA; $env:TEMP = $saved.TEMP; $env:TMP = $saved.TMP
  $out
}
function Has-Finding($res, [string]$level, [string]$whereLike) { @($res.Findings | Where-Object { $_.Level -eq $level -and $_.Where -like $whereLike }).Count -gt 0 }

$checkParams = @((Get-Command $check).Parameters.Keys)
$remedParams = @((Get-Command $remed).Parameters.Keys)
$saved = [pscustomobject]@{ APPDATA = $env:APPDATA; LOCALAPPDATA = $env:LOCALAPPDATA; TEMP = $env:TEMP; TMP = $env:TMP }
if (Test-Path $wowKey) { throw "$wowKey already exists in this registry view; refusing to run (it would be removed at the end)." }
New-Dir $Root | Out-Null
Write-Host "fixture root: $Root"
$helper = $null
try {
  Write-Host "`n[N0] empty fixture"
  $c = New-Case 'n0'; $r = Invoke-Check $c
  Assert ($r.Report.Verdict -eq 'clean-known' -and $r.Code -eq 0) 'N0 verdict clean-known, exit 0'
  Assert ($r.Findings.Count -eq 0) 'N0 no findings'
  Assert (@($r.Report.Profiles).Count -eq 2) 'N0 two profiles checked (current + other)'
  Assert (-not $r.Report.HostsBlocked) 'N0 empty hosts reads as not blocked'

  Write-Host "`n[P1] other user's TEMP has k2f-bcreds file"
  $c = New-Case 'p1'; New-File "$($c.Other)\Temp\k2f-bcreds-1.json" | Out-Null; $r = Invoke-Check $c
  Assert (Has-Finding $r 'RED' "$($c.Users)\other\*k2f-bcreds-1.json") 'P1 RED for other user temp file'
  Assert ($r.Code -eq 3) 'P1 exit 3 (live)'

  Write-Host "`n[P2/N2] Edge PlatformExperienceHelper in other user's profile"
  $c = New-Case 'p2'
  New-File "$($c.Other)\Microsoft\Edge\User Data\PlatformExperienceHelper\$hex\platform_experience_helper.dll" ('MZ' + ('x' * 100)) | Out-Null
  $r = Invoke-Check $c
  Assert (Has-Finding $r 'RED' "*\Edge\User Data\PlatformExperienceHelper\$hex\platform_experience_helper.dll") 'P2 RED for unsigned Edge dll'
  $c = New-Case 'n2'
  $d = New-Dir "$($c.Other)\Microsoft\Edge\User Data\PlatformExperienceHelper\$hex"
  Copy-Item "$env:SystemRoot\System32\version.dll" "$d\platform_experience_helper.dll"
  $r = Invoke-Check $c
  Assert (-not (Has-Finding $r 'RED' '*PlatformExperienceHelper*')) 'N2 Microsoft-signed dll in the same place is not flagged'

  Write-Host "`n[P3/N3] launcher located from url_protocol.reg (UTF-16, hmt exe name)"
  $c = New-Case 'p3'
  $exe = "$(Split-Path $c.Install)\nikke_launcher_hmt.exe"
  $reg = "Windows Registry Editor Version 5.00`r`n[HKEY_CURRENT_USER\SOFTWARE\Classes\nikkelauncherhmt\DefaultIcon]`r`n@=`"$($exe -replace '\\', '\\')`"`r`n"
  New-Dir "$($c.Roaming)\nikke_launcher_hmt" | Out-Null
  [IO.File]::WriteAllText("$($c.Roaming)\nikke_launcher_hmt\url_protocol.reg", $reg, [Text.Encoding]::Unicode)
  $r = Invoke-Check $c -NoInstall
  Assert (@($r.Report.Launchers) -contains (Split-Path $c.Install)) 'P3 launcher found via url_protocol.reg'
  $c = New-Case 'n3'
  New-Dir "$($c.Roaming)\nikke_launcher_hmt" | Out-Null
  [IO.File]::WriteAllText("$($c.Roaming)\nikke_launcher_hmt\url_protocol.reg", ($reg -replace [regex]::Escape(($exe -replace '\\', '\\')), 'Z:\\\\gone\\\\launcher\\\\nikke_launcher_hmt.exe'), [Text.Encoding]::Unicode)
  $r = Invoke-Check $c -NoInstall
  Assert (-not (@($r.Report.Launchers) -like 'Z:*')) 'N3 stale url_protocol path is not reported as a launcher'

  Write-Host "`n[P4/P4b/N4] launcher network records"
  $hsts = 'wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw='
  $c = New-Case 'p4'; New-File "$($c.Roaming)\nikke_launcher\tbs_cache\TransportSecurity" "{`"sts`":[{`"host`":`"$hsts`"}]}" | Out-Null; $r = Invoke-Check $c
  Assert (Has-Finding $r 'RED' '*\TransportSecurity') 'P4 RED for analytics HSTS hash'
  Assert ($r.Report.Verdict -eq 'infected-history' -and $r.Code -eq 2) 'P4 counts as history, exit 2'
  $c = New-Case 'p4b'; New-File "$($c.Roaming)\nikke_launcher\tbs_cache\Network Persistent State" '{"server":"https://insightjs.com"}' | Out-Null; $r = Invoke-Check $c
  Assert (Has-Finding $r 'YELLOW' '*\Network Persistent State') 'P4b YELLOW for insightjs.com only'
  Assert ($r.Report.Verdict -eq 'contact' -and $r.Code -eq 1) 'P4b verdict contact, exit 1'
  $c = New-Case 'n4'; New-File "$($c.Roaming)\nikke_launcher\tbs_cache\Network Persistent State" '{"server":"https://sg-gpts.playerinfinite.com"}' | Out-Null; $r = Invoke-Check $c
  Assert ($r.Findings.Count -eq 0) 'N4 unrelated network record not flagged'

  Write-Host "`n[P5/N5] hosts parsing"
  $c = New-Case 'p5'; [IO.File]::WriteAllText($c.Hosts, "127.0.0.1 insightjs.com analytics.insightjs.com`r`n::1 insightjs.org # k2f`r`n"); $r = Invoke-Check $c
  Assert ($r.Report.HostsBlocked -eq $true) 'P5 127.0.0.1 / ::1 entries count as blocked'
  $c = New-Case 'n5'; [IO.File]::WriteAllText($c.Hosts, "0.0.0.0 insightjs.com`r`n# 0.0.0.0 analytics.insightjs.com`r`n0.0.0.0 insightjs.org`r`n"); $r = Invoke-Check $c
  Assert ($r.Report.HostsBlocked -eq $false) 'N5 commented-out entry does not count'

  Write-Host "`n[P6] WOW6432Node COM hijack key (this registry view)"
  New-Item -Path "$wowKey\InprocServer32" -Force | Out-Null
  $c = New-Case 'p6'; $r = Invoke-Check $c
  Assert (Has-Finding $r 'RED' "HKCU\Software\Classes\WOW6432Node\CLSID\$clsid") 'P6 RED for 32-bit view key'
  $o = Invoke-Remediate $c
  Assert ($o -match [regex]::Escape("HKCU\Software\Classes\WOW6432Node\CLSID\$clsid")) 'P6 Remediate dry-run lists the 32-bit key'
  Assert (Test-Path $wowKey) 'P6 dry-run leaves the key in place'
  Remove-Item $wowKey -Recurse -Force

  Write-Host "`n[P7] any process loading the dll from a 64-hex folder"
  $c = New-Case 'p7'
  $d = New-Dir "$($c.Dir)\loader\$hex"; Copy-Item "$env:SystemRoot\System32\version.dll" "$d\platform_experience_helper.dll"
  # Helper code goes through a file: Start-Process joins -ArgumentList with spaces and would break inner quotes.
  $hs = "$($c.Dir)\loader.ps1"
  [IO.File]::WriteAllText($hs, "Add-Type -Name N -Namespace K -MemberDefinition '[DllImport(`"kernel32`")] public static extern System.IntPtr LoadLibrary(string p);'`r`n[void][K.N]::LoadLibrary('$d\platform_experience_helper.dll')`r`nStart-Sleep 300`r`n")
  $helper = Start-Process $ps -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$hs`"" -WindowStyle Hidden -PassThru
  $loaded = $false
  for ($i = 0; $i -lt 30 -and -not $loaded; $i++) { Start-Sleep -Milliseconds 500; try { $loaded = @((Get-Process -Id $helper.Id).Modules | Where-Object ModuleName -eq 'platform_experience_helper.dll').Count -gt 0 } catch {} }
  Assert $loaded 'P7 setup: helper loaded the dll'
  $r = Invoke-Check $c
  Assert (Has-Finding $r 'RED' "*\loader\$hex\platform_experience_helper.dll") 'P7 RED for powershell.exe loading the dll'
  Stop-Process -Id $helper.Id -Force; $helper = $null

  Write-Host "`n[P8/N8] Delta Force Garena layout: launcher\service\debug.log, %APPDATA%\df_garena_launcher"
  $dfLog = "[1104/010203.000:INFO:CONSOLE(1)] `"k2f_chan registered`", source: (1)`r`n[1104/010204.000:INFO:CONSOLE(1)] `"agent started as PC`", source: (1)`r`n"
  $c = New-Case 'p8'; Remove-Item -LiteralPath $c.Install -Recurse -Force
  $dfDbg = New-File "$(Split-Path $c.Install)\service\debug.log" $dfLog
  New-File "$($c.Roaming)\df_garena_launcher\tbs_cache\Network Persistent State" '{"server":"https://insightjs.org"}' | Out-Null
  $r = Invoke-Check $c
  Assert (@($r.Report.Launchers) -contains (Split-Path $c.Install)) 'P8 service\debug.log layout recognised as a launcher'
  Assert (Has-Finding $r 'RED' $dfDbg) 'P8 RED for k2f_chan + agent started in service\debug.log'
  Assert (Has-Finding $r 'YELLOW' '*\df_garena_launcher\tbs_cache\Network Persistent State') 'P8 YELLOW for insightjs in df_garena_launcher cache'
  Assert ($r.Report.Verdict -eq 'infected-history' -and $r.Code -eq 2) 'P8 debug.log counts as history, exit 2'
  $c = New-Case 'n8'; Remove-Item -LiteralPath $c.Install -Recurse -Force
  New-File "$(Split-Path $c.Install)\service\debug.log" "[0909/205702.000:INFO:CONSOLE(17)] `"[js-bridge][response][Srv_Com_QuitApp]`", source: https://launcher.jupiterlauncher.com/assets/configs.js (17)`r`n" | Out-Null
  New-File "$($c.Roaming)\df_garena_launcher\tbs_cache\Network Persistent State" '{"server":"https://launcher.jupiterlauncher.com"}' | Out-Null
  $r = Invoke-Check $c
  Assert (@($r.Report.Launchers) -contains (Split-Path $c.Install)) 'N8 clean Delta Force launcher still recognised'
  Assert ($r.Findings.Count -eq 0 -and $r.Code -eq 0) 'N8 clean Delta Force logs not flagged'

  Write-Host "`n[R1] Remediate -Apply on fixture: other user's cache, Edge dll, temp"
  $c = New-Case 'r1'
  $edge = New-File "$($c.Other)\Microsoft\Edge\User Data\PlatformExperienceHelper\$hex\platform_experience_helper.dll" ('MZ' + ('x' * 100))
  $tbs = New-File "$($c.OtherRoaming)\nikke_launcher\tbs_cache\Local Storage\leveldb\000003.log" 'k2f.agent.state'
  $tmpf = New-File "$($c.Other)\Temp\k2f_screen_1.jpg"
  $r = Invoke-Check $c
  Assert ($r.Report.Verdict -eq 'infected-live') 'R1 before: infected-live'
  $o = Invoke-Remediate $c
  Assert ((Test-Path $edge) -and (Test-Path $tbs) -and (Test-Path $tmpf)) 'R1 dry-run moves nothing'
  $o = Invoke-Remediate $c -Apply
  Assert (-not (Test-Path (Split-Path $edge)) -and -not (Test-Path (Split-Path $tbs -Parent | Split-Path | Split-Path)) -and -not (Test-Path $tmpf)) 'R1 apply: sources gone'
  $q = "$($c.Dir)\quarantine"
  Assert ((Test-Path "$q\peh\other-edge\$hex\platform_experience_helper.dll.quarantined") -and (Test-Path "$q\other-nikke_launcher-tbs_cache") -and (Test-Path "$q\temp\k2f_screen_1.jpg")) 'R1 apply: all three in quarantine'
  $r = Invoke-Check $c
  Assert ($r.Report.Verdict -eq 'clean-known') 'R1 after: clean-known'
} finally {
  $env:APPDATA = $saved.APPDATA; $env:LOCALAPPDATA = $saved.LOCALAPPDATA; $env:TEMP = $saved.TEMP; $env:TMP = $saved.TMP
  if ($helper) { Stop-Process -Id $helper.Id -Force -ErrorAction SilentlyContinue }
  if (Test-Path $wowKey) { Remove-Item $wowKey -Recurse -Force }
  Start-Sleep -Milliseconds 500
  Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "`n$($script:pass) passed, $($script:fail) failed"
exit $script:fail
