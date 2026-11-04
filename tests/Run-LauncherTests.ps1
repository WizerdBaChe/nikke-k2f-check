<#
.SYNOPSIS
  Tests for the double-click launchers: Run-Check.cmd and the one-file dist\nikke-k2f-check.cmd.
.DESCRIPTION
  Builds the one-file launcher, then runs both launchers non-interactively (K2F_NOPAUSE=1, stdin from nul).
  L1/L2 run against this PC as it is (smoke: the launcher's exit code must equal Check-K2F.ps1's own).
  L3 checks the extracted files are byte-identical to the repo files. L4 points TEMP at a fixture holding a
  k2f-bcreds file: the launcher must report the hit (exit 3) and change nothing without a Y.
  L5/L6 are the negative controls: a damaged copy must refuse to run (exit 91 checksum, 90 missing part).
  Evidence rung: 0 (example tests). Exit code = number of failed assertions.
#>
param([string]$Root = (Join-Path $env:TEMP ('k2f-launcher-' + [guid]::NewGuid().ToString('N').Substring(0, 8))))

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$one = Join-Path $Root 'nikke-k2f-check.cmd'
$script:fail = 0; $script:pass = 0
function Assert([bool]$cond, [string]$name) {
  if ($cond) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $name" -ForegroundColor Red }
}
function Invoke-Cmd([string]$file, [string]$arg) {
  $ErrorActionPreference = 'Continue'
  $out = & cmd.exe /d /c "`"$file`" $arg < nul" 2>&1 | Out-String
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  [pscustomobject]@{ Code = $code; Out = $out }
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
$savedTemp = $env:TEMP; $savedTmp = $env:TMP
$env:K2F_NOPAUSE = '1'
try {
  & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'tools\Build-OneFile.ps1') -Out $one | Out-Null
  & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Check-K2F.ps1') | Out-Null
  $direct = $LASTEXITCODE
  Write-Host "Check-K2F.ps1 on this PC: exit $direct"

  Write-Host "`n[L1/L2] launchers on this PC, check-only and default mode"
  $r = Invoke-Cmd $one 'check'; Assert ($r.Code -eq $direct) "L1 one-file 'check' exit $($r.Code) = Check-K2F exit $direct"
  $r = Invoke-Cmd $one ''; Assert ($r.Code -eq $direct) "L1b one-file default mode exit $($r.Code) = $direct (no Y given)"
  $r = Invoke-Cmd (Join-Path $repo 'Run-Check.cmd') 'check'; Assert ($r.Code -eq $direct) "L2 Run-Check.cmd 'check' exit $($r.Code) = $direct"

  Write-Host "`n[L3] extracted files are the repo files"
  $stamp = ([regex]::Match([IO.File]::ReadAllText($one), 'build ([0-9a-f]{12})')).Groups[1].Value
  $ex = Join-Path $savedTemp "nikke-k2f-check-$stamp"
  foreach ($n in 'Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1') {
    $a = (Get-FileHash (Join-Path $repo $n)).Hash; $b = (Get-FileHash (Join-Path $ex $n) -ErrorAction SilentlyContinue).Hash
    Assert ($a -eq $b) "L3 $n byte-identical"
  }

  Write-Host "`n[L4] hit in TEMP: launcher reports it and changes nothing without a Y"
  $fx = New-Item -ItemType Directory -Force -Path (Join-Path $Root 'fxtemp')
  $hit = Join-Path $fx.FullName 'k2f-bcreds-1.json'; [IO.File]::WriteAllText($hit, 'x')
  $env:TEMP = $fx.FullName; $env:TMP = $fx.FullName
  $r = Invoke-Cmd $one ''
  $env:TEMP = $savedTemp; $env:TMP = $savedTmp
  Assert ($r.Code -eq 3) "L4 exit $($r.Code) = 3 (infected, live)"
  Assert ($r.Out -match 'k2f-bcreds-1\.json') 'L4 the report reaches the screen (finding path printed)'
  Assert (Test-Path $hit) 'L4 fixture file still in place (no change without Y)'

  Write-Host "`n[L5/L6] damaged copies refuse to run"
  $t = [IO.File]::ReadAllText($one)
  $m = [regex]::Match($t, '#<K2F-FILE Check-K2F\.ps1 sha256=[0-9a-f]{64}>\r\n(.)')
  $i = $m.Groups[1].Index; $flip = if ($t[$i] -eq 'A') { 'B' } else { 'A' }
  $bad = Join-Path $Root 'damaged.cmd'; [IO.File]::WriteAllText($bad, $t.Remove($i, 1).Insert($i, $flip), (New-Object Text.ASCIIEncoding))
  $r = Invoke-Cmd $bad 'check'; Assert ($r.Code -eq 91) "L5 one changed character: exit $($r.Code) = 91"
  $cut = [regex]::Replace($t, '(?s)#<K2F-FILE Remediate-K2F\.ps1 .*?#</K2F-FILE>\r\n', '')
  $bad2 = Join-Path $Root 'missing.cmd'; [IO.File]::WriteAllText($bad2, $cut, (New-Object Text.ASCIIEncoding))
  $r = Invoke-Cmd $bad2 'check'; Assert ($r.Code -eq 90) "L6 one part removed: exit $($r.Code) = 90"
} finally {
  $env:TEMP = $savedTemp; $env:TMP = $savedTmp; Remove-Item Env:\K2F_NOPAUSE -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "`n$($script:pass) passed, $($script:fail) failed"
exit $script:fail
