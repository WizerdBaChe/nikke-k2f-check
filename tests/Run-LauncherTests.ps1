<#
.SYNOPSIS
  Tests for the double-click launchers: Run-Check.cmd and the one-file dist\nikke-k2f-check.cmd.
.DESCRIPTION
  Builds the one-file launcher, then runs both launchers non-interactively (K2F_NOPAUSE=1, stdin from nul).
  L1/L2 run against this PC as it is (smoke: the launcher's exit code must equal Check-K2F.ps1's own).
  L3 checks each run extracts into its own folder and the extracted files are byte-identical to the repo files. L4 points TEMP at a fixture holding a
  k2f-bcreds file: the launcher must report the hit (exit 3) and change nothing without a Y.
  L5/L6 are the negative controls: a damaged copy must refuse to run (exit 91 checksum, 90 missing part).
  L7-L9 run the elevated bootstrap without UAC (-StageRoot): an untouched copy runs, a script swapped after hashing
  is refused (L8c shows the old relaunch route ran it), and embedded hashes outrank the files on disk.
  Not covered (manual acceptance, docs/DEVELOPER.md): the admin-only ACL under %ProgramData% and the UAC prompt
  answered with a different administrator's password (-CallerSid -> HKU\<SID>).
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
  # Each run extracts into its own nikke-k2f-check-<stamp>-<random> folder; L1 and L1b made two.
  $runs = @(Get-ChildItem -LiteralPath $savedTemp -Directory -Filter "nikke-k2f-check-$stamp-*" | Where-Object { $_.Name -match "^nikke-k2f-check-$stamp-[0-9a-f]{8}$" } | Sort-Object LastWriteTime)
  Assert ($runs.Count -ge 2) "L3 each run gets its own folder ($($runs.Count) for build $stamp)"
  $ex = if ($runs) { $runs[-1].FullName } else { '' }
  foreach ($n in 'Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1', 'K2F-Common.ps1') {
    $a = (Get-FileHash (Join-Path $repo $n)).Hash; $b = (Get-FileHash (Join-Path $ex $n) -ErrorAction SilentlyContinue).Hash
    Assert ($a -eq $b) "L3 $n byte-identical"
  }

  Write-Host "`n[L7/L8/L9] elevated half: runs only verified copies (bootstrap run without UAC, -StageRoot)"
  $src = New-Item -ItemType Directory -Force -Path (Join-Path $Root 'src')
  $stage = New-Item -ItemType Directory -Force -Path (Join-Path $Root 'stage')
  foreach ($n in 'Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1', 'K2F-Common.ps1') { Copy-Item (Join-Path $repo $n) $src.FullName }
  $srcRun = Join-Path $src.FullName 'Run-K2F.ps1'
  function Invoke-Boot([string]$enc) {
    $ErrorActionPreference = 'Continue'
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc 2>&1 | Out-String
    $code = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    [pscustomobject]@{ Code = $code; Out = $out }
  }
  $enc = (& $ps -NoProfile -ExecutionPolicy Bypass -File $srcRun -EmitBootstrap -StageRoot $stage.FullName | Out-String).Trim()
  $r = Invoke-Boot $enc
  Assert ($r.Code -eq 0 -and $r.Out -match '下面先列出會做的事') "L7 untouched copy: cleanup flow starts from the staged copy (exit $($r.Code))"
  Assert (@(Get-ChildItem -LiteralPath $stage.FullName -Directory).Count -eq 0) 'L7 staged copy removed afterwards'
  # Same-user tamper: swap a script after the hashes were taken (the window between the Y and the UAC prompt).
  $marker = Join-Path $Root 'tampered-ran.txt'
  $enc = (& $ps -NoProfile -ExecutionPolicy Bypass -File $srcRun -EmitBootstrap -StageRoot $stage.FullName | Out-String).Trim()
  [IO.File]::AppendAllText((Join-Path $src.FullName 'Remediate-K2F.ps1'), "`r`n[IO.File]::WriteAllText('$marker', 'ran')`r`n")
  $r = Invoke-Boot $enc
  Assert ($r.Code -eq 92 -and -not (Test-Path $marker)) "L8 script swapped after hashing: refused, exit $($r.Code) = 92, tampered code ran=$(Test-Path $marker)"
  # Control: the route used before 2026-11-05 (-File <user-writable Run-K2F.ps1> -Fix) runs the swapped file.
  $ErrorActionPreference = 'Continue'; & $ps -NoProfile -ExecutionPolicy Bypass -File $srcRun -Fix 2>&1 | Out-Null; $ErrorActionPreference = 'Stop'
  Assert (Test-Path $marker) "L8c control: the old relaunch route runs the swapped file (ran=$(Test-Path $marker))"
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  # Embedded hashes win over the files on disk: a wrong K2F_HASHES entry refuses even untouched files.
  Copy-Item (Join-Path $repo 'Remediate-K2F.ps1') $src.FullName -Force
  $h = @('Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1', 'K2F-Common.ps1' | ForEach-Object { "$_=$((Get-FileHash (Join-Path $src.FullName $_)).Hash.ToLower())" })
  $h[2] = 'Remediate-K2F.ps1=' + ('0' * 64)
  $env:K2F_HASHES = $h -join ';'
  try { $enc = (& $ps -NoProfile -ExecutionPolicy Bypass -File $srcRun -EmitBootstrap -StageRoot $stage.FullName | Out-String).Trim() } finally { Remove-Item Env:\K2F_HASHES }
  $r = Invoke-Boot $enc
  Assert ($r.Code -eq 92) "L9 expected hash taken from K2F_HASHES, not from disk: exit $($r.Code) = 92"

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
