<#
.SYNOPSIS
  Builds dist\nikke-k2f-check.cmd: one double-clickable file that carries Run-K2F.ps1, Check-K2F.ps1 and
  Remediate-K2F.ps1 (base64, each with its SHA-256), writes them to a new %TEMP%\nikke-k2f-check-<stamp>-<random>\,
  re-hashes them from disk and runs Run-K2F.ps1. Nothing is downloaded at run time. The output is pure ASCII with CRLF line endings.
.PARAMETER Out
  Output path (default dist\nikke-k2f-check.cmd under the repo).
#>
[CmdletBinding()]
param([string]$Out)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Out) { $Out = Join-Path $repo 'dist\nikke-k2f-check.cmd' }
$names = 'Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1'
$sha = [Security.Cryptography.SHA256]::Create()
function Hex([byte[]]$b) { -join ($sha.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) }

$blocks = @(); $all = New-Object System.Collections.Generic.List[byte]
foreach ($n in $names) {
  $bytes = [IO.File]::ReadAllBytes((Join-Path $repo $n)); $all.AddRange($bytes)
  $b64 = [Convert]::ToBase64String($bytes)
  $lines = for ($i = 0; $i -lt $b64.Length; $i += 120) { $b64.Substring($i, [Math]::Min(120, $b64.Length - $i)) }
  $blocks += "#<K2F-FILE $n sha256=$(Hex $bytes)>`r`n" + ($lines -join "`r`n") + "`r`n#</K2F-FILE>"
}
$stamp = (Hex $all.ToArray()).Substring(0, 12)

# Boot code runs inside PowerShell; it is never parsed by cmd (cmd stops at "exit /b").
$boot = @'
param([string]$Mode)
$t = [IO.File]::ReadAllText($env:K2F_SELF)
# A fresh folder per run: a name nobody could prepare in advance.
$dir = Join-Path $env:TEMP ('nikke-k2f-check-@STAMP@-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
$ms = [regex]::Matches($t, '(?s)#<K2F-FILE ([A-Za-z0-9._-]+) sha256=([0-9a-f]{64})>\r?\n(.*?)\r?\n#</K2F-FILE>')
if ($ms.Count -ne @COUNT@) { Write-Host 'This file is damaged (parts missing). Download it again from https://github.com/WizerdBaChe/nikke-k2f-check/releases' -ForegroundColor Red; exit 90 }
$h = [Security.Cryptography.SHA256]::Create()
foreach ($m in $ms) {
  $bytes = [Convert]::FromBase64String(($m.Groups[3].Value -replace '\s', ''))
  $got = -join ($h.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
  if ($got -ne $m.Groups[2].Value) { Write-Host "This file is damaged ($($m.Groups[1].Value) does not match its checksum). Download it again." -ForegroundColor Red; exit 91 }
  [IO.File]::WriteAllBytes((Join-Path $dir $m.Groups[1].Value), $bytes)
}
# Read back what is on disk right before running it: the files must still be the ones just verified.
foreach ($m in $ms) {
  $got = -join ($h.ComputeHash([IO.File]::ReadAllBytes((Join-Path $dir $m.Groups[1].Value))) | ForEach-Object { $_.ToString('x2') })
  if ($got -ne $m.Groups[2].Value) { Write-Host "$($m.Groups[1].Value) changed on disk after it was written ($dir). Not running it." -ForegroundColor Red; exit 92 }
}
$a =@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $dir 'Run-K2F.ps1'))
if ($Mode -eq 'check') { $a += '-CheckOnly' }
& (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @a
exit $LASTEXITCODE
'@
$boot = $boot.Replace('@STAMP@', $stamp).Replace('@COUNT@', "$($names.Count)") -replace "`r?`n", "`r`n"

$head = @(
  '@echo off'
  "rem nikke-k2f-check one-file launcher, build $stamp. Source and how it works: https://github.com/WizerdBaChe/nikke-k2f-check"
  'rem Carries Run-K2F.ps1, Check-K2F.ps1 and Remediate-K2F.ps1 (base64 + SHA-256 below). It writes them to %TEMP% and runs them;'
  'rem nothing is downloaded. It only reads unless you answer Y twice. Add "check" to only check: nikke-k2f-check.cmd check'
  'setlocal'
  'set "K2F_SELF=%~f0"'
  'powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:K2F_SELF);$m=[regex]::Match($t,''(?s)#<K2F-BOOT>\r?\n(.*?)\r?\n#</K2F-BOOT>'');& ([scriptblock]::Create($m.Groups[1].Value)) ''%~1''"'
  'set "K2F_RC=%errorlevel%"'
  'if %K2F_RC% geq 90 pause'
  'exit /b %K2F_RC%'
) -join "`r`n"

$text = $head + "`r`n#<K2F-BOOT>`r`n" + $boot + "`r`n#</K2F-BOOT>`r`n" + ($blocks -join "`r`n") + "`r`n"
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
[IO.File]::WriteAllText($Out, $text, (New-Object Text.ASCIIEncoding))
$outHash = (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash
Write-Host "wrote $Out ($((Get-Item $Out).Length) bytes) build $stamp"
Write-Host "SHA256 $outHash"
