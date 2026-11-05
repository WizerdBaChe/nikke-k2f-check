<#
.SYNOPSIS
  One-click flow for non-technical users: check, then (only on a hit and only after a Y) clean up.
.DESCRIPTION
  Started by Run-Check.cmd or by the one-file launcher (tools/Build-OneFile.ps1). Never changes anything
  without two explicit Y answers: one to start cleaning (relaunches elevated), one after the dry-run list.
  Modes: default = check, then offer cleanup on a hit; -CheckOnly = check and stop; -Fix = cleanup flow
  (used by the elevated relaunch). K2F_NOPAUSE=1 skips the final key press (tests).
  Elevation (rules/privileged-remediation.md): the elevated side never runs the user-writable scripts. A small
  inline bootstrap (-EncodedCommand) carries the expected SHA-256 of each script, creates a NEW admin-only folder
  under %ProgramData% (no inheritance, Administrators + SYSTEM, ACL re-read after creation), copies the scripts in,
  hashes the copies and runs only them. Expected hashes: the ones embedded in the one-file release (K2F_HASHES, set
  by its boot code), else hashed from disk when the user answers Y (repo / ZIP use). -CallerSid passes the account
  that started the check, so a UAC prompt answered with another administrator's password still cleans that account.
  -EmitBootstrap prints the encoded bootstrap and exits; -StageRoot (tests) stages under another folder and also
  grants the current user access there, since a non-elevated test cannot own an admin-only folder.
#>
[CmdletBinding()]
param([switch]$Fix, [switch]$CheckOnly, [string]$CallerSid, [switch]$EmitBootstrap, [string]$StageRoot)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$check = Join-Path $here 'Check-K2F.ps1'
$remed = Join-Path $here 'Remediate-K2F.ps1'
$scriptNames = 'Run-K2F.ps1', 'Check-K2F.ps1', 'Remediate-K2F.ps1', 'K2F-Common.ps1'
$mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# The elevated half: copy-and-verify into a fresh admin-only folder, then run only the copies.
function New-K2FBootstrap {
  $exp = @{}
  if ($env:K2F_HASHES) {
    foreach ($kv in $env:K2F_HASHES -split ';') { $p = $kv -split '=', 2; if ($p.Count -eq 2) { $exp[$p[0]] = $p[1].ToLowerInvariant() } }
  } else {
    $h = [Security.Cryptography.SHA256]::Create()
    foreach ($n in $scriptNames) { $exp[$n] = -join ($h.ComputeHash([IO.File]::ReadAllBytes((Join-Path $here $n))) | ForEach-Object { $_.ToString('x2') }) }
  }
  foreach ($n in $scriptNames) { if (-not $exp[$n]) { throw "no expected hash for $n" } }
  $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
  $expText = ($scriptNames | ForEach-Object { "$(& $q $_) = $(& $q $exp[$_])" }) -join '; '
  $b = @'
$ErrorActionPreference = 'Stop'
$src = @SRC@; $sid = @SID@; $parent = @PARENT@; $test = @TEST@
if (-not $parent) { $parent = $env:ProgramData }
$exp = @{ @EXP@ }
$pause = { if ($env:K2F_NOPAUSE -ne '1') { Write-Host ''; Write-Host '按 Enter 關閉這個視窗。'; [void](Read-Host) } }
try {
  $dir = Join-Path $parent ('nikke-k2f-check-run-' + [guid]::NewGuid().ToString('N'))
  if (Test-Path -LiteralPath $dir) { throw "folder already exists: $dir" }
  $adm = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
  $ids = @($adm, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))
  if ($test) { $ids += [Security.Principal.WindowsIdentity]::GetCurrent().User }
  $sec = New-Object Security.AccessControl.DirectorySecurity
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($id in $ids) { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule $id, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')) }
  if (-not $test) { $sec.SetOwner($adm) }
  [void][IO.Directory]::CreateDirectory($dir, $sec)
  $acl = Get-Acl -LiteralPath $dir
  $ok = @($ids | ForEach-Object { $_.Value })
  $extra = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $ok -notcontains $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
  if (-not $acl.AreAccessRulesProtected -or $extra.Count) { throw "folder is not admin-only: $dir" }
  $h = [Security.Cryptography.SHA256]::Create()
  foreach ($n in $exp.Keys) {
    $d = Join-Path $dir $n
    [IO.File]::WriteAllBytes($d, [IO.File]::ReadAllBytes((Join-Path $src $n)))
    $got = -join ($h.ComputeHash([IO.File]::ReadAllBytes($d)) | ForEach-Object { $_.ToString('x2') })
    if ($got -ne $exp[$n]) {
      Write-Host "$n 在檢查之後被改過（預期 $($exp[$n])，實際 $got）。不執行，沒有做任何更動。" -ForegroundColor Red
      Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; & $pause; exit 92
    }
  }
} catch { Write-Host "無法準備受保護的副本：$($_.Exception.Message)。沒有做任何更動。" -ForegroundColor Red; & $pause; exit 93 }
& (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'Run-K2F.ps1') -Fix -CallerSid $sid
$rc = $LASTEXITCODE
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
exit $rc
'@
  $b = $b.Replace('@SRC@', (& $q $here)).Replace('@SID@', (& $q $mySid)).Replace('@PARENT@', (& $q $StageRoot)).Replace('@TEST@', $(if ($StageRoot) { '$true' } else { '$false' })).Replace('@EXP@', $expText)
  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($b))
}
if ($EmitBootstrap) { New-K2FBootstrap; exit 0 }

# -Fix for another account: the elevated window belongs to whoever typed the UAC password; clean the caller's registry.
$userArgs = @{}
if ($Fix -and $CallerSid -and $CallerSid -ne $mySid) { $userArgs = @{ UserSid = $CallerSid } }

function Wait-Key {
  if ($env:K2F_NOPAUSE -eq '1') { return }
  Write-Host ''; Write-Host '按 Enter 關閉這個視窗。' -ForegroundColor DarkGray; [void](Read-Host)
}
function Ask-Yes([string]$q) {
  if ($env:K2F_NOPAUSE -eq '1') { return $false }
  $a = Read-Host "$q（輸入 Y 再按 Enter；直接按 Enter 就是不要）"
  return ($a -match '^\s*[yY]')
}
function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
# In-process call: its exit code lands in $LASTEXITCODE, and Out-Host keeps any stray output on screen
# instead of in this function's return value (a child process here swallowed the whole report).
function Invoke-Check {
  & $check @userArgs | Out-Host
  return $LASTEXITCODE
}

if (-not $Fix) {
  Write-Host '== NIKKE 啟動器木馬：自我檢查 ==' -ForegroundColor Cyan
  Write-Host '只讀取檔案，不會改任何東西。大約 30 秒到 1 分鐘。'; Write-Host ''
  $code = Invoke-Check
  Write-Host ''
  if ($code -eq 0) {
    Write-Host '沒有發現已知痕跡。9 月 27 日之後開過電腦版啟動器的話，重要帳號的密碼還是建議換掉。' -ForegroundColor Green
    Wait-Key; exit 0
  }
  if ($code -eq 4) {
    Write-Host '有些檔案讀不到，這次檢查不完整（不代表中毒）。請關掉 NIKKE 啟動器，或重新開機後再執行一次這個檔案。' -ForegroundColor Yellow
    Wait-Key; exit 4
  }
  Write-Host '這台電腦有痕跡。請先用「手機」換掉重要帳號的密碼，並在各網站按「登出所有裝置」：' -ForegroundColor Yellow
  Write-Host '  Google（也是 Chrome 的密碼庫）、Discord、Steam、Level Infinite（NIKKE）、銀行、加密貨幣錢包。' -ForegroundColor Yellow
  Write-Host '  說明頁：https://wizerdbache.github.io/nikke-k2f-check/' -ForegroundColor Yellow
  if ($CheckOnly) { Wait-Key; exit $code }
  Write-Host ''
  if (-not (Ask-Yes '要現在清除木馬元件嗎？會先列出要做的事，再問你一次')) { Write-Host '沒有做任何更動。'; Wait-Key; exit $code }
  try { $enc = New-K2FBootstrap } catch { Write-Host "準備清除程式失敗：$($_.Exception.Message)。沒有做任何更動。" -ForegroundColor Red; Wait-Key; exit $code }
  Write-Host '提醒：木馬如果此刻還在執行，它和你是同一個帳號，系統管理員提示擋不住它。最穩的做法是用另一個系統管理員帳號登入、或在安全模式下執行這個檔案。' -ForegroundColor DarkGray
  if (Test-Admin) { & $ps -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc; exit $LASTEXITCODE }
  Write-Host '清除需要系統管理員權限：等一下跳出的視窗請按「是」。' -ForegroundColor Cyan
  try { Start-Process $ps -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -ErrorAction Stop }
  catch { Write-Host '沒有取得系統管理員權限，沒有做任何更動。' -ForegroundColor Yellow }
  Wait-Key; exit $code
}

# -Fix: elevated cleanup flow
Write-Host '== NIKKE 啟動器木馬：清除 ==' -ForegroundColor Cyan
if ($userArgs.UserSid) { Write-Host "這個系統管理員視窗屬於另一個帳號；登錄會處理啟動檢查的帳號（$CallerSid）。" -ForegroundColor Yellow }
Write-Host '下面先列出會做的事（這一步還沒有改任何東西）：'; Write-Host ''
& $remed @userArgs | Out-Host
Write-Host ''
if (-not (Ask-Yes '照上面「總結」的清單清除嗎？檔案會搬到隔離資料夾，不會刪除（例外列在總結下方）')) { Write-Host '沒有做任何更動。'; Wait-Key; exit 0 }
& $remed -Apply @userArgs | Out-Host
Write-Host ''; Write-Host '清除完成，再檢查一次：' -ForegroundColor Cyan; Write-Host ''
$code = Invoke-Check
Write-Host ''
Write-Host '如果上面說檔案被鎖住，請重新開機後再執行一次這個檔案。' -ForegroundColor Yellow
Write-Host '在官方確認安全之前，先不要打開電腦版啟動器。' -ForegroundColor Yellow
Wait-Key; exit $code
