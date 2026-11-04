<#
.SYNOPSIS
  One-click flow for non-technical users: check, then (only on a hit and only after a Y) clean up.
.DESCRIPTION
  Started by Run-Check.cmd or by the one-file launcher (tools/Build-OneFile.ps1). Never changes anything
  without two explicit Y answers: one to start cleaning (relaunches elevated), one after the dry-run list.
  Modes: default = check, then offer cleanup on a hit; -CheckOnly = check and stop; -Fix = cleanup flow
  (used by the elevated relaunch). K2F_NOPAUSE=1 skips the final key press (tests).
#>
[CmdletBinding()]
param([switch]$Fix, [switch]$CheckOnly)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$check = Join-Path $here 'Check-K2F.ps1'
$remed = Join-Path $here 'Remediate-K2F.ps1'

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
  & $check | Out-Host
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
  if (Test-Admin) { & $ps -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Fix; exit $LASTEXITCODE }
  Write-Host '清除需要系統管理員權限：等一下跳出的視窗請按「是」。' -ForegroundColor Cyan
  try { Start-Process $ps -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Fix') -ErrorAction Stop }
  catch { Write-Host '沒有取得系統管理員權限，沒有做任何更動。' -ForegroundColor Yellow }
  Wait-Key; exit $code
}

# -Fix: elevated cleanup flow
Write-Host '== NIKKE 啟動器木馬：清除 ==' -ForegroundColor Cyan
Write-Host '下面先列出會做的事（這一步還沒有改任何東西）：'; Write-Host ''
& $remed | Out-Host
Write-Host ''
if (-not (Ask-Yes '照上面「總結」的清單清除嗎？東西都會搬到隔離資料夾，不會刪除')) { Write-Host '沒有做任何更動。'; Wait-Key; exit 0 }
& $remed -Apply | Out-Host
Write-Host ''; Write-Host '清除完成，再檢查一次：' -ForegroundColor Cyan; Write-Host ''
$code = Invoke-Check
Write-Host ''
Write-Host '如果上面說檔案被鎖住，請重新開機後再執行一次這個檔案。' -ForegroundColor Yellow
Write-Host '在官方確認安全之前，先不要打開電腦版啟動器。' -ForegroundColor Yellow
Wait-Key; exit $code
