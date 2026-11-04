<#
.SYNOPSIS
  Check whether the 4 Level Infinite CDN scripts the NIKKE launcher loads are back to their known-clean versions.
.DESCRIPTION
  Sends HEAD requests only (nothing is downloaded or executed) and compares each ETag with the clean and
  tampered ETags published in the MotherSphere analysis. A CDN has many edge nodes: one clean answer from
  your node does not prove every node is clean, so run it a few times over a day before reopening the launcher.
  An ETag that is neither known-clean nor known-tampered means the file changed again: treat as unknown.
#>
[CmdletBinding()] param()

$files = @(
  @{ Name = 'aegis-fix.min.js';     Url = 'https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js';                    Clean = '44c576454a5b0b4ed60e1a983aa4e782'; Bad = '50d1861152ea7f6875ffceb7d08445b5' },
  @{ Name = 'images.7fec4c32.js';   Url = 'https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js';   Clean = '6e5f79cf9b7c364249f9de83ba7fa59e'; Bad = '481e9b5ab8fb93406bf31980b53e0578' },
  @{ Name = 'FeedList.feb647c9.js'; Url = 'https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js'; Clean = '04ee9800128396ba26f10ca70f170967'; Bad = 'b7d842200372ad0d9a84ef4cc8511311' },
  @{ Name = 'vue-bucket.min.js';    Url = 'https://na-webassets.playerinfinite.com/comm/assets/lib/vue-bucket.min.js';              Clean = '63bc3a47b35b80a5d200dc5624d7126e'; Bad = 'dd06875637a29cddd3bae2ba84142c78' }
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$bad = 0; $unknown = 0
foreach ($f in $files) {
  try {
    $r = Invoke-WebRequest -Uri $f.Url -Method Head -UseBasicParsing -TimeoutSec 20
    $etag = ($r.Headers['ETag'] -as [string]).Trim('"').ToLower() -replace '^w/"?', ''
    $len = $r.Headers['Content-Length']
    if ($etag -eq $f.Clean)   { Write-Host ("  [乾淨]   {0}  ETag {1}  {2} bytes" -f $f.Name, $etag, $len) -ForegroundColor Green }
    elseif ($etag -eq $f.Bad) { Write-Host ("  [被竄改] {0}  ETag {1}  {2} bytes" -f $f.Name, $etag, $len) -ForegroundColor Red; $bad++ }
    else                      { Write-Host ("  [未知]   {0}  ETag {1}  {2} bytes（與已知版本都不同）" -f $f.Name, $etag, $len) -ForegroundColor Yellow; $unknown++ }
  } catch {
    Write-Host ("  [連不上] {0}  {1}" -f $f.Name, $_.Exception.Message) -ForegroundColor Yellow; $unknown++
  }
}
Write-Host ''
if ($bad) { Write-Host '有檔案仍是被竄改版本：不要打開啟動器。' -ForegroundColor Red; exit 2 }
elseif ($unknown) { Write-Host '有檔案無法確認：先不要打開啟動器，過一段時間再查。' -ForegroundColor Yellow; exit 1 }
else { Write-Host '你這個 CDN 節點回傳的 4 個檔案都是已知乾淨版。CDN 有多個節點，建議隔幾小時再查幾次都乾淨再開。' -ForegroundColor Green; exit 0 }
