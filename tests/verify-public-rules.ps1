$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$code = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\src\enhanced_rules.hpp'))
$rows = [regex]::Matches($code, '\{L"([0-9A-F]{64})", L"([^"]+)", (mandiant|plugx|robin),')
if ($rows.Count -ne 14) { throw 'Expected 14 additional vendor hashes' }
$urls = @{
    mandiant='https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets'
    plugx='https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/'
    robin='https://www.zscaler.com/blogs/security-research/tracking-updates-raspberry-robin'
}
$pages = @{}
foreach ($source in $urls.Keys) {
    $pages[$source] = (Invoke-WebRequest -UseBasicParsing -Uri $urls[$source] -TimeoutSec 45).Content.ToUpperInvariant()
}
foreach ($row in $rows) {
    $digest=$row.Groups[1].Value
    $source=$row.Groups[3].Value
    if (-not $pages[$source].Contains($digest)) { throw "Hash not found in declared primary source: $source $digest" }
    "PASS $source $digest"
}
'TOTAL PASS 14 vendor hashes verified against current primary-source HTML'
