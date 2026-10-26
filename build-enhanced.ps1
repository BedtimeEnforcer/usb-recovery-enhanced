param(
    [switch]$Tests,
    [string]$ToolchainBin = $env:USB_TOOLCHAIN_BIN,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist')
)
$ErrorActionPreference = 'Stop'
if (-not $ToolchainBin) {
    $compiler = Get-Command g++.exe -ErrorAction SilentlyContinue
    if (-not $compiler) { throw 'Install a MinGW-w64 toolchain and pass -ToolchainBin <bin directory>.' }
    $ToolchainBin = Split-Path -Parent $compiler.Source
}
$bin = (Resolve-Path -LiteralPath $ToolchainBin).Path
foreach ($tool in @('g++.exe','windres.exe','objdump.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bin $tool))) { throw "Missing tool: $tool" }
}
$stage = Join-Path $env:TEMP ('usb-enhanced-build-' + [guid]::NewGuid().ToString('N'))
$out = $OutputDirectory
New-Item -ItemType Directory -Path $stage,$out -Force | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'src\*') -Destination $stage -Force
Push-Location $stage
try {
    $env:PATH = $bin + ';' + $env:PATH
    & "$bin\windres.exe" -i app.rc -o resources.o
    if ($LASTEXITCODE -ne 0) { throw 'Resource build failed' }
    & "$bin\g++.exe" -std=c++17 -O2 -Wall -Wextra -static -static-libgcc -static-libstdc++ -municode -mwindows -DUNICODE -D_UNICODE -DUSB_ENHANCED main.cpp resources.o -o UsbRecoveryEnhanced.exe '-Wl,--major-os-version,6,--minor-os-version,1,--major-subsystem-version,6,--minor-subsystem-version,1' -ladvapi32 -lcrypt32 -lshell32 -lcomctl32 -lcomdlg32 -luser32 -lgdi32 -lole32 -loleaut32 -luuid -ltaskschd
    if ($LASTEXITCODE -ne 0) { throw 'Enhanced build failed' }
    Copy-Item -LiteralPath 'UsbRecoveryEnhanced.exe' -Destination (Join-Path $out 'U盘修复助手-加强版.exe') -Force
    & "$bin\objdump.exe" -p UsbRecoveryEnhanced.exe | Out-File -LiteralPath (Join-Path $out 'pe-imports.txt') -Encoding utf8
    if ($Tests) {
        foreach ($test in @('tests','report-tests','enhanced-tests','remediation-tests','workflow-tests','ui-progress-tests')) {
            $entryFlags = @()
            if ($test -ne 'report-tests') { $entryFlags = @('-municode') }
            $uiFlags = @()
            if ($test -eq 'ui-progress-tests') { $uiFlags = @('-DUSB_ENHANCED','resources.o') }
            & "$bin\g++.exe" -std=c++17 -O2 -Wall -Wextra -static @entryFlags @uiFlags -DUNICODE -D_UNICODE (Join-Path $PSScriptRoot "tests\$test.cpp") -o "$test.exe" -I(Join-Path $PSScriptRoot 'src') -ladvapi32 -lcrypt32 -lshell32 -lcomctl32 -lcomdlg32 -luser32 -lgdi32 -lole32 -loleaut32 -luuid -ltaskschd
            if ($LASTEXITCODE -ne 0) { throw "Test compilation failed: $test" }
            Copy-Item -LiteralPath "$test.exe" -Destination $out -Force
            $fixture = Join-Path $stage ('fixture-' + $test + '-' + [guid]::NewGuid().ToString('N'))
            & ".\$test.exe" $fixture | Tee-Object -FilePath (Join-Path $out "$test-results.txt")
            if ($LASTEXITCODE -ne 0) { throw "Test failed: $test" }
        }
    }
    # --rules only creates a new file. Export to a unique path, then replace the generated report.
    $export = Join-Path $stage ('rules-' + [guid]::NewGuid().ToString('N') + '.txt')
    $process = Start-Process -FilePath (Join-Path $stage 'UsbRecoveryEnhanced.exe') -ArgumentList @('--rules',('"' + $export + '"')) -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $export)) { throw 'Rule export failed' }
    Copy-Item -LiteralPath $export -Destination (Join-Path $out '规则与处理方案.txt') -Force
} finally { Pop-Location }
$exe = Join-Path $out 'U盘修复助手-加强版.exe'
((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash + '  U盘修复助手-加强版.exe') | Set-Content -LiteralPath (Join-Path $out 'SHA256.txt') -Encoding utf8
Get-Item -LiteralPath $exe | Select-Object FullName,Length
