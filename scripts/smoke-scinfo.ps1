param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort,
    [switch]$SkipBuild,
    [switch]$SkipInstall,
    [switch]$SkipReset,
    [switch]$NoPin
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "minidriver-test-common.ps1")
$buildDir = Join-Path $repoRoot "out\build\$Arch-Clang-$Config"
$cmake = "cmake"
$vsCMake = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if (!(Get-Command $cmake -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $vsCMake)) {
    $cmake = $vsCMake
}

Push-Location $repoRoot
try {
    if (!$SkipBuild) {
        & (Join-Path $repoRoot "build.ps1") -Arch $Arch -Config $Config
    }

    if (!$SkipInstall) {
        & $cmake --build $buildDir --target canokey-minidriver-debug-install
        if ($LASTEXITCODE -ne 0) {
            throw "Debug install target failed with exit code $LASTEXITCODE."
        }
    }

    if (!$SkipReset) {
        Invoke-ComReset $ComPort
    }

    $certutilArgs = @("-silent")
    if (!$NoPin) {
        $certutilArgs += @("-pin", $Pin)
    }
    $certutilArgs += @("-scinfo", $ReaderName)

    Write-Host "Running certutil $($certutilArgs -join ' ')"
    & certutil @certutilArgs
    $exitCode = $LASTEXITCODE
    Write-Host "certutil exit code: $exitCode"

    exit $exitCode
} finally {
    Pop-Location
}
