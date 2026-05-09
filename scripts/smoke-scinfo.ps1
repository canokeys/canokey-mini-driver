param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort = "COM3",
    [switch]$SkipBuild,
    [switch]$SkipInstall,
    [switch]$SkipReset,
    [switch]$NoPin
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repoRoot "out\build\$Arch-Clang-$Config"
$cmake = "cmake"
$vsCMake = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if (!(Get-Command $cmake -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $vsCMake)) {
    $cmake = $vsCMake
}

function Invoke-ComReset {
    param([string]$PortName)

    Write-Host "Resetting CanoKey through $PortName..."
    $port = New-Object System.IO.Ports.SerialPort $PortName,38400,'None',8,'One'
    try {
        $port.NewLine = "`r`n"
        $port.Open()
        $port.WriteLine("reset ciu")
        Start-Sleep -Milliseconds 300
    } finally {
        if ($port.IsOpen) {
            $port.Close()
        }
    }
    Start-Sleep -Seconds 6
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
