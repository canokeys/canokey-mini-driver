param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort = "COM3",
    [string[]]$BaseCspContainer,
    [string[]]$RsaKspContainer,
    [string[]]$EccKspContainer,
    [string[]]$EcdhKspContainer,
    [string[]]$DecryptKspContainer,
    [switch]$RunScinfo,
    [switch]$SkipBuild,
    [switch]$SkipInstall,
    [switch]$SkipReset,
    [switch]$NoPin,
    [switch]$DiscoverOnly,
    [switch]$ContinueOnError
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "minidriver-test-common.ps1")

Push-Location $repoRoot
try {
    Initialize-MinidriverTestEnvironment `
        -RepoRoot $repoRoot `
        -Arch $Arch `
        -Config $Config `
        -ComPort $ComPort `
        -SkipBuild:$SkipBuild `
        -SkipInstall:$SkipInstall `
        -SkipReset:$SkipReset

    if ($RunScinfo) {
        Invoke-CertutilScinfo -ReaderName $ReaderName -Pin $Pin -NoPin:$NoPin
    }

    $pinArg = if ($NoPin) { $null } else { $Pin }
    $discovery = Get-MinidriverTestDiscovery
    $selection = Select-MinidriverTestKeys `
        -Discovery $discovery `
        -BaseCspContainer $BaseCspContainer `
        -RsaKspContainer $RsaKspContainer `
        -EccKspContainer $EccKspContainer `
        -EcdhKspContainer $EcdhKspContainer `
        -DecryptKspContainer $DecryptKspContainer

    Write-MinidriverTestDiscovery -Discovery $discovery -Selection $selection

    if ($DiscoverOnly) {
        return
    }

    $results = @()
    $results += Invoke-MinidriverSignTests `
        -Selection $selection `
        -ReaderName $ReaderName `
        -PinArg $pinArg `
        -ContinueOnError:$ContinueOnError
    $results += Invoke-MinidriverDecryptTests `
        -Selection $selection `
        -PinArg $pinArg `
        -ContinueOnError:$ContinueOnError
    $results += Invoke-MinidriverDeriveTests `
        -Selection $selection `
        -PinArg $pinArg `
        -ContinueOnError:$ContinueOnError

    Complete-MinidriverTestRun -Results $results
} finally {
    Pop-Location
}
