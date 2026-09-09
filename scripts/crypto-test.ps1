param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort,
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
    if ($selection.DecryptKspContainers.Count -gt 0) {
        $results += Invoke-MinidriverDecryptTests `
            -Selection $selection `
            -PinArg $pinArg `
            -ContinueOnError:$ContinueOnError
    } else {
        Write-Host "Skipping optional RSA decrypt coverage because no RSA 9D key-exchange container was discovered."
    }
    if ($selection.EcdhKspContainers.Count -gt 0) {
        $results += Invoke-MinidriverDeriveTests `
            -Selection $selection `
            -PinArg $pinArg `
            -ContinueOnError:$ContinueOnError
    } else {
        Write-Host "Skipping optional ECDH coverage because no Windows-mapped ECDH container was discovered."
    }

    Complete-MinidriverTestRun -Results $results
} finally {
    Pop-Location
}
