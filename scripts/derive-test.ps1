param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort,
    [string[]]$EcdhKspContainer,
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
        -EcdhKspContainer $EcdhKspContainer

    Write-MinidriverTestDiscovery -Discovery $discovery -Selection $selection

    if ($DiscoverOnly) {
        return
    }

    $results = @(Invoke-MinidriverDeriveTests `
            -Selection $selection `
            -PinArg $pinArg `
            -ContinueOnError:$ContinueOnError)
    Complete-MinidriverTestRun -Results $results
} finally {
    Pop-Location
}
