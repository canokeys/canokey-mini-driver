param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [ValidateSet("ECDSA_P256", "RSA")]
    [string]$Algorithm = "ECDSA_P256",
    [ValidateSet(256, 2048, 3072, 4096)]
    [int]$KeySize = 256,
    [string]$ContainerName = ([Guid]::NewGuid().ToString())
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "minidriver-test-common.ps1")

if ($Algorithm -eq "ECDSA_P256" -and $KeySize -ne 256) {
    throw "ECDSA_P256 requires KeySize 256."
}
if ($Algorithm -eq "RSA" -and $KeySize -lt 2048) {
    throw "RSA requires KeySize 2048, 3072, or 4096."
}

Write-Host "Creating $Algorithm key '$ContainerName' through Microsoft Smart Card KSP..."
$beforeContainers = @([CanokeyMinidriver.SignTestNative]::EnumCngKeys() |
    Select-Object -ExpandProperty Name -Unique)
$key = [CanokeyMinidriver.SignTestNative]::CreateCngKey(
    $ReaderName,
    $Pin,
    $Algorithm,
    $ContainerName,
    $KeySize)

$expectedGroup = if ($Algorithm -eq "RSA") { "RSA" } else { "ECDSA" }
$newKeys = @([CanokeyMinidriver.SignTestNative]::EnumCngKeys() |
    Where-Object { $beforeContainers -notcontains $_.Name -and $_.AlgorithmGroup -match $expectedGroup })
$actualContainer = if ($newKeys.Count -gt 0) { $newKeys[0].Name } else { $key.Name }
$actualGroup = if ($newKeys.Count -gt 0) { $newKeys[0].AlgorithmGroup } else { $key.AlgorithmGroup }

$openKeySpec = if ($Algorithm -eq "RSA") {
    2
} else {
    [CanokeyMinidriver.SignTestNative]::SignatureKeySpecForGroup($actualGroup)
}
$mode = if ($Algorithm -eq "RSA") { "RSA_PKCS1_SHA256" } else { "ECDSA_SHA256" }
$result = [CanokeyMinidriver.SignTestNative]::CngSign($actualContainer, $Pin, $mode, $openKeySpec)

[pscustomobject]@{
    RequestedContainer = $ContainerName
    Container = $actualContainer
    AlgorithmGroup = $actualGroup
    KeySize = $KeySize
    SignatureLength = $result.SignatureLength
    Verified = $result.Verified
} | Format-List
