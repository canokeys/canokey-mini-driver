param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [ValidateSet("ECDSA_P256", "RSA")]
    [string]$Algorithm = "ECDSA_P256",
    [ValidateSet(256, 2048, 3072, 4096)]
    [int]$KeySize = 256,
    [ValidateSet("Signature", "KeyExchange")]
    [string]$KeyRole = "Signature",
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
if ($Algorithm -ne "RSA" -and $KeyRole -ne "Signature") {
    throw "KeyExchange role is supported only for RSA."
}

Write-Host "Creating $Algorithm/$KeyRole key '$ContainerName' through Microsoft Smart Card KSP..."
$requestedLegacyKeySpec = if ($Algorithm -eq "RSA" -and $KeyRole -eq "KeyExchange") {
    1
} elseif ($Algorithm -eq "RSA") {
    2
} else {
    0
}
$key = [CanokeyMinidriver.SignTestNative]::CreateCngKey(
    $ReaderName,
    $Pin,
    $Algorithm,
    $ContainerName,
    $KeySize,
    $requestedLegacyKeySpec)

$actualContainer = $key.Name
$actualGroup = $key.AlgorithmGroup

$openKeySpec = if ($Algorithm -eq "RSA") {
    $key.LegacyKeySpec
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
