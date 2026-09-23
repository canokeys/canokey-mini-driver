param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$DllPath = (Join-Path $PSScriptRoot "..\out\build\x64-Clang-Debug\canokey-minidriver.dll"),
    [ValidateRange(0, 5)]
    [byte]$ContainerIndex = 4,
    [ValidateSet("ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "RSA_SIGN_2048", "RSA_SIGN_3072", "RSA_SIGN_4096", "RSA_KEYX_2048", "RSA_KEYX_3072", "RSA_KEYX_4096")]
    [string]$KeySpec = "ECDSA_P256",
    [string]$Pin = "123456",
    [switch]$UsePinProtectedManagementKey,
    [switch]$Import,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"
if (-not $UsePinProtectedManagementKey) {
    throw "Pass -UsePinProtectedManagementKey for the USER + protected management-key fixture."
}
. (Join-Path $PSScriptRoot "minidriver-test-common.ps1")
$specMap = @{
    ECDSA_P256    = @{ KeySpec = 3; KeySize = 256 }
    ECDSA_P384    = @{ KeySpec = 4; KeySize = 384 }
    ECDSA_P521    = @{ KeySpec = 5; KeySize = 521 }
    RSA_SIGN_2048 = @{ KeySpec = 2; KeySize = 2048 }
    RSA_SIGN_3072 = @{ KeySpec = 2; KeySize = 3072 }
    RSA_SIGN_4096 = @{ KeySpec = 2; KeySize = 4096 }
    RSA_KEYX_2048 = @{ KeySpec = 1; KeySize = 2048 }
    RSA_KEYX_3072 = @{ KeySpec = 1; KeySize = 3072 }
    RSA_KEYX_4096 = @{ KeySpec = 1; KeySize = 4096 }
}

$selected = $specMap[$KeySpec]
$mode = if ($Import) { 'import' } else { 'generate' }
$result = Invoke-MinidriverDdiTest -DllPath $DllPath -ReaderName $ReaderName -Credentials @{ CNK_PIV_PIN = $Pin } `
    -Arguments @($mode, "$ContainerIndex", "$($selected.KeySpec)", "$($selected.KeySize)")
if ($PassThru) { $result } else { $result | Format-List }
