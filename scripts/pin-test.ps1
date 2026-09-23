param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$DllPath = (Join-Path $PSScriptRoot "..\out\build\x64-Clang-Debug\canokey-minidriver.dll"),
    [string]$Pin = "123456",
    [string]$TemporaryPin = "123457",
    [string]$Puk = "12345678",
    [switch]$SkipPukReset
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "minidriver-test-common.ps1")
$mode = if ($SkipPukReset) { 'pin-only' } else { 'pin' }
Invoke-MinidriverDdiTest -DllPath $DllPath -ReaderName $ReaderName -Arguments @($mode) -Credentials @{
    CNK_PIV_PIN = $Pin; CNK_PIV_TEST_PIN = $TemporaryPin; CNK_PIV_PUK = $Puk
}
