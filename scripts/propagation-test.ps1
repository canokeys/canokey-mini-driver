param(
    [Parameter(Mandatory)][string[]]$Thumbprint,
    [Parameter(Mandatory)][string]$ExpectedDllSha256,
    [Parameter(Mandatory)][string]$ReportDirectory,
    [string]$Pin = $env:CNK_PIV_PIN,
    [string]$ComPort
)

# Explicitly selected development RSA/EC certificates only. This test removes their
# user-store copies, never their private keys or card objects. It does not deploy
# a DLL, change Calais, restart services, or repair certificate associations.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'minidriver-test-common.ps1')
if ([string]::IsNullOrEmpty($Pin)) { throw 'Set CNK_PIV_PIN or pass -Pin.' }
$mapping = Get-ItemProperty 'HKLM:/SOFTWARE/Microsoft/Cryptography/Calais/SmartCards/CanoKey'
$dll = $mapping.'80000001'
if ((Get-FileHash -LiteralPath $dll).Hash -ne $ExpectedDllSha256) { throw 'Mapped DLL hash differs from the expected build.' }
foreach ($name in @('SCardSvr', 'CertPropSvc')) {
    if ((Get-Service $name).Status -ne 'Running') { throw "$name must already be running." }
}

if (-not ('CanokeyMinidriver.PropagationSession' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace CanokeyMinidriver {
    public static class PropagationSession {
        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int kind, out IntPtr data, out uint size);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr data);
        public static void RequireUnlocked() {
            IntPtr data; uint size;
            if (!WTSQuerySessionInformationW(IntPtr.Zero, UInt32.MaxValue, 25, out data, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                // WTSINFOEXW's union is aligned to 8 bytes. Its level-1 prefix
                // contains session ID, connection state and lock flags.
                if (size < 20 || Marshal.ReadInt32(data) != 1)
                    throw new InvalidOperationException("Unknown WTS session information");
                if (Marshal.ReadInt32(data, 12) != 0 || Marshal.ReadInt32(data, 16) != 1)
                    throw new InvalidOperationException("Propagation acceptance requires an unlocked interactive Windows session");
            } finally { WTSFreeMemory(data); }
        }
    }
}
'@
}
[CanokeyMinidriver.PropagationSession]::RequireUnlocked()

if (-not ('CanokeyMinidriver.CertificateAssociation' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace CanokeyMinidriver {
    public sealed class CertificateAssociation {
        public string Container { get; private set; }
        public string Provider { get; private set; }
        public uint KeySpec { get; private set; }
        [StructLayout(LayoutKind.Sequential)]
        private struct KeyInfo {
            public IntPtr Container, Provider;
            public uint ProviderType, Flags, Count;
            public IntPtr Parameters;
            public uint KeySpec;
        }
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertGetCertificateContextProperty(IntPtr cert, uint property, IntPtr value, ref uint size);
        public static CertificateAssociation Read(X509Certificate2 cert) {
            uint size = 0;
            if (!CertGetCertificateContextProperty(cert.Handle, 2, IntPtr.Zero, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
            try {
                if (!CertGetCertificateContextProperty(cert.Handle, 2, buffer, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                KeyInfo info = (KeyInfo)Marshal.PtrToStructure(buffer, typeof(KeyInfo));
                return new CertificateAssociation {
                    Container = Marshal.PtrToStringUni(info.Container),
                    Provider = Marshal.PtrToStringUni(info.Provider), KeySpec = info.KeySpec
                };
            } finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
'@
}

$reportPath = [IO.Path]::GetFullPath($ReportDirectory)
New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
$originals = @()
$before = @{}
$mutated = $false
$passed = $false
$store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    foreach ($fingerprint in ($Thumbprint | Select-Object -Unique)) {
        $cert = Get-Item "Cert:/CurrentUser/My/$fingerprint"
        $publicKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
        if (!$publicKey) { $publicKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert) }
        if (!$publicKey) { throw 'This propagation test accepts RSA and EC certificates only.' }
        $publicKey.Dispose()
        $association = [CanokeyMinidriver.CertificateAssociation]::Read($cert)
        if ($association.Provider -notin @('Microsoft Smart Card Key Storage Provider', 'Microsoft Base Smart Card Crypto Provider')) { throw 'Expected a smart-card provider association.' }
        [IO.File]::WriteAllBytes((Join-Path $reportPath "$fingerprint.ser"),
            $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::SerializedCert))
        $originals += $cert
        $before[$cert.Thumbprint] = $association
    }
    if (!$originals.Count) { throw 'At least one explicit certificate is required.' }
    $before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $reportPath 'associations-before.json')
    $mutated = $true
    foreach ($cert in $originals) { $store.Remove($cert) }
    foreach ($cert in $originals) {
        if (Test-Path "Cert:/CurrentUser/My/$($cert.Thumbprint)") { throw 'Certificate removal was not observed.' }
    }
    Write-Host "Observed $($originals.Count) selected certificates absent from the user store."
    Invoke-ComReset $ComPort
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $returned = @(Get-ChildItem Cert:/CurrentUser/My | Where-Object { $before.ContainsKey($_.Thumbprint) })
        if ($returned.Count -eq $originals.Count) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($returned.Count -ne $originals.Count) { throw 'CertPropSvc did not restore every selected certificate.' }
    $results = foreach ($cert in $returned) {
        $association = [CanokeyMinidriver.CertificateAssociation]::Read($cert)
        $expected = $before[$cert.Thumbprint]
        if (!$cert.HasPrivateKey -or $association.Container -ne $expected.Container -or
            $association.Provider -ne $expected.Provider -or $association.KeySpec -ne $expected.KeySpec) {
            throw "Certificate association changed: $($cert.Thumbprint)"
        }
        $publicKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
        if ($publicKey) {
            try { $bits = $publicKey.KeySize } finally { $publicKey.Dispose() }
            $keySpec = [CanokeyMinidriver.SignTestNative]::SignatureKeySpecForGroup("ECDSA_P$bits")
            $mode = 'ECDSA_SHA256'
        } else {
            $entry = @([CanokeyMinidriver.SignTestNative]::EnumCngKeys() | Where-Object { $_.Name -eq $association.Container -and $_.AlgorithmGroup -match 'RSA' })
            if ($entry.Count -ne 1 -or $entry[0].LegacyKeySpec -notin @(1, 2)) { throw 'RSA container has no unambiguous Windows key spec.' }
            $keySpec = $entry[0].LegacyKeySpec
            $mode = 'RSA_PKCS1_SHA256'
        }
        $signature = [CanokeyMinidriver.SignTestNative]::CngSign($association.Container, $Pin, $mode, $keySpec, $cert)
        [pscustomobject]@{ Thumbprint = $cert.Thumbprint; Association = $association; Signature = $signature }
    }
    [pscustomobject]@{ Dll = $dll; Sha256 = $ExpectedDllSha256; TimeUtc = [DateTime]::UtcNow; Certificates = @($results) } |
        ConvertTo-Json -Depth 6 | Set-Content (Join-Path $reportPath 'propagation.json')
    $passed = $true
    Write-Host "PASS: $($results.Count) certificates propagated with stable associations and matching KSP signatures."
} finally {
    if ($mutated -and !$passed) {
        # Restore the original certificate contexts, including provider properties,
        # after any partial removal, reset, propagation or signing failure.
        foreach ($cert in $originals) {
            $existing = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $cert.Thumbprint, $false)
            foreach ($copy in $existing) { $store.Remove($copy) }
            $store.Add($cert)
        }
        Write-Warning 'Test failed; the selected user-store certificate contexts were restored.'
    }
    $store.Close()
}
