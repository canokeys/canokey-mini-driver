param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$Pin = "123456",
    [string]$Arch = "x64",
    [string]$Config = "Debug",
    [string]$ComPort = "COM3",
    [string[]]$BaseCspContainer,
    [string[]]$RsaKspContainer,
    [string[]]$EccKspContainer,
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
$buildDir = Join-Path $repoRoot "out\build\$Arch-Clang-$Config"

function Find-CMake {
    $cmake = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmake) {
        return $cmake.Source
    }

    $vsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vsWhere) {
        $found = & $vsWhere -latest -products * -find "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" |
            Select-Object -First 1
        if (![string]::IsNullOrWhiteSpace($found)) {
            return $found
        }
    }

    throw "cmake was not found in PATH or Visual Studio."
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

function Invoke-CertutilScinfo {
    $certutilArgs = @("-silent")
    if (!$NoPin) {
        $certutilArgs += @("-pin", $Pin)
    }
    $certutilArgs += @("-scinfo", $ReaderName)

    Write-Host "Running certutil $($certutilArgs -join ' ')"
    $output = & certutil @certutilArgs 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $output | ForEach-Object { Write-Host $_ }
        throw "certutil -scinfo failed with exit code $exitCode."
    }
    $output | ForEach-Object { Write-Host $_ }
}

if (-not ("CanokeyMinidriver.SignTestNative" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CanokeyMinidriver {
    public sealed class SignResult {
        public string Provider { get; set; }
        public string Container { get; set; }
        public string Algorithm { get; set; }
        public string Padding { get; set; }
        public int SignatureLength { get; set; }
        public bool Verified { get; set; }
    }

    public static class SignTestNative {
        private const string BaseSmartCardCsp = "Microsoft Base Smart Card Crypto Provider";
        private const string SmartCardKsp = "Microsoft Smart Card Key Storage Provider";
        private const uint PROV_RSA_FULL = 1;
        private const uint CRYPT_SILENT = 0x00000040;
        private const uint AT_SIGNATURE = 2;
        private const uint PP_ENUMCONTAINERS = 2;
        private const uint PP_SIGNATURE_PIN = 33;
        private const uint CALG_SHA1 = 0x00008004;
        private const uint CALG_SHA_256 = 0x0000800c;
        private const uint CRYPT_FIRST = 1;
        private const uint CRYPT_NEXT = 2;
        private const int NCRYPT_SILENT_FLAG = 0x00000040;
        private const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;
        private const int NCRYPT_PAD_PSS_FLAG = 0x00000008;
        private static readonly byte[] TestData = Encoding.ASCII.GetBytes("canokey minidriver signing test");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct KeyName {
            public string Name;
            public string AlgorithmGroup;
            public uint LegacyKeySpec;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NCryptKeyName {
            public string pszName;
            public string pszAlgid;
            public uint dwLegacyKeySpec;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BCRYPT_PKCS1_PADDING_INFO {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BCRYPT_PSS_PADDING_INFO {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public int cbSalt;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptAcquireContext(out IntPtr phProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptSetProvParam(IntPtr hProv, uint dwParam, byte[] pbData, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptCreateHash(IntPtr hProv, uint Algid, IntPtr hKey, uint dwFlags, out IntPtr phHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptHashData(IntPtr hHash, byte[] pbData, uint dwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptSignHash(IntPtr hHash, uint dwKeySpec, string sDescription, uint dwFlags, byte[] pbSignature, ref uint pdwSigLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptGetUserKey(IntPtr hProv, uint dwKeySpec, out IntPtr phUserKey);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptVerifySignature(IntPtr hHash, byte[] pbSignature, uint dwSigLen, IntPtr hPubKey, string sDescription, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDestroyHash(IntPtr hHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptEnumKeys(IntPtr hProvider, string pszScope, out IntPtr ppKeyName, ref IntPtr ppEnumState, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptVerifySignature(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFreeObject(IntPtr hObject);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFreeBuffer(IntPtr pvInput);

        public static SignResult CapiSign(string container, string readerName, string pin, string hashAlgorithm) {
            IntPtr hProv = IntPtr.Zero;
            IntPtr hHash = IntPtr.Zero;
            IntPtr hVerifyHash = IntPtr.Zero;
            IntPtr hPubKey = IntPtr.Zero;
            string openedContainer = null;
            try {
                hProv = AcquireCapiProvider(container, readerName, out openedContainer);
                if (!String.IsNullOrEmpty(pin)) {
                    byte[] pinBytes = Encoding.ASCII.GetBytes(pin + "\0");
                    CheckWin32(CryptSetProvParam(hProv, PP_SIGNATURE_PIN, pinBytes, 0), "CryptSetProvParam(PP_SIGNATURE_PIN)");
                }

                uint algId = CapiHashAlgorithm(hashAlgorithm);
                CheckWin32(CryptCreateHash(hProv, algId, IntPtr.Zero, 0, out hHash), "CryptCreateHash");
                CheckWin32(CryptHashData(hHash, TestData, (uint)TestData.Length, 0), "CryptHashData");

                uint cbSignature = 0;
                CheckWin32(CryptSignHash(hHash, AT_SIGNATURE, null, 0, null, ref cbSignature), "CryptSignHash(size)");
                byte[] signature = new byte[cbSignature];
                CheckWin32(CryptSignHash(hHash, AT_SIGNATURE, null, 0, signature, ref cbSignature), "CryptSignHash");

                CheckWin32(CryptCreateHash(hProv, algId, IntPtr.Zero, 0, out hVerifyHash), "CryptCreateHash(verify)");
                CheckWin32(CryptHashData(hVerifyHash, TestData, (uint)TestData.Length, 0), "CryptHashData(verify)");
                CheckWin32(CryptGetUserKey(hProv, AT_SIGNATURE, out hPubKey), "CryptGetUserKey(AT_SIGNATURE)");
                CheckWin32(CryptVerifySignature(hVerifyHash, signature, cbSignature, hPubKey, null, 0), "CryptVerifySignature");

                return new SignResult {
                    Provider = BaseSmartCardCsp,
                    Container = openedContainer,
                    Algorithm = hashAlgorithm,
                    Padding = "PKCS1",
                    SignatureLength = (int)cbSignature,
                    Verified = true
                };
            } finally {
                if (hPubKey != IntPtr.Zero) CryptDestroyKey(hPubKey);
                if (hVerifyHash != IntPtr.Zero) CryptDestroyHash(hVerifyHash);
                if (hHash != IntPtr.Zero) CryptDestroyHash(hHash);
                if (hProv != IntPtr.Zero) CryptReleaseContext(hProv, 0);
            }
        }

        public static string[] EnumCapiContainers() {
            IntPtr hProv = IntPtr.Zero;
            try {
                CheckWin32(CryptAcquireContext(out hProv, null, BaseSmartCardCsp, PROV_RSA_FULL, CRYPT_SILENT), "CryptAcquireContext(enum)");
                System.Collections.Generic.List<string> containers = new System.Collections.Generic.List<string>();
                uint flags = CRYPT_FIRST;
                while (true) {
                    byte[] buffer = new byte[1024];
                    uint cbData = (uint)buffer.Length;
                    bool ok = CryptGetProvParam(hProv, PP_ENUMCONTAINERS, buffer, ref cbData, flags);
                    if (!ok) {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 0x103) break; // ERROR_NO_MORE_ITEMS
                        throw new InvalidOperationException("CryptGetProvParam(PP_ENUMCONTAINERS) failed: " + FormatWin32(error));
                    }
                    string name = ReadAnsiNullTerminated(buffer, (int)cbData);
                    if (!String.IsNullOrEmpty(name)) {
                        containers.Add(name);
                    }
                    flags = CRYPT_NEXT;
                }
                return containers.ToArray();
            } finally {
                if (hProv != IntPtr.Zero) CryptReleaseContext(hProv, 0);
            }
        }

        public static KeyName[] EnumCngKeys() {
            IntPtr hProvider = IntPtr.Zero;
            IntPtr enumState = IntPtr.Zero;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider");
                System.Collections.Generic.List<KeyName> keys = new System.Collections.Generic.List<KeyName>();
                while (true) {
                    IntPtr keyNamePtr;
                    int status = NCryptEnumKeys(hProvider, null, out keyNamePtr, ref enumState, NCRYPT_SILENT_FLAG);
                    if (status == unchecked((int)0x8009002A)) break; // NTE_NO_MORE_ITEMS
                    CheckStatus(status, "NCryptEnumKeys");
                    try {
                        NCryptKeyName keyName = (NCryptKeyName)Marshal.PtrToStructure(keyNamePtr, typeof(NCryptKeyName));
                        keys.Add(new KeyName {
                            Name = keyName.pszName,
                            AlgorithmGroup = keyName.pszAlgid,
                            LegacyKeySpec = keyName.dwLegacyKeySpec,
                            Flags = keyName.dwFlags
                        });
                    } finally {
                        if (keyNamePtr != IntPtr.Zero) NCryptFreeBuffer(keyNamePtr);
                    }
                }
                return keys.ToArray();
            } finally {
                if (enumState != IntPtr.Zero) NCryptFreeObject(enumState);
                if (hProvider != IntPtr.Zero) NCryptFreeObject(hProvider);
            }
        }

        public static string GetCngAlgorithmGroup(string container) {
            IntPtr hProvider = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider");
                CheckStatus(NCryptOpenKey(hProvider, out hKey, container, 0, NCRYPT_SILENT_FLAG), "NCryptOpenKey");
                return GetCngStringProperty(hKey, "Algorithm Group");
            } finally {
                if (hKey != IntPtr.Zero) NCryptFreeObject(hKey);
                if (hProvider != IntPtr.Zero) NCryptFreeObject(hProvider);
            }
        }

        public static SignResult CngSign(string container, string pin, string mode) {
            IntPtr hProvider = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr pPaddingInfo = IntPtr.Zero;
            Type paddingType = null;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider");
                CheckStatus(NCryptOpenKey(hProvider, out hKey, container, 0, NCRYPT_SILENT_FLAG), "NCryptOpenKey");
                if (!String.IsNullOrEmpty(pin)) {
                    byte[] pinBytes = Encoding.Unicode.GetBytes(pin + "\0");
                    CheckStatus(NCryptSetProperty(hKey, "SmartCardPin", pinBytes, pinBytes.Length, NCRYPT_SILENT_FLAG), "NCryptSetProperty(SmartCardPin)");
                }

                string group = GetCngStringProperty(hKey, "Algorithm Group");
                string hashAlgorithm = "SHA256";
                byte[] hash = Hash(hashAlgorithm, TestData);
                int flags = 0;
                string padding = "none";

                if (String.Equals(mode, "RSA_PKCS1_SHA256", StringComparison.OrdinalIgnoreCase)) {
                    RequireGroup(group, "RSA", mode);
                    BCRYPT_PKCS1_PADDING_INFO info = new BCRYPT_PKCS1_PADDING_INFO { pszAlgId = hashAlgorithm };
                    paddingType = typeof(BCRYPT_PKCS1_PADDING_INFO);
                    pPaddingInfo = AllocStruct(info, paddingType);
                    flags = NCRYPT_PAD_PKCS1_FLAG;
                    padding = "PKCS1";
                } else if (String.Equals(mode, "RSA_PSS_SHA256", StringComparison.OrdinalIgnoreCase)) {
                    RequireGroup(group, "RSA", mode);
                    BCRYPT_PSS_PADDING_INFO info = new BCRYPT_PSS_PADDING_INFO { pszAlgId = hashAlgorithm, cbSalt = hash.Length };
                    paddingType = typeof(BCRYPT_PSS_PADDING_INFO);
                    pPaddingInfo = AllocStruct(info, paddingType);
                    flags = NCRYPT_PAD_PSS_FLAG;
                    padding = "PSS";
                } else if (String.Equals(mode, "ECDSA_SHA256", StringComparison.OrdinalIgnoreCase)) {
                    RequireGroup(group, "ECDSA", mode);
                    padding = "ECDSA";
                } else {
                    throw new ArgumentException("Unsupported CNG sign mode: " + mode);
                }

                int cbSignature;
                CheckStatus(NCryptSignHash(hKey, pPaddingInfo, hash, hash.Length, null, 0, out cbSignature, flags), "NCryptSignHash(size)");
                byte[] signature = new byte[cbSignature];
                CheckStatus(NCryptSignHash(hKey, pPaddingInfo, hash, hash.Length, signature, signature.Length, out cbSignature, flags), "NCryptSignHash");
                CheckStatus(NCryptVerifySignature(hKey, pPaddingInfo, hash, hash.Length, signature, cbSignature, flags), "NCryptVerifySignature");

                return new SignResult {
                    Provider = SmartCardKsp,
                    Container = container,
                    Algorithm = mode,
                    Padding = padding,
                    SignatureLength = cbSignature,
                    Verified = true
                };
            } finally {
                if (pPaddingInfo != IntPtr.Zero) {
                    if (paddingType != null) Marshal.DestroyStructure(pPaddingInfo, paddingType);
                    Marshal.FreeHGlobal(pPaddingInfo);
                }
                if (hKey != IntPtr.Zero) NCryptFreeObject(hKey);
                if (hProvider != IntPtr.Zero) NCryptFreeObject(hProvider);
            }
        }

        private static IntPtr AcquireCapiProvider(string container, string readerName, out string openedContainer) {
            string[] candidates;
            if (String.IsNullOrEmpty(readerName)) {
                candidates = new string[] { container };
            } else {
                candidates = new string[] { "\\\\.\\" + readerName + "\\" + container, container };
            }

            int lastError = 0;
            foreach (string candidate in candidates) {
                IntPtr hProv;
                if (CryptAcquireContext(out hProv, candidate, BaseSmartCardCsp, PROV_RSA_FULL, CRYPT_SILENT)) {
                    openedContainer = candidate;
                    return hProv;
                }
                lastError = Marshal.GetLastWin32Error();
            }

            throw new InvalidOperationException("CryptAcquireContext failed: " + FormatWin32(lastError));
        }

        private static uint CapiHashAlgorithm(string hashAlgorithm) {
            if (String.Equals(hashAlgorithm, "SHA1", StringComparison.OrdinalIgnoreCase)) return CALG_SHA1;
            if (String.Equals(hashAlgorithm, "SHA256", StringComparison.OrdinalIgnoreCase)) return CALG_SHA_256;
            throw new ArgumentException("Unsupported CAPI hash algorithm: " + hashAlgorithm);
        }

        private static string ReadAnsiNullTerminated(byte[] buffer, int length) {
            int end = 0;
            while (end < length && buffer[end] != 0) end++;
            return Encoding.Default.GetString(buffer, 0, end);
        }

        private static byte[] Hash(string hashAlgorithm, byte[] data) {
            using (HashAlgorithm h = HashAlgorithm.Create(hashAlgorithm)) {
                if (h == null) throw new ArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
                return h.ComputeHash(data);
            }
        }

        private static string GetCngStringProperty(IntPtr hObject, string property) {
            int cbResult;
            CheckStatus(NCryptGetProperty(hObject, property, null, 0, out cbResult, 0), "NCryptGetProperty(" + property + ", size)");
            byte[] buffer = new byte[cbResult];
            CheckStatus(NCryptGetProperty(hObject, property, buffer, buffer.Length, out cbResult, 0), "NCryptGetProperty(" + property + ")");
            return Encoding.Unicode.GetString(buffer, 0, cbResult).TrimEnd('\0');
        }

        private static void RequireGroup(string group, string expected, string mode) {
            if (group == null || group.IndexOf(expected, StringComparison.OrdinalIgnoreCase) < 0) {
                throw new InvalidOperationException(mode + " requires " + expected + " key, but container algorithm group is " + group);
            }
        }

        private static IntPtr AllocStruct(object value, Type type) {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(type));
            Marshal.StructureToPtr(value, ptr, false);
            return ptr;
        }

        private static void CheckWin32(bool ok, string api) {
            if (!ok) {
                throw new InvalidOperationException(api + " failed: " + FormatWin32(Marshal.GetLastWin32Error()));
            }
        }

        private static void CheckStatus(int status, string api) {
            if (status != 0) {
                uint code = unchecked((uint)status);
                throw new InvalidOperationException(api + " failed: 0x" + code.ToString("X8"));
            }
        }

        private static string FormatWin32(int error) {
            return "0x" + error.ToString("X8") + " (" + new Win32Exception(error).Message + ")";
        }
    }
}
'@
}

function Invoke-SignCase {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "Running $Name..."
    try {
        $result = & $Action
        [pscustomobject]@{
            Name = $Name
            Status = "PASS"
            Provider = $result.Provider
            Container = $result.Container
            Algorithm = $result.Algorithm
            Padding = $result.Padding
            SignatureBytes = $result.SignatureLength
            Verified = $result.Verified
            Error = $null
        }
    } catch {
        if (!$ContinueOnError) {
            throw
        }
        [pscustomobject]@{
            Name = $Name
            Status = "FAIL"
            Provider = $null
            Container = $null
            Algorithm = $null
            Padding = $null
            SignatureBytes = $null
            Verified = $false
            Error = $_.Exception.Message
        }
    }
}

Push-Location $repoRoot
try {
    if (!$SkipBuild) {
        & (Join-Path $repoRoot "build.ps1") -Arch $Arch -Config $Config
    }

    if (!$SkipInstall) {
        $cmake = Find-CMake
        & $cmake --build $buildDir --target canokey-minidriver-debug-install
        if ($LASTEXITCODE -ne 0) {
            throw "Debug install target failed with exit code $LASTEXITCODE."
        }
    }

    if (!$SkipReset) {
        Invoke-ComReset $ComPort
    }

    $pinArg = if ($NoPin) { $null } else { $Pin }
    if ($RunScinfo) {
        Invoke-CertutilScinfo
    }

    $capiContainers = @([CanokeyMinidriver.SignTestNative]::EnumCapiContainers())
    $kspInfo = @([CanokeyMinidriver.SignTestNative]::EnumCngKeys() | ForEach-Object {
            [pscustomobject]@{
                Container = $_.Name
                AlgorithmGroup = $_.AlgorithmGroup
                LegacyKeySpec = $_.LegacyKeySpec
                Flags = $_.Flags
            }
        })
    $rsaKspNames = @($kspInfo |
        Where-Object { $_.AlgorithmGroup -match "RSA" } |
        Select-Object -ExpandProperty Container -Unique)

    $selectedBaseCspContainers = @()
    if ($BaseCspContainer) {
        $selectedBaseCspContainers = @($BaseCspContainer)
    } elseif ($rsaKspNames.Count -gt 0) {
        $selectedBaseCspContainers = @($capiContainers |
            Where-Object { $rsaKspNames -contains $_ } |
            Select-Object -Unique)
        if ($selectedBaseCspContainers.Count -eq 0) {
            $selectedBaseCspContainers = @($capiContainers | Select-Object -Unique)
        }
    } else {
        $selectedBaseCspContainers = @($capiContainers | Select-Object -Unique)
    }

    $selectedRsaKspContainers = @()
    if ($RsaKspContainer) {
        $selectedRsaKspContainers = @($RsaKspContainer)
    } else {
        $selectedRsaKspContainers = @($rsaKspNames)
    }
    $selectedEccKspContainers = @()
    if ($EccKspContainer) {
        $selectedEccKspContainers = @($EccKspContainer)
    } else {
        $selectedEccKspContainers = @($kspInfo |
            Where-Object { $_.AlgorithmGroup -match "ECDSA" } |
            Select-Object -ExpandProperty Container -Unique)
    }

    Write-Host ""
    Write-Host "Discovered CAPI containers:"
    if ($capiContainers.Count -gt 0) {
        $capiContainers | ForEach-Object { "  $_" } | Write-Host
    } else {
        Write-Host "  <none>"
    }

    Write-Host ""
    Write-Host "Discovered CNG keys:"
    if ($kspInfo.Count -gt 0) {
        $kspInfo | Format-Table -AutoSize
    } else {
        Write-Host "  <none>"
    }

    Write-Host ""
    [pscustomobject]@{
        SelectedBaseCspContainers = ($selectedBaseCspContainers -join ", ")
        SelectedRsaKspContainers = ($selectedRsaKspContainers -join ", ")
        SelectedEccKspContainers = ($selectedEccKspContainers -join ", ")
    } | Format-List

    if ($DiscoverOnly) {
        return
    }

    if ($selectedBaseCspContainers.Count -eq 0) {
        throw "No Base Smart Card CSP RSA container was discovered."
    }
    if ($selectedRsaKspContainers.Count -eq 0) {
        throw "No Smart Card KSP RSA container was discovered."
    }
    if ($selectedEccKspContainers.Count -eq 0) {
        throw "No Smart Card KSP ECDSA container was discovered."
    }

    $results = @()
    foreach ($container in $selectedBaseCspContainers) {
        $results += Invoke-SignCase "CAPI RSA/SHA1 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CapiSign($container, $ReaderName, $pinArg, "SHA1")
        }
        $results += Invoke-SignCase "CAPI RSA/SHA256 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CapiSign($container, $ReaderName, $pinArg, "SHA256")
        }
    }
    foreach ($container in $selectedRsaKspContainers) {
        $results += Invoke-SignCase "CNG RSA/SHA256 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($container, $pinArg, "RSA_PKCS1_SHA256")
        }
        $results += Invoke-SignCase "CNG RSA/SHA256 PSS [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($container, $pinArg, "RSA_PSS_SHA256")
        }
    }
    foreach ($container in $selectedEccKspContainers) {
        $results += Invoke-SignCase "CNG ECDSA P-256/SHA256 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($container, $pinArg, "ECDSA_SHA256")
        }
    }

    Write-Host ""
    $results | Format-Table -AutoSize

    if (($results | Where-Object { $_.Status -ne "PASS" }).Count -gt 0) {
        exit 1
    }
} finally {
    Pop-Location
}
