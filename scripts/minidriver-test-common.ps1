# Common helpers for CanoKey minidriver API-level tests.
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
    param(
        [string]$ReaderName,
        [string]$Pin,
        [switch]$NoPin
    )

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
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CanokeyMinidriver {
    public sealed class SignResult {
        public string Provider { get; set; }
        public string Container { get; set; }
        public int LegacyKeySpec { get; set; }
        public string Algorithm { get; set; }
        public string Padding { get; set; }
        public int OutputLength { get; set; }
        public int SignatureLength {
            get { return OutputLength; }
            set { OutputLength = value; }
        }
        public bool Verified { get; set; }
    }

    public static class SignTestNative {
        private const string BaseSmartCardCsp = "Microsoft Base Smart Card Crypto Provider";
        private const string SmartCardKsp = "Microsoft Smart Card Key Storage Provider";
        private const string SoftwareKsp = "Microsoft Software Key Storage Provider";
        private const string BcryptKdfRawSecret = "TRUNCATE";
        private const string BcryptEccPublicBlob = "ECCPUBLICBLOB";
        private const uint PROV_RSA_FULL = 1;
        private const uint CRYPT_SILENT = 0x00000040;
        private const uint AT_KEYEXCHANGE = 1;
        private const uint AT_SIGNATURE = 2;
        private const int AT_ECDSA_P256 = 3;
        private const int AT_ECDSA_P384 = 4;
        private const int AT_ECDSA_P521 = 5;
        private const int AT_ECDHE_P256 = 6;
        private const int AT_ECDHE_P384 = 7;
        private const int AT_ECDHE_P521 = 8;
        private const uint PP_ENUMCONTAINERS = 2;
        private const uint PP_SIGNATURE_PIN = 33;
        private const uint CALG_SHA1 = 0x00008004;
        private const uint CALG_SHA_256 = 0x0000800c;
        private const uint CRYPT_FIRST = 1;
        private const uint CRYPT_NEXT = 2;
        private const int NCRYPT_SILENT_FLAG = 0x00000040;
        private const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;
        private const int NCRYPT_PAD_OAEP_FLAG = 0x00000004;
        private const int NCRYPT_PAD_PSS_FLAG = 0x00000008;
        private const uint NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001;
        private static readonly byte[] TestData = Encoding.ASCII.GetBytes("canokey minidriver signing test");
        private static readonly byte[] DecryptTestData = Encoding.ASCII.GetBytes("canokey minidriver decrypt test");

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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BCRYPT_OAEP_PADDING_INFO {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public IntPtr pbLabel;
            public int cbLabel;
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
        private static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);

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
        private static extern int NCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPubKey, out IntPtr phAgreedSecret, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptDeriveKey(IntPtr hSharedSecret, string pwszKDF, IntPtr pParameterList, byte[] pbDerivedKey, int cbDerivedKey, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, byte[] pbData, int cbData, int dwFlags);

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
                    LegacyKeySpec = (int)AT_SIGNATURE,
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

        public static SignResult CngSign(string container, string pin, string mode, int legacyKeySpec) {
            IntPtr hProvider = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr pPaddingInfo = IntPtr.Zero;
            Type paddingType = null;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider");
                CheckStatus(NCryptOpenKey(hProvider, out hKey, container, legacyKeySpec, NCRYPT_SILENT_FLAG), "NCryptOpenKey");
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
                    LegacyKeySpec = legacyKeySpec,
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

        public static SignResult CngDecrypt(string container, string pin, string mode, int legacyKeySpec) {
            IntPtr hProvider = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr pPaddingInfo = IntPtr.Zero;
            Type paddingType = null;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider");
                CheckStatus(NCryptOpenKey(hProvider, out hKey, container, legacyKeySpec, NCRYPT_SILENT_FLAG), "NCryptOpenKey");
                if (!String.IsNullOrEmpty(pin)) {
                    byte[] pinBytes = Encoding.Unicode.GetBytes(pin + "\0");
                    CheckStatus(NCryptSetProperty(hKey, "SmartCardPin", pinBytes, pinBytes.Length, NCRYPT_SILENT_FLAG), "NCryptSetProperty(SmartCardPin)");
                }

                string group = GetCngStringProperty(hKey, "Algorithm Group");
                RequireGroup(group, "RSA", mode);

                int flags;
                string padding;
                if (String.Equals(mode, "RSA_PKCS1", StringComparison.OrdinalIgnoreCase)) {
                    flags = NCRYPT_PAD_PKCS1_FLAG;
                    padding = "PKCS1";
                } else if (String.Equals(mode, "RSA_OAEP_SHA256", StringComparison.OrdinalIgnoreCase)) {
                    BCRYPT_OAEP_PADDING_INFO info = new BCRYPT_OAEP_PADDING_INFO {
                        pszAlgId = "SHA256",
                        pbLabel = IntPtr.Zero,
                        cbLabel = 0
                    };
                    paddingType = typeof(BCRYPT_OAEP_PADDING_INFO);
                    pPaddingInfo = AllocStruct(info, paddingType);
                    flags = NCRYPT_PAD_OAEP_FLAG;
                    padding = "OAEP-SHA256";
                } else {
                    throw new ArgumentException("Unsupported CNG decrypt mode: " + mode);
                }

                int cbCiphertext;
                CheckStatus(NCryptEncrypt(hKey, DecryptTestData, DecryptTestData.Length, pPaddingInfo, null, 0, out cbCiphertext, flags), "NCryptEncrypt(size)");
                byte[] ciphertext = new byte[cbCiphertext];
                CheckStatus(NCryptEncrypt(hKey, DecryptTestData, DecryptTestData.Length, pPaddingInfo, ciphertext, ciphertext.Length, out cbCiphertext, flags), "NCryptEncrypt");

                int cbPlaintext;
                CheckStatus(NCryptDecrypt(hKey, ciphertext, cbCiphertext, pPaddingInfo, null, 0, out cbPlaintext, flags), "NCryptDecrypt(size)");
                byte[] plaintext = new byte[cbPlaintext];
                CheckStatus(NCryptDecrypt(hKey, ciphertext, cbCiphertext, pPaddingInfo, plaintext, plaintext.Length, out cbPlaintext, flags), "NCryptDecrypt");

                if (cbPlaintext != DecryptTestData.Length) {
                    throw new InvalidOperationException("Decrypt returned " + cbPlaintext + " bytes; expected " + DecryptTestData.Length);
                }
                for (int i = 0; i < DecryptTestData.Length; i++) {
                    if (plaintext[i] != DecryptTestData[i]) {
                        throw new InvalidOperationException("Decrypt output mismatch at byte " + i +
                            "; expected " + Hex(DecryptTestData, DecryptTestData.Length) +
                            "; actual " + Hex(plaintext, cbPlaintext));
                    }
                }

                return new SignResult {
                    Provider = SmartCardKsp,
                    Container = container,
                    LegacyKeySpec = legacyKeySpec,
                    Algorithm = mode,
                    Padding = padding,
                    SignatureLength = cbPlaintext,
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

        public static SignResult CngEcdh(string container, string pin, int legacyKeySpec) {
            IntPtr hSmartProvider = IntPtr.Zero;
            IntPtr hCardKey = IntPtr.Zero;
            IntPtr hSoftwareProvider = IntPtr.Zero;
            IntPtr hPeerPrivateKey = IntPtr.Zero;
            IntPtr hPeerPublicForCard = IntPtr.Zero;
            IntPtr hCardPublicForPeer = IntPtr.Zero;
            IntPtr hCardSecret = IntPtr.Zero;
            IntPtr hSoftwareSecret = IntPtr.Zero;
            try {
                CheckStatus(NCryptOpenStorageProvider(out hSmartProvider, SmartCardKsp, 0), "NCryptOpenStorageProvider(smart)");
                CheckStatus(NCryptOpenKey(hSmartProvider, out hCardKey, container, legacyKeySpec, NCRYPT_SILENT_FLAG), "NCryptOpenKey(ECDH)");
                if (!String.IsNullOrEmpty(pin)) {
                    byte[] pinBytes = Encoding.Unicode.GetBytes(pin + "\0");
                    CheckStatus(NCryptSetProperty(hCardKey, "SmartCardPin", pinBytes, pinBytes.Length, NCRYPT_SILENT_FLAG), "NCryptSetProperty(SmartCardPin)");
                }

                string group = GetCngStringProperty(hCardKey, "Algorithm Group");
                RequireGroup(group, "ECDH", "ECDH_RAW_SECRET");
                string algorithm = EcdhAlgorithmForKeySpec(legacyKeySpec);

                CheckStatus(NCryptOpenStorageProvider(out hSoftwareProvider, SoftwareKsp, 0), "NCryptOpenStorageProvider(software)");
                CheckStatus(NCryptCreatePersistedKey(hSoftwareProvider, out hPeerPrivateKey, algorithm, null, 0, 0), "NCryptCreatePersistedKey(peer)");
                CheckStatus(NCryptFinalizeKey(hPeerPrivateKey, 0), "NCryptFinalizeKey(peer)");

                byte[] peerPublicBlob = ExportKeyBlob(hPeerPrivateKey, BcryptEccPublicBlob);
                CheckStatus(NCryptImportKey(hSmartProvider, IntPtr.Zero, BcryptEccPublicBlob, IntPtr.Zero, out hPeerPublicForCard,
                    peerPublicBlob, peerPublicBlob.Length, 0), "NCryptImportKey(peer public to smart provider)");

                byte[] cardPublicBlob = ExportKeyBlob(hCardKey, BcryptEccPublicBlob);
                CheckStatus(NCryptImportKey(hSoftwareProvider, IntPtr.Zero, BcryptEccPublicBlob, IntPtr.Zero, out hCardPublicForPeer,
                    cardPublicBlob, cardPublicBlob.Length, 0), "NCryptImportKey(card public to software provider)");

                CheckStatus(NCryptSecretAgreement(hCardKey, hPeerPublicForCard, out hCardSecret, NCRYPT_SILENT_FLAG), "NCryptSecretAgreement(card)");
                CheckStatus(NCryptSecretAgreement(hPeerPrivateKey, hCardPublicForPeer, out hSoftwareSecret, 0), "NCryptSecretAgreement(software)");

                byte[] cardSecret = DeriveRawSecret(hCardSecret);
                byte[] softwareSecret = DeriveRawSecret(hSoftwareSecret);
                if (!ByteArraysEqual(cardSecret, softwareSecret)) {
                    throw new InvalidOperationException("ECDH raw secret mismatch; card " + Hex(cardSecret, cardSecret.Length) +
                        "; software " + Hex(softwareSecret, softwareSecret.Length));
                }

                return new SignResult {
                    Provider = SmartCardKsp,
                    Container = container,
                    LegacyKeySpec = legacyKeySpec,
                    Algorithm = "ECDH_RAW_SECRET",
                    Padding = "RAW",
                    OutputLength = cardSecret.Length,
                    Verified = true
                };
            } finally {
                if (hSoftwareSecret != IntPtr.Zero) NCryptFreeObject(hSoftwareSecret);
                if (hCardSecret != IntPtr.Zero) NCryptFreeObject(hCardSecret);
                if (hCardPublicForPeer != IntPtr.Zero) NCryptFreeObject(hCardPublicForPeer);
                if (hPeerPublicForCard != IntPtr.Zero) NCryptFreeObject(hPeerPublicForCard);
                if (hPeerPrivateKey != IntPtr.Zero) NCryptFreeObject(hPeerPrivateKey);
                if (hSoftwareProvider != IntPtr.Zero) NCryptFreeObject(hSoftwareProvider);
                if (hCardKey != IntPtr.Zero) NCryptFreeObject(hCardKey);
                if (hSmartProvider != IntPtr.Zero) NCryptFreeObject(hSmartProvider);
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

        private static byte[] ExportKeyBlob(IntPtr hKey, string blobType) {
            int cbResult;
            CheckStatus(NCryptExportKey(hKey, IntPtr.Zero, blobType, IntPtr.Zero, null, 0, out cbResult, 0),
                "NCryptExportKey(" + blobType + ", size)");
            byte[] blob = new byte[cbResult];
            CheckStatus(NCryptExportKey(hKey, IntPtr.Zero, blobType, IntPtr.Zero, blob, blob.Length, out cbResult, 0),
                "NCryptExportKey(" + blobType + ")");
            if (cbResult != blob.Length) {
                Array.Resize(ref blob, cbResult);
            }
            return blob;
        }

        private static byte[] DeriveRawSecret(IntPtr hSecret) {
            int cbResult;
            CheckStatus(NCryptDeriveKey(hSecret, BcryptKdfRawSecret, IntPtr.Zero, null, 0, out cbResult, 0),
                "NCryptDeriveKey(raw secret, size)");
            byte[] secret = new byte[cbResult];
            CheckStatus(NCryptDeriveKey(hSecret, BcryptKdfRawSecret, IntPtr.Zero, secret, secret.Length, out cbResult, 0),
                "NCryptDeriveKey(raw secret)");
            if (cbResult != secret.Length) {
                Array.Resize(ref secret, cbResult);
            }
            return secret;
        }

        public static int SignatureKeySpecForGroup(string algorithmGroup) {
            if (String.Equals(algorithmGroup, "ECDSA_P256", StringComparison.OrdinalIgnoreCase)) return AT_ECDSA_P256;
            if (String.Equals(algorithmGroup, "ECDSA_P384", StringComparison.OrdinalIgnoreCase)) return AT_ECDSA_P384;
            if (String.Equals(algorithmGroup, "ECDSA_P521", StringComparison.OrdinalIgnoreCase)) return AT_ECDSA_P521;
            return 0;
        }

        public static int EcdhKeySpecForGroup(string algorithmGroup) {
            if (String.Equals(algorithmGroup, "ECDH_P256", StringComparison.OrdinalIgnoreCase)) return AT_ECDHE_P256;
            if (String.Equals(algorithmGroup, "ECDH_P384", StringComparison.OrdinalIgnoreCase)) return AT_ECDHE_P384;
            if (String.Equals(algorithmGroup, "ECDH_P521", StringComparison.OrdinalIgnoreCase)) return AT_ECDHE_P521;
            return 0;
        }

        private static string EcdhAlgorithmForKeySpec(int legacyKeySpec) {
            switch (legacyKeySpec) {
            case AT_ECDHE_P256:
                return "ECDH_P256";
            case AT_ECDHE_P384:
                return "ECDH_P384";
            case AT_ECDHE_P521:
                return "ECDH_P521";
            default:
                throw new ArgumentException("Unsupported ECDH key spec: " + legacyKeySpec);
            }
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

        private static string Hex(byte[] data, int length) {
            StringBuilder sb = new StringBuilder(length * 3);
            for (int i = 0; i < length; i++) {
                if (i != 0) sb.Append(' ');
                sb.Append(data[i].ToString("x2"));
            }
            return sb.ToString();
        }

        private static bool ByteArraysEqual(byte[] left, byte[] right) {
            if (left == null || right == null || left.Length != right.Length) return false;
            int diff = 0;
            for (int i = 0; i < left.Length; i++) diff |= left[i] ^ right[i];
            return diff == 0;
        }
    }
}
'@
}

function Invoke-MinidriverTestCase {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [switch]$ContinueOnError
    )

    Write-Host "Running $Name..."
    try {
        $result = & $Action
        [pscustomobject]@{
            Name = $Name
            Status = "PASS"
            Provider = $result.Provider
            Container = $result.Container
            LegacyKeySpec = $result.LegacyKeySpec
            Algorithm = $result.Algorithm
            Padding = $result.Padding
            OutputBytes = $result.OutputLength
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
            LegacyKeySpec = $null
            Algorithm = $null
            Padding = $null
            OutputBytes = $null
            Verified = $false
            Error = $_.Exception.Message
        }
    }
}

function Initialize-MinidriverTestEnvironment {
    param(
        [string]$RepoRoot,
        [string]$Arch,
        [string]$Config,
        [string]$ComPort,
        [switch]$SkipBuild,
        [switch]$SkipInstall,
        [switch]$SkipReset
    )

    if (!$SkipBuild) {
        & (Join-Path $RepoRoot "build.ps1") -Arch $Arch -Config $Config
    }

    if (!$SkipInstall) {
        $buildDir = Join-Path $RepoRoot "out\build\$Arch-Clang-$Config"
        $cmake = Find-CMake
        & $cmake --build $buildDir --target canokey-minidriver-debug-install
        if ($LASTEXITCODE -ne 0) {
            throw "Debug install target failed with exit code $LASTEXITCODE."
        }
    }

    if (!$SkipReset) {
        Invoke-ComReset $ComPort
    }
}

function Get-MinidriverTestDiscovery {
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
    $rsaKspSignKeys = @($kspInfo |
        Where-Object { $_.AlgorithmGroup -match "RSA" -and $_.LegacyKeySpec -eq 2 } |
        Sort-Object Container -Unique)
    $rsaKspDecryptKeys = @($kspInfo |
        Where-Object { $_.AlgorithmGroup -match "RSA" -and $_.LegacyKeySpec -eq 1 } |
        Sort-Object Container -Unique)
    $ecdsaKspKeys = @($kspInfo |
        Where-Object { $_.AlgorithmGroup -match "ECDSA" } |
        ForEach-Object {
            [pscustomobject]@{
                Container = $_.Container
                AlgorithmGroup = $_.AlgorithmGroup
                LegacyKeySpec = $_.LegacyKeySpec
                Flags = $_.Flags
                OpenKeySpec = [CanokeyMinidriver.SignTestNative]::SignatureKeySpecForGroup($_.AlgorithmGroup)
            }
        } |
        Where-Object { $_.OpenKeySpec -ne 0 } |
        Sort-Object Container, AlgorithmGroup -Unique)
    $ecdhKspKeys = @($kspInfo |
        Where-Object { $_.AlgorithmGroup -match "ECDH" } |
        ForEach-Object {
            [pscustomobject]@{
                Container = $_.Container
                AlgorithmGroup = $_.AlgorithmGroup
                LegacyKeySpec = $_.LegacyKeySpec
                Flags = $_.Flags
                OpenKeySpec = [CanokeyMinidriver.SignTestNative]::EcdhKeySpecForGroup($_.AlgorithmGroup)
            }
        } |
        Where-Object { $_.OpenKeySpec -ne 0 } |
        Sort-Object Container, AlgorithmGroup -Unique)

    [pscustomobject]@{
        CapiContainers = $capiContainers
        KspInfo = $kspInfo
        RsaKspNames = $rsaKspNames
        RsaKspSignKeys = $rsaKspSignKeys
        RsaKspDecryptKeys = $rsaKspDecryptKeys
        EcdsaKspKeys = $ecdsaKspKeys
        EcdhKspKeys = $ecdhKspKeys
    }
}

function Select-MinidriverTestKeys {
    param(
        [pscustomobject]$Discovery,
        [string[]]$BaseCspContainer,
        [string[]]$RsaKspContainer,
        [string[]]$EccKspContainer,
        [string[]]$EcdhKspContainer,
        [string[]]$DecryptKspContainer
    )

    $selectedBaseCspContainers = @()
    if ($BaseCspContainer) {
        $selectedBaseCspContainers = @($BaseCspContainer)
    } elseif ($Discovery.RsaKspNames.Count -gt 0) {
        $selectedBaseCspContainers = @($Discovery.CapiContainers |
            Where-Object { $Discovery.RsaKspNames -contains $_ } |
            Select-Object -Unique)
        if ($selectedBaseCspContainers.Count -eq 0) {
            $selectedBaseCspContainers = @($Discovery.CapiContainers | Select-Object -Unique)
        }
    } else {
        $selectedBaseCspContainers = @($Discovery.CapiContainers | Select-Object -Unique)
    }

    $selectedRsaKspContainers = @()
    if ($RsaKspContainer) {
        $selectedRsaKspContainers = @($RsaKspContainer)
    } else {
        $selectedRsaKspContainers = @($Discovery.RsaKspSignKeys | Select-Object -ExpandProperty Container -Unique)
    }

    $selectedEccKspContainers = @()
    if ($EccKspContainer) {
        $selectedEccKspContainers = @($EccKspContainer | ForEach-Object {
                [pscustomobject]@{
                    Container = $_
                    AlgorithmGroup = "ECDSA_P256"
                    OpenKeySpec = 3
                }
            })
    } else {
        $selectedEccKspContainers = @($Discovery.EcdsaKspKeys)
    }

    $selectedEcdhKspContainers = @()
    if ($EcdhKspContainer) {
        $selectedEcdhKspContainers = @($EcdhKspContainer | ForEach-Object {
                [pscustomobject]@{
                    Container = $_
                    AlgorithmGroup = "ECDH_P256"
                    OpenKeySpec = 6
                }
            })
    } else {
        $selectedEcdhKspContainers = @($Discovery.EcdhKspKeys)
    }

    $selectedDecryptKspContainers = @()
    if ($DecryptKspContainer) {
        $selectedDecryptKspContainers = @($DecryptKspContainer)
    } else {
        $selectedDecryptKspContainers = @($Discovery.RsaKspDecryptKeys | Select-Object -ExpandProperty Container -Unique)
    }

    [pscustomobject]@{
        BaseCspContainers = $selectedBaseCspContainers
        RsaKspContainers = $selectedRsaKspContainers
        EccKspContainers = $selectedEccKspContainers
        EcdhKspContainers = $selectedEcdhKspContainers
        DecryptKspContainers = $selectedDecryptKspContainers
    }
}

function Write-MinidriverTestDiscovery {
    param(
        [pscustomobject]$Discovery,
        [pscustomobject]$Selection
    )

    Write-Host ""
    Write-Host "Discovered CAPI containers:"
    if ($Discovery.CapiContainers.Count -gt 0) {
        $Discovery.CapiContainers | ForEach-Object { "  $_" } | Write-Host
    } else {
        Write-Host "  <none>"
    }

    Write-Host ""
    Write-Host "Discovered CNG keys:"
    if ($Discovery.KspInfo.Count -gt 0) {
        $Discovery.KspInfo | Format-Table -AutoSize
    } else {
        Write-Host "  <none>"
    }

    Write-Host ""
    [pscustomobject]@{
        SelectedBaseCspContainers = ($Selection.BaseCspContainers -join ", ")
        SelectedRsaKspContainers = ($Selection.RsaKspContainers -join ", ")
        SelectedEccKspContainers = (($Selection.EccKspContainers | ForEach-Object { "$($_.Container)/$($_.AlgorithmGroup)" }) -join ", ")
        SelectedEcdhKspContainers = (($Selection.EcdhKspContainers | ForEach-Object { "$($_.Container)/$($_.AlgorithmGroup)" }) -join ", ")
        SelectedDecryptKspContainers = ($Selection.DecryptKspContainers -join ", ")
    } | Format-List
}

function Invoke-MinidriverSignTests {
    param(
        [pscustomobject]$Selection,
        [string]$ReaderName,
        [string]$PinArg,
        [switch]$ContinueOnError
    )

    if ($Selection.BaseCspContainers.Count -eq 0) {
        throw "No Base Smart Card CSP RSA container was discovered."
    }
    if ($Selection.RsaKspContainers.Count -eq 0) {
        throw "No Smart Card KSP RSA container was discovered."
    }
    if ($Selection.EccKspContainers.Count -eq 0) {
        throw "No Smart Card KSP ECDSA container was discovered."
    }

    $results = @()
    foreach ($container in $Selection.BaseCspContainers) {
        $results += Invoke-MinidriverTestCase "CAPI RSA/SHA1 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CapiSign($container, $ReaderName, $PinArg, "SHA1")
        } -ContinueOnError:$ContinueOnError
        $results += Invoke-MinidriverTestCase "CAPI RSA/SHA256 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CapiSign($container, $ReaderName, $PinArg, "SHA256")
        } -ContinueOnError:$ContinueOnError
    }
    foreach ($container in $Selection.RsaKspContainers) {
        $results += Invoke-MinidriverTestCase "CNG RSA/SHA256 PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($container, $PinArg, "RSA_PKCS1_SHA256", 2)
        } -ContinueOnError:$ContinueOnError
        $results += Invoke-MinidriverTestCase "CNG RSA/SHA256 PSS [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($container, $PinArg, "RSA_PSS_SHA256", 2)
        } -ContinueOnError:$ContinueOnError
    }
    foreach ($key in $Selection.EccKspContainers) {
        $results += Invoke-MinidriverTestCase "CNG $($key.AlgorithmGroup)/SHA256 [$($key.Container)]" {
            [CanokeyMinidriver.SignTestNative]::CngSign($key.Container, $PinArg, "ECDSA_SHA256", $key.OpenKeySpec)
        } -ContinueOnError:$ContinueOnError
    }

    $results
}

function Invoke-MinidriverDecryptTests {
    param(
        [pscustomobject]$Selection,
        [string]$PinArg,
        [switch]$ContinueOnError
    )

    if ($Selection.DecryptKspContainers.Count -eq 0) {
        throw "No Smart Card KSP RSA decrypt container was discovered."
    }

    $results = @()
    foreach ($container in $Selection.DecryptKspContainers) {
        $results += Invoke-MinidriverTestCase "CNG RSA decrypt PKCS1 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngDecrypt($container, $PinArg, "RSA_PKCS1", 1)
        } -ContinueOnError:$ContinueOnError
        $results += Invoke-MinidriverTestCase "CNG RSA decrypt OAEP-SHA256 [$container]" {
            [CanokeyMinidriver.SignTestNative]::CngDecrypt($container, $PinArg, "RSA_OAEP_SHA256", 1)
        } -ContinueOnError:$ContinueOnError
    }

    $results
}

function Invoke-MinidriverDeriveTests {
    param(
        [pscustomobject]$Selection,
        [string]$PinArg,
        [switch]$ContinueOnError
    )

    if ($Selection.EcdhKspContainers.Count -eq 0) {
        throw "No Smart Card KSP ECDH container was discovered."
    }

    $results = @()
    foreach ($key in $Selection.EcdhKspContainers) {
        $results += Invoke-MinidriverTestCase "CNG $($key.AlgorithmGroup) raw secret [$($key.Container)]" {
            [CanokeyMinidriver.SignTestNative]::CngEcdh($key.Container, $PinArg, $key.OpenKeySpec)
        } -ContinueOnError:$ContinueOnError
    }

    $results
}

function Complete-MinidriverTestRun {
    param([object[]]$Results)

    Write-Host ""
    $Results | Format-Table -AutoSize

    if (($Results | Where-Object { $_.Status -ne "PASS" }).Count -gt 0) {
        exit 1
    }
}
