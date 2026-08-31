param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$DllPath = (Join-Path $PSScriptRoot "..\out\build\x64-Clang-Debug\canokey-minidriver.dll"),
    [ValidateRange(0, 5)]
    [byte]$ContainerIndex = 4,
    [ValidateSet("ECDSA_P256", "ECDHE_P256", "RSA_SIGN_2048", "RSA_SIGN_3072", "RSA_SIGN_4096")]
    [string]$KeySpec = "ECDSA_P256",
    [string]$ManagementKey = "010203040506070801020304050607080102030405060708",
    [string]$Pin = "123456",
    [switch]$UsePinProtectedManagementKey
)

$ErrorActionPreference = "Stop"

if (-not ("CanokeyMinidriver.KeygenTestNative" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace CanokeyMinidriver {
    public static class KeygenTestNative {
        private const uint SCARD_SCOPE_SYSTEM = 2;
        private const uint SCARD_SHARE_SHARED = 2;
        private const uint SCARD_PROTOCOL_T0 = 1;
        private const uint SCARD_PROTOCOL_T1 = 2;
        private const uint SCARD_LEAVE_CARD = 0;
        private const uint CARD_DATA_CURRENT_VERSION = 7;
        private const uint ROLE_ADMIN = 2;
        private const uint ROLE_USER = 1;
        private const uint CARD_CREATE_CONTAINER_KEY_GEN = 1;
        private const uint CONTAINER_INFO_CURRENT_VERSION = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct CARD_DATA {
            public uint dwVersion;
            public IntPtr pbAtr;
            public uint cbAtr;
            public IntPtr pwszCardName;
            public IntPtr pfnCspAlloc;
            public IntPtr pfnCspReAlloc;
            public IntPtr pfnCspFree;
            public IntPtr pfnCspCacheAddFile;
            public IntPtr pfnCspCacheLookupFile;
            public IntPtr pfnCspCacheDeleteFile;
            public IntPtr pvCacheContext;
            public IntPtr pfnCspPadData;
            public IntPtr hSCardCtx;
            public IntPtr hScard;
            public IntPtr pvVendorSpecific;
            public IntPtr pfnCardDeleteContext;
            public IntPtr pfnCardQueryCapabilities;
            public IntPtr pfnCardDeleteContainer;
            public IntPtr pfnCardCreateContainer;
            public IntPtr pfnCardGetContainerInfo;
            public IntPtr pfnCardAuthenticatePin;
            public IntPtr pfnCardGetChallenge;
            public IntPtr pfnCardAuthenticateChallenge;
            public IntPtr pfnCardUnblockPin;
            public IntPtr pfnCardChangeAuthenticator;
            public IntPtr pfnCardDeauthenticate;
            public IntPtr pfnCardCreateDirectory;
            public IntPtr pfnCardDeleteDirectory;
            public IntPtr pvUnused3;
            public IntPtr pvUnused4;
            public IntPtr pfnCardCreateFile;
            public IntPtr pfnCardReadFile;
            public IntPtr pfnCardWriteFile;
            public IntPtr pfnCardDeleteFile;
            public IntPtr pfnCardEnumFiles;
            public IntPtr pfnCardGetFileInfo;
            public IntPtr pfnCardQueryFreeSpace;
            public IntPtr pfnCardQueryKeySizes;
            public IntPtr pfnCardSignData;
            public IntPtr pfnCardRSADecrypt;
            public IntPtr pfnCardConstructDHAgreement;
            public IntPtr pfnCardDeriveKey;
            public IntPtr pfnCardDestroyDHAgreement;
            public IntPtr pfnCspGetDHAgreement;
            public IntPtr pfnCardGetChallengeEx;
            public IntPtr pfnCardAuthenticateEx;
            public IntPtr pfnCardChangeAuthenticatorEx;
            public IntPtr pfnCardDeauthenticateEx;
            public IntPtr pfnCardGetContainerProperty;
            public IntPtr pfnCardSetContainerProperty;
            public IntPtr pfnCardGetProperty;
            public IntPtr pfnCardSetProperty;
            public IntPtr pfnCspUnpadData;
            public IntPtr pfnMDImportSessionKey;
            public IntPtr pfnMDEncryptData;
            public IntPtr pfnCardImportSessionKey;
            public IntPtr pfnCardGetSharedKeyHandle;
            public IntPtr pfnCardGetAlgorithmProperty;
            public IntPtr pfnCardGetKeyProperty;
            public IntPtr pfnCardSetKeyProperty;
            public IntPtr pfnCardDestroyKey;
            public IntPtr pfnCardProcessEncryptedData;
            public IntPtr pfnCardCreateContainerEx;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTAINER_INFO {
            public uint dwVersion;
            public uint dwReserved;
            public uint cbSigPublicKey;
            public IntPtr pbSigPublicKey;
            public uint cbKeyExPublicKey;
            public IntPtr pbKeyExPublicKey;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr CspAlloc(UIntPtr size);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr CspReAlloc(IntPtr address, UIntPtr size);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void CspFree(IntPtr address);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardAcquireContext(ref CARD_DATA cardData, uint flags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardDeleteContext(ref CARD_DATA cardData);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardAuthenticateEx(ref CARD_DATA cardData, uint pinId, uint flags, byte[] pinData,
            uint pinDataLen, IntPtr sessionPin, IntPtr sessionPinLen, IntPtr attemptsRemaining);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardCreateContainerEx(ref CARD_DATA cardData, byte containerIndex, uint flags,
            uint keySpec, uint keySize, IntPtr keyData, uint pinId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardGetContainerInfo(ref CARD_DATA cardData, byte containerIndex, uint flags,
            ref CONTAINER_INFO containerInfo);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        private delegate uint CardGetProperty(ref CARD_DATA cardData, string property, [Out] byte[] output,
            uint outputLen, out uint resultLen, uint flags);

        private static readonly CspAlloc AllocCallback = Alloc;
        private static readonly CspReAlloc ReAllocCallback = ReAlloc;
        private static readonly CspFree FreeCallback = Free;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr module);

        [DllImport("winscard.dll")]
        private static extern uint SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
        private static extern uint SCardListReaders(IntPtr context, string groups, IntPtr readers, ref uint readerCount);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
        private static extern uint SCardConnect(IntPtr context, string reader, uint shareMode, uint preferredProtocols,
            out IntPtr card, out uint activeProtocol);

        [DllImport("winscard.dll")]
        private static extern uint SCardDisconnect(IntPtr card, uint disposition);

        [DllImport("winscard.dll")]
        private static extern uint SCardReleaseContext(IntPtr context);

        public sealed class Result {
            public byte ContainerIndex { get; set; }
            public uint KeySpec { get; set; }
            public uint KeySize { get; set; }
            public uint SignaturePublicKeyBytes { get; set; }
            public uint KeyExchangePublicKeyBytes { get; set; }
            public uint AuthenticatedPins { get; set; }
        }

        public static Result Generate(string dllPath, string readerName, byte containerIndex, uint keySpec,
            uint keySize, byte[] managementKey, byte[] userPin, bool usePinProtectedManagementKey) {
            IntPtr module = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;
            IntPtr card = IntPtr.Zero;
            IntPtr atr = IntPtr.Zero;
            IntPtr cardName = IntPtr.Zero;
            CARD_DATA data = new CARD_DATA();

            try {
                CheckScard(SCardEstablishContext(SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out context),
                    "SCardEstablishContext");
                if (String.IsNullOrEmpty(readerName)) {
                    readerName = FirstReader(context);
                }
                uint activeProtocol;
                CheckScard(SCardConnect(context, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                    out card, out activeProtocol), "SCardConnect");

                module = LoadLibrary(dllPath);
                if (module == IntPtr.Zero) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadLibrary failed");
                }
                IntPtr acquirePtr = GetProcAddress(module, "CardAcquireContext");
                if (acquirePtr == IntPtr.Zero) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcAddress(CardAcquireContext) failed");
                }

                byte[] atrBytes = new byte[] {0x3b,0xf7,0x11,0x00,0x00,0x81,0x31,0xfe,0x65,0x43,0x61,0x6e,0x6f,0x6b,0x65,0x79,0x99};
                atr = Marshal.AllocHGlobal(atrBytes.Length);
                Marshal.Copy(atrBytes, 0, atr, atrBytes.Length);
                cardName = Marshal.StringToHGlobalUni("CanoKey");

                data.dwVersion = CARD_DATA_CURRENT_VERSION;
                data.pbAtr = atr;
                data.cbAtr = (uint)atrBytes.Length;
                data.pwszCardName = cardName;
                data.pfnCspAlloc = Marshal.GetFunctionPointerForDelegate(AllocCallback);
                data.pfnCspReAlloc = Marshal.GetFunctionPointerForDelegate(ReAllocCallback);
                data.pfnCspFree = Marshal.GetFunctionPointerForDelegate(FreeCallback);
                data.hSCardCtx = context;
                data.hScard = card;

                CardAcquireContext acquire = Marshal.GetDelegateForFunctionPointer<CardAcquireContext>(acquirePtr);
                CheckCard(acquire(ref data, 0), "CardAcquireContext");

                CardAuthenticateEx authenticate = Marshal.GetDelegateForFunctionPointer<CardAuthenticateEx>(data.pfnCardAuthenticateEx);
                byte[] authenticationData = usePinProtectedManagementKey ? userPin : managementKey;
                uint authenticationRole = usePinProtectedManagementKey ? ROLE_USER : ROLE_ADMIN;
                CheckCard(authenticate(ref data, authenticationRole, 0, authenticationData, (uint)authenticationData.Length,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero), usePinProtectedManagementKey
                        ? "CardAuthenticateEx(ROLE_USER)" : "CardAuthenticateEx(ROLE_ADMIN)");

                byte[] authenticatedState = new byte[4];
                uint authenticatedStateLen;
                CardGetProperty getProperty = Marshal.GetDelegateForFunctionPointer<CardGetProperty>(data.pfnCardGetProperty);
                CheckCard(getProperty(ref data, "Authenticated State", authenticatedState, (uint)authenticatedState.Length,
                    out authenticatedStateLen, 0), "CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
                if (authenticatedStateLen != authenticatedState.Length) {
                    throw new InvalidOperationException("Unexpected authenticated-state length.");
                }
                uint authenticatedPins = BitConverter.ToUInt32(authenticatedState, 0);
                if (usePinProtectedManagementKey && (authenticatedPins & ((1u << (int)ROLE_USER) | (1u << (int)ROLE_ADMIN))) !=
                    ((1u << (int)ROLE_USER) | (1u << (int)ROLE_ADMIN))) {
                    throw new InvalidOperationException("PIN-protected login did not authenticate USER and ADMIN roles.");
                }

                CardCreateContainerEx create = Marshal.GetDelegateForFunctionPointer<CardCreateContainerEx>(data.pfnCardCreateContainerEx);
                CheckCard(create(ref data, containerIndex, CARD_CREATE_CONTAINER_KEY_GEN, keySpec, keySize,
                    IntPtr.Zero, ROLE_USER), "CardCreateContainerEx");

                CONTAINER_INFO info = new CONTAINER_INFO { dwVersion = CONTAINER_INFO_CURRENT_VERSION };
                CardGetContainerInfo getInfo = Marshal.GetDelegateForFunctionPointer<CardGetContainerInfo>(data.pfnCardGetContainerInfo);
                CheckCard(getInfo(ref data, containerIndex, 0, ref info), "CardGetContainerInfo");

                return new Result {
                    ContainerIndex = containerIndex,
                    KeySpec = keySpec,
                    KeySize = keySize,
                    SignaturePublicKeyBytes = info.cbSigPublicKey,
                    KeyExchangePublicKeyBytes = info.cbKeyExPublicKey,
                    AuthenticatedPins = authenticatedPins
                };
            } finally {
                if (data.pfnCardDeleteContext != IntPtr.Zero) {
                    CardDeleteContext deleteContext = Marshal.GetDelegateForFunctionPointer<CardDeleteContext>(data.pfnCardDeleteContext);
                    deleteContext(ref data);
                }
                if (card != IntPtr.Zero) SCardDisconnect(card, SCARD_LEAVE_CARD);
                if (context != IntPtr.Zero) SCardReleaseContext(context);
                if (module != IntPtr.Zero) FreeLibrary(module);
                if (atr != IntPtr.Zero) Marshal.FreeHGlobal(atr);
                if (cardName != IntPtr.Zero) Marshal.FreeHGlobal(cardName);
            }
        }

        private static string FirstReader(IntPtr context) {
            uint count = 0;
            CheckScard(SCardListReaders(context, null, IntPtr.Zero, ref count), "SCardListReaders(size)");
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)count * 2));
            try {
                CheckScard(SCardListReaders(context, null, buffer, ref count), "SCardListReaders");
                string multi = Marshal.PtrToStringUni(buffer, checked((int)count));
                if (String.IsNullOrEmpty(multi)) throw new InvalidOperationException("No smart-card readers found.");
                foreach (string part in multi.Split('\0')) {
                    if (!String.IsNullOrEmpty(part)) return part;
                }
                throw new InvalidOperationException("No smart-card readers found.");
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static IntPtr Alloc(UIntPtr size) {
            ulong value = size.ToUInt64();
            if (value > Int32.MaxValue) return IntPtr.Zero;
            return Marshal.AllocHGlobal((int)value);
        }

        private static IntPtr ReAlloc(IntPtr address, UIntPtr size) {
            ulong value = size.ToUInt64();
            if (value > Int32.MaxValue) return IntPtr.Zero;
            return Marshal.ReAllocHGlobal(address, (IntPtr)(int)value);
        }

        private static void Free(IntPtr address) {
            if (address != IntPtr.Zero) Marshal.FreeHGlobal(address);
        }

        private static void CheckScard(uint status, string api) {
            if (status != 0) {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }

        private static void CheckCard(uint status, string api) {
            if (status != 0) {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }
    }
}
'@
}

function Convert-HexStringToBytes {
    param([string]$Hex)

    $compact = ($Hex -replace '[:\-\s]', '')
    if (($compact.Length % 2) -ne 0) {
        throw "Management key hex length must be even."
    }
    $bytes = New-Object byte[] ($compact.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($compact.Substring($i * 2, 2), 16)
    }
    $bytes
}

$specMap = @{
    ECDSA_P256    = @{ KeySpec = 3; KeySize = 256 }
    ECDHE_P256    = @{ KeySpec = 6; KeySize = 256 }
    RSA_SIGN_2048 = @{ KeySpec = 2; KeySize = 2048 }
    RSA_SIGN_3072 = @{ KeySpec = 2; KeySize = 3072 }
    RSA_SIGN_4096 = @{ KeySpec = 2; KeySize = 4096 }
}

$resolvedDll = (Resolve-Path -LiteralPath $DllPath).ProviderPath
$mgmtKey = if ($UsePinProtectedManagementKey) { [byte[]]::new(0) } else { Convert-HexStringToBytes $ManagementKey }
if (-not $UsePinProtectedManagementKey -and $mgmtKey.Length -ne 24) { throw "Management key must decode to 24 bytes." }
$userPin = [Text.Encoding]::UTF8.GetBytes($Pin)

$selected = $specMap[$KeySpec]
Write-Host "Generating $KeySpec in container index $ContainerIndex using $resolvedDll"
Write-Host $(if ($UsePinProtectedManagementKey) { "Authentication: USER PIN + protected management key" } else { "Authentication: explicit management key" })
$result = [CanokeyMinidriver.KeygenTestNative]::Generate(
    $resolvedDll,
    $ReaderName,
    $ContainerIndex,
    [uint32]$selected.KeySpec,
    [uint32]$selected.KeySize,
    $mgmtKey,
    $userPin,
    $UsePinProtectedManagementKey.IsPresent)

$result | Format-List
