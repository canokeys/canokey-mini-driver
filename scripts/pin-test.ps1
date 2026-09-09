param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$DllPath = (Join-Path $PSScriptRoot "..\out\build\x64-Clang-Debug\canokey-minidriver.dll"),
    [string]$Pin = "123456",
    [string]$TemporaryPin = "123457",
    [string]$Puk = "12345678",
    [switch]$SkipPukReset
)

$ErrorActionPreference = "Stop"

if (-not ("CanokeyMinidriver.PinTestNative" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CanokeyMinidriver {
    public static class PinTestNative {
        private const uint SCARD_SCOPE_SYSTEM = 2;
        private const uint SCARD_SHARE_SHARED = 2;
        private const uint SCARD_PROTOCOL_T0 = 1;
        private const uint SCARD_PROTOCOL_T1 = 2;
        private const uint SCARD_LEAVE_CARD = 0;
        private const uint CARD_DATA_CURRENT_VERSION = 7;
        private const uint ROLE_USER = 1;
        private const uint ROLE_ADMIN = 2;
        private const uint CMD_ROLE_PUK = 3;
        private const uint CARD_AUTHENTICATE_PIN_PIN = 2;
        private const uint PIN_CHANGE_FLAG_UNBLOCK = 1;
        private const uint PIN_CHANGE_FLAG_CHANGEPIN = 2;
        private const uint PIN_INFO_CURRENT_VERSION = 6;
        private const uint PIN_CACHE_POLICY_CURRENT_VERSION = 6;
        private const uint SCARD_S_SUCCESS = 0;
        private const uint SCARD_W_SECURITY_VIOLATION = 0x8010006A;

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
        private struct PIN_CACHE_POLICY {
            public uint dwVersion;
            public uint PinCachePolicyType;
            public uint dwPinCachePolicyInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PIN_INFO {
            public uint dwVersion;
            public uint PinType;
            public uint PinPurpose;
            public uint dwChangePermission;
            public uint dwUnblockPermission;
            public PIN_CACHE_POLICY PinCachePolicy;
            public uint dwFlags;
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
        private delegate uint CardGetProperty(ref CARD_DATA cardData, [MarshalAs(UnmanagedType.LPWStr)] string property,
            IntPtr data, uint dataLen, out uint returnedLen, uint flags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardAuthenticateEx(ref CARD_DATA cardData, uint pinId, uint flags, byte[] pinData,
            uint pinDataLen, IntPtr sessionPin, IntPtr sessionPinLen, out uint attemptsRemaining);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardChangeAuthenticator(ref CARD_DATA cardData, [MarshalAs(UnmanagedType.LPWStr)] string userId,
            byte[] currentAuthenticator, uint currentAuthenticatorLen, byte[] newAuthenticator, uint newAuthenticatorLen,
            uint retryCount, uint flags, out uint attemptsRemaining);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardUnblockPin(ref CARD_DATA cardData, [MarshalAs(UnmanagedType.LPWStr)] string userId,
            byte[] authenticationData, uint authenticationDataLen, byte[] newPinData, uint newPinDataLen,
            uint retryCount, uint flags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardChangeAuthenticatorEx(ref CARD_DATA cardData, uint flags, uint authenticatingPinId,
            byte[] authenticatingPinData, uint authenticatingPinDataLen, uint targetPinId, byte[] targetData,
            uint targetDataLen, uint retryCount, out uint attemptsRemaining);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint CardDeauthenticateEx(ref CARD_DATA cardData, uint pinSet, uint flags);

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

        public sealed class PinInfoResult {
            public uint PinId { get; set; }
            public uint PinType { get; set; }
            public uint PinPurpose { get; set; }
            public uint ChangePermission { get; set; }
            public uint UnblockPermission { get; set; }
            public uint CachePolicyType { get; set; }
            public uint CachePolicyInfo { get; set; }
            public uint VerifyStrength { get; set; }
        }

        public sealed class Result {
            public uint PinSet { get; set; }
            public PinInfoResult[] PinInfos { get; set; }
            public uint AuthenticateAttempts { get; set; }
            public uint ChangeByOldPinAttempts { get; set; }
            public uint ChangeBackAttempts { get; set; }
            public uint PukResetAttempts { get; set; }
            public bool PukResetTested { get; set; }
            public bool PukResetBlockedByPolicy { get; set; }
        }

        public static Result Run(string dllPath, string readerName, byte[] pin, byte[] temporaryPin, byte[] puk, bool skipPukReset) {
            IntPtr module = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;
            IntPtr card = IntPtr.Zero;
            IntPtr atr = IntPtr.Zero;
            IntPtr cardName = IntPtr.Zero;
            CARD_DATA data = new CARD_DATA();
            bool acquired = false;
            bool pinMayBeTemporary = false;
            bool pinStateKnownTemporary = false;

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
                acquired = true;

                CardGetProperty getProperty = Marshal.GetDelegateForFunctionPointer<CardGetProperty>(data.pfnCardGetProperty);
                uint pinSet = ReadPinSet(ref data, getProperty);
                PinInfoResult[] pinInfos = new PinInfoResult[] {
                    ReadPinInfo(ref data, getProperty, ROLE_USER),
                    ReadPinInfo(ref data, getProperty, ROLE_ADMIN),
                    ReadPinInfo(ref data, getProperty, CMD_ROLE_PUK)
                };

                CardAuthenticateEx authenticate = Marshal.GetDelegateForFunctionPointer<CardAuthenticateEx>(data.pfnCardAuthenticateEx);
                uint authAttempts;
                CheckCard(authenticate(ref data, ROLE_USER, 0, pin, (uint)pin.Length, IntPtr.Zero, IntPtr.Zero,
                    out authAttempts), "CardAuthenticateEx(ROLE_USER)");

                CardChangeAuthenticator change = Marshal.GetDelegateForFunctionPointer<CardChangeAuthenticator>(data.pfnCardChangeAuthenticator);
                uint changeAttempts;
                // The card mutation can succeed even if the post-change login
                // fails, so cleanup must assume the temporary PIN in advance.
                pinMayBeTemporary = true;
                CheckCard(change(ref data, "user", pin, (uint)pin.Length, temporaryPin, (uint)temporaryPin.Length,
                    0, CARD_AUTHENTICATE_PIN_PIN, out changeAttempts), "CardChangeAuthenticator(user)");
                pinStateKnownTemporary = true;

                uint changeBackAttempts;
                pinStateKnownTemporary = false;
                CheckCard(change(ref data, "user", temporaryPin, (uint)temporaryPin.Length, pin, (uint)pin.Length,
                    0, CARD_AUTHENTICATE_PIN_PIN, out changeBackAttempts), "CardChangeAuthenticator(user restore)");
                pinMayBeTemporary = false;

                uint pukAttempts = 0;
                bool pukTested = false;
                bool pukResetBlockedByPolicy = false;
                if (!skipPukReset) {
                    CardChangeAuthenticatorEx changeEx =
                        Marshal.GetDelegateForFunctionPointer<CardChangeAuthenticatorEx>(data.pfnCardChangeAuthenticatorEx);
                    pinMayBeTemporary = true;
                    uint unblockStatus = changeEx(ref data, PIN_CHANGE_FLAG_UNBLOCK, CMD_ROLE_PUK, puk, (uint)puk.Length,
                        ROLE_USER, temporaryPin, (uint)temporaryPin.Length, 0, out pukAttempts);
                    if (unblockStatus == SCARD_W_SECURITY_VIOLATION) {
                        pinMayBeTemporary = false;
                        pukResetBlockedByPolicy = true;
                    } else {
                        CheckCard(unblockStatus, "CardChangeAuthenticatorEx(PUK reset to temporary PIN)");
                        pukTested = true;

                        pinStateKnownTemporary = false;
                        CheckCard(change(ref data, "user", temporaryPin, (uint)temporaryPin.Length, pin, (uint)pin.Length,
                            0, CARD_AUTHENTICATE_PIN_PIN, out changeBackAttempts),
                            "CardChangeAuthenticator(user restore after PUK reset)");
                        pinMayBeTemporary = false;
                    }
                }

                return new Result {
                    PinSet = pinSet,
                    PinInfos = pinInfos,
                    AuthenticateAttempts = authAttempts,
                    ChangeByOldPinAttempts = changeAttempts,
                    ChangeBackAttempts = changeBackAttempts,
                    PukResetAttempts = pukAttempts,
                    PukResetTested = pukTested,
                    PukResetBlockedByPolicy = pukResetBlockedByPolicy
                };
            } finally {
                if (pinMayBeTemporary && pinStateKnownTemporary && acquired) {
                    try {
                        CardChangeAuthenticator change =
                            Marshal.GetDelegateForFunctionPointer<CardChangeAuthenticator>(data.pfnCardChangeAuthenticator);
                        uint ignored;
                        change(ref data, "user", temporaryPin, (uint)temporaryPin.Length, pin, (uint)pin.Length,
                            0, CARD_AUTHENTICATE_PIN_PIN, out ignored);
                    } catch {
                        Console.Error.WriteLine("PIN restoration retry failed; card state may be temporary.");
                    }
                } else if (pinMayBeTemporary && acquired) {
                    Console.Error.WriteLine("PIN restoration skipped because the last PIN mutation outcome is ambiguous.");
                }
                bool contextDeleted = data.pvVendorSpecific == IntPtr.Zero;
                if (!contextDeleted && data.pfnCardDeleteContext != IntPtr.Zero) {
                    CardDeleteContext deleteContext = Marshal.GetDelegateForFunctionPointer<CardDeleteContext>(data.pfnCardDeleteContext);
                    contextDeleted = deleteContext(ref data) == 0 && data.pvVendorSpecific == IntPtr.Zero;
                }
                if (card != IntPtr.Zero) SCardDisconnect(card, SCARD_LEAVE_CARD);
                if (context != IntPtr.Zero) SCardReleaseContext(context);
                if (module != IntPtr.Zero && contextDeleted) FreeLibrary(module);
                if (atr != IntPtr.Zero) Marshal.FreeHGlobal(atr);
                if (cardName != IntPtr.Zero) Marshal.FreeHGlobal(cardName);
            }
        }

        private static uint ReadPinSet(ref CARD_DATA data, CardGetProperty getProperty) {
            uint returnedLen;
            IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
            try {
                CheckCard(getProperty(ref data, "PIN List", buffer, sizeof(uint), out returnedLen, 0),
                    "CardGetProperty(CP_CARD_LIST_PINS)");
                return (uint)Marshal.ReadInt32(buffer);
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static PinInfoResult ReadPinInfo(ref CARD_DATA data, CardGetProperty getProperty, uint pinId) {
            int size = Marshal.SizeOf(typeof(PIN_INFO));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                PIN_INFO request = new PIN_INFO {
                    dwVersion = PIN_INFO_CURRENT_VERSION,
                    PinCachePolicy = new PIN_CACHE_POLICY {
                        dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION
                    }
                };
                Marshal.StructureToPtr(request, buffer, false);
                uint returnedLen;
                CheckCard(getProperty(ref data, "PIN Information", buffer, (uint)size, out returnedLen, pinId),
                    "CardGetProperty(CP_CARD_PIN_INFO " + pinId + ")");
                PIN_INFO info = Marshal.PtrToStructure<PIN_INFO>(buffer);
                CheckCard(getProperty(ref data, "PIN Strength Verify", buffer, sizeof(uint), out returnedLen, pinId),
                    "CardGetProperty(CP_CARD_PIN_STRENGTH_VERIFY " + pinId + ")");
                uint verifyStrength = (uint)Marshal.ReadInt32(buffer);
                return new PinInfoResult {
                    PinId = pinId,
                    PinType = info.PinType,
                    PinPurpose = info.PinPurpose,
                    ChangePermission = info.dwChangePermission,
                    UnblockPermission = info.dwUnblockPermission,
                    CachePolicyType = info.PinCachePolicy.PinCachePolicyType,
                    CachePolicyInfo = info.PinCachePolicy.dwPinCachePolicyInfo,
                    VerifyStrength = verifyStrength
                };
            } finally {
                Marshal.FreeHGlobal(buffer);
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
            if (status != SCARD_S_SUCCESS) {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }

        private static void CheckCard(uint status, string api) {
            if (status != SCARD_S_SUCCESS) {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }
    }
}
'@
}

function Convert-ToAsciiBytes {
    param([string]$Value)
    [System.Text.Encoding]::ASCII.GetBytes($Value)
}

$resolvedDll = (Resolve-Path -LiteralPath $DllPath).ProviderPath
$pinBytes = Convert-ToAsciiBytes $Pin
$temporaryPinBytes = Convert-ToAsciiBytes $TemporaryPin
$pukBytes = Convert-ToAsciiBytes $Puk

if ($Pin -eq $TemporaryPin) {
    throw "TemporaryPin must be different from Pin."
}

Write-Host "Testing PIN management through $resolvedDll"
Write-Host "Reader: $ReaderName"
if ($SkipPukReset) {
    Write-Host "PUK reset test: skipped"
} else {
    Write-Host "PUK reset test: enabled (this uses PUK to set a temporary PIN, then restores the PIN)"
}

$result = [CanokeyMinidriver.PinTestNative]::Run(
    $resolvedDll,
    $ReaderName,
    $pinBytes,
    $temporaryPinBytes,
    $pukBytes,
    [bool]$SkipPukReset)

$result | Format-List PinSet, AuthenticateAttempts, ChangeByOldPinAttempts, ChangeBackAttempts, PukResetAttempts, PukResetTested, PukResetBlockedByPolicy
$result.PinInfos | Format-Table -AutoSize
