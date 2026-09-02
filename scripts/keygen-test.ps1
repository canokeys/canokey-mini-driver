param(
    [string]$ReaderName = "canokeys.org OpenPGP PIV OATH 0",
    [string]$DllPath = (Join-Path $PSScriptRoot "..\out\build\x64-Clang-Debug\canokey-minidriver.dll"),
    [ValidateRange(0, 23)]
    [byte]$ContainerIndex = 4,
    [ValidateSet("ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "ECDHE_P256", "ECDHE_P384", "ECDHE_P521", "RSA_SIGN_2048", "RSA_SIGN_3072", "RSA_SIGN_4096", "RSA_KEYX_2048", "RSA_KEYX_3072", "RSA_KEYX_4096")]
    [string]$KeySpec = "ECDSA_P256",
    [string]$ManagementKey = "010203040506070801020304050607080102030405060708",
    [string]$Pin = "123456",
    [switch]$UsePinProtectedManagementKey,
    [switch]$Import
)

$ErrorActionPreference = "Stop"

if (-not $UsePinProtectedManagementKey) {
    throw "Container creation requires the supported USER + PIN-protected management-key flow. Pass -UsePinProtectedManagementKey."
}

if (-not ("CanokeyMinidriver.KeygenTestNative" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Security.Cryptography;
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
        private const uint AT_KEYEXCHANGE = 1;
        private const uint AT_SIGNATURE = 2;
        private const uint AT_ECDSA_P256 = 3;
        private const uint AT_ECDSA_P384 = 4;
        private const uint AT_ECDSA_P521 = 5;
        private const uint AT_ECDHE_P256 = 6;
        private const uint AT_ECDHE_P384 = 7;
        private const uint AT_ECDHE_P521 = 8;
        private const uint CARD_CREATE_CONTAINER_KEY_GEN = 1;
        private const uint CARD_CREATE_CONTAINER_KEY_IMPORT = 2;
        private const uint CONTAINER_INFO_CURRENT_VERSION = 1;
        private const uint PRIVATEKEYBLOB = 0x07;
        private const uint PUBLICKEYBLOB = 0x06;
        private const uint CUR_BLOB_VERSION = 0x02;
        private const uint CALG_RSA_SIGN = 0x00002400;
        private const uint CALG_RSA_KEYX = 0x0000a400;
        private const uint RSA1 = 0x31415352;
        private const uint RSA2 = 0x32415352;
        private const uint BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314b4345;
        private const uint BCRYPT_ECDH_PRIVATE_P256_MAGIC = 0x324b4345;
        private const uint BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334b4345;
        private const uint BCRYPT_ECDH_PRIVATE_P384_MAGIC = 0x344b4345;
        private const uint BCRYPT_ECDH_PUBLIC_P521_MAGIC = 0x354b4345;
        private const uint BCRYPT_ECDH_PRIVATE_P521_MAGIC = 0x364b4345;
        private const uint BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345;
        private const uint BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345;
        private const uint BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345;
        private const uint BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345;
        private const uint BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345;
        private const uint BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345;

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
            public string Operation { get; set; }
            public byte ContainerIndex { get; set; }
            public uint KeySpec { get; set; }
            public uint KeySize { get; set; }
            public uint SignaturePublicKeyBytes { get; set; }
            public uint KeyExchangePublicKeyBytes { get; set; }
            public uint AuthenticatedPins { get; set; }
            public bool PublicKeyMatches { get; set; }
        }

        public static byte[] CreateImportBlob(uint keySpec, uint keySize, out byte[] expectedPublicBlob) {
            if (keySpec == AT_SIGNATURE || keySpec == AT_KEYEXCHANGE) {
                using (RSA rsa = RSA.Create(checked((int)keySize))) {
                    return CreateRsaImportBlob(rsa.ExportParameters(true), keySpec, keySize, out expectedPublicBlob);
                }
            }

            ECCurve curve = keySpec == AT_ECDSA_P521 || keySpec == AT_ECDHE_P521
                ? ECCurve.NamedCurves.nistP521
                : keySpec == AT_ECDSA_P384 || keySpec == AT_ECDHE_P384
                    ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256;
            ECParameters parameters;
            if (keySpec == AT_ECDHE_P256 || keySpec == AT_ECDHE_P384 || keySpec == AT_ECDHE_P521) {
                using (ECDiffieHellman key = ECDiffieHellman.Create(curve)) {
                    parameters = key.ExportParameters(true);
                }
            } else {
                using (ECDsa key = ECDsa.Create(curve)) {
                    parameters = key.ExportParameters(true);
                }
            }
            return CreateEcImportBlob(parameters, keySpec, out expectedPublicBlob);
        }

        private static byte[] CreateRsaImportBlob(RSAParameters parameters, uint keySpec, uint keySize,
            out byte[] expectedPublicBlob) {
            int modulusBytes = checked((int)keySize / 8);
            int componentBytes = modulusBytes / 2;
            uint algorithm = keySpec == AT_KEYEXCHANGE ? CALG_RSA_KEYX : CALG_RSA_SIGN;
            uint exponent = 0;
            foreach (byte value in parameters.Exponent) exponent = (exponent << 8) | value;

            expectedPublicBlob = new byte[20 + modulusBytes];
            expectedPublicBlob[0] = (byte)PUBLICKEYBLOB;
            expectedPublicBlob[1] = (byte)CUR_BLOB_VERSION;
            WriteUInt32(expectedPublicBlob, 4, algorithm);
            WriteUInt32(expectedPublicBlob, 8, RSA1);
            WriteUInt32(expectedPublicBlob, 12, keySize);
            WriteUInt32(expectedPublicBlob, 16, exponent);
            CopyBigEndianAsLittleEndian(parameters.Modulus, expectedPublicBlob, 20, modulusBytes);

            byte[] privateBlob = new byte[20 + modulusBytes * 2 + componentBytes * 5];
            privateBlob[0] = (byte)PRIVATEKEYBLOB;
            privateBlob[1] = (byte)CUR_BLOB_VERSION;
            WriteUInt32(privateBlob, 4, algorithm);
            WriteUInt32(privateBlob, 8, RSA2);
            WriteUInt32(privateBlob, 12, keySize);
            WriteUInt32(privateBlob, 16, exponent);
            int offset = 20;
            CopyBigEndianAsLittleEndian(parameters.Modulus, privateBlob, offset, modulusBytes);
            offset += modulusBytes;
            CopyBigEndianAsLittleEndian(parameters.P, privateBlob, offset, componentBytes);
            offset += componentBytes;
            CopyBigEndianAsLittleEndian(parameters.Q, privateBlob, offset, componentBytes);
            offset += componentBytes;
            CopyBigEndianAsLittleEndian(parameters.DP, privateBlob, offset, componentBytes);
            offset += componentBytes;
            CopyBigEndianAsLittleEndian(parameters.DQ, privateBlob, offset, componentBytes);
            offset += componentBytes;
            CopyBigEndianAsLittleEndian(parameters.InverseQ, privateBlob, offset, componentBytes);
            offset += componentBytes;
            CopyBigEndianAsLittleEndian(parameters.D, privateBlob, offset, modulusBytes);
            return privateBlob;
        }

        private static byte[] CreateEcImportBlob(ECParameters parameters, uint keySpec, out byte[] expectedPublicBlob) {
            int keyBytes = parameters.D.Length;
            uint publicMagic;
            uint privateMagic;
            switch (keySpec) {
            case AT_ECDSA_P256:
                publicMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
                privateMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                break;
            case AT_ECDHE_P256:
                publicMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
                privateMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
                break;
            case AT_ECDSA_P384:
                publicMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
                privateMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
                break;
            case AT_ECDHE_P384:
                publicMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
                privateMagic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
                break;
            case AT_ECDSA_P521:
                publicMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
                privateMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
                break;
            case AT_ECDHE_P521:
                publicMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
                privateMagic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
                break;
            default:
                throw new ArgumentOutOfRangeException("keySpec");
            }

            expectedPublicBlob = new byte[8 + keyBytes * 2];
            WriteUInt32(expectedPublicBlob, 0, publicMagic);
            WriteUInt32(expectedPublicBlob, 4, (uint)keyBytes);
            Buffer.BlockCopy(parameters.Q.X, 0, expectedPublicBlob, 8, keyBytes);
            Buffer.BlockCopy(parameters.Q.Y, 0, expectedPublicBlob, 8 + keyBytes, keyBytes);

            byte[] privateBlob = new byte[8 + keyBytes * 3];
            WriteUInt32(privateBlob, 0, privateMagic);
            WriteUInt32(privateBlob, 4, (uint)keyBytes);
            Buffer.BlockCopy(parameters.Q.X, 0, privateBlob, 8, keyBytes);
            Buffer.BlockCopy(parameters.Q.Y, 0, privateBlob, 8 + keyBytes, keyBytes);
            Buffer.BlockCopy(parameters.D, 0, privateBlob, 8 + keyBytes * 2, keyBytes);
            return privateBlob;
        }

        private static void CopyBigEndianAsLittleEndian(byte[] source, byte[] destination, int offset, int length) {
            for (int i = 0; i < length; i++) {
                destination[offset + i] = i < source.Length ? source[source.Length - 1 - i] : (byte)0;
            }
        }

        private static void WriteUInt32(byte[] output, int offset, uint value) {
            output[offset] = (byte)value;
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
        }

        private static bool ByteArraysEqual(byte[] left, byte[] right) {
            if (left == null || right == null || left.Length != right.Length) return false;
            for (int i = 0; i < left.Length; i++) if (left[i] != right[i]) return false;
            return true;
        }

        public static Result Generate(string dllPath, string readerName, byte containerIndex, uint keySpec,
            uint keySize, byte[] managementKey, byte[] userPin, bool usePinProtectedManagementKey,
            byte[] keyData, byte[] expectedPublicBlob) {
            IntPtr module = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;
            IntPtr card = IntPtr.Zero;
            IntPtr atr = IntPtr.Zero;
            IntPtr cardName = IntPtr.Zero;
            GCHandle keyDataHandle = default(GCHandle);
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

                CardGetProperty getProperty = Marshal.GetDelegateForFunctionPointer<CardGetProperty>(data.pfnCardGetProperty);
                byte[] cardIdBefore = new byte[16];
                uint cardIdLen;
                CheckCard(getProperty(ref data, "Card Identifier", cardIdBefore, (uint)cardIdBefore.Length,
                    out cardIdLen, 0), "CardGetProperty(CP_CARD_GUID before mutation)");
                if (cardIdLen != cardIdBefore.Length) {
                    throw new InvalidOperationException("Unexpected card identifier length.");
                }

                CardAuthenticateEx authenticate = Marshal.GetDelegateForFunctionPointer<CardAuthenticateEx>(data.pfnCardAuthenticateEx);
                // Container creation is a Windows USER operation. The default
                // path therefore authenticates USER first; PIN-managed mode
                // additionally recovers the management key inside PKCS#11.
                byte[] authenticationData = userPin;
                uint authenticationRole = ROLE_USER;
                CheckCard(authenticate(ref data, authenticationRole, 0, authenticationData, (uint)authenticationData.Length,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero), "CardAuthenticateEx(ROLE_USER)");

                byte[] authenticatedState = new byte[4];
                uint authenticatedStateLen;
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
                uint createFlags = keyData == null ? CARD_CREATE_CONTAINER_KEY_GEN : CARD_CREATE_CONTAINER_KEY_IMPORT;
                IntPtr keyDataPointer = IntPtr.Zero;
                if (keyData != null) {
                    keyDataHandle = GCHandle.Alloc(keyData, GCHandleType.Pinned);
                    keyDataPointer = keyDataHandle.AddrOfPinnedObject();
                }
                CheckCard(create(ref data, containerIndex, createFlags, keySpec, keySize,
                    keyDataPointer, ROLE_USER), "CardCreateContainerEx");

                byte[] cardIdAfter = new byte[16];
                CheckCard(getProperty(ref data, "Card Identifier", cardIdAfter, (uint)cardIdAfter.Length,
                    out cardIdLen, 0), "CardGetProperty(CP_CARD_GUID after mutation)");
                if (cardIdLen != cardIdAfter.Length || !ByteArraysEqual(cardIdBefore, cardIdAfter)) {
                    throw new InvalidOperationException("Card identifier changed after provisioning.");
                }

                CONTAINER_INFO info = new CONTAINER_INFO { dwVersion = CONTAINER_INFO_CURRENT_VERSION };
                CardGetContainerInfo getInfo = Marshal.GetDelegateForFunctionPointer<CardGetContainerInfo>(data.pfnCardGetContainerInfo);
                CheckCard(getInfo(ref data, containerIndex, 0, ref info), "CardGetContainerInfo");

                IntPtr publicKeyPointer = keySpec == AT_KEYEXCHANGE || keySpec == AT_ECDHE_P256 ||
                    keySpec == AT_ECDHE_P384 || keySpec == AT_ECDHE_P521
                    ? info.pbKeyExPublicKey : info.pbSigPublicKey;
                uint publicKeyLength = keySpec == AT_KEYEXCHANGE || keySpec == AT_ECDHE_P256 ||
                    keySpec == AT_ECDHE_P384 || keySpec == AT_ECDHE_P521
                    ? info.cbKeyExPublicKey : info.cbSigPublicKey;
                bool publicKeyMatches = expectedPublicBlob == null;
                if (expectedPublicBlob != null && publicKeyPointer != IntPtr.Zero) {
                    byte[] actualPublicBlob = new byte[checked((int)publicKeyLength)];
                    Marshal.Copy(publicKeyPointer, actualPublicBlob, 0, checked((int)publicKeyLength));
                    publicKeyMatches = ByteArraysEqual(actualPublicBlob, expectedPublicBlob);
                }
                if (info.pbSigPublicKey != IntPtr.Zero) Free(info.pbSigPublicKey);
                if (info.pbKeyExPublicKey != IntPtr.Zero) Free(info.pbKeyExPublicKey);
                if (!publicKeyMatches) throw new InvalidOperationException("Imported public key does not match card metadata.");

                CardDeleteContext deleteContext = Marshal.GetDelegateForFunctionPointer<CardDeleteContext>(data.pfnCardDeleteContext);
                CheckCard(deleteContext(ref data), "CardDeleteContext(before identity reacquire)");
                CheckCard(acquire(ref data, 0), "CardAcquireContext(identity reacquire)");
                getProperty = Marshal.GetDelegateForFunctionPointer<CardGetProperty>(data.pfnCardGetProperty);
                CheckCard(getProperty(ref data, "Card Identifier", cardIdAfter, (uint)cardIdAfter.Length,
                    out cardIdLen, 0), "CardGetProperty(CP_CARD_GUID after reacquire)");
                if (cardIdLen != cardIdAfter.Length || !ByteArraysEqual(cardIdBefore, cardIdAfter)) {
                    throw new InvalidOperationException("Card identifier changed after reacquiring the card context.");
                }

                return new Result {
                    Operation = keyData == null ? "Generate" : "Import",
                    ContainerIndex = containerIndex,
                    KeySpec = keySpec,
                    KeySize = keySize,
                    SignaturePublicKeyBytes = info.cbSigPublicKey,
                    KeyExchangePublicKeyBytes = info.cbKeyExPublicKey,
                    AuthenticatedPins = authenticatedPins,
                    PublicKeyMatches = publicKeyMatches
                };
            } finally {
                if (keyDataHandle.IsAllocated) keyDataHandle.Free();
                if (keyData != null) Array.Clear(keyData, 0, keyData.Length);
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
    ECDSA_P384    = @{ KeySpec = 4; KeySize = 384 }
    ECDSA_P521    = @{ KeySpec = 5; KeySize = 521 }
    ECDHE_P256    = @{ KeySpec = 6; KeySize = 256 }
    ECDHE_P384    = @{ KeySpec = 7; KeySize = 384 }
    ECDHE_P521    = @{ KeySpec = 8; KeySize = 521 }
    RSA_SIGN_2048 = @{ KeySpec = 2; KeySize = 2048 }
    RSA_SIGN_3072 = @{ KeySpec = 2; KeySize = 3072 }
    RSA_SIGN_4096 = @{ KeySpec = 2; KeySize = 4096 }
    RSA_KEYX_2048 = @{ KeySpec = 1; KeySize = 2048 }
    RSA_KEYX_3072 = @{ KeySpec = 1; KeySize = 3072 }
    RSA_KEYX_4096 = @{ KeySpec = 1; KeySize = 4096 }
}

$resolvedDll = (Resolve-Path -LiteralPath $DllPath).ProviderPath
$mgmtKey = [byte[]]::new(0)
$userPin = [Text.Encoding]::UTF8.GetBytes($Pin)

$selected = $specMap[$KeySpec]
$keyData = $null
$expectedPublicBlob = $null
if ($Import) {
    $keyData = [CanokeyMinidriver.KeygenTestNative]::CreateImportBlob(
        [uint32]$selected.KeySpec,
        [uint32]$selected.KeySize,
        [ref]$expectedPublicBlob)
}
$verb = if ($Import) { "Importing" } else { "Generating" }
$requestKeySize = if (-not $Import -and $KeySpec -match '^ECD') { 0 } else { [uint32]$selected.KeySize }
Write-Host "$verb $KeySpec in container index $ContainerIndex using $resolvedDll"
Write-Host "Authentication: USER PIN + protected management key"
$result = [CanokeyMinidriver.KeygenTestNative]::Generate(
    $resolvedDll,
    $ReaderName,
    $ContainerIndex,
    [uint32]$selected.KeySpec,
    [uint32]$requestKeySize,
    $mgmtKey,
    $userPin,
    $UsePinProtectedManagementKey.IsPresent,
    $keyData,
    $expectedPublicBlob)

$result | Format-List
