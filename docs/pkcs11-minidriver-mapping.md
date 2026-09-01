# PKCS#11 to Windows Smart Card Minidriver Mapping

This document describes the implemented boundary between CanoKey PKCS#11 and
the Windows Smart Card Minidriver. It is an implementation guide, not a
replacement for either specification.

Relevant contracts:

- OASIS PKCS#11 Cryptographic Token Interface
- Microsoft Smart Card Minidriver Specification (`cardmod.h`)
- NIST SP 800-73 PIV application and data model

For ownership and module boundaries, also read `docs/architecture.md`.

## 1. Architecture

The Windows request path is:

```text
Application
  -> Microsoft Base Smart Card CSP or Smart Card KSP
  -> canokey-minidriver.dll
  -> statically linked canokey-pkcs11 managed mode
  -> PIV APDUs over the Windows-owned card handle
```

The minidriver is responsible for:

- validating `cardmod.h` structures, versions, flags, and buffer sizes;
- exposing Windows card files, properties, containers, and role state;
- applying Windows-specific PIV slot and key-usage policy;
- converting Windows key blobs, padding descriptions, and byte order;
- translating PKCS#11 failures into the correct `SCARD_*` result for each API.

PKCS#11 is responsible for:

- PIV APDU construction and transport;
- token object discovery and cryptographic operation state;
- firmware feature and algorithm discovery;
- PIN-policy enforcement;
- management-key authentication;
- sensitive temporary-buffer lifetime and zeroization.

The minidriver must not issue a parallel raw PC/SC command path for operations
owned by PKCS#11.

## 2. Context and Session Lifetime

`CardAcquireContext` enables PKCS#11 managed mode before calling
`C_Initialize`. Managed mode receives the caller-owned `SCARDCONTEXT`,
`SCARDHANDLE`, and allocation callbacks, so PKCS#11 does not reconnect to the
same card independently.

Each `CMD_CONTEXT` owns one PKCS#11 session:

```text
CardAcquireContext
  -> C_CNK_InitializeManaged
  -> C_Initialize
  -> C_OpenSession

CardDeleteContext
  -> C_CloseSession
  -> C_Finalize
```

The close-before-finalize order is required. Reversing it can retain stale
session state and eventually exhaust the firmware session table during repeated
Windows probes.

Authentication and cryptographic operation state belong to that session. They
must not be kept in process-global minidriver state.

## 3. Implemented PKCS#11 Surface

### 3.1 Foundation

The bundled library implements the standard initialization, slot/token,
session, object-search, and attribute APIs used by the minidriver, including:

```text
C_Initialize / C_Finalize / C_GetInfo / C_GetFunctionList
C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo
C_GetMechanismList / C_GetMechanismInfo
C_OpenSession / C_CloseSession / C_CloseAllSessions / C_GetSessionInfo
C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
C_GetAttributeValue
```

`C_WaitForSlotEvent` uses PC/SC notification in standalone mode. Managed mode
does not own the Windows card lifecycle and returns
`CKR_FUNCTION_NOT_SUPPORTED` for slot waiting.

### 3.2 Authentication and Management

The minidriver uses:

```text
C_Login / C_Logout
C_SetPIN
C_CNK_Login
C_CNK_LoginPinManaged
```

`C_CNK_LoginPinManaged` is a narrow CanoKey extension. After successful user
PIN verification, it validates PIV ADMIN DATA, reads the PIN-protected PRINTED
object, parses the management-key payload, authenticates the management key,
checks that the PUK retry counter is zero, and clears all temporary key
material. The raw management key never crosses into the minidriver.

### 3.3 Cryptographic Operations

The bundled implementation includes:

```text
C_DigestInit / C_Digest / C_DigestUpdate / C_DigestKey / C_DigestFinal
C_SignInit / C_Sign / C_SignUpdate / C_SignFinal
C_VerifyInit / C_Verify / C_VerifyUpdate / C_VerifyFinal
C_EncryptInit / C_Encrypt
C_DecryptInit / C_Decrypt
C_DeriveKey
```

The Windows minidriver directly consumes signing, RSA decryption, and ECDH
derivation. Digest, verification, and encryption are host-side PKCS#11
features and are not separate `cardmod.h` callbacks.

### 3.4 Provisioning and Object Operations

The bundled implementation includes:

```text
C_GenerateKeyPair
C_GenerateKey
C_CreateObject
C_CopyObject
C_DestroyObject
C_GetObjectSize
C_SetAttributeValue
```

PIV key-pair generation and private-key import are persistent token mutations.
`C_DestroyObject` and `C_SetAttributeValue` intentionally have narrower
semantics for session secrets and do not provide generic PIV container deletion
or arbitrary persistent-object mutation.

### 3.5 Randomness

Firmware PIV version 6.0 and newer exposes token randomness through
`C_GenerateRandom`. Requests larger than one APDU are chunked by PKCS#11.
`C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED` because the firmware RNG
does not accept external seed material.

Windows cardmod has no generic random-generation DDI. `CardGetChallenge` and
`CardGetChallengeEx` are challenge/response PIN callbacks and must not be used
as an RNG transport.

### 3.6 Intentionally Unsupported Operations

Operations without a complete token contract return
`CKR_FUNCTION_NOT_SUPPORTED`, including:

```text
C_EncryptUpdate / C_EncryptFinal
C_DecryptUpdate / C_DecryptFinal
C_SignRecoverInit / C_SignRecover
C_VerifyRecoverInit / C_VerifyRecover
C_DigestEncryptUpdate / C_DecryptDigestUpdate
C_SignEncryptUpdate / C_DecryptVerifyUpdate
C_WrapKey / C_UnwrapKey
C_GetOperationState / C_SetOperationState
C_InitToken / C_InitPIN
```

## 4. Windows Minidriver Surface

### 4.1 Card and Property Plumbing

The minidriver implements the standard discovery path used by Base CSP and
Smart Card KSP:

```text
CardAcquireContext / CardDeleteContext
CardQueryCapabilities / CardQueryFreeSpace / CardQueryKeySizes
CardGetProperty / CardSetProperty
CardGetContainerProperty
CardCreateFile / CardReadFile / CardWriteFile
CardGetFileInfo / CardEnumFiles
CardGetContainerInfo
```

Directory and arbitrary file creation/deletion are not exposed as a generic PIV
filesystem. Writable card files are limited to the cache views accepted by
Windows and PIV certificate objects authorized by the management role.
`CardSetContainerProperty` is not exposed because there is no persistent
container-property contract behind it.

### 4.2 Authentication and PIN Management

The implemented role mapping is:

| Windows role | PIV meaning | PKCS#11 path |
| --- | --- | --- |
| `ROLE_USER` | PIV PIN | `C_Login(CKU_USER, ...)` |
| `ROLE_ADMIN` | PIV management key | `C_CNK_Login` or `C_CNK_LoginPinManaged` |
| `CMD_ROLE_PUK` | PIV PUK for PIN reset only | narrow unblock/reset extension |

The exposed Windows entry points include:

```text
CardAuthenticatePin / CardAuthenticateEx
CardDeauthenticateEx
CardChangeAuthenticator / CardChangeAuthenticatorEx
CardUnblockPin
```

Standalone PUK login, PUK changes, and challenge/response authentication are
intentionally unsupported. Session-PIN generation is also unsupported.

### 4.3 Cryptographic Operations

The minidriver implements:

```text
CardSignData
CardRSADecrypt
CardConstructDHAgreement
CardDeriveKey
CardDestroyDHAgreement
```

Supported Windows paths are:

- RSA PKCS#1 and PSS signing;
- ECDSA P-256 and P-384 signing;
- RSA PKCS#1 and OAEP decryption for a key-exchange container;
- P-256 and P-384 ECDH with `BCRYPT_KDF_RAW_SECRET`.

Higher-level CNG KDF parameter lists are not implemented. PKCS#11 receives
`CKD_NULL`, and the minidriver returns the raw agreement value.

### 4.4 Provisioning

`CardCreateContainer` and `CardCreateContainerEx` support:

- on-card RSA key-pair generation;
- on-card P-256 and P-384 key-pair generation;
- RSA import from a CAPI `PRIVATEKEYBLOB`;
- EC import from a CNG `BCRYPT_ECCPRIVATE_BLOB`.

Private-key blobs are parsed strictly and validated with the Windows software
crypto provider before the token is mutated. Generation and import require
management authentication, either explicit or recovered through the
PIN-protected management-key path.

Certificate writes are accepted through `CardWriteFile` for `kscN` and `kxcN`
after admin authentication. The live metadata inventory is refreshed after key
or certificate writes.

Generic `CardDeleteContainer` support is not exposed. Session-secret deletion
inside PKCS#11 is not equivalent to deleting a persistent PIV key slot.

## 5. Container and Slot Policy

Windows container indexes are stable policy assignments, not enumeration order:

| Container index | PIV object ID | PIV slot | Windows use |
| ---: | ---: | --- | --- |
| 0 | 1 | `9A` | signature; ECDH when EC |
| 1 | 2 | `9C` | signature; ECDH when EC |
| 2 | 3 | `9D` | signature; ECDH when EC; RSA key exchange when RSA |
| 3 | 4 | `9E` | signature; ECDH when EC |
| 4 | 5 | `82` | signature; ECDH when EC |
| 5 | 6 | `83` | signature; ECDH when EC |

Only an RSA key in `9D` is exposed as `AT_KEYEXCHANGE` and accepted by
`CardRSADecrypt`. Although PKCS#11 can perform an RSA private operation with a
key in another slot, the minidriver preserves the standard PIV key-management
role rather than treating algorithm capability as Windows policy.

PIV PIN policy is enforced by PKCS#11 and firmware:

- PIN-never keys may operate without a user login;
- PIN-once keys require authentication once for the session;
- PIN-always keys require the appropriate per-operation authentication path.

The minidriver must not add a blanket `ROLE_USER` check around every private-key
operation.

## 6. Request Mappings

### 6.1 Container Discovery

The minidriver reads the live PIV metadata directory through PKCS#11 and builds
its six stable `SLOT` records. Metadata determines key presence, algorithm,
public key, certificate presence, PIN policy, touch policy, and operation
capabilities.

Firmware 5.7 and newer may provide the fast metadata-directory extension.
Older supported firmware falls back to individual metadata reads. Version and
algorithm-extension checks remain inside PKCS#11.

### 6.2 Public-Key Export

`CardGetContainerInfo` converts the PKCS#11 public object into the Windows blob
required by the selected key type:

| PKCS#11 attributes | Windows output |
| --- | --- |
| `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT` | `BCRYPT_RSAKEY_BLOB` |
| `CKA_EC_PARAMS`, `CKA_EC_POINT` | `BCRYPT_ECCKEY_BLOB` |

`CKA_EC_POINT` is a DER OCTET STRING containing the uncompressed point
`04 || X || Y`. The DER wrapper is decoded before the coordinates are copied to
the CNG blob.

### 6.3 Signing

`CardSignData` maps Windows padding and key type to PKCS#11 mechanisms:

| Windows request | PKCS#11 mechanism |
| --- | --- |
| RSA PKCS#1 | `CKM_RSA_PKCS` |
| RSA PSS | `CKM_RSA_PKCS_PSS` |
| raw RSA | `CKM_RSA_X_509` |
| ECDSA | `CKM_ECDSA` |

For PSS, the Windows hash algorithm and salt length are converted into
`CK_RSA_PKCS_PSS_PARAMS`, including the matching MGF1 algorithm.

### 6.4 RSA Decryption

`CardRSADecrypt` accepts only an RSA key-exchange container in `9D` and maps:

| Windows request | PKCS#11 mechanism |
| --- | --- |
| PKCS#1 v1.5 | `CKM_RSA_PKCS` |
| OAEP | `CKM_RSA_PKCS_OAEP` |
| raw RSA | `CKM_RSA_X_509` |

Windows supplies and expects the RSA buffers in little-endian order. PKCS#11
uses big-endian values. The minidriver reverses the ciphertext before
`C_Decrypt` and reverses the returned plaintext before handing it to Windows,
including modes where PKCS#11 removes padding.

### 6.5 ECDH

`CardConstructDHAgreement` creates a PKCS#11 session secret with
`CKM_ECDH1_DERIVE` and `CKD_NULL`. The agreement index stored by the minidriver
refers to that session object.

`CardDeriveKey` reads the raw X coordinate and reverses its PKCS#11 big-endian
encoding to the little-endian form expected by CNG
`BCRYPT_KDF_RAW_SECRET`. `CardDestroyDHAgreement` clears the session object and
agreement slot.

## 7. Windows Virtual Files

### 7.1 `cardid`

`cardid` is a stable 16-byte digest of the PIV CHUID, with token serial as a
fallback when CHUID is absent. It does not depend on mutable key or certificate
inventory. Its contents must be byte-for-byte identical to `CP_CARD_GUID`;
Windows uses the pair for cache identity.

### 7.2 `cardcf`

The root `cardcf` file is a valid `CARD_CACHE_FILE_FORMAT`. The minidriver
reports `CP_CACHE_MODE_NO_CACHE`, accepts well-formed same-version compatibility
writes, and intentionally does not persist freshness fields.

### 7.3 `mscp/cmapfile`

`cmapfile` is serialized from the six stable slot records. Each
`CONTAINER_MAP_RECORD` reports the stable container name, valid/default flags,
signature key size, and key-exchange key size.

Windows may write the map during enrollment. The minidriver validates its
record-aligned length and discards the contents; submitted records are never
used to choose a PIV slot. Stable slot policy and live token metadata remain
authoritative.

### 7.4 Certificate Files

Certificate filenames follow the standard container convention:

```text
mscp/ksc0, mscp/ksc1, ...  signature certificates
mscp/kxc0, mscp/kxc1, ...  key-exchange certificates
```

Reads return the DER certificate bytes from the matching PIV object. File info
uses Windows-friendly read permissions so CSP/KSP enumeration succeeds. Writes
still require admin authentication because they mutate a PIV data object.

## 8. Properties

Important property mappings include:

| Property | Source or behavior |
| --- | --- |
| `CP_CARD_GUID` | same stable 16 bytes as `cardid` |
| `CP_CARD_CAPABILITIES` | implemented cardmod capabilities |
| `CP_CARD_KEYSIZES` | supported RSA/EC Windows key specifications |
| `CP_CARD_READ_ONLY` | `FALSE` for the implemented provisioning surface |
| `CP_CARD_CACHE_MODE` | Windows cache policy for this token |
| `CP_SUPPORTS_WIN_X509_ENROLLMENT` | enabled for supported classic keys |
| `CP_CARD_PIN_INFO` | role permissions and configured cache timeout |
| `CP_CARD_LIST_PINS` | USER, ADMIN, and the narrow PUK reset role |
| `CP_CARD_AUTHENTICATED_STATE` | minidriver role bits for this context |
| `CP_CARD_SERIAL_NO` | stable token serial data |

`CP_PARENT_WINDOW` and `CP_PIN_CONTEXT_STRING` are accepted as caller context.
They are not authentication credentials.

## 9. Buffer and Memory Rules

- Buffers returned to Windows must use `pfnCspAlloc`; Windows releases them
  with `pfnCspFree`.
- On `ERROR_INSUFFICIENT_BUFFER`, report the required length before returning
  the error so the caller can retry.
- PKCS#11 two-stage output queries must not consume an operation before the
  caller supplies a sufficiently large destination.
- RSA CAPI private-blob CRT fields are little-endian; PKCS#11 integer
  attributes are big-endian.
- EC private scalar and public coordinates in `BCRYPT_ECCPRIVATE_BLOB` are
  big-endian after the CNG header.
- Sensitive PIN, management-key, imported-key, and derived-secret buffers must
  be cleared before release.

## 10. Error Translation

PKCS#11 errors are translated at the cardmod API family that owns the Windows
semantics. Authentication, crypto, data-write, and provisioning paths retain
separate mappings because one `CK_RV` can require different `SCARD_*` results
depending on the operation.

Examples:

- a missing user login maps to the Windows security-violation path for a
  private operation;
- an absent optional object maps to a missing container or file during
  enumeration;
- a small output buffer maps to the Windows buffer error with the required
  size populated;
- unsupported algorithms map to `SCARD_E_UNSUPPORTED_FEATURE`.

Do not centralize these mappings solely because their switch statements share
some cases.

## 11. Post-Quantum and Windows Boundaries

The bundled PKCS#11 3.2 implementation supports ML-DSA-65 and ML-KEM-768
across all 24 PIV key slots. Current Windows CPDK headers do not define
minidriver key specifications, structures, or callbacks for those algorithms.

The minidriver therefore exposes only classic RSA and EC containers through
Microsoft Base Smart Card CSP and Smart Card KSP. It does not invent private
Windows identifiers or an incompatible ABI. Applications can use PQC directly
through PKCS#11 until Microsoft publishes a suitable provider contract.

## 12. Verification

The primary integration tests are:

```powershell
.\scripts\smoke-scinfo.ps1
.\scripts\sign-test.ps1
.\scripts\decrypt-test.ps1
.\scripts\derive-test.ps1
.\scripts\crypto-test.ps1
.\scripts\pin-test.ps1
.\scripts\keygen-test.ps1 -UsePinProtectedManagementKey
.\scripts\keygen-test.ps1 -Import
.\scripts\ksp-keygen-test.ps1
```

Tests that generate, import, or reset credentials mutate the attached token.
Discover the current inventory first, restore temporary credentials, and do not
overwrite `9D` merely to create an RSA decrypt test prerequisite.
