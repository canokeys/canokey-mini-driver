# PKCS#11 and Windows minidriver boundary

The minidriver implements Windows cardmod policy and representations. PKCS#11
owns sessions, token authorization, reservations, host crypto and PC/SC leases.
Libcanokey owns PIV APDUs, firmware rules, bounded parsing and temporary protocol
secrets. No minidriver callback sends its own raw APDU.

See [architecture](architecture.md) for lifetime and enrollment invariants,
[PKCS#11 API contracts](../external/canokey-pkcs11/docs/api-contracts.md) for
per-entry failure/ownership rules, and [validation](validation.md) for acceptance.

## Entry points

| Windows operation | PKCS#11 boundary | Windows responsibility |
| --- | --- | --- |
| Acquire/delete context | Enable managed mode, initialize/open; close/finalize | Borrow Windows handles/allocators; close this context's session before finalizing the last context |
| USER authentication | `C_CNK_Login(CKU_USER)` | Report attempts; retain only the bounded context-specific PIN retry copy |
| ADMIN authentication | `C_CNK_Login(CKU_SO)` | Decode the supplied management-key representation |
| PIN-managed ADMIN | `C_CNK_LoginPinManaged` | Mark ADMIN only after the backend verifies protection and authenticates the key |
| Deauthentication | `C_Logout` | Respect token-wide logout; clear context PIN copies and role state |
| Change user PIN | `C_CNK_SetPIN(PIN)` | Accept current/new PIN, map retries, clear old context copies and authenticate the replacement |
| Unblock/reset PIN | `C_CNK_UnblockPIN` | PUK is reset-only; clear authentication after success |
| Discover containers/files | Find objects, attributes, metadata directory and F5 names | Publish one complete six-slot snapshot; never turn transient failures into empty slots |
| Generate/import container | `C_GenerateKeyPair` / private `C_CreateObject` | Require USER plus management authorization, reject occupied slots and validate Windows blobs before writing |
| Write certificate | certificate `C_CreateObject` | Require ADMIN and refresh the live snapshot |
| Sign | `C_SignInit` / `C_Sign` | RSA padding through the CSP callback plus `CKM_RSA_X_509`; ECDSA through `CKM_ECDSA` |
| RSA decrypt | `C_DecryptInit` / `C_Decrypt` | Map raw/PKCS#1/OAEP parameters and reverse Windows little-endian input/output |
| Construct/destroy DH agreement | `C_DeriveKey` / `C_DestroyObject` | Own a session-secret handle until explicit destruction or context teardown |
| Read DH secret | `C_GetAttributeValue` | Support raw-secret KDF only; reverse the big-endian X coordinate for Windows |

PIN changes may start from a PUBLIC PKCS#11 session: the supplied old PIN
authenticates the card command, and PUBLIC remains PUBLIC. PUK recovery reads
ADMIN DATA and resets PIN within one selected transaction. Malformed or
PIN-protected policy forbids recovery before a PUK mutation. See
[PIN-protected management](pin-only-management-key.md).

Token login is shared across PKCS#11 sessions. Operation contexts and secret
objects are session-owned. A Windows `CARD_DATA` owns one session and its own
bounded PIN-always retry copy. Managed mode supports one physical card per
process; same-card handle changes must reassert the current binding.

## Windows slot and file view

Indexes `0..5` map to PIV `9A`, `9C`, `9D`, `9E`, `82`, `83`.
RSA 9D exposes only `AT_KEYEXCHANGE`, including signing, and `mscp/kxc02`.
Other supported keys expose signature views and `mscp/kscNN`; EC 9D uses
`ksc02`. Do not publish a duplicate RSA 9D signature view or an EC key-exchange
view. Those representations break Windows key opening or certificate propagation.

RSA public output is a CAPI `PUBLICKEYBLOB` (`PUBLICKEYSTRUC`, `RSAPUBKEY`,
little-endian modulus). EC output is a `BCRYPT_ECCKEY_BLOB` with big-endian
coordinates. Match the complete `CKA_EC_PARAMS` OID; coordinate length does not
identify a curve. Only NIST P-256/P-384/P-521 and supported RSA sizes map to Windows.

`cardid` and `CP_CARD_GUID` contain the same stable 16 bytes. `cardcf` reports
zero PIN freshness and deterministic nonzero container/file freshness from the
complete live snapshot; cache mode is `CP_CACHE_MODE_NO_CACHE`. F5 names and
Windows enrollment overlays follow [container-names.md](container-names.md).

Both capability interfaces report `fCertificateCompression = TRUE`.
`CardReadFile` returns final DER after the backend unwraps/decompresses the PIV
representation. Certificate file info uses `EveryoneReadUserWriteAc`; actual
writes still require ADMIN. An unprovisioned `mscp/msroots` reads successfully
with zero length.

## Buffers, policy and errors

Returned Windows buffers use `pfnCspAlloc` and `pfnCspFree`. Short-buffer errors
must report the required size. PKCS#11 output preflight must not consume private
operations. RSA import reverses CAPI CRT components; EC import retains the
big-endian scalar. Clear temporary private material on every exit.

Stored PIV policy controls private operations: PIN-never works without USER;
PIN-once requires a cached PIN; PIN-always sign/decrypt allow one same-context
`CKU_CONTEXT_SPECIFIC` retry after Init. Clear that copy after the operation.
One-shot ECDH/ML-KEM have no such Init boundary and fail closed for PIN-always.
Windows session-PIN output remains unsupported.

Each callback family maps structured backend failures to its own `SCARD_*`
semantics. Rust error kind, phase, reference, SW and retry presence survive into
PKCS#11 diagnostics. Every PKCS#11/Rust/PCSC external call logs DEBUG completion,
including success in Release. Raw APDU logging remains separately controlled.

## Deliberately absent Windows surfaces

There is no generic cardmod RNG: `CardGetChallenge*` is challenge/response PIN
plumbing, not `C_GenerateRandom`. Generic container deletion, arbitrary filesystem
mutation, standalone PUK login/change and session-PIN generation are unsupported.

The direct ECDH DDI supports `BCRYPT_KDF_RAW_SECRET`, but CSP/KSP enumeration
publishes no EC DH containers. Ed25519, X25519, secp256k1, SM2 and PQC stay within
PKCS#11, subject to their firmware and mechanism contracts. Host Verify, Encrypt
and unrelated applet code need not remain reachable in the static minidriver link.
