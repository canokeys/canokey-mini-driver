# CanoKey Windows Minidriver Architecture

## Request Flow

Windows loads `canokey-minidriver.dll` through the Calais smart-card mapping
and calls `CardAcquireContext`. The minidriver enables CanoKey PKCS#11 managed
mode with Windows-owned allocation functions, `SCARDCONTEXT`, and
`SCARDHANDLE`, then opens one PKCS#11 session for the `CMD_CONTEXT`.

```text
Base CSP / Smart Card KSP
  -> cardmod entry point
  -> CMD_CONTEXT and slot policy
  -> managed canokey-pkcs11
  -> PIV APDU on the Windows-owned card handle
```

The PC/SC transaction boundary is the lifetime of one actual card-backed
operation, not the lifetime of `CMD_CONTEXT` or a PKCS#11 session. The backend
begins a reader transaction, selects PIV, sends every dependent APDU (including
PIN verification and command chaining), then ends the transaction. Host-only
entry points such as context/session creation and operation initialization do
not keep a reader transaction open. A second context may request another PIV
operation concurrently; PC/SC serializes the physical transactions while
PKCS#11 still protects token-wide authorization and session operation state.

The PIV standard permits a same-AID reselect to preserve security status, but
the current CanoKey firmware resets PIN/PUK/management status in `piv_select()`.
The minidriver must therefore treat every PIV SELECT as an authorization reset:
SELECT, then VERIFY, then all dependent PIV APDUs without another SELECT or
applet switch.

`CardDeleteContext` closes the PKCS#11 session before finalization. Reversing
that order can leak card sessions or exhaust the firmware session table.

## Source Responsibilities

- `context.c`: cardmod function table, context acquisition, and lifetime.
- `canokey.c`: live PIV metadata decoding and per-slot capabilities.
- `container.c`: Windows container generation/import and public-key blobs.
- `crypto.c`: cardmod sign, RSA decrypt, and ECDH operations.
- `data.c`: card files, certificates, card identity, and cmap/cache views.
- `pin.c`: Windows roles, PIN/PUK operations, and PIN-managed admin login.
- `properties.c`: cardmod properties and PIN metadata.
- `config.c`: registry-derived runtime policy.
- `logging.c`: process-safe diagnostic logging.

PKCS#11 owns PIV APDUs, cryptographic operation state, PIN-policy enforcement,
and sensitive temporary buffers. The minidriver owns Windows structure
validation, buffer endianness, role bits, container selection, and translation
to `SCARD_*` errors.

## Slot And Container Policy

Container indexes `0..5` map to PIV object IDs `1..6`, hence slots
`9A`, `9C`, `9D`, `9E`, `82`, and `83`. These six stable Windows containers are
signature-capable; supported EC keys can derive. Only an RSA key in 9D is
exposed as Windows `AT_KEYEXCHANGE` and accepted by
`CardRSADecrypt`; this preserves the standard PIV key-management role.

The mapping is policy, not merely algorithm capability. PKCS#11 can perform an
RSA private operation in another slot, but the minidriver must not expose that
slot as a Windows key-exchange container.

The current managed-mode bridge intentionally supports one physical CanoKey per
process. Windows may nevertheless create several `CARD_DATA`/PKCS#11 contexts
for that same card. Their PC/SC handles may rotate, so each entry point
reasserts the current context's handle before card I/O. A different allocator
or a different physical card must be rejected; multi-card in-process support is
outside this design and requires a per-token backend boundary.

The process-wide allocator and crypto runtime are shared. Token authentication
and metadata are shared only for the one bound card, while each context owns
its PKCS#11 session and minidriver state. The planned lifecycle change is for
`CardDeleteContext` to release one context reference and for the final context
to perform PKCS#11 finalization and reset the managed binding; the current
implementation still needs this explicit context registry.

The static PKCS#11 dependency is compiled with function/data sections and the
minidriver DLL is linked with reference elimination and identical-code folding.
This removes PKCS#11 entry points that the Windows surface does not call,
including host Verify, host Encrypt, and PQC implementations, while retaining
the complete library build for standalone consumers. Debug builds use the same
options, so stepping into discarded or folded functions may be less precise.

Container creation and import require `ROLE_USER`; administrator-only
container creation is rejected even when a management key is cached. The
minidriver accepts only NIST P-256, P-384, and P-521 EC parameters. It
matches the complete DER `CKA_EC_PARAMS` value before constructing a CNG blob;
coordinate length is not a curve identifier. This keeps secp256k1 and SM2
PKCS#11 objects out of Windows instead of incorrectly labeling them P-256.

## Authentication

`ROLE_USER` maps to the PIV PIN and `ROLE_ADMIN` maps to management-key
authentication. After USER login, `C_CNK_LoginPinManaged` may validate ADMIN
DATA and recover the PIN-protected management key entirely inside PKCS#11. The
minidriver sets the ADMIN role bit only after that succeeds; it never parses
PRINTED or receives raw management-key bytes.

PIN-never, PIN-once, and PIN-always enforcement remains in PKCS#11/firmware.
The minidriver must not add a blanket USER-login check around private-key
operations.

## Data And Cache Files

`cardid` and `CP_CARD_GUID` are the same stable token identifier. `cardcf` and
`mscp/cmapfile` are Windows cache-coherency views; live CanoKey metadata remains
authoritative. Certificate files are readable for enumeration but writes still
require ADMIN authentication.

Container generation/import and certificate writes call
`RefreshCardMetadata` after card mutation so subsequent Windows queries see the
new inventory and card identifier.

## Buffer Conventions

- PKCS#11 RSA values are big-endian; CAPI private-blob CRT fields and
  `CardRSADecrypt` buffers are little-endian.
- PKCS#11 ECDH raw secrets are big-endian; CNG `BCRYPT_KDF_RAW_SECRET` expects
  little-endian output from the minidriver.
- On insufficient output space, cardmod entry points set the required length
  before returning the Windows buffer error.

## Randomness

Windows cardmod has no generic RNG DDI. `CardGetChallenge*` is reserved for
Challenge/Response PIN authentication and remains unsupported. Firmware 6.0+
token randomness is available through the statically linked PKCS#11
`C_GenerateRandom` entry point, not through `CARD_DATA`.

## Verification

The primary local loop is:

```powershell
.\build.ps1 -Arch x64
.\scripts\keygen-test.ps1 -UsePinProtectedManagementKey
.\scripts\sign-test.ps1 -SkipBuild -SkipInstall -SkipReset
.\scripts\derive-test.ps1 -SkipBuild -SkipInstall -SkipReset
```

Run `crypto-test.ps1` when the card has every required container. It treats a
missing RSA 9D key-exchange container as a failed precondition; do not overwrite
9D solely to satisfy that matrix without explicit intent.

## Refactoring Boundaries

The minidriver source files remain aligned with cardmod responsibilities and
are small enough to keep those entry points together. Error translation stays
local to PIN, crypto, data-write, and provisioning paths because the same
PKCS#11 error can require different Windows semantics in each API family.

Shared policy or ownership logic belongs in a common module: container-index
mapping lives in `canokey.c`, post-write inventory refresh lives in `data.c`,
and only allocation/free/padding callbacks that are actually consumed are
retained globally. Do not centralize error maps merely because their switch
statements overlap.
