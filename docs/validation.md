# Review and Validation Standard

Minidriver changes must be validated together with the
`external/canokey-pkcs11` submodule. Read the PKCS#11 validation standard in
the submodule's `docs/validation.md` first, then apply the additional Windows
checks below.

## Required Invariants

- `CardAcquireContext` and `CardDeleteContext` either complete cleanup or
  return an error without silently discarding the context.
- Card handle, allocator, session, and context ownership remain consistent
  for the complete lifetime of a `CARD_DATA` instance.
- Container indexes are stable and map `0..5` to `9A`, `9C`, `9D`, `9E`, `82`,
  and `83`. Do not expose retired PIV slots to Windows without an explicit
  policy change.
- USER authentication and protected management-key authentication are separate
  states, but both are valid for the operations explicitly allowed by policy.
- Legacy and extended container creation require `ROLE_USER`; the PKCS#11
  backend may use a PIN-protected management key internally, but an
  administrator-only role must be rejected by the Windows API.
- Two-stage buffer APIs set the required output length before returning
  `ERROR_INSUFFICIENT_BUFFER`.
- All sensitive buffers, temporary DH agreements, and failed key-operation
  allocations have a deterministic cleanup path.

## Context-Specific PIN Gate

For a PIV key with PIN-always policy, the minidriver must retain a bounded USER
PIN only within the same `CARD_DATA` context and only until the next private
operation or teardown. After `C_SignInit`/`C_DecryptInit`, a first
`CKR_USER_NOT_LOGGED_IN` result may trigger exactly one
`C_Login(CKU_CONTEXT_SPECIFIC)` and one retry of the active operation. PIN-once
and PIN-never operations must not receive this extra login. The cached PIN must
be cleared on every success, terminal error, cancellation, logout,
`CardDeleteContext`, or card-handle change. Session-PIN flags remain
unsupported; the minidriver must not return the raw USER PIN through
`ppbSessionPin`.

`C_DeriveKey` is a one-shot PKCS#11 API with no operation-initiation boundary,
so the Windows ECDH path remains fail-closed for PIN-always keys until a
dedicated context-authenticated vendor extension exists. Do not emulate a
context-specific login outside an active PKCS#11 sign/decrypt operation.

## Required Checks

For each changed callback, test valid input, invalid versions/flags, invalid
container indexes, missing authentication, concurrent teardown, and allocator
or PKCS#11 failure. For destructive PIN-managed flows, verify that Logout
cannot interleave between authentication, PUK mutation, and final confirmation.

Run the x64 Ninja/ClangCL build and the API-level signing, decryption,
derivation, and key-generation tests when hardware is available. Treat the
Visual Studio generator with `-T ClangCL` as unsupported on this development
machine; use the documented Ninja flow.

For the Windows cache matrix, verify that `CP_CARD_CACHE_MODE` reports
`CP_CACHE_MODE_NO_CACHE` and that `cardcf` returns the current version with
zero freshness fields. PIV has no durable PIN freshness value, so this is
required to prevent stale Base CSP authorization after an external PIN change.
Repeated reads must expose stable public-key-derived container GUIDs across
contexts and card reinsertion. Compatibility writes from Base CSP/KSP must be
accepted without replacing the live PKCS#11-derived inventory.

Repeat the cache matrix after mutations made by an external PKCS#11/PIV
process, not only through minidriver APIs. With an existing `CARD_DATA`
context, read `cardcf`, `cmapfile`, and the affected zero-padded `kscNN`/`kxcNN`
files again. The virtual `cardcf` read must remain fast and must not trigger a
metadata scan; with the default `RefreshWindow=60`, the minidriver must refresh
live metadata within that bounded interval, preserve container GUIDs, and expose the new
certificate/key material. Because the cache mode is `CP_CACHE_MODE_NO_CACHE`,
the test must verify reread content rather than expecting freshness counters to
change. A PIN-only mutation is an authentication-state test and must not be
confused with key or file freshness.

## Windows Propagation Gate

Every minidriver code change is considered broken until it passes the Windows
smart-card propagation gate. A successful DLL build or PKCS#11 unit-test run
is not sufficient: the Windows-facing contract must still enumerate and use
the card's certificates and associated private keys.

With a development card present, run the targeted reader flow (not an
unfiltered system-wide probe):

1. Confirm `SCardSvr` and `CertPropSvc` are running and the CanoKey reader name
   is visible through PC/SC.
2. Run `certutil -silent -scinfo "<reader>"` and verify the CanoKey card is
   identified, the six policy containers (`9A`, `9C`, `9D`, `9E`, `82`, `83`)
   are enumerated, and every provisioned certificate has a matching private
   key container. The output must not regress to `cannot retrieve certificate`
   or `cannot open key` for a provisioned container.
3. Run `sign-test.ps1`/`crypto-test.ps1` for the Windows signature surface and
   verify that authentication reaches `CardAuthenticateEx` and signing reaches
   `CardSignData`. Use PKCS#11 tests separately for capabilities intentionally
   hidden from Windows, such as ECDH or PQC.
4. On a partially provisioned card, verify that `mscp/cmapfile` marks the first
   certificate-backed signing container as default; a key-only container must
   not be selected as the default Windows signing identity.
5. Repeat enumeration and one signing operation after a card reset/reinsert.
   Read `cardid`, `cardcf`, `cmapfile`, and certificate files again; `cardid`
   and `CP_CARD_GUID` must remain identical and the six container associations
   must not change.

If any gate step fails, do not merge or release the minidriver change. Do not
classify a failure as a cache issue merely because deleting Calais state or
restarting Windows makes it disappear; first fix the cardmod file, identity,
container-map, certificate, or authentication behavior that caused the
regression. CI without a physical card can validate build and unit-test
invariants, but it cannot replace this hardware-backed Windows acceptance
test.

On Windows on ARM64, repeat this gate with the native ARM64 DLL. Confirm the
DLL machine type and the Calais mapping before testing; an x64 DLL loaded by an
emulated process does not validate the native `SCardSvr`/`CertPropSvc` path.
Use `build.ps1 -Arch arm64`, pass `-Arch arm64` to scripts that support it, and
pass the ARM64 `-DllPath` to scripts that default to x64. A wrong-architecture
mapping is a failed test, even if a separate x64 process can enumerate the
reader.

The Windows CI matrix also cross-builds an ARM64 DLL on the x64 hosted runners.
That job verifies the ARM64 artifact and linker inputs only; it cannot replace
the native ARM64 propagation gate because hosted runners have no CanoKey and
do not run the minidriver inside native ARM64 `SCardSvr`.

## Review Procedure

1. Inspect the complete minidriver diff and the exact submodule commit.
2. Trace every callback to its PKCS#11 operation and verify role, slot,
   endianness, buffer ownership, and cleanup behavior.
3. Run the PKCS#11 unit/sanitizer suite and the Windows ClangCL build.
4. Request Copilot and CodeRabbit full reviews against the final submodule
   pointer, and resolve every actionable finding.
5. Repeat the review after each non-trivial fix; document any remaining
   process-wide or Windows API limitations.

Logging lifecycle tests must cover `C_CNK_ConfigLogging` before and after
initialization, reconfiguration, borrowed stream ownership, generated-file
creation failure, and managed-mode logging. Fuzz builds must verify that the
production library is linked without `CNK_TEST_TRANSPORT`; only the dedicated
fuzz target may provide fake PC/SC callbacks.
