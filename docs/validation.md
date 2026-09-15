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

## Review Change Protocol

Review findings are hypotheses, not implementation instructions. Before changing
an API or capability flag, trace the complete representation path across this
repository and `external/canokey-pkcs11`, then check the cited specification
against the actual caller and callee contracts. A review that inspects only a
final buffer is incomplete when an intermediate layer unwraps, encodes, or
reconstructs that buffer.

For Windows-facing changes, preserve a known-good hardware checkpoint and run a
single-variable acceptance test before and after the change. The checkpoint
must include the reader, firmware/PIV versions, card identity, mapped slots,
certificate fingerprints, and the exact command used for `certutil -scinfo`.
If the gate regresses, restore the last known-good binary first, then use
`git bisect` with the same card and test predicate. Do not compensate by
deleting Calais state or changing unrelated cache settings; export any exact
cache subtree before a narrowly scoped cleanup and prove that cleanup is
necessary.

For every capability or file-format change, require both evidence sources:
the normative specification and a real caller result. In particular, a
successful `CardReadFile` trace is not enough: certificate propagation must
reach the user store and `certutil` must match each certificate to its private
container. Record the result and the reason for rejecting any review finding
that conflicts with the specification or the golden hardware test.

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
`CP_CACHE_MODE_NO_CACHE`, `cardcf.bPinsFreshness` is zero, and container/file
freshness are stable non-zero hashes of the complete live snapshot. PIV has no
durable PIN freshness value, while deterministic public freshness is required
to trigger certificate propagation after key/certificate mutations.
Repeated reads must expose stable F5 names (or public-key-derived legacy names) across
contexts and card reinsertion. Compatibility writes from Base CSP/KSP must be
accepted without replacing the live PKCS#11-derived inventory. Name changes
on F5 firmware persist per key, including late cmapfile writes. Test unsupported
F5 separately from empty names, absent keys and transport/storage errors. Only
the PKCS#11 PIV-version gate (before 6.0.0/unavailable, shared with RNG) may
select legacy fallback. F5 errors on 6.0.0+ must not select legacy fallback.

Repeat the cache matrix after mutations made by an external PKCS#11/PIV
process, not only through minidriver APIs. With an existing `CARD_DATA`
context, read `cardcf`, `cmapfile`, and the affected zero-padded `kscNN`/`kxcNN`
files again. The virtual `cardcf` read must remain fast and must not trigger a
metadata scan; with the default `RefreshWindow=60`, the minidriver must refresh
live metadata within that bounded interval, preserve container GUIDs, and expose the new
certificate/key material. Verify that key changes update container freshness,
certificate-only changes update file freshness, and unchanged snapshots stay
identical across contexts. A PIN-only mutation is an authentication-state test
and must not be confused with key or file freshness.

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
3. Run `crypto-test.ps1 -Operation Sign`/`crypto-test.ps1` for the Windows signature surface and
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
6. Delete the six development certificates from the current-user certificate
   store, reset/reinsert the named card, and verify that CertPropSvc reads every
   provisioned `kscNN` plus RSA 9D `kxcNN` and recreates the certificates with
   matching private-key associations. EC containers must keep both Windows
   key-exchange fields empty throughout this test.
7. Verify both `CardQueryCapabilities` and `CP_CARD_CAPABILITIES` report
   `fCertificateCompression = TRUE`. A trace that shows successful `kscNN`
   reads is not sufficient: all six certificates must still appear in
   `certutil -scinfo` and the current-user Personal store.

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

## Persistent-name enrollment checks

On firmware with F5 name storage, create a fresh key and CSR, exit `certreq`,
reinsert the card, and accept its matching certificate without `repairstore`.
Verify certificate propagation and signing using the deployed binary on native
ARM64 and x64. Include RSA 9D with `AT_KEYEXCHANGE`, existing-key enrollment,
and application signing. Distinguish certificate-trust errors from signature
verification failures.

On firmware without F5, repeat existing-key discovery and signing, then exercise
the [legacy Request-store repair](windows-certreq-legacy.md). Verify that
unsupported algorithms still occupy their physical slots and cannot be
replaced by Windows enrollment.

Inject failures after key creation and after an earlier record in a multi-name
write has committed. Confirm that errors clear the provisional overlay and
invalidate other contexts without regenerating keys or rolling back committed
names. Re-enumeration must reveal the actual card state.

Keep dated test results, binary revisions, commands, and coverage gaps with the
change's review or release evidence. User guides describe supported behavior
and recovery steps; a previous binary's test result is not evidence for a new
build.

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

The direct DDI regression can be built with `-DCMD_BUILD_DDI_TESTS=ON` and run as
`ddi-smoke.exe <dll-path> <log-directory>` with `CNK_PIV_PIN` set. The log directory
parent must exist. Run again with `raw` as the third argument to verify public
APDU logging without submitting credentials. Use `write` with
`CNK_PIV_MANAGEMENT_KEY` to check PUBLIC rejection and ADMIN certificate writes.
The host saves original DER, writes and reads it back, and retains the ADMIN
context through explicit restoration on failure. It then deauthenticates ADMIN
and checks USER signing. Both cycles must retain PKCS#11
records; normal mode must contain no raw APDU records. This does not substitute
for Base CSP/KSP or CertPropSvc acceptance against the installed Calais mapping.

## Scoped certificate propagation regression

`scripts/propagation-test.ps1` tests explicitly selected development RSA/EC certificates
against an already deployed DLL. Supply `-Thumbprint`, `-ExpectedDllSha256` and
`-ReportDirectory`, and provide the PIN through `CNK_PIV_PIN` or `-Pin`. It checks
the existing Calais DLL hash and running services before making changes; it does
not deploy a driver or alter registry configuration. It serializes each selected
certificate and its properties, removes only its user-store copy, proves absence,
resets the discovered CIU control port, and waits for CertPropSvc to recreate it.
Provider/container/KeySpec must stay identical. Silent KSP signatures must verify
against the propagated certificate's public key, not just the KSP key handle.

On a reset, timeout, association or signing failure, the test restores the original
certificate contexts with their provider properties. Card objects and private keys
are never deleted. Test this rollback with an invalid explicit `-ComPort`; removal
must be observed and every original provider/container/KeySpec must be restored.
The test requires an unlocked interactive session before removing any certificate.
RSA uses the one legacy key spec reported for its KSP container; RSA 9D signs
through AT_KEYEXCHANGE. The caller must confirm native DLL architecture.

Do not use an unfiltered `certutil -user -store My` command as a passive inventory:
it can open unrelated private keys and trigger repeated credential/error dialogs.
Use X509Store enumeration and CertGetCertificateContextProperty to inspect public
certificate/provider metadata without opening private keys. Automated KSP signing
uses NCRYPT_SILENT_FLAG, including the actual sign call, so a failure is reported
to the test instead of opening a UI.

Current x64 acceptance covers all six Windows containers: 9A/9C P-256, 9D/9E
RSA, 82 P-384 and 83 P-521. All six certificates propagate after observed removal
and USB reinsert, retain provider/container/KeySpec and verify signatures against
their own public keys. Targeted silent scinfo, CAPI SHA1/SHA256, CNG RSA PKCS#1/PSS,
ECDSA and RSA PKCS#1/OAEP decrypt pass. Service and application logs contain the
new PKCS#11/Rust completion records. Native ARM64 runtime is outside this task's
hardware scope; architecture cross-builds remain required.

The DDI host compares P-256/P-384/P-521 ECDH with BCrypt raw-secret output,
including size queries, short buffers and agreement destruction. This checks
the DDI byte order without publishing EC key-exchange fields. PIN/PUK
change/reset/restore and 18 explicit Windows key generation/import cases pass.
The provisioning fixture is restored to default credentials with PIN protection
removed. Use only explicitly replaceable slots for these destructive cases.

CAPI enumeration acquires a verification context, so an EC default container
cannot hide the existing RSA keys. CAPI signing selects RSA signature containers;
RSA 9D is tested through its key-exchange path. Key-generation tests support
`-PassThru` for structured results and fail when the requested public-key view is
absent or imported bytes differ. Reports include DLL hashes and certificate backups.

## Native write fixtures

Configure `CMD_BUILD_DDI_TESTS=ON` and build `ddi-smoke` beside the selected DLL.
`pin-test.ps1` and `keygen-test.ps1` dispatch to this same architecture-matched
host; all cardmod layouts now come from the official `cardmod.h`. Credentials
are passed in process environment variables and restored by the wrapper.
The host acquires one CARD_DATA context, owns its allocator callbacks and card
handle, deletes the context before unloading, and clears exported private blobs.
PIN tests restore each successful temporary mutation before the next phase;
an ambiguous transport failure stops without guessing another credential.
Enrollment checks USER/protected-ADMIN state, ADMIN-role rejection, imported
public-key equality, and stable card identity before/after writes and reacquire.
These modes do not install a driver or alter machine configuration.
