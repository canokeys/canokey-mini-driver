# Persistent names and firmware compatibility

F5-capable firmware persists each Windows container name with its PIV key.
`read_canokey` includes names in an all-or-error snapshot. `data.c` publishes
them in cmapfile and includes them in cardcf freshness. Unnamed keys and old
firmware retain public-key-derived names. PKCS#11 uses the shared RNG version
gate: PIV 6.0.0 and later support F5; older/unavailable PIV versions permit
fallback. Storage, transport or malformed-name errors never permit fallback.

Enrollment stages logical indexes in CARD_DATA until a key exists. Successful
generation then persists its staged name at the resolved physical slot. Later
cmapfile name changes also persist; default/size-only writes need no management
login. No PIN, PUK or ADMIN DATA provisioning is added to this path.

Composite key/name creation and multi-record cmap writes are not atomic. A
failure can follow a committed key or earlier names. Report the failure, clear
the provisional overlay, invalidate other contexts and never regenerate or
rewrite names as an automatic rollback. Read the card before recovery.

On legacy firmware the previous context-local enrollment behavior remains,
including the cross-process certreq limitation. Use a CSR for an existing key
under its public-key-derived name, or repair the precise Request-store entry
before accept. This change does not pretend those workarounds are unnecessary
on firmware without F5, and does not invalidate existing legacy keys/certificates.

PKCS#11 covers every protocol reference, but Windows retains its six-slot
policy; retired-slot expansion and F9 publication are separate changes.

Acceptance: create a fresh key/CSR, exit certreq, reinsert, accept its matching
certificate without repairstore, then verify propagation and signing on native
ARM64 and x64. Repeat existing-key discovery/signing on firmware without F5.

## Validation checkpoint (2026-09-09)

The reviewed source builds with Windows ClangCL for x64 and ARM64. Both
architectures pass enrollment-regression and container-name-contract; PKCS#11
API contract coverage is 118/118. The standalone x64 PKCS#11 DLL also builds.

The installed, pre-cleanup driver passed seven targeted ARM64 RSA/ECDSA
signing and RSA decryption checks. Select the signature container explicitly
with `-BaseCspContainer`: the generic script otherwise tests RSA 9D using
AT_SIGNATURE even though that container exposes AT_KEYEXCHANGE only.
These checks do not validate deployment of the newly rebuilt minidriver.

Earlier F5 acceptance covered RSA certreq new/accept, existing-key ECDSA
enrollment, certificate propagation after reinsertion, and Word signatures.
Word certificate-trust warnings remain separate from signature verification.
At this checkpoint, unsupported-SM2 slot occupancy was not protected. The
subsequent occupancy guard is described in architecture.md; its new validation
must be distinguished from these earlier installed-driver results.

The cleanup has not repeated the complete Windows propagation gate, legacy
firmware hardware tests, Linux unit/sanitizer tests, or Copilot/CodeRabbit
reviews. This is a local development checkpoint, not release acceptance.
