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
- Legacy and extended container creation must accept either explicit
  `ROLE_ADMIN` or `ROLE_USER` with a protected management key, and reject an
  unauthenticated USER-only path.
- Two-stage buffer APIs set the required output length before returning
  `ERROR_INSUFFICIENT_BUFFER`.
- All sensitive buffers, temporary DH agreements, and failed key-operation
  allocations have a deterministic cleanup path.

## Required Checks

For each changed callback, test valid input, invalid versions/flags, invalid
container indexes, missing authentication, concurrent teardown, and allocator
or PKCS#11 failure. For destructive PIN-managed flows, verify that Logout
cannot interleave between authentication, PUK mutation, and final confirmation.

Run the x64 Ninja/ClangCL build and the API-level signing, decryption,
derivation, and key-generation tests when hardware is available. Treat the
Visual Studio generator with `-T ClangCL` as unsupported on this development
machine; use the documented Ninja flow.

## Review Procedure

1. Inspect the complete minidriver diff and the exact submodule commit.
2. Trace every callback to its PKCS#11 operation and verify role, slot,
   endianness, buffer ownership, and cleanup behavior.
3. Run the PKCS#11 unit/sanitizer suite and the Windows ClangCL build.
4. Request Copilot and CodeRabbit full reviews against the final submodule
   pointer, and resolve every actionable finding.
5. Repeat the review after each non-trivial fix; document any remaining
   process-wide or Windows API limitations.
