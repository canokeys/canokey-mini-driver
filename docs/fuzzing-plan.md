# PKCS#11 and Minidriver Fuzzing Plan

This plan defines a staged fuzzing workflow for `canokey-pkcs11` and the
Windows minidriver. The default targets are deterministic and do not access a
physical card. Hardware campaigns are separate, explicitly selected, bounded,
and recoverable.

## Phase 1: Local API and State-Sequence Fuzzing

Drive the real PKCS#11 function list returned by `C_GetFunctionList` with
randomized session/object/operation sequences, mechanism templates, lengths,
NULL and size-query arguments, repeated Init/Final/Cancel/Logout/Close calls,
and concurrent close/logout/finalize attempts. Add allocator, mutex callback,
and PC/SC failure injection where the backend seam permits it.

The target must not connect to a physical card. It uses a deterministic fake
managed binding or a no-card pre-initialization harness. Every iteration checks
that session references are released, token counters match the session table,
pending owners are coherent, unsupported calls do not mutate state, and
private objects are not visible in PUBLIC state. Run with ASan and UBSan; use
MSan or Valgrind where the platform supports them.

LLVM libFuzzer is the primary engine on Linux. Windows builds replay the same
corpus and reproduce minimized crashes without requiring a long-running fuzz
job.

## Phase 2: PIV TLV and APDU Parser Fuzzing

Fuzz parser entry points that accept byte buffers without opening PC/SC:

- metadata directory and per-key metadata TLV;
- public-key encodings and P-521 points;
- RSA CRT import blobs and EC private-key blobs;
- ECDSA/signature and GENERAL AUTHENTICATE responses;
- certificate/data-object encodings;
- OAEP parameters and labels.

Targets must cover truncated input, zero-length values, long-form lengths,
nested TLV boundaries, oversized output, and malformed input followed by a
retry. Each target must leave caller-visible state unchanged on failure and
zeroize sensitive temporary buffers.

## Phase 3: Fake PC/SC Transport Fuzzing

Add a deterministic transport seam that can model `SCardConnect`, transaction
begin/end, `SCardTransmit`, `SCardGetStatusChange`, `SCardCancel`, reader
removal, arbitrary response status words, truncated responses, delays, and
transport failures. Verify operation counters, finalize admission, cancellation
wakeup, fail-closed logout, retryable backend cleanup, queued reader events,
and session/token state after malformed card responses.

The fake transport must not be linked into production binaries. Failure cases
become permanent regression tests associated with the relevant API contract.

## Phase 4: Non-Destructive Hardware Fuzzing

Use only an explicitly selected development reader, slot, and token serial.
Exercise discovery, metadata/certificate reads, public-key export, signing,
verification, RSA decrypt, ECDH, random lengths/chunking, login/logout/cancel,
and reset/reconnect sequences. Each case records firmware/PIV version, source
revision, seed, call sequence, and logs. A crash or timeout saves a minimized
reproducer and restores the card through the dynamic control-port discovery
and `reset ciu`/boot recovery flow.

## Phase 5: Explicit Destructive Hardware Fuzzing

Destructive fuzzing is never part of pull-request CI. It requires all of:

```text
CNK_RUN_DESTRUCTIVE_REAL_TESTS=1
CNK_FUZZ_DESTRUCTIVE=1
CNK_REAL_SLOT_ID=<explicit slot>
CNK_REAL_TOKEN_SERIAL=<explicit serial>
```

Only dedicated test slots may be overwritten. The harness must reject missing
identity, firmware, or bounds; never default to `9D`; snapshot metadata before
and after every mutation; enforce operation and timeout limits; and stop the
campaign if reset/reconnect cannot restore the card. PUK blocking and
PIN-managed finalization require a separate explicit confirmation because they
may be irreversible.

## Corpus and Results

Keep corpora and reproducers outside generated build directories:

```text
fuzz/
  corpus/api/
  corpus/tlv/
  corpus/pcsc/
  corpus/hardware/
  seeds/
  reproducers/
  minimized/
```

Each saved failure includes the target, seed, API sequence, firmware and token
identity, stdout/stderr/log paths, destructive flag, and minimized input.

## CI and Exit Criteria

- Pull requests replay a fixed corpus with sanitizers; they do not run long
  fuzz jobs or attach physical cards.
- Nightly jobs run fake-PC/SC fuzzing for a bounded duration.
- Hardware workflows are manual, require explicit slot and serial, and keep
  destructive mode disabled by default.
- Every fuzz target has a build and replay test registered with CTest.
- Every reproduced bug becomes a focused unit/regression test and an update to
  the corresponding API contract.

Implementation starts with Phase 1 and Phase 2. Phase 3 follows once the
transport seam is defined; only then should the hardware phases be enabled.
