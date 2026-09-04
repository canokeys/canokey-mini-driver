# CanoKey Mini Driver

Windows smart card minidriver for CanoKey, built on top of
[`canokey-pkcs11`](external/canokey-pkcs11).

See [docs/architecture.md](docs/architecture.md) for module boundaries, state
ownership, slot policy, and the Windows-to-PIV request flow.

**Status:** this project is still WIP, but the development loop is usable.
Windows can load the DLL through a Calais smart card registry mapping without
installing the generated INF. Current local testing can enumerate the CanoKey
PIV certificates and run CSP/KSP signing, RSA decryption, and ECDH raw-secret
derivation tests against the development card. Release packaging, INF
installation and release validation are still in progress.

## Current State

- Debug loading works by copying `canokey-minidriver.dll` to
  `C:\canokey-minidriver\` and registering that path under the CanoKey ATR.
- Minidriver configuration is read from `HKLM\SOFTWARE\Canokeys\ckmd`.
  Logging is disabled unless `LogPath` is set there; `LogLevel` and
  `LogSensitiveData` control verbosity and APDU/hex dumps.
- New key creation can pass CanoKey/YubiKey-style PIN and touch policies to
  the PKCS#11 layer. By default, generated keys use touch policy never; 9E uses
  PIN policy never and other supported PIV key slots use PIN policy once.
- Runtime sign/decrypt/ECDH operations honor the stored PIV PIN policy through
  `canokey-pkcs11`: PIN-never keys can operate without a user PIN, while
  PIN-once and PIN-always keys still require PIN login.
- Windows provisioning rejects new PIN-always keys until a per-operation
  context-PIN bridge is available; PKCS#11 continues to enforce the policy for
  existing card keys.
- Windows PIN management is partially supported: the user PIN can be changed
  with the current PIN, and the user PIN can be unblocked/reset with the PIV
  PUK on cards that are not configured for PIN-managed management-key recovery.
  PIN-managed mode permanently blocks the PUK; PUK changes are intentionally
  not exposed.
- `scripts/pin-test.ps1` exercises the minidriver PIN contract directly. It
  temporarily changes the development PIN and restores it; by default it also
  uses the PUK to reset the PIN even when the PIN is not blocked.
- Smart Card KSP creation can use a YubiKey-compatible PIN-protected management
  key. After user PIN authentication, the minidriver reads the protected PIV
  object through PKCS#11 and enables management-authorized key writes without
  storing the management key in the registry.
- `CardCreateContainerEx` supports RSA and P-256/P-384/P-521 generation and private
  key import. RSA imports use CAPI `PRIVATEKEYBLOB`; EC imports use
  `BCRYPT_ECCPRIVATE_BLOB`. `scripts\keygen-test.ps1 -Import` covers direct
  minidriver import, and `scripts\ksp-keygen-test.ps1` covers real Microsoft
  Smart Card KSP enrollment followed by signature verification.
- The bundled PKCS#11 3.2 interface supports ML-DSA-65 and ML-KEM-768 across
  all 24 PIV key slots. Current Windows CPDK headers cannot represent these
  algorithms, so CSP/KSP exposure remains classic-only; see
  [`docs/pqc.md`](docs/pqc.md).
- Windows container indexes `0..5` map only to PIV key slots `9A`, `9C`, `9D`,
  `9E`, `82`, and `83`. RSA and the NIST P-256/P-384/P-521 curves are exposed
  through CSP/KSP. Curve identity comes from
  `CKA_EC_PARAMS`; secp256k1 and SM2 are deliberately skipped instead of being
  misreported as P-256 merely because they also use 32-byte coordinates.
- `certutil -scinfo` can see the card and current certificates.
- `scripts\crypto-test.ps1` exercises the minidriver through Windows CAPI/CNG
  APIs instead of parsing command output. The same checks can be run in focused
  groups with `sign-test.ps1`, `decrypt-test.ps1`, and `derive-test.ps1`.
- Historical hardware coverage includes 9A RSA-2048 signing, 9C EC P-256
  signing plus ECDH raw-secret derivation, and 9D RSA-2048 signing plus key
  exchange/decryption. Provisioning tests replace slots, so this is test
  coverage rather than the current card inventory.

The Windows PR surface exposes only the six stable containers `0..5`, mapped to
`9A`, `9C`, `9D`, `9E`, `82`, and `83`; the complete 24-slot inventory remains
available through PKCS#11.

Known gaps:

- Windows CSP/KSP exposure remains limited to RSA and the NIST curves defined
  by the current CPDK contract. Ed25519, X25519, SM2, secp256k1, and PQC remain
  available through PKCS#11 only.
- ECDH currently supports raw secret derivation only (`BCRYPT_KDF_RAW_SECRET` /
  PKCS#11 `CKD_NULL`). Higher-level KDF parameter lists are not implemented yet.
- INF installation is kept for later release validation.
- The test matrix depends on which keys and certificates are provisioned on the
  attached CanoKey.

## Build

### Prerequisites

Install Visual Studio 2022 with:

- Desktop development with C++
- Clang Support
- Windows Driver Kit (download from [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))

### Build with CMake

Initialize the PKCS#11 dependency after a fresh checkout:

```powershell
git submodule update --init --recursive
```

You can configure the project with CMake (or use Visual Studio GUI).
You must use `clang-cl` as the frontend, or `external/dbg.h` will fail to
compile.

After successful build, you will get `canokey-minidriver.{inf,dll}` in your build output directory.

The helper script uses the same defaults as the local debug workflow:

```powershell
.\build.ps1 -Arch x64 -Config Debug
```

Windows on ARM64 uses the native ARM64 artifact and must not reuse the x64
Calais mapping:

```powershell
.\build.ps1 -Arch arm64 -Config Debug
cmake --build out\build\arm64-Clang-Debug --target canokey-minidriver-debug-install
.\scripts\smoke-scinfo.ps1 -Arch arm64
.\scripts\crypto-test.ps1 -Arch arm64
```

On Windows ARM64, an Arm64X pure forwarder can route one Calais DLL name to
separate x64 and native ARM64 implementations. Build both implementation
architectures with the same configuration first, then build the forwarder:

```powershell
.\build.ps1 -Arch x64 -Config Release
.\build.ps1 -Arch arm64 -Config Release
.\build.ps1 -Arch arm64x -Config Release
```

The Arm64X output directory contains `canokey-minidriver.dll` (the forwarder),
`canokey-minidriver-x64.dll`, and `canokey-minidriver-arm64.dll`. The forwarder
has no application code or CRT dependency; the implementation DLLs retain the
normal CMake CRT choice for their configuration. CI publishes these files with
architecture suffixes. Each Visual Studio runner publishes one Debug and one
Release artifact (`canokey-mini-driver-debug-vs2022`,
`canokey-mini-driver-release-vs2022`, and the corresponding `vs2026` artifacts);
each package contains `canokey-minidriver-x86.*`,
`canokey-minidriver-x64.*`, `canokey-minidriver-arm64.*`, and
`canokey-minidriver-arm64x.*` files. The Arm64X forwarder uses the x64 and
ARM64 DLLs from the same package at runtime.

See [`docs/architecture-distribution.md`](docs/architecture-distribution.md)
for the complete registry, INF, artifact, and ARM32 support matrix. Each CI
artifact contains one multi-architecture `canokey-minidriver.inf` plus the DLL
and import-library files it references. Choose either INF installation or the
registry-only deployment flow; do not combine them.

For native-only validation, the DLL mapped for `SCardSvr`/`CertPropSvc` may be
the plain ARM64 build. When native ARM64 and x64-emulated callers share one
Calais mapping, register `canokey-minidriver-arm64x.dll` and keep both the x64
and ARM64 implementation DLLs beside it. Use an explicit `-DllPath` for scripts
that do not expose an architecture parameter; x64 processes under emulation are
not an ARM64 host validation.

If the TF-PSA-Crypto generator needs a specific Python environment, pass it
explicitly:

```powershell
.\build.ps1 -Arch x64 -Config Debug -Python3Executable C:\Path\To\python.exe
```

## Test

For development, you do not need to install the INF. Windows can load the
minidriver through the Calais smart card registry mapping:

```powershell
.\build.ps1 -Arch x64 -Config Debug
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

This copies the DLL to `C:\canokey-minidriver\` and creates
`C:\canokey-minidriver\logs\`. Import the debug Calais mapping and optional
`HKLM\SOFTWARE\Canokeys\ckmd` configuration described in
[`docs/development.md`](docs/development.md), then unplug and reinsert your
CanoKey or restart the calling application.

Useful local checks:

```powershell
.\scripts\smoke-scinfo.ps1
.\scripts\crypto-test.ps1
```

`smoke-scinfo.ps1` drives `certutil -silent -pin ... -scinfo` against the
CanoKey reader. `crypto-test.ps1` uses Windows cryptographic APIs directly to
enumerate containers and run the full local matrix: signing, RSA decrypt, and
ECDH raw-secret derivation against a software-generated peer key. For fast
focused reruns, use `sign-test.ps1`, `decrypt-test.ps1`, or `derive-test.ps1`
with `-SkipBuild -SkipInstall -SkipReset`.

INF installation is still useful for release-style validation and final
packaging. For that flow, enable test signing mode if needed, install the
generated INF, and uninstall the old driver package before testing a new
version.

## Troubleshooting

If you encounter any strange problems, you may try to (in order):

- Re-plug your CanoKey.
- Restart the calling application.
- Restart the `CertPropSvc` service (espcially when you cannot read or delete the log files).
- Uninstall and reinstall the driver if you are testing the INF path.
- Reboot your computer.
