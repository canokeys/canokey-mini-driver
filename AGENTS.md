# Agent Notes

## Scope

- This repository builds the Windows Smart Card Minidriver layer for CanoKey.
- The minidriver wraps `external/canokey-pkcs11`; when editing inside that
  submodule, also follow `external/canokey-pkcs11/AGENTS.md`.
- Treat `docs/` as useful design notes, not as the source of truth. Verify
  behavior against the code, PKCS#11, and the Windows Smart Card Minidriver
  contract before implementing larger changes.

## Build Environment

- Use a Windows native Visual Studio 2022 environment with Desktop C++,
  ClangCL support, Ninja/CMake, and the Windows Driver Kit installed.
- Initialize submodules before building:

```powershell
git submodule update --init --recursive
```

- Build the default host architecture:

```powershell
.\build.ps1
```

- Build a specific architecture:

```powershell
.\build.ps1 -Arch x64
.\build.ps1 -Arch arm64
```

- Build all supported Windows architectures:

```powershell
.\build.ps1 -Arch all
```

- `build.ps1` is build-only. Do not install, uninstall, or update drivers from
  that script. Only run `pnputil` or INF installation commands when the user
  explicitly asks for driver installation or removal.
- For local debugging, prefer the registry-only flow in
  `docs/development.md`: build the DLL, run the
  `canokey-minidriver-debug-install` target, and map the CanoKey ATR to that
  DLL in the Calais smart card registry key.
- Build outputs are under `out/build/<arch>-Clang-<config>/`, for example:

```text
out/build/x64-Clang-Debug/canokey-minidriver.dll
out/build/x64-Clang-Debug/canokey-minidriver.inf
```

- The debug deployment target copies the DLL to `CMD_DEBUG_INSTALL_DIR`
  (`C:/canokey-minidriver` by default) and creates `CMD_DEBUG_LOG_DIR`
  (`C:/canokey-minidriver/logs` by default). These are debug deployment
  paths only; they are not compiled into the DLL:

```powershell
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

## Development Hygiene

- English is the project language. Write source comments, documentation,
  diagnostic text, commit messages, and pull-request content in English.
  Other languages are allowed only in explicitly identified localization
  resources.
- Run `clang-format` on touched C source and header files before committing.
- The repository has a `.clang-format`; use that style rather than introducing
  local formatting preferences.
- Add succinct comments for non-obvious invariants and boundaries: Windows/
  PKCS#11 ownership, sensitive-data lifetime, cache synchronization, two-stage
  buffer semantics, endianness, and PIV slot-policy decisions. Do not add
  comments that merely narrate straightforward statements.
- Update `docs/architecture.md` when changing module ownership, slot policy,
  managed-mode lifetime, or Windows/PKCS#11 responsibility boundaries.
- The VS bundled formatter is usually available at:

```text
C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-format.exe
```

- Keep edits scoped to the minidriver behavior being changed. Avoid unrelated
  refactors, generated output, and build artifacts.
- Preserve existing user changes in the worktree. If a dirty file is relevant,
  read it and build on it rather than reverting it.
- Do not commit files under `out/`, `.vs/`, or other generated build/cache
  directories.

## Commit Conventions

- Use Conventional Commits, for example `build: update minidriver build script`.
- Use signed-off commits:

```powershell
git commit -s
```

- For non-trivial changes, include a short body explaining the why and any
  notable verification.
- Wrap commit message body lines at about 80 columns.
- Mention submodule updates explicitly when the commit changes
  `external/canokey-pkcs11`.

## Driver Safety

- Building the DLL/INF is safe. Installing the INF is a machine-level driver
  operation and may require test signing mode, elevated permissions, or reboot.
- Registry-only debugging is not INF installation. It writes an HKLM Calais
  smart card mapping to point Windows at a copied minidriver DLL. Treat the
  registry edit as an explicit user-approved debugging step.
- Do not enable test signing, install the driver, delete installed driver
  packages, restart Windows services, or write to system driver stores unless
  the user directly requests that action.
- Minidriver runtime configuration comes from
  `HKLM\SOFTWARE\Canokeys\ckmd`. Logging is disabled unless `LogPath` is set.
  `LogLevel` accepts text levels (`trace`, `debug`, `info`, `warn`, `error`,
  `fatal`, `none`) and `LogSensitiveData` enables raw APDU/hex dumps. The
  minidriver passes the registry-derived level, log file, and sensitive-data
  flag to `C_CNK_ConfigLogging(level, file, unsafe_log_apdu)`.

## Local Debug Loop

- The current preferred smoke test is:

```powershell
.\build.ps1 -Arch x64
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
certutil -silent -pin 123456 -scinfo "canokeys.org OpenPGP PIV OATH 0"
```

- The test/debug CanoKey can be USB-reset through the helper board. Do not
  identify the control interface by a hardcoded COM number: Windows can assign
  a different number after reconnecting or flashing. Probe available serial
  ports at 115200 baud with `status` and select the one whose response starts
  with `OK` and contains `ciu_power=`. A port that opens but times out is
  normally the DevKit UART, not the control interface.
- After identifying the control port, write `reset ciu` followed by CRLF and
  wait a few seconds. This simulates unplugging and replugging the device
  without touching the INF. `scripts/minidriver-test-common.ps1` implements
  this discovery; pass `-ComPort` only as an explicit override, which is still
  validated with `status`.
- The essential PowerShell reset sequence after discovery is:

```powershell
$port = New-Object System.IO.Ports.SerialPort $detectedPort,115200,'None',8,'One'
$port.NewLine = "`r`n"
$port.Open()
$port.WriteLine('reset ciu')
Start-Sleep -Milliseconds 300
$port.Close()
Start-Sleep -Seconds 6
```

- The scripted version of the same build/install/reset/scinfo loop is:

```powershell
.\scripts\smoke-scinfo.ps1
```

- Logs are written only when `HKLM\SOFTWARE\Canokeys\ckmd\LogPath` is set. For
  the local debug loop this is usually `C:/canokey-minidriver/logs`. The most
  useful files are usually from `certutil.exe`, `CredentialUIBroker.exe`, and
  `svchost.exe`.
- Prefer passing the CanoKey reader name to `certutil -scinfo`. Plain
  `certutil /scinfo` enumerates every smart-card reader and may also exercise
  Windows Hello, which adds irrelevant prompts and failures.
- For the current development card, `certutil -pin 123456` suppresses the
  Windows PIN UI. This is a local test convenience only; do not hardcode or
  document real user PINs.
- `certutil /scinfo` exercises the real Windows path. In the observed flow,
  Windows loads the DLL from the Calais registry mapping, calls
  `CardAcquireContext`, reads `mscp/cmapfile` and `mscp/kscNN`, prompts through
  `CredentialUIBroker.exe`, then reaches `CardAuthenticateEx` and
  `CardSignData`.
- For the full API-level crypto matrix, use:

```powershell
.\scripts\crypto-test.ps1
```

  It uses `CryptGetProvParam(PP_ENUMCONTAINERS)` and `NCryptEnumKeys` for API
  discovery, then signs/verifies CAPI RSA/SHA1 PKCS#1, CAPI RSA/SHA256 PKCS#1,
  CNG RSA/SHA256 PKCS#1, CNG RSA/SHA256 PSS, and CNG ECDSA P-256/SHA256. When
  a key-exchange RSA KSP container is discovered, the script also tests CNG RSA
  PKCS#1 and OAEP-SHA256 decrypt. When an ECDH KSP key is discovered, it tests
  `BCRYPT_KDF_RAW_SECRET` against a software-generated peer key. Use
  `-SkipBuild -SkipInstall -SkipReset` for fast reruns.
- `crypto-test.ps1` currently treats a missing RSA key-exchange container as a
  test precondition failure. When 9D is not an RSA key, run `sign-test.ps1` and
  `derive-test.ps1` separately; do not overwrite 9D merely to satisfy the test
  unless that destructive provisioning is explicitly intended.
- For focused reruns, use `.\scripts\sign-test.ps1`,
  `.\scripts\decrypt-test.ps1`, or `.\scripts\derive-test.ps1`. They share
  `scripts\minidriver-test-common.ps1`, so `crypto-test.ps1` can build,
  debug-install, reset, discover once, and then run all three categories in a
  single PowerShell process.
- The current development card has useful PIV material in:

```text
ID 01 -> PIV 9A -> EC P-256 key
ID 02 -> PIV 9C -> EC P-256 key
ID 03 -> PIV 9D -> EC P-256 key
ID 04 -> PIV 9E -> RSA-2048 key
ID 05 -> PIV 82 -> EC P-256 key
ID 06 -> PIV 83 -> EC P-384 key
```

This inventory is observational, not provisioning policy. Re-enumerate the
card before relying on it because key generation/import tests overwrite slots.

The current 9D key is EC, so Windows does not expose an RSA
`AT_KEYEXCHANGE` container. PKCS#11 can exercise RSA decrypt with the RSA key
in 9E, but the minidriver intentionally reserves Windows RSA key exchange for
an RSA key in 9D.

- The minidriver keeps explicit per-slot capabilities in `SLOT.capabilities`.
  The intended YubiKey-style PIV policy is:

```text
9A, 9C, 9D, 9E, 82, 83 -> signature-capable
EC keys in those slots       -> also ECDH-capable
9D RSA keys                  -> also decryption/key-exchange-capable
```

- `scripts\sign-test.ps1` should exercise every discovered signing container.
  CAPI coverage is for RSA containers; CNG coverage is split by RSA and ECDSA
  algorithm group. Open CNG signing keys with `LegacyKeySpec = AT_SIGNATURE`
  and CNG decrypt keys with `LegacyKeySpec = AT_KEYEXCHANGE`; opening a
  dual-use container with legacy key spec `0` can fail with `NTE_BAD_KEYSET`.
- Do not hardcode the development PIN in minidriver code. Authentication must
  enter through `CardAuthenticateEx`; signing should use the authenticated
  PKCS#11 session state.
- `CardCreateContainerEx` supports classic RSA and EC generation/import for
  `ROLE_USER`. RSA import consumes a CAPI `PRIVATEKEYBLOB` and converts its
  little-endian CRT components to PKCS#11 big-endian attributes. EC import
  consumes a `BCRYPT_ECCPRIVATE_BLOB` (`X || Y || d`, big-endian). Validate
  either blob with the Windows software crypto provider before writing it.
- For EC on-card generation, accept the CPDK-standard `dwKeySize == 0` as well
  as the explicit curve size used by local tests. Only `ROLE_USER` may create
  containers; `ROLE_ADMIN` creation returns `SCARD_W_SECURITY_VIOLATION`.

## Implementation Notes

- `canokey-minidriver.inf` is generated from `canokey-minidriver.inf.in`.
- The PKCS#11 dependency is linked statically into the minidriver target.
- The Windows cardmod contract has no generic random-generation DDI.
  `CardGetChallenge` and `CardGetChallengeEx` belong to Challenge/Response PIN
  authentication and must not expose the PIV RNG. Firmware 6.0+ random support
  is available through the statically linked PKCS#11 `C_GenerateRandom` API.
- `external/canokey-pkcs11` commit `1c0bb0d` adds the `C_DecryptInit` /
  `C_Decrypt` RSA path used by `CardRSADecrypt`.
- `external/canokey-pkcs11` commit `ff21a84` adds `C_DeriveKey` for PIV ECDH
  with `CKM_ECDH1_DERIVE` and `CKD_NULL`. The minidriver maps this to CNG
  `BCRYPT_KDF_RAW_SECRET`; higher-level KDF parameter lists are intentionally
  unsupported for now.
- `pfnCspGetDHAgreement` is a CSP/KSP callback supplied in `CARD_DATA`, not a
  minidriver entry point to implement. Do not overwrite it in
  `CardAcquireContext`. If future `CardDeriveKey` support accepts
  `KDF_SECRET_HANDLE` / `KDF_NCRYPT_SECRET_HANDLE` buffers, call this callback
  to translate those handles into on-card agreement indexes.
- `CMD_DEBUG_INSTALL_DIR` and `CMD_DEBUG_LOG_DIR` are CMake cache variables for
  the debug-install target only. Do not compile deployment/log paths into the
  DLL; runtime behavior should come from `HKLM\SOFTWARE\Canokeys\ckmd`.
- Keep registry parsing in the config layer. `LogPath` absence means no
  minidriver or managed PKCS#11 logging, even if `LogLevel` is present.
  `NewKeyTouchPolicy` maps to `CKA_CNK_PIV_TOUCH_POLICY` (`1` never, `2`
  always, `3` cached; default `1`). `NewKeyPinPolicy`, when present, maps to
  `CKA_CNK_PIV_PIN_POLICY` (`1` never, `2` once, `3` always). If
  `NewKeyPinPolicy` is absent, generated keys use the PIV defaults: 9E never,
  all other supported key slots once. `PinCacheTimeout` is reported through
  `CP_CARD_PIN_INFO`.
- Runtime private-key operations defer PIN policy enforcement to
  `canokey-pkcs11`. Do not add minidriver-side checks that always require
  `ROLE_USER`; PIN-never keys must be able to sign, decrypt, or derive without
  a user PIN, while PIN-once/PIN-always keys should return the PKCS#11
  login-required error path when no PIN is cached.
- PIN management is intentionally narrow. `ROLE_USER` maps to the PIV PIN,
  `ROLE_ADMIN` maps to the PIV management key / `CKU_SO`, and `CMD_ROLE_PUK`
  maps to the PIV PUK only for unblock/reset. Do not support standalone
  `CardAuthenticateEx(CMD_ROLE_PUK)` or PUK changes unless the product design
  explicitly changes. PIV PUK reset can set a new PIN even when the PIN is not
  blocked; `scripts/pin-test.ps1` covers this by using the PUK to set a
  temporary PIN and then restoring the development PIN.
- Microsoft Smart Card KSP key creation chooses a minidriver container index
  from `mscp/cmapfile`; public KSP properties select provider/reader, not a
  PIV slot directly. Keep container indexes stable: `0..5` map to PIV object
  IDs `1..6` (`9A`, `9C`, `9D`, `9E`, `82`, `83`).
- The minidriver uses CanoKey PKCS#11 managed mode; initialize managed mode
  before `C_Initialize()` when wiring card handles through this layer.
- `CardAcquireContext` owns one PKCS#11 session in `CMD_CONTEXT`. Always close
  that session in `CardDeleteContext` before finalizing PKCS#11; otherwise
  repeated Windows probes can exhaust the session table and fail later
  acquisitions with `CKR_HOST_MEMORY` / "No free session slots available".
- `CardRSADecrypt` receives and returns RSA buffers in Windows little-endian
  order. Reverse ciphertext before calling PKCS#11 and reverse the plaintext
  before returning to Windows, including PKCS#1/OAEP paths where PKCS#11 has
  already removed padding.
- `CardDeriveKey` returns ECDH raw secret bytes to Windows in little-endian
  order. PKCS#11 derives the X coordinate in big-endian form, so reverse the
  returned raw secret before handing it back to CNG.
- Keep the generated no-implementation X macro in `src/context.c` honest. Once
  an entry point has a real implementation or is intentionally left `NULL`, it
  must be removed from `INVOKE_X_ON_NO_IMPL_FUNCS`; otherwise
  `CardAcquireContext` will overwrite the explicit function table value with a
  generated unsupported-feature stub.
- For minidriver APIs that only accept `dwFlags == 0`, use
  `CMD_CHECK_DW_FLAGS` instead of open-coded checks. For structure fields named
  `dwFlags`, keep the validation local so the checked expression is explicit.
- Standard read-only card plumbing still needs successful responses: expose
  `cardcf`, `cardid`, `mscp/cmapfile`, certificate files, `CardEnumFiles`,
  `CardGetFileInfo`, and `CardQueryFreeSpace`. `CP_CARD_GUID` and the `cardid`
  file must be byte-for-byte identical and stable for the token, because
  Windows uses them for cache identity.
- Treat root `cardcf` as a Base CSP/KSP cache-coherency file. Return a valid
  `CARD_CACHE_FILE_FORMAT` and accept same-version writes; the authoritative
  token state still comes from CanoKey metadata and `mscp/cmapfile`.
- Treat `mscp/cmapfile` similarly: generate it from live key metadata, and
  accept well-formed writes from KSP as cache synchronization rather than
  persisting a separate copy.
- Do not use silent CNG/certreq contexts when debugging Windows smart-card key
  creation. `NCRYPT_SILENT_FLAG`, `certreq -q`, and `Silent = true` can stop
  before `CardCreateContainer*`; use non-silent calls and pass PIN/reader
  properties where possible.
- Microsoft Smart Card KSP key creation does not automatically ask for
  `ROLE_ADMIN` when CanoKey/PIV key generation returns `CKU_SO login is
  required`; it authenticates `ROLE_USER`, writes `cardcf`/`cmapfile`, and then
  calls `CardCreateContainer`. Use an explicit provisioning/debug path for
  management-key authentication.
- YubiKey-style PIN-protected management-key login is implemented through
  `C_CNK_LoginPinManaged()`. After normal USER authentication, the minidriver
  calls that narrow extension; `canokey-pkcs11` validates ADMIN DATA, reads and
  parses PRINTED, verifies the management key, and clears temporary sensitive
  buffers. Keep TLV parsing and raw management-key material out of the
  minidriver, and do not issue raw PC/SC APDUs from this path.
- Certificate files (`kscN`/`kxcN`) must remain Windows-friendly for
  enumeration: report `EveryoneReadUserWriteAc` for file info. The actual PIV
  certificate write is still a management operation, so require `ROLE_ADMIN`
  before `CardWriteFile` writes certificates through PKCS#11.
- On `ERROR_INSUFFICIENT_BUFFER`, set the returned length before failing so
  Windows callers can retry with the right buffer size.
- Logging must be best-effort. Failure to open the log file, or calling shutdown
  without a log file, must not assert or crash the host process.
- Keep minidriver logging thread-safe. Emit a complete log line while holding
  the logging lock, and avoid exposing mutable logging globals to callers.
