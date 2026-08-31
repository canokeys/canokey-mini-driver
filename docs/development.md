# Development Notes

## Registry-only Minidriver Loading

For local debugging, Windows can load the minidriver through the Calais smart
card registry mapping without installing the INF. This is much faster than the
driver package flow and is the recommended development loop for now.

Build the minidriver:

```powershell
.\build.ps1 -Arch x64
```

Copy the DLL and create the default debug log directory:

```powershell
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

By default this copies:

```text
C:\canokey-minidriver\canokey-minidriver.dll
```

and creates a convenience log directory:

```text
C:\canokey-minidriver\logs\
```

Then import this registry snippet as Administrator, adjusting the DLL path if
you configured a different debug install directory:

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\CanoKey]
"ATR"=hex:3b,f7,11,00,00,81,31,fe,65,43,61,6e,6f,6b,65,79,99
"ATRMask"=hex:ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
"Crypto Provider"="Microsoft Base Smart Card Crypto Provider"
"Smart Card Key Storage Provider"="Microsoft Smart Card Key Storage Provider"
"80000001"="C:\\canokey-minidriver\\canokey-minidriver.dll"
```

Optional minidriver behavior is configured separately under
`HKLM\SOFTWARE\Canokeys\ckmd`. For verbose local logging, import this as
Administrator:

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Canokeys\ckmd]
"LogPath"="C:\\canokey-minidriver\\logs"
"LogLevel"="debug"
"LogSensitiveData"=dword:00000000
"NewKeyTouchPolicy"=dword:00000001
"NewKeyPinPolicy"=dword:00000002
"PinCacheTimeout"=dword:0000003c
```

Set `LogSensitiveData` to `1` only when you explicitly need raw APDU and hex
dumps. Those logs may contain PIN-adjacent protocol data and other sensitive
wire traffic.

After updating the DLL, rebuild and rerun the debug-install target. You may need
to unplug and reinsert the CanoKey, restart the calling application, or restart
`CertPropSvc` if Windows keeps the old module loaded.

This is a development shortcut only. Release packaging still needs a proper INF
and driver installation flow.

## Custom Debug Directory

The default debug deployment root is `C:/canokey-minidriver`. Override it at
configure time:

```powershell
cmake -S . -B out\build\x64-Clang-Debug -G Ninja `
  -DCMD_DEBUG_INSTALL_DIR=C:/Logs
```

The debug-install target also creates a default log directory. If
`CMD_DEBUG_LOG_DIR` is not set separately, CMake defaults it to:

```text
<CMD_DEBUG_INSTALL_DIR>/logs
```

You can also override the log directory:

```powershell
cmake -S . -B out\build\x64-Clang-Debug -G Ninja `
  -DCMD_DEBUG_INSTALL_DIR=C:/canokey-minidriver `
  -DCMD_DEBUG_LOG_DIR=C:/canokey-minidriver/logs
```

`CMD_DEBUG_LOG_DIR` is not compiled into the DLL. It only creates the directory
for local debugging. The DLL decides whether and where to write logs by reading
`LogPath` from `HKLM\SOFTWARE\Canokeys\ckmd`.

## Logging

The minidriver reads logging configuration from:

```text
HKLM\SOFTWARE\Canokeys\ckmd
```

Supported values:

- `LogPath` (`REG_SZ` or `REG_EXPAND_SZ`): log directory. If this value is
  absent, minidriver logging is completely disabled.
- `LogLevel` (`REG_SZ`): `trace`, `debug`, `info`, `warn`, `error`, `fatal`,
  `none`, or the corresponding numeric level. If `LogPath` exists and
  `LogLevel` is missing or invalid, the default is `warn`.
- `LogSensitiveData` (`REG_DWORD` or text bool): set to `1`, `true`, `yes`, or
  `on` to enable raw APDU/hex dumps. Leave this off unless the sensitive wire
  traffic is needed for local debugging.
- `NewKeyTouchPolicy` (`REG_DWORD`): YubiKey-style touch policy for keys
  created/imported through the minidriver: `1` = never, `2` = always,
  `3` = cached. The default is `1`.
- `NewKeyPinPolicy` (`REG_DWORD`): optional YubiKey-style PIN policy override
  for keys created/imported through the minidriver: `1` = never, `2` = once,
  `3` = always. If absent, generated keys use PIV defaults: 9E uses never and
  every other supported key slot uses once.
- `PinCacheTimeout` (`REG_DWORD`): number of seconds reported to Base CSP in
  `CP_CARD_PIN_INFO` as a timed PIN cache recommendation.

Runtime private-key operations honor the stored PIV PIN policy in
`canokey-pkcs11`: keys with PIN policy never can sign, decrypt, or derive
without a `CKU_USER` login; keys with PIN policy once or always require a
cached user PIN. The test scripts' `-NoPin` switch is therefore useful for
checking PIN-never keys, but existing 9A/9C/9D/82/83 keys with the default
PIN-once policy should still fail without a PIN.

The minidriver exposes three PIN identifiers to Windows:

- `ROLE_USER`: the PIV user PIN. It can be authenticated, changed with the
  current PIN, and unblocked/reset with the PIV PUK.
- `ROLE_ADMIN`: the PIV management key. It can be authenticated explicitly for
  development/provisioning flows, but cannot be changed through Windows PIN
  APIs.
- `CMD_ROLE_PUK`: the PIV PUK. It is an unblock-only secret advertised through
  `CP_CARD_PIN_INFO`; it is not a login role and cannot be changed through the
  minidriver.

`CardChangeAuthenticatorEx(PIN_CHANGE_FLAG_CHANGEPIN)` maps to
`C_SetPIN()` for `ROLE_USER`, and leaves the user PIN authenticated after a
successful change. `CardChangeAuthenticatorEx(PIN_CHANGE_FLAG_UNBLOCK)` and
`CardUnblockPin()` map to `C_CNK_UnblockPIN()`, then immediately log out so the
unblocked user PIN is deauthenticated as required by the Windows minidriver
contract. Nonzero retry-count changes and PUK changes are not supported.

For local regression testing:

```powershell
.\scripts\pin-test.ps1
```

This directly loads the debug minidriver, validates `CP_CARD_LIST_PINS` and
`CP_CARD_PIN_INFO`, changes the development PIN to a temporary value and back,
then uses the PIV PUK to reset the PIN to a temporary value and changes it back
again. PIV permits PUK-based PIN reset even when the PIN is not blocked, so the
test does not intentionally block the PIN. Use `-SkipPukReset` to avoid
exercising the PUK path.

Debug builds define `CMD_VERBOSE`. When `LogPath` enables logging, the
minidriver creates one log file per host process from `DllMain` and passes the
same `FILE *`, level, and sensitive-data flag to `canokey-pkcs11` through
`C_CNK_ConfigLogging()`. Standalone `canokey-pkcs11` still has its own
environment-variable logging, but the managed minidriver path is registry
controlled.

Log files are named like:

```text
canokey_minidriver_YYYYMMDD_HHMMSS_<process>_<pid>_<tid>.log
```

For verbose local APDU debugging, update the registry first:

```powershell
New-Item -Path HKLM:\SOFTWARE\Canokeys\ckmd -Force | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\Canokeys\ckmd -Name LogPath -Value 'C:\canokey-minidriver\logs' -PropertyType String -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Canokeys\ckmd -Name LogLevel -Value debug -PropertyType String -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Canokeys\ckmd -Name LogSensitiveData -Value 1 -PropertyType DWord -Force
.\scripts\smoke-scinfo.ps1 -SkipBuild -SkipInstall -SkipReset
```

## Automated Smoke Test

For the current development card, target the CanoKey reader directly and pass
the test PIN on the command line:

```powershell
certutil -silent -pin 123456 -scinfo "canokeys.org OpenPGP PIV OATH 0"
```

Specifying the reader name keeps `certutil` from probing Windows Hello or other
smart-card readers. Passing `-pin` avoids the Windows PIN prompt during repeated
debug runs. This is only appropriate for the local development key and its test
PIN.

The repository also has a convenience wrapper for the current debug loop:

```powershell
.\scripts\smoke-scinfo.ps1
```

By default it builds x64 Debug, runs the debug-install target, probes available
serial ports with the DevKit `status` command, resets through the responding
control port, and then runs the targeted `certutil` command above. COM numbers
are not stable across reconnects and firmware updates. A port that opens but
does not answer `status` is normally the UART interface. Use `-ComPort` only to
override discovery; the selected port is still validated before reset.

`certutil -scinfo` is a broad Windows smoke test: it exercises certificate
enumeration, public-key matching, PIN authentication, and private-key signing
through both the legacy Base Smart Card CSP and the Smart Card KSP paths.

## API Crypto Tests

For the full local API-level crypto matrix, use:

```powershell
.\scripts\crypto-test.ps1
```

The crypto tests use Windows CryptoAPI/CNG APIs directly instead of parsing
`certutil` output. It discovers containers with
`CryptGetProvParam(PP_ENUMCONTAINERS)` and `NCryptEnumKeys`, then verifies:

- CAPI RSA/SHA1 PKCS#1 through Microsoft Base Smart Card Crypto Provider
- CAPI RSA/SHA256 PKCS#1 through Microsoft Base Smart Card Crypto Provider
- CNG RSA/SHA256 PKCS#1 through Microsoft Smart Card Key Storage Provider
- CNG RSA/SHA256 PSS through Microsoft Smart Card Key Storage Provider
- CNG ECDSA P-256/SHA256 through Microsoft Smart Card Key Storage Provider
- CNG ECDH P-256 raw-secret derivation through Microsoft Smart Card Key Storage
  Provider, checked against a software-generated peer key
- CNG RSA PKCS#1 decrypt for discovered key-exchange RSA containers
- CNG RSA OAEP-SHA256 decrypt for discovered key-exchange RSA containers

Like the smoke wrapper, it defaults to building x64 Debug, running the debug
install target, discovering and resetting the DevKit control port, and passing
the local test PIN.
Use `-SkipBuild -SkipInstall -SkipReset` for a fast rerun against the currently
loaded DLL, and `-DiscoverOnly` to list containers without signing.

Focused entry points are also available when iterating on one capability:

```powershell
.\scripts\sign-test.ps1
.\scripts\decrypt-test.ps1
.\scripts\derive-test.ps1
```

All four scripts share `scripts\minidriver-test-common.ps1`, so
`crypto-test.ps1` can build, debug-install, reset, discover once, and then run
signing, decrypt, and derive tests without recompiling or reloading between
groups.

For the current development card, the full matrix passes with 9A RSA-2048
signing, 9C EC P-256 signing plus ECDH raw-secret derivation, and 9D RSA-2048
signing plus key exchange. The script opens CNG RSA signature keys with
`LegacyKeySpec = AT_SIGNATURE`, RSA decryption keys with
`LegacyKeySpec = AT_KEYEXCHANGE`, ECDSA keys with the matching `AT_ECDSA_*`
spec, and ECDH keys with the matching `AT_ECDHE_*` spec; using `0` for a
container that appears as multiple key specs can fail or open the wrong
algorithm group.

ECDH currently supports only raw secret derivation (`BCRYPT_KDF_RAW_SECRET`,
which maps to PKCS#11 `CKD_NULL`). `CardDeriveKey` does not yet implement
higher-level KDF parameter lists. The `pfnCspGetDHAgreement` member in
`CARD_DATA` is a callback from the CSP/KSP to the minidriver; keep it as a
caller-owned callback, and only call it later if supporting KDF buffers such as
`KDF_SECRET_HANDLE` / `KDF_NCRYPT_SECRET_HANDLE`.

When creating keys through Microsoft Smart Card KSP, callers select the smart
card provider and reader, not a PIV slot directly. The KSP reads `mscp/cmapfile`
and chooses a container index for the new key; the minidriver maps container
indexes `0..5` to PIV object IDs `1..6` (`9A`, `9C`, `9D`, `9E`, `82`, `83`).
Creating a new smart-card key must not use a silent context: Microsoft documents
that new smart-card containers can require UI, and local testing showed
`certreq -q`/`Silent = true` and `NCRYPT_SILENT_FLAG` stop before
`CardCreateContainer*`. Non-silent `NCryptFinalizeKey` first writes the root
`cardcf` cache file and an updated `mscp/cmapfile` before continuing toward
container selection, so keep both writes tolerant even though the authoritative
state comes from CanoKey metadata.

Local testing also showed that the KSP does not automatically ask for
`ROLE_ADMIN` when `CardCreateContainer` fails because the underlying PIV
operation needs the management key. The KSP authenticates `ROLE_USER`, chooses
the next container from `mscp/cmapfile`, and then calls `CardCreateContainer`.
For CanoKey/PIV, key generation and private-key import therefore need an
explicit management-key path, such as a provisioning/debug tool that calls
`CardAuthenticateEx(ROLE_ADMIN)` first, or a later secure configuration bridge.

YubiKey appears to bridge this gap with its "protect management key with PIN"
model: the management key is stored on-card in a PIN-protected object, so the
minidriver can recover it after the normal user PIN prompt and then perform PIV
management operations on behalf of Windows. CanoKey will need an equivalent
card-side PIN-protected management-key mechanism, or a local development-only
configuration such as an explicit management-key registry value, before normal
Windows KSP enrollment can generate/import PIV keys without a separate
provisioning tool. See `docs/pin-only-management-key.md` for the current
research notes and proposed PKCS#11/minidriver split.

Certificate files (`kscN` and `kxcN`) are different from key generation.
Windows expects user certificate files to behave like everyone-read/user-write
files for enumeration and enrollment plumbing, so `CardGetFileInfo` reports
`EveryoneReadUserWriteAc` for them. The actual PIV certificate write is still a
card-management operation: `CardWriteFile` requires `ROLE_ADMIN`
authentication before passing the certificate to PKCS#11.

## INF Installation

INF installation is still useful for release-style validation, PnP/device
manager testing, and final packaging work. It is not required for the
registry-only debug loop above.

Do not run `pnputil`, install the INF, enable test signing, or delete installed
driver packages unless that is the task at hand.
