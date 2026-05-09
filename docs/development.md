# Development Notes

## Registry-only Minidriver Loading

For local debugging, Windows can load the minidriver through the Calais smart
card registry mapping without installing the INF. This is much faster than the
driver package flow and is the recommended development loop for now.

Build the minidriver:

```powershell
.\build.ps1 -Arch x64
```

Copy the DLL and create the log directory:

```powershell
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

By default this copies:

```text
C:\canokey-minidriver\canokey-minidriver.dll
```

and creates:

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

If `CMD_LOG_DIR` is not set separately, CMake defaults it to:

```text
<CMD_DEBUG_INSTALL_DIR>/logs
```

You can also override the log directory:

```powershell
cmake -S . -B out\build\x64-Clang-Debug -G Ninja `
  -DCMD_DEBUG_INSTALL_DIR=C:/canokey-minidriver `
  -DCMD_LOG_DIR=C:/canokey-minidriver/logs
```

`build.ps1` keeps the default unless you configure the build directory manually.

## Logging

Debug builds define `CMD_VERBOSE`, initialize minidriver logging from
`DllMain`, and pass the same `FILE *` to `canokey-pkcs11` through
`C_CNK_ConfigLogging()`.

Log files are named like:

```text
canokey_minidriver_YYYYMMDD_HHMMSS_<process>_<pid>_<tid>.log
```

The default location is:

```text
C:\canokey-minidriver\logs\
```

The log directory is compiled into the DLL through `CMD_LOG_DIR`, so if you
change it, rebuild the DLL and rerun `canokey-minidriver-debug-install`.

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

By default it builds x64 Debug, runs the debug-install target, resets the
development board through `COM3`, and then runs the targeted `certutil` command
above.

`certutil -scinfo` is a broad Windows smoke test: it exercises certificate
enumeration, public-key matching, PIN authentication, and private-key signing
through both the legacy Base Smart Card CSP and the Smart Card KSP paths.

## Signing Matrix Test

For targeted signing coverage, use:

```powershell
.\scripts\sign-test.ps1
```

The signing test uses Windows CryptoAPI/CNG APIs directly instead of parsing
`certutil` output. It discovers containers with
`CryptGetProvParam(PP_ENUMCONTAINERS)` and `NCryptEnumKeys`, then verifies:

- CAPI RSA/SHA1 PKCS#1 through Microsoft Base Smart Card Crypto Provider
- CAPI RSA/SHA256 PKCS#1 through Microsoft Base Smart Card Crypto Provider
- CNG RSA/SHA256 PKCS#1 through Microsoft Smart Card Key Storage Provider
- CNG RSA/SHA256 PSS through Microsoft Smart Card Key Storage Provider
- CNG ECDSA P-256/SHA256 through Microsoft Smart Card Key Storage Provider
- CNG RSA PKCS#1 decrypt for discovered key-exchange RSA containers
- CNG RSA OAEP-SHA256 decrypt for discovered key-exchange RSA containers

Like the smoke wrapper, it defaults to building x64 Debug, running the debug
install target, resetting the board on `COM3`, and passing the local test PIN.
Use `-SkipBuild -SkipInstall -SkipReset` for a fast rerun against the currently
loaded DLL, and `-DiscoverOnly` to list containers without signing.

For the current development card, the full matrix passes with 9A RSA-2048
signing, 9C EC P-256 signing, and 9D RSA-2048 signing plus key exchange. The
script opens CNG signature keys with `LegacyKeySpec = AT_SIGNATURE` and
decryption keys with `LegacyKeySpec = AT_KEYEXCHANGE`; using `0` for a container
that appears as both key specs can fail with `NTE_BAD_KEYSET`.

## INF Installation

INF installation is still useful for release-style validation, PnP/device
manager testing, and final packaging work. It is not required for the
registry-only debug loop above.

Do not run `pnputil`, install the INF, enable test signing, or delete installed
driver packages unless that is the task at hand.
