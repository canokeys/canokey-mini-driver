# CanoKey Mini Driver

Windows smart card minidriver for CanoKey, built on top of
[`canokey-pkcs11`](external/canokey-pkcs11).

**Status:** this project is still WIP, but the development loop is usable.
Windows can load the DLL through a Calais smart card registry mapping without
installing the generated INF. Current local testing can enumerate the CanoKey
PIV certificates and run CSP/KSP signing and RSA decryption tests against the
development card. Release packaging, INF installation, and broader PIV slot
coverage are still in progress.

## Current State

- Debug loading works by copying `canokey-minidriver.dll` to
  `C:\canokey-minidriver\` and registering that path under the CanoKey ATR.
- Debug logs are written under `C:\canokey-minidriver\logs\` by default.
- `certutil -scinfo` can see the card and current certificates.
- `scripts\sign-test.ps1` exercises the minidriver through Windows CAPI/CNG
  APIs instead of parsing command output.
- The current development card has been tested with 9A RSA-2048 signing, 9C
  EC P-256 signing, and 9D RSA-2048 signing plus key exchange/decryption.

Known gaps:

- Full YubiKey-style PIV slot mapping still needs broader card coverage.
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

You can configure the project with CMake (or use Visual Studio GUI).
You must use `clang-cl` as the frontend, or `external/dbg.h` will fail to
compile.

After successful build, you will get `canokey-minidriver.{inf,dll}` in your build output directory.

The helper script uses the same defaults as the local debug workflow:

```powershell
.\build.ps1 -Arch x64 -Config Debug
```

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
`C:\canokey-minidriver\logs\`. Import the debug registry mapping described in
[`docs/development.md`](docs/development.md), then unplug and reinsert your
CanoKey or restart the calling application.

Useful local checks:

```powershell
.\scripts\smoke-scinfo.ps1
.\scripts\sign-test.ps1
```

`smoke-scinfo.ps1` drives `certutil -silent -pin ... -scinfo` against the
CanoKey reader. `sign-test.ps1` uses Windows cryptographic APIs directly to
enumerate containers and test signing. If a decrypt-capable RSA KSP container
is present, it also runs CNG PKCS#1 and OAEP-SHA256 decrypt checks.

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
