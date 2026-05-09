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
  (`C:/canokey-minidriver` by default) and creates `CMD_LOG_DIR`
  (`C:/canokey-minidriver/logs` by default):

```powershell
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

## Development Hygiene

- Run `clang-format` on touched C source and header files before committing.
- The repository has a `.clang-format`; use that style rather than introducing
  local formatting preferences.
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
- Debug builds write minidriver logs under the compiled `CMD_LOG_DIR` when
  loaded by a host process.

## Local Debug Loop

- The current preferred smoke test is:

```powershell
.\build.ps1 -Arch x64
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
certutil -silent -pin 123456 -scinfo "canokeys.org OpenPGP PIV OATH 0"
```

- The test/debug CanoKey can be USB-reset through the helper board on `COM3`.
  To make Windows unload/reload the smart card stack after copying a new DLL,
  open `COM3`, write `reset ciu` followed by a carriage return/newline, then
  wait a few seconds before running the next probe. This simulates unplugging
  and replugging the device without touching the INF.
- Use `COM3` for this reset path. Do not fall back to `COM4`. If opening
  `COM3` fails with `Access denied` or `not currently available`, check for an
  existing serial monitor/debugger holding the port before retrying.
- The working PowerShell reset snippet is:

```powershell
$port = New-Object System.IO.Ports.SerialPort 'COM3',38400,'None',8,'One'
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

- The smoke wrapper treats the current WIP `certutil` trailing
  `NTE_BAD_KEYSET` result as non-fatal. Pass `-StrictExitCode` when the exact
  `certutil` process exit code matters.
- Logs are written under `C:/canokey-minidriver/logs` by default. The most useful
  files are usually from `certutil.exe`, `CredentialUIBroker.exe`, and
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
- The current development card has useful PIV material in:

```text
ID 01 -> PIV 9A -> RSA-2048 key and certificate
ID 02 -> PIV 9C -> EC P-256 key and certificate
```

- Do not hardcode the development PIN in minidriver code. Authentication must
  enter through `CardAuthenticateEx`; signing should use the authenticated
  PKCS#11 session state.

## Implementation Notes

- `canokey-minidriver.inf` is generated from `canokey-minidriver.inf.in`.
- The PKCS#11 dependency is linked statically into the minidriver target.
- `CMD_DEBUG_INSTALL_DIR` and `CMD_LOG_DIR` are CMake cache variables and are
  compiled into the DLL as preprocessor definitions.
- The minidriver uses CanoKey PKCS#11 managed mode; initialize managed mode
  before `C_Initialize()` when wiring card handles through this layer.
- `CardAcquireContext` owns one PKCS#11 session in `CMD_CONTEXT`. Always close
  that session in `CardDeleteContext` before finalizing PKCS#11; otherwise
  repeated Windows probes can exhaust the session table and fail later
  acquisitions with `CKR_HOST_MEMORY` / "No free session slots available".
