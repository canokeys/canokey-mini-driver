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
- Build outputs are under `out/build/<arch>-Clang-<config>/`, for example:

```text
out/build/x64-Clang-Debug/canokey-minidriver.dll
out/build/x64-Clang-Debug/canokey-minidriver.inf
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
- Do not enable test signing, install the driver, delete installed driver
  packages, restart Windows services, or write to system driver stores unless
  the user directly requests that action.
- Debug builds write minidriver logs under `C:\Logs` when loaded by a host
  process.

## Implementation Notes

- `canokey-minidriver.inf` is generated from `canokey-minidriver.inf.in`.
- The PKCS#11 dependency is linked statically into the minidriver target.
- The minidriver uses CanoKey PKCS#11 managed mode; initialize managed mode
  before `C_Initialize()` when wiring card handles through this layer.
