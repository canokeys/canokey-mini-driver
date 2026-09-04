# Architecture Distribution

This document describes the Windows architecture layout for the CanoKey
minidriver. It covers CI artifacts and the registry-only development flow. It
does not claim that the current INF is ready for release installation; the
current INF still needs architecture-specific DDInstall sections.

## Artifact Layout

Each Visual Studio runner publishes one Debug and one Release artifact:

```text
canokey-mini-driver-debug-vs2022
canokey-mini-driver-release-vs2022
canokey-mini-driver-debug-vs2026
canokey-mini-driver-release-vs2026
```

Each artifact contains one file set for every supported output architecture:

```text
canokey-minidriver-x86.dll
canokey-minidriver-x86.lib
canokey-minidriver-x64.dll
canokey-minidriver-x64.lib
canokey-minidriver-arm64.dll
canokey-minidriver-arm64.lib
canokey-minidriver-arm64x.dll
canokey-minidriver-arm64x.lib
```

The `.lib` files are import libraries for applications that link to the
minidriver entry point. They are not runtime dependencies and must not be
installed in a Windows system directory.

The Arm64X forwarder is built from the x64 and ARM64 implementation outputs
with the same configuration. Its runtime set is:

```text
canokey-minidriver-arm64x.dll
canokey-minidriver-x64.dll
canokey-minidriver-arm64.dll
```

Keep these three DLLs in the same directory. The forwarder exports the same
`CardAcquireContext` and `DllMain` names as the implementation DLLs and routes
the native Arm64 view to the ARM64 DLL and the x64-compatible view to the x64
DLL. The forwarder contains no minidriver or PKCS#11 implementation code.

Do not mix Debug and Release files. Do not combine implementation DLLs from
different Visual Studio runners when diagnosing a failure; select one runner's
artifact as a complete set.

## Runtime Matrix

| Windows OS | Calling process | Calais view | DLL registered in `80000001` | Required files |
| --- | --- | --- | --- | --- |
| x86 | x86 | native | `canokey-minidriver-x86.dll` | x86 DLL |
| x64 | x64 | native 64-bit | `canokey-minidriver-x64.dll` | x64 DLL |
| x64 | x86 under WOW64 | 32-bit | `canokey-minidriver-x86.dll` | x86 DLL |
| ARM64 | native Arm64 | native 64-bit | `canokey-minidriver-arm64x.dll` | Arm64X, x64, ARM64 DLLs |
| ARM64 | x64 emulation | native 64-bit | `canokey-minidriver-arm64x.dll` | Arm64X, x64, ARM64 DLLs |

On x64 Windows, native 64-bit and WOW64 registry views can select different
DLLs. Keep the DLL names distinct or place generic names in separate
directories. The x86 process must see the 32-bit Calais view and the x86 DLL.

On ARM64 Windows, x64 emulation does not provide a second 64-bit registry or
system-directory view. Native Arm64 and x64 callers therefore use the same
Calais value and must be served by the Arm64X forwarder. The forwarder must not
be replaced with the plain ARM64 implementation DLL.

## Registry-Only Development Mapping

The registry-only flow does not install an INF or a driver package. It writes a
Calais mapping to a DLL path for local testing.

### x64 Windows, native 64-bit path

Register the native 64-bit Calais view with the x64 implementation:

```text
HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\CanoKey
  80000001 = C:\canokey-minidriver\canokey-minidriver-x64.dll
```

The file can retain its architecture suffix. Renaming it to the generic
`canokey-minidriver.dll` is optional.

### x64 Windows, x86 path

Register the 32-bit/WOW64 Calais view with the x86 implementation:

```text
32-bit Calais view
  80000001 = C:\canokey-minidriver\canokey-minidriver-x86.dll
```

If both views use the generic filename, place the x64 copy in the native
system directory and the x86 copy in the WOW64 system directory. Do not put
two files with the same name in one directory.

### ARM64 Windows

Register the native 64-bit Calais view with the Arm64X forwarder:

```text
HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\CanoKey
  80000001 = C:\canokey-minidriver\canokey-minidriver-arm64x.dll
```

The same directory must contain:

```text
C:\canokey-minidriver\canokey-minidriver-arm64x.dll
C:\canokey-minidriver\canokey-minidriver-x64.dll
C:\canokey-minidriver\canokey-minidriver-arm64.dll
```

The Calais value is a string path. The registry does not select between the
x64 and ARM64 implementation DLLs; the Arm64X loader does that after the
forwarder is loaded.

## Current INF Status

The generated `canokey-minidriver.inf` remains in each build directory for
development and future packaging, but it is intentionally excluded from CI
artifacts. It is not a complete multi-architecture release installer. These
issues must be fixed before using it for package installation:

1. `CanoKey.NTamd64.6.1`, `CanoKey.NTx86.6.1`, and `CanoKey.NTarm64.10` all
   reference `CanoKeyMiniDriver_amd64_Install`.
2. That install section enables only `CopyFiles_amd64` and `AddReg_default`.
   `CopyFiles_arm64`, `CopyFiles_x86`, `CopyFiles_wow64`, and `AddReg_wow64`
   are not connected to active install sections.
3. The ARM64X package needs to copy the forwarder plus both implementation DLLs
   to the same runtime directory. The current copy sections only describe one
   minidriver DLL.
4. The template still uses the old `SmartCardModuleAMD64` name
   (`canokey-minidriver-amd64.dll`), while the CI artifact uses the explicit
   `canokey-minidriver-x64.dll` name.
5. The CI artifact deliberately contains no INF until the source-disk and
   copy-file entries can describe each package layout accurately.

The formal INF should use separate architecture-specific install sections and
register the filename that is actually copied for that OS. For an ARM64X
package, its ARM64 section must copy all three runtime DLLs and register the
forwarder as `80000001`. The x64 and x86 sections must register their own
implementation DLLs in the appropriate registry/filesystem view.

## ARM32 Status

This repository does not currently build or publish a 32-bit ARM (`ARM`, often
called ARM32) minidriver. `build.ps1` supports only `x86`, `x64`, `arm64`, and
`arm64x`; there is no ARM32 compiler target, output artifact, or validated INF
section.

Do not install the x86 DLL as an ARM32 DLL. Do not infer ARM32 compatibility
from the ARM64 build. A future ARM32 port would need a separate `arm` build,
an ARM32-compatible PKCS#11/PCSC dependency set, ARM32 Calais registration,
and a native ARM32 smart-card host acceptance test. Windows ARM32 registry and
filesystem redirection is distinct from x86 WOW64 redirection, so an x86 view
is not evidence for ARM32 support.

## Validation Rules

Before release packaging:

1. Check every final DLL machine type with `llvm-readobj --file-headers`.
2. For ARM64X, verify the `.a64xrm` section and test both a native Arm64 host
   and an x64 process on Windows ARM64.
3. Verify that `80000001` resolves to the intended file in the intended
   registry view.
4. For ARM64X, keep all three runtime DLLs beside the forwarder and verify that
   both implementation names match the forwarding DEF files.
5. Run `certutil -silent -pin ... -scinfo` and one signing operation after a
   card reset/reinsert. An emulated x64 test alone does not validate the native
   Arm64 Smart Card host.
