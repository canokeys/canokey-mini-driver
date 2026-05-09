# CanoKey Mini Driver

**Note: This project is still WIP.**

## Build

### Prerequisites

Install Visual Studio 2022 with:

- Desktop development with C++
- Clang Support
- Windows Driver Kit (download from [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))

### Build with CMake

You can configure the project with CMake (or use Visual Studio GUI).
You must you clang-cl as frontend, or `thirdpart/dbg.h` will fail to compile.

After successful build, you will get `canokey-minidriver.{inf,dll}` in your build output directory.

## Test

For development, you do not need to install the INF. Windows can load the
minidriver through the Calais smart card registry mapping:

```powershell
.\build.ps1 -Arch x64
cmake --build out\build\x64-Clang-Debug --target canokey-minidriver-debug-install
```

This copies the DLL to `C:\canokey-minidriver\` and creates
`C:\canokey-minidriver\logs\`. Import the debug registry mapping described in
[`docs/development.md`](docs/development.md), then unplug and reinsert your
CanoKey or restart the calling application.

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
