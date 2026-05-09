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

## INF Installation

INF installation is still useful for release-style validation, PnP/device
manager testing, and final packaging work. It is not required for the
registry-only debug loop above.

Do not run `pnputil`, install the INF, enable test signing, or delete installed
driver packages unless that is the task at hand.
