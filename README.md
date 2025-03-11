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

After successful build, you will get `canokey_minidriver.{inf,dll}` in your build output directory.

## Test

1. Before loading the mini driver, you should [enable test signing mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) and reboot.
1. Right-click on `canokey_minidriver.inf` and select `Install`, then ignore any warnings.
1. Insert your CanoKey, go to Device Manager - Smart card readers. If Microsoft driver is loaded, right-click and select "Update driver" - "Browse my computer for drivers" and select "Let me pick from a list of available drivers on my computer", then select "CanoKey Mini Driver".
1. Unplug and reinsert your CanoKey, you should now see log files under `C:\Logs\`.

If you would like to test a new version, you **should** uninstall the old driver first.
To do so, right-click on `canokey_minidriver.inf` and select `Uninstall`, check "Delete the driver software for this device" and click `OK`.
Then you can install the new version and test again.