param(
    [ValidateSet("x86", "x64", "arm64", "arm64x", "all")]
    [string]$Arch = "x64",

    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Debug",

    [string]$Python3Executable,

    [switch]$CleanFirst,
    [switch]$VerboseBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($repoRoot)) {
    $repoRoot = (Get-Location).Path
}

$cmakeName = "canokey-minidriver"
$vsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"

if ([string]::IsNullOrWhiteSpace($Python3Executable) -and ![string]::IsNullOrWhiteSpace($env:Python3_EXECUTABLE)) {
    $Python3Executable = $env:Python3_EXECUTABLE
}

if (![string]::IsNullOrWhiteSpace($Python3Executable)) {
    $resolvedPython = Resolve-Path -LiteralPath $Python3Executable -ErrorAction Stop
    $Python3Executable = $resolvedPython.ProviderPath
}

function Find-VisualStudio {
    if (Test-Path -LiteralPath $vsWhere) {
        $installPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -eq 0 -and ![string]::IsNullOrWhiteSpace($installPath)) {
            return $installPath.Trim()
        }
    }

    $candidates = @(
        Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community",
        Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Professional",
        Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Enterprise",
        Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\BuildTools"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $candidate "Common7\Tools\VsDevCmd.bat")) {
            return $candidate
        }
    }

    throw "Visual Studio 2022 with C++ tools was not found."
}

function Convert-ArchName {
    param([string]$TargetArch)

    switch ($TargetArch) {
        "x86" { return "x86" }
        "x64" { return "x64" }
        "arm64" { return "arm64" }
        default { throw "Unsupported architecture: $TargetArch" }
    }
}

function Get-ClangTarget {
    param([string]$TargetArch)

    switch ($TargetArch) {
        "x86" { return "i686-pc-windows-msvc" }
        "x64" { return "amd64-pc-windows-msvc" }
        "arm64" { return "arm64-pc-windows-msvc" }
        default { throw "Unsupported architecture: $TargetArch" }
    }
}

function Get-VsToolPath {
    param(
        [string]$VsInstall,
        [string]$RelativePath
    )

    $path = Join-Path $VsInstall $RelativePath
    if (!(Test-Path -LiteralPath $path)) {
        throw "Required Visual Studio tool was not found: $path"
    }
    return $path
}

function Get-LatestMsvcToolsetPath {
    param([string]$VsInstall)

    $msvcRoot = Join-Path $VsInstall "VC\Tools\MSVC"
    if (!(Test-Path -LiteralPath $msvcRoot)) {
        throw "MSVC toolset directory was not found: $msvcRoot"
    }

    $toolset = Get-ChildItem -LiteralPath $msvcRoot -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $toolset) {
        throw "No MSVC toolset was found under: $msvcRoot"
    }

    return $toolset.FullName
}

function Assert-MsvcTargetLibraries {
    param(
        [string]$VsInstall,
        [string]$TargetArch,
        [string]$BuildConfig
    )

    $toolsetPath = Get-LatestMsvcToolsetPath $VsInstall
    $libDir = Join-Path $toolsetPath "lib\$TargetArch"
    # CMake selects the debug CRT only for Debug; the other configurations
    # link the release CRT. Check the same runtime that the linker will use.
    $runtimeLibrary = if ($BuildConfig -eq "Debug") { "msvcrtd.lib" } else { "msvcrt.lib" }
    $requiredLibs = @($runtimeLibrary, "oldnames.lib")

    foreach ($lib in $requiredLibs) {
        $libPath = Join-Path $libDir $lib
        if (!(Test-Path -LiteralPath $libPath)) {
            throw "Missing MSVC $TargetArch library $lib. Install the Visual Studio C++ $TargetArch build tools."
        }
    }
}

function Invoke-VsCommand {
    param(
        [string]$VsInstall,
        [string]$TargetArch,
        [string]$Command
    )

    $vsDevCmd = Get-VsToolPath $VsInstall "Common7\Tools\VsDevCmd.bat"
    $hostArch = "x64"
    $cmdLine = "`"$vsDevCmd`" -arch=$TargetArch -host_arch=$hostArch && $Command"
    & cmd.exe /s /c $cmdLine
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE."
    }
}

function Invoke-CMakeBuild {
    param(
        [string]$VsInstall,
        [string]$TargetArch
    )

    $cmake = Get-VsToolPath $VsInstall "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    $ninja = Get-VsToolPath $VsInstall "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
    $clangCl = Get-VsToolPath $VsInstall "VC\Tools\Llvm\x64\bin\clang-cl.exe"

    $normalizedArch = Convert-ArchName $TargetArch
    Assert-MsvcTargetLibraries $VsInstall $normalizedArch $Config

    $clangTarget = Get-ClangTarget $normalizedArch
    $buildDir = Join-Path $repoRoot "out\build\$normalizedArch-Clang-$Config"
    $installDir = Join-Path $repoRoot "out\install\$normalizedArch-Clang-$Config"

    Write-Host "Configuring $normalizedArch $Config..."
    $configureCommand = @(
        "`"$cmake`"",
        "-S `"$repoRoot`"",
        "-B `"$buildDir`"",
        "-G Ninja",
        "-DCMAKE_MAKE_PROGRAM=`"$ninja`"",
        "-DCMAKE_C_COMPILER=`"$clangCl`"",
        "-DCMAKE_CXX_COMPILER=`"$clangCl`"",
        "-DCMAKE_C_COMPILER_TARGET=$clangTarget",
        "-DCMAKE_CXX_COMPILER_TARGET=$clangTarget",
        "-DCMAKE_BUILD_TYPE=$Config",
        "-DCMAKE_INSTALL_PREFIX=`"$installDir`""
    )
    if (![string]::IsNullOrWhiteSpace($Python3Executable)) {
        $configureCommand += "-DPython3_EXECUTABLE=`"$Python3Executable`""
    }
    $configureCommand = $configureCommand -join " "
    Invoke-VsCommand $VsInstall $normalizedArch $configureCommand

    Write-Host "Building $normalizedArch $Config..."
    $buildArgs = @("`"$cmake`"", "--build `"$buildDir`"")
    if ($CleanFirst) {
        $buildArgs += "--clean-first"
    }
    if ($VerboseBuild) {
        $buildArgs += "-v"
    }

    Invoke-VsCommand $VsInstall $normalizedArch ($buildArgs -join " ")

    $dllPath = Join-Path $buildDir "$cmakeName.dll"
    $infPath = Join-Path $buildDir "$cmakeName.inf"
    if (!(Test-Path -LiteralPath $dllPath)) {
        throw "Expected DLL was not produced: $dllPath"
    }
    if (!(Test-Path -LiteralPath $infPath)) {
        throw "Expected INF was not produced: $infPath"
    }

    Write-Host "Built:"
    Write-Host "  $dllPath"
    Write-Host "  $infPath"
}

function Invoke-Arm64XBuild {
    param(
        [string]$VsInstall
    )

    $cmake = Get-VsToolPath $VsInstall "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    $ninja = Get-VsToolPath $VsInstall "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
    $clangCl = Get-VsToolPath $VsInstall "VC\Tools\Llvm\x64\bin\clang-cl.exe"
    $toolsetPath = Get-LatestMsvcToolsetPath $VsInstall
    $linker = Join-Path $toolsetPath "bin\Hostx64\x64\link.exe"
    $libTool = Join-Path $toolsetPath "bin\Hostx64\x64\lib.exe"
    $windowsKitLibRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib"
    $windowsKit = Get-ChildItem -LiteralPath $windowsKitLibRoot -Directory |
        Where-Object { $_.Name -match '^10\.' } |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $windowsKit) {
        throw "No Windows SDK library directory was found under: $windowsKitLibRoot"
    }
    $arm64RuntimeLib = Join-Path $windowsKit.FullName "um\arm64\arm64rt.lib"
    if (!(Test-Path -LiteralPath $linker)) {
        throw "Required ARM64X linker was not found: $linker"
    }
    if (!(Test-Path -LiteralPath $libTool)) {
        throw "Required ARM64X import-library tool was not found: $libTool"
    }
    if (!(Test-Path -LiteralPath $arm64RuntimeLib)) {
        throw "Required ARM64X support library was not found: $arm64RuntimeLib"
    }

    $x64BuildDir = Join-Path $repoRoot "out\build\x64-Clang-$Config"
    $arm64BuildDir = Join-Path $repoRoot "out\build\arm64-Clang-$Config"
    $x64Dll = Join-Path $x64BuildDir "$cmakeName.dll"
    $arm64Dll = Join-Path $arm64BuildDir "$cmakeName.dll"
    foreach ($input in @($x64Dll, $arm64Dll)) {
        if (!(Test-Path -LiteralPath $input)) {
            throw "ARM64X input is missing. Build x64 and arm64 $Config first: $input"
        }
    }

    $buildDir = Join-Path $repoRoot "out\build\arm64x-Clang-$Config"
    $installDir = Join-Path $repoRoot "out\install\arm64x-Clang-$Config"
    Write-Host "Configuring arm64x $Config..."
    $configureCommand = @(
        "`"$cmake`"",
        "-S `"$repoRoot`"",
        "-B `"$buildDir`"",
        "-G Ninja",
        "-DCMAKE_MAKE_PROGRAM=`"$ninja`"",
        "-DCMAKE_C_COMPILER=`"$clangCl`"",
        "-DCMAKE_C_COMPILER_TARGET=amd64-pc-windows-msvc",
        "-DCMAKE_BUILD_TYPE=$Config",
        "-DCMAKE_INSTALL_PREFIX=`"$installDir`"",
        "-DCMD_BUILD_ARM64X_FORWARDER=ON",
        "-DCMD_ARM64X_X64_DLL=`"$x64Dll`"",
        "-DCMD_ARM64X_ARM64_DLL=`"$arm64Dll`"",
        "-DCMD_ARM64X_X64_DLL_NAME=canokey-minidriver-x64.dll",
        "-DCMD_ARM64X_ARM64_DLL_NAME=canokey-minidriver-arm64.dll",
        "-DCMD_ARM64X_LIB_TOOL=`"$libTool`"",
        "-DCMD_ARM64X_ARM64RT_LIB=`"$arm64RuntimeLib`"",
        "-DCMD_ARM64X_LINKER=`"$linker`""
    )
    if (![string]::IsNullOrWhiteSpace($Python3Executable)) {
        $configureCommand += "-DPython3_EXECUTABLE=`"$Python3Executable`""
    }
    Invoke-VsCommand $VsInstall "x64" ($configureCommand -join " ")

    Write-Host "Building arm64x $Config..."
    $buildArgs = @("`"$cmake`"", "--build `"$buildDir`"")
    if ($CleanFirst) {
        $buildArgs += "--clean-first"
    }
    if ($VerboseBuild) {
        $buildArgs += "-v"
    }
    Invoke-VsCommand $VsInstall "x64" ($buildArgs -join " ")

    foreach ($output in @(
            (Join-Path $buildDir "$cmakeName.dll"),
            (Join-Path $buildDir "$cmakeName.lib"),
            (Join-Path $buildDir "$cmakeName.inf"),
            (Join-Path $buildDir "canokey-minidriver-x64.dll"),
            (Join-Path $buildDir "canokey-minidriver-arm64.dll"))) {
        if (!(Test-Path -LiteralPath $output)) {
            throw "Expected ARM64X output was not produced: $output"
        }
    }
    Write-Host "Built:"
    Write-Host "  $(Join-Path $buildDir "$cmakeName.dll")"
    Write-Host "  $(Join-Path $buildDir "$cmakeName.lib")"
    Write-Host "  $(Join-Path $buildDir "$cmakeName.inf")"
}

$vsInstall = Find-VisualStudio
$targetArchs = if ($Arch -eq "all") {
    @("x86", "x64", "arm64", "arm64x")
} else {
    @($Arch)
}

foreach ($targetArch in $targetArchs) {
    if ($targetArch -eq "arm64x") {
        Invoke-Arm64XBuild $vsInstall
    } else {
        Invoke-CMakeBuild $vsInstall $targetArch
    }
}

Write-Host "Build succeeded."
