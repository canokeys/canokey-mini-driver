param(
    [ValidateSet("x64", "arm64", "all")]
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
        "x64" { return "x64" }
        "arm64" { return "arm64" }
        default { throw "Unsupported architecture: $TargetArch" }
    }
}

function Get-ClangTarget {
    param([string]$TargetArch)

    switch ($TargetArch) {
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
        [string]$TargetArch
    )

    $toolsetPath = Get-LatestMsvcToolsetPath $VsInstall
    $libDir = Join-Path $toolsetPath "lib\$TargetArch"
    $requiredLibs = @("msvcrtd.lib", "oldnames.lib")

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
    Assert-MsvcTargetLibraries $VsInstall $normalizedArch

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

$vsInstall = Find-VisualStudio
$targetArchs = if ($Arch -eq "all") {
    @("x64", "arm64")
} else {
    @($Arch)
}

foreach ($targetArch in $targetArchs) {
    Invoke-CMakeBuild $vsInstall $targetArch
}

Write-Host "Build succeeded."
