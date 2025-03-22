# Set paths
$buildDir = "./out/build/arm64-Clang-Debug"
$infName = "canokey-minidriver.inf"

Write-Host "Step 1: Building project..."
Push-Location $buildDir
$buildResult = cmake --build . 2>&1
Pop-Location

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed:"
    Write-Output $buildResult
    exit 1
}
Write-Host "Build succeeded."

# Step 2: Uninstall existing driver if present
Write-Host "Step 2: Searching for existing driver..."
$driverList = pnputil /enum-drivers
$infRegex = [regex]::Escape($infName)

# Use Select-String with context to find the oemXXX.inf line before the matching INF line
$oemMatch = $null
$match = $driverList | Select-String -Pattern $infRegex -Context 1,0

if ($match -and $match.Context.PreContext.Count -gt 0) {
    $prevLine = $match.Context.PreContext[-1]
    if ($prevLine -like "*:*") {
        $oemMatch = $prevLine.Split(":")[1].Trim()
    }
}

if (!$oemMatch) {
    Write-Host "No matching installed INF found. Skipping uninstall."
} else {
    Write-Host "Found driver: $oemMatch. Uninstalling..."
    pnputil /delete-driver $oemMatch /uninstall /force
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Driver uninstall failed. Aborting."
        exit 1
    }
    Write-Host "Driver uninstalled successfully."
}

# Step 3: Install new driver
Write-Host "Step 3: Installing new driver..."
$infPath = Join-Path $buildDir $infName
pnputil /add-driver $infPath /install
