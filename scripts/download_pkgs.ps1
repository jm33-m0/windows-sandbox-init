# Function to log messages
function logMessage {
    param (
        [string] $message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    $logEntry | Out-File -FilePath $logFile -Append
    Write-Verbose $logEntry
}

# Current directory: root of the repository
$cwd = Get-Location -ErrorAction Stop
$logFile = "$cwd\download_pkgs.log"

# Change to the packages directory
$packagePath = "..\packages"
Set-Location -Path $packagePath -ErrorAction Stop
$packagePath = Get-Location -ErrorAction Stop
$manifestPath = "$packagePath\packages.json"

# Initialize log file
logMessage "========== Starting download process =========="
logMessage "Working directory: $packagePath"
logMessage "Manifest path: $manifestPath"

# Define bootstrap package info mapping filename to URL and checksum
$bootstrapPackageInfo = @{
    "aria2.zip"      = @{
        url       = "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip"
        sha256sum = "67d015301eef0b612191212d564c5bb0a14b5b9c4796b76454276a4d28d9b288"
    }
    "7z.exe"         = @{
        url       = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-x64.exe"
        sha256sum = "78afa2a1c773caf3cf7edf62f857d2a8a5da55fb0fff5da416074c0d28b2b55f"
    }
    "AutoHotKey.exe" = @{
        url       = "https://www.autohotkey.com/download/ahk-v2.exe"
        sha256sum = "fd55129cbd356f49d2151e0a8b9662d90d2dbbb9579cc2410fde38df94787a3a"
    }
    "tun2socks.zip"  = @{
        url       = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-windows-amd64-v3.zip"
        sha256sum = "fa10f679bf7e6c2380af72b588cd0f61cb7c382b86f991d76eb9b96f4e104352"
    }
    "wintun.zip"     = @{
        url       = "https://www.wintun.net/builds/wintun-0.14.1.zip"
        sha256sum = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
    }
}

# Function to calculate file checksum
function getFileChecksum {
    param (
        [string]$filePath
    )
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    return $hash.Hash.ToUpper()
}

# Function to extract aria2c.exe from zip file
function extractAria2c {
    param (
        [string]$zipPath
    )
    $extractPath = "$packagePath\aria2_temp"
    $aria2cPath = "$packagePath\aria2c.exe"
    
    if (Test-Path -Path $aria2cPath) {
        logMessage "aria2c.exe already exists, skipping extraction"
        return $aria2cPath
    }
    
    logMessage "Extracting aria2c.exe from $zipPath"
    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }
    
    # Extract the zip file
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    
    # Find and copy aria2c.exe to packages directory
    $aria2cFiles = Get-ChildItem -Path $extractPath -Name "aria2c.exe" -Recurse
    if ($aria2cFiles.Count -gt 0) {
        # Get the full path by reconstructing it
        $aria2cSourceFile = Get-ChildItem -Path $extractPath -Filter "aria2c.exe" -Recurse | Select-Object -First 1
        if ($aria2cSourceFile) {
            Copy-Item -Path $aria2cSourceFile.FullName -Destination $aria2cPath
            logMessage "aria2c.exe extracted to $aria2cPath"
        }
        else {
            logMessage "ERROR: Could not access aria2c.exe file"
            throw "Could not access aria2c.exe file"
        }
    }
    else {
        logMessage "ERROR: aria2c.exe not found in zip file"
        logMessage "Available files in extraction directory:"
        Get-ChildItem -Path $extractPath -Recurse | ForEach-Object { logMessage "  $($_.FullName)" }
        throw "aria2c.exe not found in zip file"
    }
    
    # Clean up temporary extraction directory
    Remove-Item -Path $extractPath -Recurse -Force
    
    return $aria2cPath
}

# Modified Function to download file using aria2c with multi-threading
function downloadFile {
    param (
        [string]$url,
        [string]$output,
        [string]$checksum,
        [string]$aria2cPath = $null
    )
    logMessage "Checking if $output needs to be downloaded"
    if (Test-Path -Path $output) {
        $existingChecksum = getFileChecksum -filePath $output
        if ($existingChecksum -eq $checksum.ToUpper()) {
            logMessage "File already exists and checksum matches: $output"
            return $null
        }
        else {
            logMessage "Checksum mismatch for $output. Redownloading..."
            Remove-Item -Path $output -Force
        }
    }
    
    logMessage "Downloading $output from $url"
    
    if ($aria2cPath -and (Test-Path -Path $aria2cPath)) {
        # Use aria2c with multi-threading
        logMessage "Using aria2c for download with multi-threading"
        $aria2cArgs = @(
            "--max-connection-per-server=16",
            "--split=16",
            "--min-split-size=1M",
            "--max-concurrent-downloads=16",
            "--continue=true",
            "--auto-file-renaming=false",
            "--allow-overwrite=true",
            "--out=$output",
            $url
        )
        
        $process = Start-Process -FilePath $aria2cPath -ArgumentList $aria2cArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -ne 0) {
            logMessage "ERROR: aria2c download failed with exit code $($process.ExitCode)"
            throw "aria2c download failed"
        }
    }
    else {
        # Fallback to Invoke-WebRequest for bootstrap packages
        logMessage "Using Invoke-WebRequest (fallback method)"
        Invoke-WebRequest -Uri $url -OutFile $output
    }
    
    logMessage "Downloaded: $output"
    $newChecksum = getFileChecksum -filePath $output
    logMessage "Checksum for $output : $newChecksum"
    return $newChecksum
}

# Step 1: Download and setup aria2c first
$aria2cPath = "$packagePath\aria2c.exe"
logMessage "Setting up aria2c downloader..."

# Check if aria2c already exists
if (-not (Test-Path -Path $aria2cPath)) {
    # Download aria2.zip first
    $aria2Info = $bootstrapPackageInfo["aria2.zip"]
    logMessage "Downloading aria2.zip to set up downloader"
    $newChecksum = downloadFile -url $aria2Info.url -output "aria2.zip" -checksum $aria2Info.sha256sum
    
    if ($newChecksum -and $newChecksum.ToUpper() -ne $aria2Info.sha256sum.ToUpper()) {
        logMessage "ERROR: Checksum mismatch for aria2.zip, download failed"
        logMessage "Expected: $($aria2Info.sha256sum.ToUpper())"
        logMessage "Got: $($newChecksum.ToUpper())"
        throw "Failed to download aria2.zip with correct checksum"
    }
    else {
        logMessage "aria2.zip downloaded successfully"
    }
    
    # Extract aria2c.exe
    if (Test-Path -Path "aria2.zip") {
        try {
            $aria2cPath = extractAria2c -zipPath "aria2.zip"
            logMessage "aria2c.exe is now available at: $aria2cPath"
        }
        catch {
            logMessage "ERROR: Failed to extract aria2c.exe: $_"
            throw "Failed to extract aria2c.exe"
        }
    }
}
else {
    logMessage "aria2c.exe already exists at: $aria2cPath"
}

# Step 2: Download remaining bootstrap packages using aria2c
logMessage "Downloading remaining bootstrap packages..."
foreach ($filename in $bootstrapPackageInfo.Keys) {
    # Skip aria2.zip as it's already handled
    if ($filename -eq "aria2.zip") {
        continue
    }
    
    $info = $bootstrapPackageInfo[$filename]
    logMessage "Downloading bootstrap package: $filename"
    $newChecksum = downloadFile -url $info.url -output $filename -checksum $info.sha256sum -aria2cPath $aria2cPath
    if ($newChecksum -and $newChecksum.ToUpper() -ne $info.sha256sum.ToUpper()) {
        logMessage "ERROR: Checksum mismatch for $filename, download failed"
        logMessage "Expected: $($info.sha256sum.ToUpper())"
        logMessage "Got: $($newChecksum.ToUpper())"
    }
    else {
        logMessage "Checksum matches for $filename, download successful"
    }
}

# Download files from JSON manifest using aria2c and update manifest checksum if needed
logMessage "Downloading packages from JSON manifest"
$files = Get-Content -Path $manifestPath | ConvertFrom-Json -ErrorAction Stop
$updated = $false
foreach ($file in $files) {
    logMessage "Processing package: $($file.filename)"
    $newChecksum = downloadFile -url $file.url -output $file.filename -checksum $file.sha256sum -aria2cPath $aria2cPath
    if ($newChecksum -and $newChecksum.ToUpper() -ne $file.sha256sum.ToUpper()) {
        logMessage "Updating checksum for $($file.filename) in manifest"
        $file.sha256sum = $newChecksum.ToUpper()
        $updated = $true
    }
}

# Save updated manifest if any checksums were updated
if ($updated) {
    logMessage "Saving updated manifest to $manifestPath"
    $files | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath
}

# Change back to the root directory
Set-Location -Path $cwd -ErrorAction Stop

logMessage "========== Download process completed =========="
