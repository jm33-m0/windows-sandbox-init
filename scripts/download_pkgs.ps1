# Current directory: root of the repository
$cwd = Get-Location -ErrorAction Stop
$logFile = "$cwd\download_pkgs.log"

# Change to the packages directory
$packagePath = "..\packages"
Set-Location -Path $packagePath -ErrorAction Stop
$packagePath = Get-Location -ErrorAction Stop
$manifestPath = "$packagePath\packages.json"

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

# Function to calculate file checksum
function getFileChecksum {
    param (
        [string]$filePath
    )
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    return $hash.Hash.ToUpper()
}

# Modified Function to download file; returns new checksum if downloaded (no *.sha256 usage)
function downloadFile {
    param (
        [string]$url,
        [string]$output,
        [string]$checksum
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
        }
    }
    logMessage "Downloading $output from $url"
    Invoke-WebRequest -Uri $url -OutFile $output
    logMessage "Downloaded: $output"
    $newChecksum = getFileChecksum -filePath $output
    logMessage "Checksum for $output : $newChecksum"
    return $newChecksum
}

# Download bootstrap packages
foreach ($filename in $bootstrapPackageInfo.Keys) {
    $info = $bootstrapPackageInfo[$filename]
    logMessage "Downloading bootstrap package: $filename"
    $newChecksum = downloadFile -url $info.url -output $filename -checksum $info.sha256sum
    if ($newChecksum -eq $info.sha256sum) {
        logMessage "Checksum mismatch for $filename, download failed"
    }
    else {
        logMessage "Checksum matches for $filename, download successful"
    }
}

# Download files from JSON manifest and update manifest checksum if needed
logMessage "Downloading packages"
$files = Get-Content -Path $manifestPath | ConvertFrom-Json -ErrorAction Stop
foreach ($file in $files) {
    $newChecksum = downloadFile -url $file.url -output $file.filename -checksum $file.sha256sum
    if ($newChecksum) {
        $file.sha256sum = $newChecksum 
    }
}

# Change back to the root directory
Set-Location -Path $cwd -ErrorAction Stop