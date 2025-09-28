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
    "7z.exe"         = @{
        url       = "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.exe"
        sha256sum = "BDD1A33DE78618D16EE4CE148B849932C05D0015491C34887846D431D29F308E"
    }
    "AutoHotKey.exe" = @{
        url       = "https://www.autohotkey.com/download/ahk-v2.exe"
        sha256sum = "FD55129CBD356F49D2151E0A8B9662D90D2DBBB9579CC2410FDE38DF94787A3A"
    }
    "tun2socks.zip"  = @{
        url       = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-windows-amd64-v3.zip"
        sha256sum = "427FABCB0798815EA87800466F168023502FC0C12A17F45B40C078BAC25FBAC5"
    }
    "wintun.zip"     = @{
        url       = "https://www.wintun.net/builds/wintun-0.14.1.zip"
        sha256sum = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
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
    if ($newChecksum -ne $info.sha256sum) {
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
