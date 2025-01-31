# URLs and filenames
$files = @(
    @{ url = "https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe"; filename = "Everything.exe"; checksum = "" },
    @{ url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.6/npp.8.7.6.Installer.x64.exe"; filename = "npp.exe"; checksum = "" },
    @{ url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip"; filename = "ghidra.zip"; checksum = "" },
    @{ url = "https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip"; filename = "detect-it-easy.zip"; checksum = "" },
    @{ url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"; filename = "Sysinternals.zip"; checksum = "" },
    @{ url = "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.msi"; filename = "7z.msi"; checksum = "checksum6" },
    @{ url = "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2025-01-17_12-45.zip"; filename = "x64dbg.zip"; checksum = "" },
    @{ url = "https://github.com/x64dbg/x64dbg/releases/download/snapshot/symbols-snapshot_2025-01-17_12-45.zip"; filename = "x64dbg_symbols.zip"; checksum = "" },
    @{ url = "https://tdf.jensgutermuth.de/libreoffice/stable/24.8.4/win/x86_64/LibreOffice_24.8.4_Win_x86-64.msi"; filename = "LibreOffice.msi"; checksum = "" },
    @{ url = "https://download.visualstudio.microsoft.com/download/pr/e2393a1d-1011-45c9-a507-46b696f6f2a4/2e6485db3be11cdad7550d17c5196767/microsoft-jdk-21.0.6-windows-x64.msi"; filename = "jdk.msi"; checksum = "" }
)

# Function to log messages
function logMessage {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp - $message"
}

# Function to calculate file checksum
function getFileChecksum {
    param (
        [string]$filePath
    )
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    return $hash.Hash.ToUpper()
}

# Function to load .sha256 files and update checksum dictionary
function loadChecksums {
    param (
        [string]$directory
    )
    logMessage "Loading checksums from .sha256 files in $directory"
    Get-ChildItem -Path $directory -Filter *.sha256 | ForEach-Object {
        $filePath = $_.FullName
        $content = Get-Content -Path $filePath
        $checksum = $content[0]
        $filename = $content[1]
        if ($checksum -and $filename) {
            $file = $files | Where-Object { $_.filename -eq $filename }
            if ($file) {
                $file.checksum = $checksum
                logMessage "Loaded checksum: $filename - $checksum"
            }
        }
        else {
            logMessage "Invalid checksum file: $filePath"
        }
    }
}

# Function to download file if it does not exist or checksum does not match
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
            return
        }
        else {
            logMessage "Checksum mismatch for $output. Redownloading..."
        }
    }
    Invoke-WebRequest -Uri $url -OutFile $output
    logMessage "Downloaded: $output"
    $checksum_file = "$output.sha256"
    $checksum = getFileChecksum -filePath $output
    Set-Content -Path $checksum_file -Value "$checksum`n$output"
    logMessage "Checksum '$checksum' written to: $checksum_file"
}

# Load checksums from .sha256 files
try {
    loadChecksums -directory "."
}
catch {
    logMessage "Failed to load checksums. Aborting. Error: $_"
    exit 1
}

# Download files
foreach ($file in $files) {
    downloadFile -url $file.url -output $file.filename -checksum $file.checksum
}