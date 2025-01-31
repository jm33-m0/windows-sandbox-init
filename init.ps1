[CmdletBinding(PositionalBinding = $false)]
Param(
    [Parameter(Mandatory = $false)]
    [string] $Src = "C:\tooling"
)
Set-ExecutionPolicy Unrestricted -Scope LocalMachine

$logFile = "$Home\Desktop\init_log.txt"
function log_message {
    param (
        [string] $message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    $logEntry | Out-File -FilePath $logFile -Append
    Write-Output $logEntry
}

function check_error {
    param (
        [string] $errorMessage
    )
    if ($LASTEXITCODE -ne 0) {
        log_message $errorMessage
        throw $errorMessage
    }
}

log_message "Script started."

function config_explorer() {
    # Set Explorer to show file extension names and all hidden files including system files
    $showAllFiles = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt"
    )
    $values = 1, 1, 0
    $propertyNames = "Hidden", "ShowSuperHidden", "HideFileExt"
    for ($i = 0; $i -lt $showAllFiles.Length; $i++) {
        if (-not (Test-Path $showAllFiles[$i])) {
            New-Item -Path $showAllFiles[$i] -Force | Out-Null
            log_message "Created registry path: $showAllFiles[$i]"
        }
        Set-ItemProperty -Path $showAllFiles[$i] -Name $propertyNames[$i] -Value $values[$i]
        check_error "Failed to set $propertyNames[$i] to $values[$i] at $showAllFiles[$i]"
        log_message "Set $propertyNames[$i] to $values[$i] at $showAllFiles[$i]"
    }
}

function create_shortcut {
    param (
        [string] $shortcutPath,
        [string] $targetPath
    )
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    $shortcut.Save()
    log_message "Created shortcut for $targetPath on desktop."
}

function install_msi {
    param (
        [string] $msiPath
    )
    log_message "Installing MSI: $msiPath"
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/quiet", "/norestart", "/i", $msiPath -Wait
    check_error "Failed to install $msiPath"
    log_message "Installed $msiPath"
}

function install_nsis {
    param (
        [string] $nsisPath
    )
    log_message "Installing $nsisPath"
    Start-Process -FilePath $nsisPath -ArgumentList "/S" -Wait
    check_error "Failed to install $nsisPath"
    log_message "Installed $nsisPath"
}

function process_files {
    param (
        [string] $path,
        [string] $filter,
        [scriptblock] $callback_function
    )
    Get-ChildItem -Path $path -Filter $filter | ForEach-Object {
        $filePath = $_.FullName
        & $callback_function $filePath
    }
}

# Install all MSI files in the source directory
process_files -path $Src -filter "*.msi" -callback_function { param($filePath) install_msi $filePath }

# Run all EXE files in the source directory with /S argument
process_files -path $Src -filter "*.exe" -callback_function { param($filePath) install_nsis $filePath }

# Config Notepad++ with config.xml
Copy-Item -Path .\config.xml -Destination "$env:APPDATA\Notepad++\config.xml" -Force
check_error "Failed to copy config.xml to Notepad++ directory"
log_message "Copied config.xml to Notepad++ directory."
# Make shortcut for Notepad++ on desktop
create_shortcut -shortcutPath "$env:HOME\Desktop\Notepad++.lnk" -targetPath "C:\Program Files\Notepad++\notepad++.exe"

# Unzip all ZIP files in the source directory to the desktop using 7-Zip
$sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
Get-ChildItem -Path $Src -Filter *.zip | ForEach-Object {
    $destination = Join-Path "$Home\Desktop" ($_.BaseName)
    Start-Process -FilePath $sevenZipPath -ArgumentList "x", $_.FullName, "-o$destination", "-y" -Wait
    check_error "Failed to unzip $($_.FullName) to $destination using 7-Zip"
    log_message "Unzipped $($_.FullName) to $destination using 7-Zip"
}
# Make shortcut for 7-Zip on desktop
create_shortcut -shortcutPath "$env:HOME\Desktop\7-Zip.lnk" -targetPath "C:\Program Files\7-Zip\7zFM.exe"

log_message "Script completed."