[CmdletBinding(PositionalBinding = $false)]
Param(
    [Parameter(Mandatory = $false)]
    [string] $Src = "C:\tooling"
)
Set-ExecutionPolicy Unrestricted -Scope LocalMachine

$logFile = "$Home\Desktop\init_log.txt"
$sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
$ghidraPath = "$env:USERPROFILE\Desktop\ghidra_11.2.1_PUBLIC"
$diePath = "$env:USERPROFILE\Desktop\die_win64_portable_3.10_x64"

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
    if (-not $?) {
        $actualError = $Error[0].ToString()
        log_message "$errorMessage $actualError"
        return $false
    }
    return $true
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
        [string] $targetPath,
        [string] $name, 
        [string] $iconPath
    )
    $desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
    $shortcutPath = [System.IO.Path]::Combine($desktopPath, $name + ".lnk")
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    if ($iconPath) {
        $shortcut.IconLocation = $iconPath
    }
    $shortcut.Save()
    log_message "Created shortcut for $targetPath on desktop with name $name."
}

function install_msi {
    param (
        [string] $msiPath
    )
    log_message "Installing MSI: $msiPath"
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/quiet", "/norestart", "/i", $msiPath -Wait
    if (check_error "Failed to install $msiPath") {
        log_message "Installed $msiPath"
    }
}

function install_nsis {
    param (
        [string] $nsisPath
    )
    log_message "Installing $nsisPath"
    Start-Process -FilePath $nsisPath -ArgumentList "/S" -Wait
    if (check_error "Failed to install $nsisPath") {
        log_message "Installed $nsisPath"
    }
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

function show_completion_message {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show('All tasks are completed.', 'Completion', 'OK', 'Information')
}

# Install all MSI files in the source directory
process_files -path $Src -filter "*.msi" -callback_function { param($filePath) install_msi $filePath }

# Run all EXE files in the source directory with /S argument
process_files -path $Src -filter "*.exe" -callback_function { param($filePath) install_nsis $filePath }

# Config Notepad++ with config.xml
Copy-Item -Path $Src\config.xml -Destination "$env:APPDATA\Notepad++\config.xml" -Force
if (check_error "Failed to copy config.xml to Notepad++ directory") {
    log_message "Copied config.xml to Notepad++ directory."
}
# Make shortcut for Notepad++ on desktop
create_shortcut -targetPath "C:\Program Files\Notepad++\notepad++.exe"

# Unzip all ZIP files in the source directory to the desktop using 7-Zip
Get-ChildItem -Path $Src -Filter *.zip | ForEach-Object {
    $destination = Join-Path "$Home\Desktop" ($_.BaseName)
    Start-Process -FilePath $sevenZipPath -ArgumentList "x", $_.FullName, "-o$destination", "-y" -Wait
    if (check_error "Failed to unzip $($_.FullName) to $destination using 7-Zip") {
        log_message "Unzipped $($_.FullName) to $destination using 7-Zip"
    }
}
# Make shortcut for 7-Zip on desktop
create_shortcut -targetPath "C:\Program Files\7-Zip\7zFM.exe" -name "7-Zip"

# Configure Ghidra
Copy-Item -Path $Src\lauch.properties -Destination "$ghidraPath\support" -Force
if (check_error "Failed to copy lauch.properties to Ghidra directory") {
    log_message "Copied lauch.properties to Ghidra directory."
}
create_shortcut -targetPath "$ghidraPath\ghidraRun.bat" -iconPath "$ghidraPath\support\ghidra.ico" -name "Ghidra"

# Configure x64dbg
Start-Process -FilePath "$env:USERPROFILE\Desktop\snapshot_2025-01-17_12-45\release\x96dbg.exe" -Wait

# Configure DIE
create_shortcut -targetPath "$diePath\die.exe" -name "Detect It Easy"

log_message "Script completed."
show_completion_message