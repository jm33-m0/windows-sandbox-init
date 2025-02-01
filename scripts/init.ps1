[CmdletBinding(PositionalBinding = $false)]
Param(
    [Parameter(Mandatory = $false)]
    [string] $RootPath = "C:\tooling",
    [string] $PackagePath = "C:\tooling\packages",
    [string] $ScriptPath = "C:\tooling\scripts"
)
Set-ExecutionPolicy Unrestricted -Scope LocalMachine

# Paths
$desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
$logFile = "$desktopPath\init_log.txt"
$sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
$ghidraPath = "$desktopPath\ghidra"
$diePath = "$desktopPath\detect-it-easy"
$sysinternalsPath = "$desktopPath\Sysinternals"
$x64dbgPath = "$desktopPath\x64dbg"

# cd to the script directory
Set-Location -Path $ScriptPath -ErrorAction Stop

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

# Start timer
$scriptStartTime = Get-Date

function config_explorer() {
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -value 0
}

function restart_explorer {
    Stop-Process -Name explorer -Force
}

function get_basename {
    param (
        [string] $filePath
    )
    return [System.IO.Path]::GetFileNameWithoutExtension($filePath)
}

function create_shortcut {
    param (
        [string] $targetPath,
        [string] $name, 
        [string] $iconPath
    )
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
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $msiPath, "/qn", "/norestart" -Wait
    if (check_error "Failed to install $msiPath") {
        log_message "Installed $msiPath"
    }
}

function install_nsis {
    param (
        [string] $nsisPath
    )
    log_message "Installing $nsisPath"
    
    # needs manual intervention
    if ($nsisPath -like "*Wireshark.exe") { 
        create_shortcut -targetPath $nsisPath -name "Wireshark Installer"
        return
    }
    $arguments = "/S"
    Start-Process -FilePath $nsisPath -ArgumentList $arguments -Wait
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

function show_message_box {
    param (
        [string] $message,
        [string] $title = "Message",
        [string] $button = "OK",
        [string] $icon = "Information"
    )
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($message, $title, $button, $icon)
}

function set_default_app {
    param (
        [string] $extension,
        [string] $appPath
    )
    $extensionKey = "HKCU:\Software\Classes\$extension"
    $appKey = "HKCU:\Software\Classes\$extension\shell\open\command"
    if (-not (Test-Path $extensionKey)) {
        New-Item -Path $extensionKey -Force | Out-Null
        log_message "Created registry path: $extensionKey"
    }
    Set-ItemProperty -Path $extensionKey -Name "(Default)" -Value "Notepad++_file"
    if (check_error "Failed to set default app for $extension") {
        log_message "Set default app for $extension"
    }
    if (-not (Test-Path $appKey)) {
        New-Item -Path $appKey -Force | Out-Null
        log_message "Created registry path: $appKey"
    }
    Set-ItemProperty -Path $appKey -Name "(Default)" -Value "`"$appPath`" `"%1`""
    if (check_error "Failed to set open command for $extension") {
        log_message "Set open command for $extension"
    }
}

function npp_setup {
    # Config Notepad++ with config.xml
    Copy-Item -Path $RootPath\npp_config\* -Destination "$env:APPDATA\Notepad++" -Force
    if (check_error "Failed to copy config files to Notepad++ directory") {
        log_message "Copied config files to Notepad++ directory."
    }
    # Make shortcut for Notepad++ on desktop
    create_shortcut -targetPath "C:\Program Files\Notepad++\notepad++.exe" -name "Notepad++"

    # Make Notepad++ the default app for .txt and .ini files
    set_default_app -extension ".txt" -appPath "C:\Program Files\Notepad++\notepad++.exe"
    set_default_app -extension ".ini" -appPath "C:\Program Files\Notepad++\notepad++.exe"
}

# Create a shortcut for MALWARE directory on the desktop
create_shortcut -targetPath $RootPath\MALWARE -name "MALWARE"

# Run all EXE files in the source directory with /S argument
process_files -path $PackagePath -filter "*.exe" -callback_function { param($filePath) install_nsis $filePath }
npp_setup

# Install all MSI files in the source directory
process_files -path $PackagePath -filter "*.msi" -callback_function { param($filePath) install_msi $filePath }

# Unzip all ZIP files in the source directory to the desktop using 7-Zip
Get-ChildItem -Path $PackagePath -Filter *.zip | ForEach-Object {
    $destination = Join-Path $desktopPath ($_.BaseName)
    Start-Process -FilePath $sevenZipPath -ArgumentList "x", $_.FullName, "-o$destination", "-y" -Wait
    if (check_error "Failed to unzip $($_.FullName) to $destination using 7-Zip") {
        log_message "Unzipped $($_.FullName) to $destination using 7-Zip"
    }
    # Check if the extraction created an extra directory level
    $extractedItems = Get-ChildItem -Path $destination
    if ($extractedItems.Count -eq 1 -and $extractedItems[0].PSIsContainer) {
        $innerFolder = $extractedItems[0].FullName
        Get-ChildItem -Path $innerFolder | Move-Item -Destination $destination -Force
        Remove-Item -Path $innerFolder -Force
        log_message "Moved contents of $innerFolder to $destination"
    }
}
# Make shortcut for 7-Zip on desktop
create_shortcut -targetPath "C:\Program Files\7-Zip\7zFM.exe" -name "7-Zip"

# Configure Ghidra
Copy-Item -Path $RootPath\ghidra_config\* -Destination "$ghidraPath\support" -Force
if (check_error "Failed to copy config files to Ghidra directory") {
    log_message "Copied config files to Ghidra directory."
}
create_shortcut -targetPath "$ghidraPath\ghidraRun.bat" -iconPath "$ghidraPath\support\ghidra.ico" -name "Ghidra"

# Configure x64dbg
create_shortcut -targetPath "$x64dbgPath\release\x64\x64dbg.exe" -name "x64dbg"
create_shortcut -targetPath "$x64dbgPath\release\x32\x32dbg.exe" -name "x32dbg"

# Configure DIE
create_shortcut -targetPath "$diePath\die.exe" -name "Detect It Easy"

# Configure Sysinternals
create_shortcut -targetPath "$sysinternalsPath/procexp64.exe" -name "Process Explorer"
create_shortcut -targetPath "$sysinternalsPath/procmon64.exe" -name "Process Monitor"
create_shortcut -targetPath "$sysinternalsPath/tcpview64.exe" -name "TCPView"
create_shortcut -targetPath "$sysinternalsPath/autoruns64.exe" -name "Autoruns"

# Configure JDK
# Set JAVA_HOME environment variable
$javaHome = "$desktopPath\jdk"
[Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "User")
if (check_error "Failed to set JAVA_HOME environment variable") {
    log_message "Set JAVA_HOME environment variable to $javaHome"
}

# Add JAVA_HOME to the system PATH
$path = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($path -notlike "*$javaHome*") {
    $newPath = "$path;$javaHome\bin"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    if (check_error "Failed to add JAVA_HOME to system PATH") {
        log_message "Added JAVA_HOME to system PATH"
    }
}

# Configure LibreOffice
create_shortcut -targetPath "$desktopPath\LibreOffice\LibreOfficePortable.exe" -name "LibreOffice"

# Configure ImHex
create_shortcut -targetPath "$desktopPath\ImHex\imhex-gui.exe" -name "ImHex"
New-Item -Path "$desktopPath\ImHex\config" -ItemType Directory -Force
Copy-Item $RootPath\imhex_config\settings.json -Destination "$desktopPath\ImHex\config" -Force

log_message "Script completed."

# Calculate time spent
$scriptEndTime = Get-Date
$timeSpent = $scriptEndTime - $scriptStartTime
$timeSpentMessage = "Installation completed in $($timeSpent.Hours) hours, $($timeSpent.Minutes) minutes, and $($timeSpent.Seconds) seconds. You will need to run Wireshark.exe to install Wireshark manually because its npcap dependency cannot be silently installed."

show_message_box -message $timeSpentMessage -title 'Completion' -button 'OK' -icon 'Information'