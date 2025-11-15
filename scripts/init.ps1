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
    Write-Verbose $logEntry
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

function network_setup {
    $tun2socks = "$desktopPath\tun2socks\tun2socks-windows-amd64-v3.exe"
    Copy-Item -Path "$desktopPath\wintun\bin\amd64\wintun.dll" -Destination "$desktopPath\tun2socks" -Force
    $tunIp = "10.9.8.7"
    $gateway = "10.9.8.1" # fake, we just need a gateway to set the default route
    log_message "Setting up TUN device with IP $tunIp and gateway $gateway."

    # Check if a default route already exists
    $existingRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    if ($existingRoute) {
        log_message "Default route exists; aborting network setup."
        return
    }

    # Start tun2socks to forward traffic from TUN device to SOCKS5 proxy on local port 1080
    Start-Process -FilePath $tun2socks -ArgumentList "-device", "wintun", "-proxy", "socks5://127.0.0.1:1080" -NoNewWindow

    # Wait for tun2socks to start
    Start-Sleep -Seconds 2

    # Set IP address and gateway
    $tunInterface = Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "WireGuard Tunnel" }
    $tunInterface | New-NetIPAddress -IPAddress $tunIp -PrefixLength 24 -DefaultGateway $gateway
    if (check_error "Failed to create TUN device") {
        log_message "TUN device created successfully with IP $tunIp and gateway $gateway."
    }
}

log_message "Script started."

# Start timer
$scriptStartTime = Get-Date

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

function prompt_yes_no {
    param (
        [string] $message,
        [string] $title = "Prompt"
    )
    Add-Type -AssemblyName PresentationFramework
    $result = [System.Windows.MessageBox]::Show($message, $title, "YesNo", "Question")
    return $result -eq [System.Windows.MessageBoxResult]::Yes
}

function install_nsis {
    param (
        [string] $nsisPath
    )

    $arguments = "/S"
    $packageName = get_basename -filePath $nsisPath

    # AutoHotkey
    if ($nsisPath -like "*AutoHotKey.exe") { 
        # already installed
        return
    }

    # Use AHK installer
    if (($nsisPath -like "*Wireshark.exe") -or ($nsisPath -like "*npcap.exe")) { 
        Copy-Item -Path $nsisPath -Destination $desktopPath -Force
        $arguments = ""
    }

    if ($arguments -eq "/S") {
        # install silently
        log_message "Installing $nsisPath silently."
        Start-Process -FilePath $nsisPath -ArgumentList $arguments -Wait
    }
    else {
        log_message "Installing $nsisPath"
        # install using AHKv2 script "unattended_install.ahk"
        $ahkPath = "C:\Program Files\AutoHotkey\v2\AutoHotkey.exe"
        $pkgPath = [System.IO.Path]::Combine($desktopPath, $packageName + ".exe")
        $procName = $packageName + ".exe"
        $ahkScriptPath = Join-Path $ScriptPath "unattented_install.ahk"
        Start-Process -FilePath $ahkPath -ArgumentList $ahkScriptPath, $pkgPath, $procName -Wait -ErrorAction Stop
        log_message "Command executed: $ahkPath $ahkScriptPath $pkgPath $procName"
        Remove-Item -Path $pkgPath -Force
    }
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
    $appName = [System.IO.Path]::GetFileNameWithoutExtension($appPath)
    $progId = "${appName}.AssocFile.${extension.TrimStart('.')}"
    
    # Set the file extension association
    $extensionKey = "HKCU:\Software\Classes\$extension"
    if (-not (Test-Path $extensionKey)) {
        New-Item -Path $extensionKey -Force | Out-Null
        log_message "Created registry path: $extensionKey"
    }
    Set-ItemProperty -Path $extensionKey -Name "(Default)" -Value $progId
    if (check_error "Failed to set default app for $extension") {
        log_message "Set default app for $extension to $progId"
    }
    
    # Create the ProgID
    $progIdKey = "HKCU:\Software\Classes\$progId"
    if (-not (Test-Path $progIdKey)) {
        New-Item -Path $progIdKey -Force | Out-Null
        log_message "Created registry path: $progIdKey"
    }
    Set-ItemProperty -Path $progIdKey -Name "(Default)" -Value "$appName File"
    
    # Set the shell\open\command
    $commandKey = "$progIdKey\shell\open\command"
    if (-not (Test-Path $commandKey)) {
        New-Item -Path $commandKey -Force | Out-Null
        log_message "Created registry path: $commandKey"
    }
    Set-ItemProperty -Path $commandKey -Name "(Default)" -Value "`"$appPath`" `"%1`""
    if (check_error "Failed to set open command for $extension") {
        log_message "Set open command for $extension"
    }
    
    # Register with Windows' UserChoice (more reliable method)
    $userChoiceKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice"
    if (-not (Test-Path $userChoiceKey)) {
        New-Item -Path $userChoiceKey -Force | Out-Null
        log_message "Created registry path: $userChoiceKey"
    }
    Set-ItemProperty -Path $userChoiceKey -Name "ProgId" -Value $progId -ErrorAction SilentlyContinue
    
    # Also set in the OpenWithProgids for better compatibility
    $openWithKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\OpenWithProgids"
    if (-not (Test-Path $openWithKey)) {
        New-Item -Path $openWithKey -Force | Out-Null
        log_message "Created registry path: $openWithKey"
    }
    Set-ItemProperty -Path $openWithKey -Name $progId -Value ([byte[]]@()) -Type Binary -ErrorAction SilentlyContinue
    
    log_message "Completed file association setup for $extension with $appName"
}

function refresh_file_associations {
    # Refresh the shell icon cache and notify the system of changes
    try {
        # Try to call SHChangeNotify directly via P/Invoke instead of rundll32 to avoid RunDLL popup
        $code = @'
using System;
using System.Runtime.InteropServices;
namespace Win32 {
    public static class Shell32 {
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(UInt32 wEventId, UInt32 uFlags, IntPtr dwItem1, IntPtr dwItem2);
    }
}
'@
        Add-Type -TypeDefinition $code -ErrorAction Stop
        [Win32.Shell32]::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
        log_message "Refreshed file associations and sent SHChangeNotify"
    }
    catch {
        # Fallback: attempt rundll32 with correct argument format but keep it hidden and non-interactive
        try {
            $args = "shell32.dll,SHChangeNotify 0x8000000,0"
            Start-Process -FilePath "rundll32.exe" -ArgumentList $args -Wait -NoNewWindow -WindowStyle Hidden
            log_message "Refreshed file associations using rundll32 fallback"
        }
        catch {
            log_message "Warning: Could not refresh file associations cache: $($_.Exception.Message)"
        }
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
    set_default_app -extension ".log" -appPath "C:\Program Files\Notepad++\notepad++.exe"
    set_default_app -extension ".cfg" -appPath "C:\Program Files\Notepad++\notepad++.exe"
    set_default_app -extension ".conf" -appPath "C:\Program Files\Notepad++\notepad++.exe"
    refresh_file_associations
}

# Create a shortcut for MALWARE directory on the desktop
create_shortcut -targetPath $RootPath\MALWARE -name "MALWARE"

# Install AutoHotkey
log_message "Installing AutoHotkey silently."
Start-Process -FilePath "$PackagePath\AutoHotKey.exe" -ArgumentList "/silent" -Wait

# Run all EXE files in the source directory with /S argument
process_files -path $PackagePath -filter "*.exe" -callback_function { param($filePath) install_nsis $filePath }

# Install all MSI files in the source directory
process_files -path $PackagePath -filter "*.msi" -callback_function { param($filePath) install_msi $filePath }

# Unzip all ZIP files in the source directory to the desktop using 7-Zip
Get-ChildItem -Path $PackagePath -Filter *.zip | ForEach-Object {
    $destination = Join-Path $desktopPath ($_.BaseName)
    Start-Process -FilePath $sevenZipPath -ArgumentList "x", $_.FullName, "-o$destination", "-y" -NoNewWindow -Wait
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

# Set 7-Zip as default app for common archive formats
set_default_app -extension ".7z" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".zip" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".tar" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".gz" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".rar" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".iso" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".cab" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".arj" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".bz2" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".xz" -appPath "C:\Program Files\7-Zip\7zFM.exe"
set_default_app -extension ".lzma" -appPath "C:\Program Files\7-Zip\7zFM.exe"
refresh_file_associations

# Configure Notepad++
npp_setup

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
# Set JAVA_HOME environment variable for both User and System
$javaHome = "$desktopPath\jdk"

# Set JAVA_HOME for User
[Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "User")
if (check_error "Failed to set JAVA_HOME environment variable for User") {
    log_message "Set JAVA_HOME environment variable to $javaHome for User"
}

# Set JAVA_HOME for System (requires admin privileges)
try {
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "Machine")
    log_message "Set JAVA_HOME environment variable to $javaHome for System"
}
catch {
    log_message "Warning: Could not set JAVA_HOME for System scope. This may require administrator privileges."
}

# Add JAVA_HOME to the User PATH
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$javaHome*") {
    $newUserPath = "$userPath;$javaHome\bin"
    [System.Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    if (check_error "Failed to add JAVA_HOME to User PATH") {
        log_message "Added JAVA_HOME to User PATH"
    }
}

# Add JAVA_HOME to the System PATH (requires admin privileges)
try {
    $systemPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($systemPath -notlike "*$javaHome*") {
        $newSystemPath = "$systemPath;$javaHome\bin"
        [System.Environment]::SetEnvironmentVariable("Path", $newSystemPath, "Machine")
        log_message "Added JAVA_HOME to System PATH"
    }
    else {
        log_message "JAVA_HOME already exists in System PATH"
    }
}
catch {
    log_message "Warning: Could not add JAVA_HOME to System PATH. This may require administrator privileges."
}

# Configure ImHex
create_shortcut -targetPath "$desktopPath\ImHex\imhex-gui.exe" -name "ImHex"
New-Item -Path "$desktopPath\ImHex\config" -ItemType Directory -Force
Copy-Item $RootPath\imhex_config\settings.json -Destination "$desktopPath\ImHex\config" -Force

# Configure Wireshark
create_shortcut -targetPath "$desktopPath\WiresharkPortable64\WiresharkPortable64.exe" -name "Wireshark"


# Configure network
network_setup

# Create a shortcut for powershell.exe
create_shortcut -targetPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -name "PowerShell"

# Final refresh of file associations to ensure all changes take effect
refresh_file_associations

# Calculate time spent
$scriptEndTime = Get-Date
$timeSpent = $scriptEndTime - $scriptStartTime
$timeSpentMessage = "Installation completed in "
if ($timeSpent.Hours -gt 0) {
    $timeSpentMessage += "$($timeSpent.Hours) hours, "
}
if ($timeSpent.Minutes -gt 0) {
    $timeSpentMessage += "$($timeSpent.Minutes) minutes, "
}
$timeSpentMessage += "$($timeSpent.Seconds) seconds."

log_message "$timeSpentMessage"
show_message_box -message $timeSpentMessage -title 'Completion' -button 'OK' -icon 'Information'