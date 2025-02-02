#Requires AutoHotkey v2
AutoInstall(installerPath) {
    Run(installerPath)

    ; continuously click controls with specific text if window is active
    loop {
        ; ensure the target process window always has focus
        if WinExist("ahk_exe " . processName)
            WinActivate("ahk_exe " . processName)
        if !ProcessExist(processName)
            break
        if WinActive("ahk_exe " . processName) {
            ; try controls with text containing target keywords (case insensitive)
            candidates := ["OK", "Next", "Install", "Agree", "Finish", "Exit", "Yes", "Done", "Noted", "Continue"]
            controlList := WinGetControls("ahk_exe " . processName)
            for index, ctrl in controlList {
                try {
                    ctrlText := ControlGetText(ctrl, "ahk_exe " . processName)
                }
                catch {
                    ; if control is not readable
                    continue
                }
                if (ctrlText != "") {
                    lowerText := StrLower(ctrlText)
                    for candidate in candidates {
                        if InStr(lowerText, candidate) {
                            try {
                                ControlClick(ctrl, "ahk_exe " . processName)
                            } catch {
                                ; if control is not clickable, continue
                                continue
                            }
                            break  ; stop checking other candidates for this control
                        }
                    }
                }
            }
        }
        Sleep(100)
    }
}

; parse command-line arguments and require installerPath
if (!A_Args[1]) {
    MsgBox("Installer path argument missing.")
    ExitApp()
}
if (!A_Args[2]) {
    MsgBox("Process name argument missing.")
    ExitApp()
}
installerPath := A_Args[1]
processName := A_Args[2]

AutoInstall(installerPath)