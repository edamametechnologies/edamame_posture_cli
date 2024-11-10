SendMode "Input"
SetWorkingDir A_ScriptDir
SetTitleMatchMode "RegEx"

if (A_Args.Length < 1) {
    FileAppend "Too few arguments given", "*"
    exit
}

InstallFile := A_Args[1]

Run InstallFile

WinWait "Npcap [\d\.]+ Setup", , 1
if WinExist("Npcap [\d\.]+ Setup", "already installed") {
    BlockInput True
    Sleep 150
    WinActivate
    Send "!y"
    BlockInput False
}

WinWait "Npcap [\d\.]+ Setup", , 1
if WinExist("Npcap [\d\.]+ Setup") {
    BlockInput True
    Sleep 150
    WinActivate
    Send "{Enter}"
    Sleep 150
    Send "{Tab}"
    Sleep 50
    Send "{Space}"
    Sleep 50
    Send "{Enter}"
    BlockInput False
} else {
    exit -1
}
WinWait "Npcap [\d\.]+ Setup", "Setup was completed successfully", 30
if (WinExist) {
    BlockInput True
    Sleep 250
    WinActivate
    Send "{Enter}"
    Sleep 50
    Send "{Enter}"
    BlockInput False
}
