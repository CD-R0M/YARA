import pe
rule anti_debugging {
  meta:
    author = "CD_R0M_"
    description = "Malware authors will often introduct windows API's designed to thwart malware analysis or debugging"
    
  strings:
    $ad1 = "CreateToolhelp32Snapshot"
    $ad2 = "GetTickCount"
    $ad3 = "CheckRemoteDebuggerPresent"
    $ad4 = "IsDebuggerPresent"
    $ad5 = "NtQueryInformationProcess"
    $ad6 = "FindWindowA"
    $ad7 = "FindWindowExA"
    $ad8 = "GetForegroundWindow"
    $ad9 = "GetTickCount64"
    $ad10 = "QueryPerformanceFrequency"
    $ad11 = "GetNativeSystemInfo"
    $ad12 = "RtlGetVersion"
    $ad13 = "GetSystemTimeAsFileTime"
    $ad14 = "CountClipboardFormats"
    
    $imp = "kernel32.dll"
    
  condition:
    uint16(0) == 0x5A4D and any of ($ad*) and $imp and (pe.imports("LoadLibraryA", "GetProcAddress") or pe.imports("CreateRemoteThread", "VirtualAllocEx"))
