rule command_and_control {
  meta:
    author = "CD_R0M_"
    description = "This rule searches for common strings found me malware which reaches out for further network connections. Based on a sample used by a Ransomware group"
    HundredDaysofYara = "7"
    
  strings:
    $a1 = "WSACleanup" nocase
    $a2 = "WSAGetLastError" nocase
    $a3 = "WSAStartup" nocase
    $a4 = "accept" nocase
    $a5 = "bind" nocase
    $a6 = "closesocket" nocase
    $a7 = "connect" nocase
    $a8 = "listen" nocase
    $a9 = "recv" nocase
    $a10 = "send" nocase
    $a11 = "socket" nocase
    
    $b1 = "ws2_32.dll"
  
  condition:
   uint16(0) == 0x5a4d and 5 of ($a*) and $b1
