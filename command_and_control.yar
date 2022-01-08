rule command_and_control {
  meta:
    author = "CD_R0M_"
    description = "This rule searches for common strings found by malware using C2. Based on a sample used by a Ransomware group"
    HundredDaysofYara = "7"
    
  strings:
    $a1 = "WSACleanup" nocase
    $a2 = "WSAGetLastError" nocase
    $a3 = "WSAStartup" nocase
    
    $b1 = "accept" nocase
    $b2 = "bind" nocase
    $b3 = "closesocket" nocase
    $b4 = "connect" nocase
    $b5 = "listen" nocase
    $b6 = "recv" nocase
    $b7 = "send" nocase
    $b8 = "socket" nocase
    
    $c1 = "ws2_32.dll"
  
  condition:
   uint16(0) == 0x5a4d and all of ($a*) and 4 of ($b*) and $c1
}
