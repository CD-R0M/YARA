import "pe"

rule applocker_bypass_spooler {
    meta:
        author = "CD_R0M_"
		    description = "Grzegorz Tworek @0gtweet shared an Applocker bypass, which steals the token from spooler and creates a child process. Only looking for obvious strings here"
		    reference = "https://twitter.com/0gtweet/status/1484422524091961347"
		    HundredDaysofYARA = "Day 21"
    strings:
        $a1 = "elevateAndRunAsSpooler"
		    $a2 = "elevateAsWinlogon"

    condition:
        uint16(0) == 0x5a4d
		    and all of ($a*)
}

rule applocker_bypass_spooler_imports {
    meta:
      author = "CD_R0M_"
		  description = "Grzegorz Tworek @0gtweet shared an Applocker bypass, which steals the token from spooler and creates a child process. More generically looking at imports here"
		  reference = "https://twitter.com/0gtweet/status/1484422524091961347"
		  HundredDaysofYARA = "Day 21"

    condition:
        uint16(0) == 0x5a4d
		    and pe.imports("ADVAPI32.dll", "DuplicateTokenEx")
		    and pe.imports("ADVAPI32.dll", "LookupPrivilegeValueW")
		    and pe.imports("ADVAPI32.dll", "AdjustTokenPrivileges")
		    and pe.imports("ADVAPI32.dll", "SetTokenInformation")
		    and pe.imports("ADVAPI32.dll", "OpenProcessToken")
		    and pe.imports("KERNEL32.dll", "GetCurrentProcessId")
		    and pe.imports("KERNEL32.dll", "Process32NextW")
		    and pe.imports("KERNEL32.dll", "GetCurrentThreadId")
		    and pe.imports("KERNEL32.dll", "RtlLookupFunctionEntry")
}
