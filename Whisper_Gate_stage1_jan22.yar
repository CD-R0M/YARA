import "pe"

rule Whisper_Gate_stage1_jan22 {
	meta:
		author = "CD_R0M_"
		description = "Stage1.exe malware, as reported by Micrososft."
    		hash = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
    		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations"
		HundredDaysofYARA = "Day 16"
	
  	strings:
		$a1= "Your hard drive has been corrupted." nocase ascii
    		$a2 = "In case you want to recover all hard drives" nocase ascii
    		$a3 = "send message via" nocase ascii
		
	condition:
		uint16(0) == 0x5A4D
		and all of ($a*)
    		and pe.imports("kernel32.dll", "LoadLibraryA")
		and pe.imports("msvcrt.dll", "memcpy")
}
