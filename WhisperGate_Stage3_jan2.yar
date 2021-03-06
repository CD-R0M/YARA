rule Whisper_Gate_stage3_jan22 {
	meta:
		author = "CD_R0M_"
		description = "Stage1.exe malware, as reported by Micrososft."
    		hash = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
    		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations"
		HundredDaysofYARA = "Day 18"
	
  	strings:
		$a1= {460072006b006d006c006b0064006b006400750062006b007a006e0062006b006d00630066002e0064006c006c}

	condition:
		uint16(0) == 0x5A4D
		and all of ($a*)
}
