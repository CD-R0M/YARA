rule random_Stage1exe {
	meta:
		author = "CD_R0M_"
		description = "I found a random binary on VT named stage1.exe (recently . Not the binary Microsoft Identified, but my first Golang sample. "
    		hash = "5f84be88bce05dc96fff308e7fab134c8f30bf071e418e44364b616c795605ee"
		HundredDaysofYARA = "Day 14"
	
  	strings:
		$a1= "RedTeam_Malware_Dev"
		

	condition:
		uint16(0) == 0x5A4D
		and $a1
}
