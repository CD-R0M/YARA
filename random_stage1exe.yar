rule random_Stage1exe {
	meta:
		author = "CD_R0M_"
		description = "I found a random binary on VT named stage1.exe. Not the binary Microsoft dentified, but thought it might be fun and was my first Golang sample. Looks like an exploit dev doing some testing"
    		hash = "5f84be88bce05dc96fff308e7fab134c8f30bf071e418e44364b616c795605ee"
		HundredDaysofYARA = "Day 14"
	
  	strings:
		$a1= "RedTeam_Malware_Dev"
		

	condition:
		uint16(0) == 0x5A4D
		and $a1
}
