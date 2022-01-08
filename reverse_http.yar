rule reverse_http {
	meta: 
		author = "CD_R0M_"
		description = "Identify strings with http reversed (ptth)"
		HundredDaysofYARA = "Day 1"

	strings:
		$string1 = "ptth"
	condition:
		uint16(0) == 0x5a4d and $string1
}
