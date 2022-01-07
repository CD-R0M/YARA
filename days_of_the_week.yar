rule days_of_the_week {
	meta:
		author = "CD_R0M_"
    description = "Listing out days of the week could indcate malware attempting to create some form of persistence"
		HundredDaysofYARA = "Day 2"
	strings:
		$string1 = "Sunday" nocase
		$string2 = "Monday" nocase
		$string3 = "Tuesday" nocase
		$string4 = "Wednesday" nocase
		$string5 = "Thursday" nocase
		$string6 = "Friday" nocase
		$string7 = "Saturday" nocase

	condition:
		uint16(0) == 0x5a4d and all of them
}
