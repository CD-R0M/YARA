rule searching_for_EDR {
	meta:
		author = "CD_R0M_"
		description = "Strings containing major EDR/telemetry products may indicate a file attempting to avoid detection"
		HundredDaysofYARA = "Day 3"
	strings:
		$string1 = "Crowdstrike" nocase
		$string2 = "Sentinelone" nocase
		$string3 = "Carbon black" nocase
		$string4 = "Cybereason" nocase
		$string5 ="Trend Micro" nocase
		$string6 = "Defender" nocase
		$string7 = "sysmon" nocase
		$string8 ="Symantec" nocase
		$string9 ="Malwarebytes" nocase
		$string10 ="Sophos" nocase
		$string11 ="Cisco" nocase
		$string12 ="Fireeye" nocase
	condition:
		uint16(0) == 0x5a4d and 3 of them
}
