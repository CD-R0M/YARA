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
		
		$wide_str1 = "Crowdstrike" wide
		$wide_str2 = "Sentinelone" wide
		$wide_str3 = "Carbon black" wide
		$wide_str4 = "Cybereason" wide
		$wide_str5 ="Trend Micro" wide
		$wide_str6 = "Defender" wide
		$wide_str7 = "sysmon" wide
		$wide_str8 ="Symantec" wide
		$wide_str9 ="Malwarebytes" wide
		$wide_str10 ="Sophos" wide
		$wide_str11 ="Cisco" wide
		$wide_str12 ="Fireeye" wide
	condition:
		uint16(0) == 0x5a4d and (3 of ($string*) or 3 of ($wide_str12))
}
