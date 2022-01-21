rule advancedrun_bundled {
	meta:
		   author = "CD_R0M_"
		   description = "Threat will somtimes bundle AdvancedRun.exe with their payloads, to execute commands with elevated privileges."
		   HundredDaysofYARA = "Day 20"
	
	strings:
		   $a1= "Advanced Run" nocase ascii wide
		   $a2 = "AffinityMask" nocase ascii wide
		   $a3 = "RunAsProcessName" nocase ascii wide
		   $a4 = "RunAsInvoker" nocase ascii wide
		   $a5 = "@SeDebugPrivilege" nocase ascii wide
		   $a6 = "__COMPAT_LAYER" nocase ascii wide
		   $a7 = "/SpecialRun" nocase ascii wide
		   
		   $b1 = {2200430075007200720065006e0074002000550073006500720020002d00200041006c006c006f0077002000550041004300200045006c00650076006100740069006f006e002400430075007200720065006e0074002000550073006500720020002d00200057006900740068006f00750074002000550041004300200045006c00650076006100740069006f006e002300410064006d0069006e006900730074007200610074006f0072002000280046006f007200630065002000550041004300200045006c00650076006100740069006f006e002900}
		   	// "Current User - Allow UAC Elevation$Current User - Without UAC Elevation#Administrator (Force UAC Elevation)
		   $b2 = {550073006500720020006f00660020007400680065002000730065006c00650063007400650064002000700072006f00630065007300730030004300680069006c00640020006f0066002000730065006c00650063007400650064002000700072006f006300650073007300200028005500730069006e006700200063006f0064006500200069006e006a0065006300740069006f006e00290020005300700065006300690066006900650064002000750073006500720020006e0061006d006500200061006e0064002000700061007300730077006f0072006400}
		   	// User of the selected process0Child of selected process (Using code injection) Specified user name and password
	condition:
		     uint16(0) == 0x5A4D
		     and 3 of ($a*)
		     and all of ($b*)
}
