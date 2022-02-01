rule bazar_loader_2022_02_01{
	meta:
		author = "CD_R0M_"
		description = "Potential Bazarloader Sample"
		hash = "ca3c7c4b570751c0dbf9063a23035967dfca4a2c7a8ce6bb2997439257ac6f10"
		reference = "https://twitter.com/th3_protoCOL/status/1488600980979552256"
		HundredDaysofYARA = "Day 22"
	
	strings:
		$a1= "spload"
		$a2 = "NAQmmFk6Rp1corJ1"
		$a3 = "JJfZiG"
		
		$b1 = "0lWyY{-_Gt.$miL6/oC,%,|%$YQ/z"
		$b2 = "P8tT~eB>JBku{eUHU>(#mZnjSkjd@mW"
		$b3 = "?eIeT7fQfB9H1c&?y:}0!PZ"
	condition:
		all of ($a*) or
		any of ($b*)
			
}
