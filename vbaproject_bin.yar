rule vbaproject_bin {
	meta:
		author = "CD_R0M_"
		description = "{76 62 61 50 72 6f 6a 65 63 74 2e 62 69 6e} is hex for vbaproject.bin. Macros are often used by threat actors. Work in progress - Ran out of time"
		Hundreddaysofyara = "Day 4"
	strings:
		$s1 = {76 62 61 50 72 6f 6a 65 63 74 2e 62 69 6e}

	condition:
		$s1
}
