import math
rule potentially_obfuscated_hta {
	meta:
		author = "CD_R0M_"
		description = "Overly obfuscated variables are often used to avoid detection of strings by malware. However, they are very uncommon for legitimate use"
    		HundredDaysofYara = "5"
		hash = "3bd98b1a3320c1c8626d01c4e471c9e2726eb74e"

	strings:
		$a1 = "<script" nocase
		$a2 ="var" nocase
		$a3 ="</script>" nocase

	condition:
		filesize < 2MB and all of ($a*) and math.entropy(0, filesize) >= 5
}
