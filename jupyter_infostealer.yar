rule Jupyter_infostealer {
  meta:
    author = "CD_R0M_"
    description = "Rule for Jupyter Infostealer/Solarmarker malware from september 2021-December 2022"
	hash = "9d52082b5cb651b43b0f49e83354a11c5a200fd8"
    HundredDaysofYara = "10"
	
  strings:
	$pdf1 = "sumatraPDF" nocase ascii wide
	$pdf2 = "EMCO EVALUATION" nocase ascii wide

	$pers = "Startup" nocase ascii wide
	
	$reg1 = "classes" nocase ascii wide
	$reg2 = "shell" nocase ascii wide
	$reg3 = "open" nocase ascii wide
	$reg4 = "command" nocase ascii wide
	
	$pwrshell = "system.text.encoding" nocase ascii wide
	
  condition:
    1 of ($pdf*) and $pers and all of ($reg*) and $pwrshell
}
