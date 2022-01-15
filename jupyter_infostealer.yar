rule Jupyter_infostealer {
  meta:
    author = "CD_R0M_"
    description = "Rule for Jupyter Infostealer/Solarmarker malware from september 2021-December 2022"
	hash = "9d52082b5cb651b43b0f49e83354a11c5a200fd8"
    HundredDaysofYara = "10"
	
  strings:
	$a1 = "sumatraPDF" nocase ascii
	$a2 = "EMCO" nocase ascii
	$a3 = "XML Installer" nocase ascii
	$a4 = "SlimReader" nocase ascii
	
	$pers = "Startup" nocase ascii
	
	$reg1 = "classes" nocase ascii
	$reg2 = "shell" nocase ascii
	$reg3 = "open" nocase ascii
	$reg4 = "command" nocase ascii
	
	$pwrshell = "system.text.encoding" nocase ascii
	
  condition:
    1 of ($a*) and $pers and all of ($reg*) and $pwrshell
}
