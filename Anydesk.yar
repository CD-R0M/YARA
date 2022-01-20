import "pe"

rule Anydesk_masquerading {
	meta:
             author = "CD_R0M_"
	     description = "Anydesk is commonly used by threat actors for remote access. This rule aims to identify legitimate anydesk, renamed binaries and trojanized versions."
	     HundredDaysofYARA = "Day 19"
	
	strings:
		$a1= "AnyDesk.pdb" nocase ascii wide
		$a2 = "AnyDesk Software GmbH" nocase ascii wide
		
	condition:
		 uint16(0) == 0x5A4D
		 and all of ($a*)
}

rule Anydesk_masquerading {
	meta:
		    author = "CD_R0M_"
		    description = "Anydesk is commonly used by threat actors. This rule aims to identify legitimate anydesk, renamed binaries and trojanized versions."
		    HundredDaysofYARA = "Day 19"
	
	strings:
		     $a1= "AnyDesk.pdb" nocase ascii wide
			 $a2 = "AnyDesk Software GmbH" nocase ascii wide

	condition:
		     uint16(0) == 0x5A4D
		     and all of ($a*) and
			 for any i in (0 .. pe.number_of_signatures) : (
				pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA"
			)
}

