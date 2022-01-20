import "pe"

rule Anydesk_masquerading {
	meta:
		    author = "CD_R0M_"
		    description = "Anydesk is commonly used by threat actors. Although not often, occassionly it is renamed. Knowing about it in your environment is valuable"
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
		    description = "Anydesk is commonly used by threat actors. Although not often, occassionly it is renamed. Knowing About it in your environment is valuable"
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

