import "pe"

rule hdata_section{
	meta:
		    author = "CD_R0M_"
		    description = "check for existence of hdata section. This is rarely used legitimately"
		    HundredDaysofYARA = "Day 23"

	condition:
			  for any section in pe.sections: (section.name contains "hdata")
			
}
