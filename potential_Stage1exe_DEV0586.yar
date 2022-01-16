import "pe"

rule potential_Stage1exe_DEV0586 {
	meta:
		author = "CD_R0M_"
		description = "Sample identified by @ffforward. Potentially related to Stage1.exe binary microsoft referenced"
		reference = "https://twitter.com/ffforward/status/1482697016987865096"
    		hash = "312bbd2041ddd599f1588d2a49da581e518500e21b41c57857dcd12565de247c"
		HundredDaysofYARA = "Day 15"
	
  	strings:
		$a1= {52756e50726f6772616d3d222554454d50255c5374616765312e65786522}
		$a2 = {52756e50726f6772616d3d22686964636f6e3a2554454d50255c5374616765322e6578652078202d79202d6f2554454d5025202d70786e713872504d785649383763694777574a487852547933696175486349697274654f4f454c76334235766b53396b4a6f48425541616859316457786a38794122}
	condition:
		uint16(0) == 0x5A4D
		and all of ($a*)
		and pe.imports("kernel32.dll", "LoadLibraryA")
		and pe.imports("kernel32.dll", "VirtualAlloc")
}
