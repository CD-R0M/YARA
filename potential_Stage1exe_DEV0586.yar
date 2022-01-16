import "pe"

rule potential_Stage1exe_DEV0586 {
	meta:
		author = "CD_R0M_"
		description = "I found a random binary on VT named stage1.exe. Not the binary Microsoft Identified, but my first Golang sample. Looks like an exploit dev testing"
    hash = "5f84be88bce05dc96fff308e7fab134c8f30bf071e418e44364b616c795605ee"
		HundredDaysofYARA = "Day 14"
	
  	strings:
		$a1= {52756e50726f6772616d3d222554454d50255c5374616765312e65786522}
		$a2 = {52756e50726f6772616d3d22686964636f6e3a2554454d50255c5374616765322e6578652078202d79202d6f2554454d5025202d70786e713872504d785649383763694777574a487852547933696175486349697274654f4f454c76334235766b53396b4a6f48425541616859316457786a38794122}
	condition:
		uint16(0) == 0x5A4D
		and $a1
		and pe.imports("kernel32.dll", "LoadLibraryA")
		and pe.imports("kernel32.dll", "VirtualAlloc")
}
