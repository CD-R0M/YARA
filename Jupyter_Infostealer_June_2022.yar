rule Jupyter_infostealer_June_2022 {
  meta:
    	author = "CD_R0M_"
    	description = "Rule aims to detect multiple variants of Jupyter Infostealer"
    	hash = "9d52082b5cb651b43b0f49e83354a11c5a200fd8"
    	hash2 = "8c12f63dde4a40e6e52725525b381279b2c9772bbb159a514a372cb2d232e906"
    	hash3 = "e99896598b6c6df29735f4c0f08c99ff49275cba850c81c1249e865b6f4f8ba8"
    	hash4 = "5cf24553e521de102628e1ebdadb69a6623904f08b51cf5b1ea14779e03e8682"
    	hash5 = "11543f09c416237d92090cebbefafdb2f03cec72a6f3fdedf8afe3c315181b5a"
	
  strings:
	$a1 = "ReadAllText" ascii
	$a2 = "MPB_" ascii wide
	$a3 = "System.Convert" ascii
	$b1 = "g988j988l988n988p988q988s888t888u888v888w888x888y888y888z888{888{888{888|888|888|888|888|888}888}888}888}888~888~888~888~889~889~889}889}899}899}899|899|899|899|899|888{988{899x" ascii
	$b2 = "supportedOS Id=" ascii
	$c1 = "IOSdyabisytda" wide fullword nocase
	$c2 = "Random" ascii
	$c3 = "System.Management.Automation" ascii
	$d1 = {6561746500436F6D70696C657247656E657261746564417474726962757465004775696441747472696275746500417373656D626C795469746C6541747472696275746500417373656D626C7954726164656D61726B41747472696275746500416C6C6F774E756C6C41747472696275746500417373656D626C7946696C6556657273696F6E417474726962757465}
	$d2 = {4465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F}
	$d3 = {61626C650049446973706F7361626C650052756E74696D654669656C6448616E646C650052756E74696D655479706548616E646C65004765745479706546726F6D48616E646C6500}
	$d4 = "asInvoker" ascii
	$d5 = "ProcessStartInfo" ascii
	$d6 = "WrapNonExceptionThrows" ascii
	$e1 = "Nitro Pro" ascii
	$e2 = "Evaluation" ascii nocase
	$e3 = "Advanced Installer" ascii nocase
	$f1 = "EMCO MSI Package Builder" ascii
      	$f2 = "powershell-ep bypass -windowstyle hidden -command" ascii
	$f3 = "powershell-ExecutionPolicy bypass"
	$msi = { D0 CF 11 E0 A1 B1 1A E1 }
  condition:
	(all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*) or all of ($e*) or 2 of ($f*)) and
	filesize > 7MB and
	(uint16(0) == 0x5A4D or $msi at 0)
}
