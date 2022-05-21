rule Raspberry_Robin_DLL_MAY_2022 {
	meta:
		author = "CD_R0M_"
		description = "Detects DLL dropped by Raspberry Robin."
		hash1 = "1d2c8db9ac6082f32e9178469c2c416e5e170095d7f84a771dbb91192c681598"
		hash2 = "1a5fcb209b5af4c620453a70653263109716f277150f0d389810df85ec0beac1"
		reference = "https://redcanary.com/blog/raspberry-robin/"
		date = "2022-05-21"
		
	strings:
		$a1 = "GetBinaryType" ascii
		
		$b1 = "MakeSignature" ascii
		$b2 = "DeletePort" ascii
		$b3 = "GetUrlCacheEntryInfoEx" ascii
		$b4 = "DeleteVolumeMountPoint" ascii
		$b5 = "CryptCATCDFClose" ascii
		$b6 = "CertCreateSelfSignCertificate" ascii
		
		
	condition:
		filesize < 2MB and $a1 and 2 of ($b*)
}


rule Raspberry_Robin_DLL_MAY_2022_2 {
	meta:
		author = "CD_R0M_"
		description = "Detects DLL dropped by Raspberry Robin. More specific with pdb paths to limit FP."
		hash1 = "1d2c8db9ac6082f32e9178469c2c416e5e170095d7f84a771dbb91192c681598"
		hash2 = "1a5fcb209b5af4c620453a70653263109716f277150f0d389810df85ec0beac1"
		reference = "https://redcanary.com/blog/raspberry-robin/"
		date = "2022-05-21"
		
	strings:
		$a1 = "GetBinaryType" ascii
		
		$b1 = "MakeSignature" ascii
		$b2 = "DeletePort" ascii
		$b3 = "GetUrlCacheEntryInfoEx" ascii
		$b4 = "DeleteVolumeMountPoint" ascii
		$b5 = "CryptCATCDFClose" ascii
		$b6 = "CertCreateSelfSignCertificate" ascii
		
		$c1 = "r:\\n\\te\\ere\\fpon\\oracl.pdb"
		$c2 = "d:\\in\\the\\town\\where\\ahung.pdb"
		
	condition:
		filesize < 2MB and $a1 and 2 of ($b*) and 1 of ($c*)
}

