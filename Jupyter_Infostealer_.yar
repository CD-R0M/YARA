import "pe"
import "dotnet"

rule Mal_Infostealer_EXE_Jupyter_Cert_36ff
{
    meta:
        description = "Detects Jupter executables by certificate OOO Sistema (36ff)"
        author = "BlackBerry Research & Intelligence Team"
        date = "2021-10-14"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"       

    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_signatures) : (
            pe.signatures[i].issuer contains "Certum Extended Validation Code Signing CA SHA2" and
            pe.signatures[i].serial == "36:ff:67:4e:b3:05:e9:9c:35:56:5f:a3:01:d5:c4:b0" // Serial variable must be lowercase
            )
}

rule Mal_Infostealer_MSI_EXE_Jupyter_Certificate
{
    meta:
        description = "Detects Jupter by certificate"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-04"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        // MSI Installer
        $msi = { D0 CF 11 E0 A1 B1 1A E1 }

        // MSI Strings
        $a1 = "EMCO MSI Package Builder"

        // PowerShell execution strings
        $b1 = "powershell-ExecutionPolicy bypass -command \"iex([\\[]IO.File[\\]]::ReadAllText('[CurrentUserProfileFolder]" nocase
        $b2 = "powershell-ep bypass -file \"[AppDataFolder]" nocase
        $b3 = /powershell-ep bypass -windowstyle hidden -command \"\$xp=\'\[AppDataFolder\].{0,256}\.{0,256}\'/ nocase
        $b4 = /powershell-ep bypass -windowstyle hidden -command \"\$p=\'\[AppDataFolder\].{0,256}\.{0,256}\'/ nocase
        $b5 = /powershell-ExecutionPolicy bypass -command \"iex\(\[\\\[\]IO.File\[\\\]\]::ReadAllText\(\'\[CurrentUserProfileFolder\].{1,256}\..{1,256}\'\)\)/ nocase

        // Certificate Name
        $c1 = "OOO ENDI"
        $c2 = "OOO MVS"
        $c3 = "OOO LEVELAP"
        $c4 = "Soto Manufacturing SRL"
        $c5 = "Decapolis Consulting Inc."

        // Co-signers
        $f1 = "SSL.com EV Root Certification Authority RSA R2"
        $f2 = "SSL.com EV Code Signing Intermediate CA RSA R3"
        $f3 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
        $f4 = "DigiCert Trusted Root G40"

    condition:
        ($msi at 0 or uint16(0) == 0x5a4d) and
        all of ($a*) and
        1 of ($b*) and
        1 of ($c*) and
        2 of ($f*)
}

rule Mal_Infostealer_MSI_Jupyter_Embedded_PowerShell
{
    meta:
        description = "Detects Jupter by a specific PowerShell command present in the MSI Installer"
        author = "BlackBerry Threat Research Team"
        date = "2021-10-14"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        // MSI Installer
        $msi = { D0 CF 11 E0 A1 B1 1A E1 }

        // Embedded PowerShell Command
        $x1 = /powershell-ep bypass -windowstyle hidden -command \"\$xp=\'\[AppDataFolder\]pd\w*\.(log|txt)\';\$xk=\'[a-zA-Z]{52}\';\$xb=\[\\\[\]System\.Convert\[\\\]\]::FromBase64String\(\[\\\[\]System\.IO\.File\[\\\]\]::ReadAllText\(\$xp\)\);remove-item \$xp;for\(\$i=0;\$i -lt \$xb.count;\)\[\\\{\]for\(\$j=0;\$j -lt \$xk\.length;\$j\+\+\)\[\\\{\]\$xb\[\\\[\]\$i\[\\\]\]=\$xb\[\\\[\]\$i\[\\\]\] -bxor \$xk\[\\\[\]\$j\[\\\]\];\$i\+\+;if\(\$i -ge \$xb.count\)\[\\\{\]\$j=\$xk\.length;\[\\\}\]\[\\\}\]\[\\\}\];\$xb=\[\\\[\]System.Text.Encoding\[\\\]\]::UTF8\.GetString\(\$xb\);iex \$xb;/ nocase

    condition:
        $msi at 0 and
        all of ($x*)
}

rule Mal_Infostealer_PowerShell_Jupyter_Updated_Samples
{
    meta:
        description = "Detects Jupter powershell via common strings"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-04"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $c1 = /\.[T|t][O|o][L|l][O|o][W|w][E|e][R|r]\(\)\)?;[I|i][E|e][X|x]/
        $c2 = "get-random -minimum 50000 -maximum 200000" nocase
        $c3 = "ReaDALlBYTES" nocase
        $c4 = /createshortcut\(\$env\:appdata\+'\\m\'\+\'icr\'\+\'oso\'\+\'ft\'\+\'\\w\'\+\'ind\'\+\'ow\'\+\'s\\\'\+\'st\'\+\'art\'\+\' me\'\+\'nu\'\+\'\\pr\'\+\'ogr\'\+\'ams\\\'\+\'st\'\+\'art\'\+\'up\'\+\'\\.{29}\.lnk\'\)/ nocase

    condition:
        all of ($c*)
}

rule Mal_Infostealer_Win32_Jupyter_Main_Module
{
    meta:
        description = "Detects Jupter main module"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-23"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $g1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 } // h.t.t.p.:././.
        $g2 = { 5C 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 5C 00 52 00 4F 00 41 00 4D 00 49 00 4E 00 47 } // \.A.P.P.D.A.T.A.\.R.O.A.M.I.N.G
        $g3 = { 63 00 68 00 61 00 6E 00 67 00 65 00 5F 00 73 00 74 00 61 00 74 00 75 00 73 } // c.h.a.n.g.e._.s.t.a.t.u.s
        $g4 = { 50 00 4F 00 53 00 54 } // P.O.S.T
        $g5 = { 69 00 73 00 5F 00 73 00 75 00 63 00 63 00 65 00 73 00 73 } // i.s._.s.u.c.c.e.s.s
        $g6 = { 75 00 73 00 65 00 72 00 70 00 72 00 6F 00 66 00 69 00 6C 00 65 } // u.s.e.r.p.r.o.f.i.l.e
        $g7 = { 44 00 45 00 53 00 4B 00 54 00 4F 00 50 00 2D } // D.E.S.K.T.O.P.-
        $g8 = { 4C 00 41 00 50 00 54 00 4F 00 50 00 2D } // L.A.P.T.O.P.-
        $g9 = { 78 00 38 00 36} // x.8.6
        $g10 = { 78 00 36 00 34 } // x.6.4
        $g11 = { 41 00 64 00 6D 00 69 00 6E } // A.d.m.i.n
        $g12 = { 56 00 69 00 73 00 74 00 61 } // V.i.s.t.a
        $g13 = { 64 00 6E 00 73 } // d.n.s
        $g14 = { 64 00 7A 00 6B 00 61 00 62 72 } // d.z.k.a.b.r
        $g15 = { 78 00 7A 00 6B 00 61 00 62 00 73 00 72 } // x.z.k.a.b.s.r
        $g16 = { 64 00 7A 00 6B 00 61 00 62 00 73 00 72 } // d.z.k.a.b.s.r

        // Version Strings
        $h1 = { 4F 00 43 00 2D } // O.C.-
        $h2 = { 4E 00 56 00 2D } // N.V.-
        $h3 = { 53 00 50 00 2D } // S.P.-
        $h4 = { 49 00 4E 00 2D } // I.N.-

        $i = "System.Net"

    condition:
        10 of ($g*) and
        1 of ($h*) and
        (pe.imports("mscoree.dll", "_CorDllMain") or $i) // DotNet
}

rule Mal_Infostealer_Win32_Jupyter_InfoStealer_Module
{
    meta:
        description = "Detects Jupter infostealer module"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-08"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $d1 = "WebRequest" nocase
        $d2 = "HttpWebRequest" nocase
        $d3 = "WebResponse" nocase
        $d4 = "GetResponseStream" nocase
        $d5 = "GetResponse" nocase
        $d6 = "IsInRole" nocase
        $d7 = "get_UTF8" nocase
        $d8 = "FromBase64String" nocase
        $d9 = "get_OSVersion" nocase
        $d10 = "GetFiles" nocase
        $d11 = "GetExtension" nocase
        $d12 = "get_Current" nocase
        $d13 = "GetEnumerator" nocase

        $j1 = { 6C 6F 67 69 6E 73 } // logins
        $j2 = { 43 00 6F 00 6F 00 6B 00 69 00 65 00 73 } // C.o.o.k.i.e.s
        $j3 = { 00 6C 00 6F 00 67 00 69 00 6E 00 73 00 2E 00 6A 00 73 00 6F 00 6E 00 } // .l.o.g.i.n.s...j.s.o.n.
        $j4 = { 00 63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 } // .c.o.o.k.i.e.s...s.q.l.i.t.e.

    condition:
        // DotNet
        pe.imports("mscoree.dll", "_CorDllMain") and
        12 of ($d*) and
        2 of ($j*)
}

rule Mal_Infostealer_Win32_Jupyter_Download_and_Execute_Module
{
    meta:
        description = "Detects Jupter download and execute module. Research has shown it downloading SolarDelphi / JupyterStealer."
        author = "BlackBerry Threat Research Team"
        date = "2021-11-09"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $e1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 }
        $e2 = { 47 00 45 00 54 00 00 3D 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 77 00 69 00 6E 00 76 00 65 00 72 00 2E 00 65 00 78 00 65 }
        $e3 = { 00 2F 00 67 00 65 00 74 00 2F 00 }
        $e4 = "FromBase64String"
        $e5 = "get_UTF8"
        $e6 = "WebResponse"
        $e7 = "GetResponse"
        $e8 = "Invoke"

    condition:
        // DotNet
        pe.imports("mscoree.dll", "_CorDllMain") and
        dotnet.version == "v4.0.30319" and
        dotnet.assembly.version.major == 0 and
        dotnet.assembly.version.minor == 0 and
        all of ($e*)
}
