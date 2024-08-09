rule APT10_ANEL_InitRoutine {
      meta:
        description = "ANEL malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "2371f5b63b1e44ca52ce8140840f3a8b01b7e3002f0a7f0d61aecf539566e6a1"

    	strings:
    		$GetAddress = { C7 45 ?? ?? 69 72 74 C7 45 ?? 75 61 6C 50 C7 45 ?? 72 6F 74 65 66 C7 45 ?? 63 74 [3-4] C7 45 ?? ?? 65 72 6E C7 45 ?? 65 6C 33 32 C7 45 ?? 2E 64 6C 6C [3-4] FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }
    	condition:
    		$GetAddress
}

rule APT10_redleaves_strings {
      meta:
        description = "RedLeaves malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "ff0b79ed5ca3a5e1a9dabf8e47b15366c1d0783d0396af2cbba8e253020dbb34"

    	strings:
    		$v1a = "red_autumnal_leaves_dllmain.dll"
        $w1a = "RedLeavesCMDSimulatorMutex" wide
    	condition:
    		$v1a or $w1a
}

rule APT10_redleaves_dropper1 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $a2a = {E8 ?? ?? FF FF 68 ?? 08 00 00 FF}
        $d2a = {83 C2 02 88 0E 83 FA 08}
        $d2b = {83 C2 02 88 0E 83 FA 10}
     condition:
        all of them
}

rule APT10_redleaves_dropper2 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "3f5e631dce7f8ea555684079b5d742fcfe29e9a5cea29ec99ecf26abc21ddb74"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $c2a = {B8 CD CC CC CC F7 E1 C1 EA 03}
        $c2b = {68 80 00 00 00 6A 01 6A 01 6A 01 6A 01 6A FF 50}
     condition:
        all of them
}

rule APT10_redleaves_dll {
      meta:
        description = "RedLeaves loader dll"
        author = "JPCERT/CC Incident Response Group"
        hash = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

     strings:
        $a2a = {40 3D ?? ?? 06 00 7C EA 6A 40 68 00 10 00 00 68 ?? ?? 06 00 6A 00 FF 15 ?? ?? ?? ?? 85 C0}
     condition:
        all of them
}

rule APT10_Himawari_strings {
      meta:
        description = "detect Himawari(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
        hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

      strings:
        $h1 = "himawariA"
        $h2 = "himawariB"
        $h3 = "HimawariDemo"
      condition: all of them
}

rule APT10_Lavender_strings {
      meta:
        description = "detect Lavender(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

      strings:
        $a1 = { C7 ?? ?? 4C 41 56 45 }
        $a2 = { C7 ?? ?? 4E 44 45 52 }
      condition: all of them
}

rule APT10_Armadill_strings {
      meta:
        description = "detect Armadill(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"

      strings:
        $a1 = { C7 ?? ?? 41 72 6D 61 }
        $a2 = { C7 ?? ?? 64 69 6C 6C }
      condition: all of them
}

rule APT10_zark20rk_strings {
      meta:
        description = "detect zark20rk(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

      strings:
        $a1 = { C7 ?? ?? 7A 61 72 6B }
        $a2 = { C7 ?? ?? 32 30 72 6B }
      condition: all of them
}

rule APT10_HTSrl_signed {
      meta:
        description = "HT Srl signature using APT10"
        author = "JPCERT/CC Incident Response Group"
        hash = "2965c1b6ab9d1601752cb4aa26d64a444b0a535b1a190a70d5ce935be3f91699"

    	strings:
            $c="IT"
            $st="Italy"
            $l="Milan"
            $ou="Digital ID Class 3 - Microsoft Software Validation v2"
            $cn="HT Srl"
    	condition:
        	all of them
}

rule APT10_ChChes_lnk {
      meta:
        description = "LNK malware ChChes downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"

    	strings:
    		$v1a = "cmd.exe"
     		$v1b = "john-pc"
    		$v1c = "win-hg68mmgacjc"
        $v1d = "t-user-nb"
        $v1e = "C:\\Users\\suzuki\\Documents\\my\\card.rtf" wide
    	condition:
    		$v1a and ($v1b or $v1c or $v1d) or $v1e
}

rule APT10_ChChes_strings
{
      meta:
        description = "ChChes malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "7d515a46a7f4edfbae11837324f7c56b9a8164020e32aaaa3bef7d38763dd82d "

    	strings:
    		$v1a = "/%r.html"
    		$v1b = "http://"
    		$v1c = "atan2"
    		$v1d = "_hypot"
    		$v1e = "_nextafter"
    		$d1a = { 68 04 E1 00 00 }
    	condition:
    		all of them
}

rule APT10_ChChes_powershell {
      meta:
        description = "ChChes dropper PowerShell based PowerSploit"
        author = "JPCERT/CC Incident Response Group"
        hash = "9fbd69da93fbe0e8f57df3161db0b932d01b6593da86222fabef2be31899156d"

    	strings:
    		$v1a = "Invoke-Shellcode"
    		$v1b = "Invoke-shCdpot"
    		$v1c = "invoke-ExEDoc"
    	condition:
    		$v1c and ($v1a or $v1b)
}

rule CryptHunter_downloaderjs {
     meta:
        description = "JS downloader executed from an lnk file used in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "bb7349d4fd7efa838a92fc4a97ec2a25b82dde36236bdc09b531c20370d7f848"

     strings:
        $a = "pi.ProcessID!==0 && pi.ProcessID!==4){"
        $b = "prs=prs+pi.CommandLine.toLowerCase();}"

     condition:
       any of them
}

rule CryptHunter_lnk_bitly {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        reference = "internal research"
        hash1 = "01b5cd525d18e28177924d8a7805c2010de6842b8ef430f29ed32b3e5d7d99a0"

      strings:
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta" wide ascii
        $url1 = "https://bit.ly" wide ascii

      condition:
        (uint16(0) == 0x004c) and
        (filesize<100KB)  and
        ((1 of ($a*)) and ($url1))
}

rule CryptHunter_httpbotjs_str {
    meta:
        description = "HTTP bot js in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b316b81bc0b0deb81da5e218b85ca83d7260cc40dae97766bc94a6931707dc1b"

     strings:
        $base64 = "W0NtZGxldEJpbmRpbmcoKV1QYXJhbShbUGFyYW1ldGVyKFBvc2l0aW9uPTApXVtTdHJpbmddJFVSTCxbUGFyYW1ldGVyKFBvc2l0aW9uPTEpXVtTdHJpbmddJFVJRCkNCmZ1bmN0aW9uIEh0dHBSZXEyew" ascii
        $var1 = { 40 28 27 22 2b 70 32 61 2b 22 27 2c 20 27 22 2b 75 69 64 2b 22 27 29 3b 7d }

     condition:
        all of them
}



rule CryptHunter_devobjDLL_VMprotect {
    meta:
      description = "Hunt devobjDLL"
      author = "JPCERT/CC Incident Response Group"
      hash = "1599F7365DB421E4FE07A169309624E7E25D4F28CD1B101D340D54D66B6EB921"
    
    strings:
        /* Function Address: 0x7ff83da22fc9 : sub_7FF83DA22FC9
        D0 E5                               shl     ch, 1                 
        50                                  push    rax                   
        48 0D 66 DD D2 68                   or      rax, 68D2DD66h        
        66 0F BA F9 0F                      btc     cx, 0Fh               
        0F 98 C5                            sets    ch                    
        48 0F AB F8                         bts     rax, rdi              
        48 89 D9                            mov     rcx, rbx; lpLibFileName
        66 0F B6 C1                         movzx   ax, cl                
        48 D3 D8                            rcr     rax, cl               
        48 83 EC 20                         sub     rsp, 20h              
        66 0F B6 C3                         movzx   ax, bl                
        0F 96 C0                            setbe   al                    
        */
        $func0 = { D0 E5 50 48 0D 66 DD D2 68 66 0F BA F9 0F 0F 98 C5 48 0F AB F8 48 89 D9 66 0F B6 C1 48 D3 D8 48 83 EC 20 66 0F B6 C3 0F 96 C0 }

        /* Function Address: 0x7ff83da2c408 : sub_7FF83DA2C408
        57                                  push    rdi                   
        48 83 EC 10                         sub     rsp, 10h              
        33 C0                               xor     eax, eax              
        33 C9                               xor     ecx, ecx              
        0F A2                               cpuid                         
        44 8B C1                            mov     r8d, ecx              
        45 33 DB                            xor     r11d, r11d            
        44 8B D2                            mov     r10d, edx             
        41 81 F0 6E 74 65 6C                xor     r8d, 6C65746Eh        
        41 81 F2 69 6E 65 49                xor     r10d, 49656E69h       
        44 8B CB                            mov     r9d, ebx              
        8B F0                               mov     esi, eax              
        33 C9                               xor     ecx, ecx              
        */
        $func1 = { 57 48 83 EC 10 33 C0 33 C9 0F A2 44 8B C1 45 33 DB 44 8B D2 41 81 F0 6E 74 65 6C 41 81 F2 69 6E 65 49 44 8B CB 8B F0 33 C9 }

        /* Function Address: 0x7ff83da2fe8c : sub_7FF83DA2FE8C
        33 C9                               xor     ecx, ecx              
        3B D0                               cmp     edx, eax              
        0F 92 C1                            setb    cl                    
        33 C0                               xor     eax, eax              
        45 3B F1                            cmp     r14d, r9d             
        44 8B F2                            mov     r14d, edx             
        0F 97 C0                            setnbe  al                    
        0B C8                               or      ecx, eax              
        C1 E1 02                            shl     ecx, 2                
        83 C9 08                            or      ecx, 8                
        0B F9                               or      edi, ecx              
        49 FF C0                            inc     r8                    
        */
        $func2 = { 33 C9 3B D0 0F 92 C1 33 C0 45 3B F1 44 8B F2 0F 97 C0 0B C8 C1 E1 02 83 C9 08 0B F9 49 FF C0 }

        /* Function Address: 0x7ff83da31fcc : sub_7FF83DA31FCC
        8B C8                               mov     ecx, eax              
        83 E1 3F                            and     ecx, 3Fh              
        48 33 C2                            xor     rax, rdx              
        48 D3 C8                            ror     rax, cl               
        49 BA 70 28 D9 78 45 2E 01 99       mov     r10, 99012E4578D92870h
        45 33 C0                            xor     r8d, r8d              
        33 D2                               xor     edx, edx              
        33 C9                               xor     ecx, ecx              
        */
        $func3 = { 8B C8 83 E1 3F 48 33 C2 48 D3 C8 49 BA 70 28 D9 78 45 2E 01 99 45 33 C0 33 D2 33 C9 }

        /* Function Address: 0x7ff83da34234 : sub_7FF83DA34234
        4C 8B C1                            mov     r8, rcx               
        B8 20 00 00 00                      mov     eax, 20h ; ' '        
        41 83 E0 1F                         and     r8d, 1Fh              
        49 2B C0                            sub     rax, r8               
        49 F7 D8                            neg     r8                    
        4D 1B D2                            sbb     r10, r10              
        4C 23 D0                            and     r10, rax              
        49 8B C1                            mov     rax, r9               
        49 3B D2                            cmp     rdx, r10              
        4C 0F 42 D2                         cmovb   r10, rdx              
        49 03 CA                            add     rcx, r10              
        4C 3B C9                            cmp     r9, rcx               
        */
        $func4 = { 4C 8B C1 B8 20 00 00 00 41 83 E0 1F 49 2B C0 49 F7 D8 4D 1B D2 4C 23 D0 49 8B C1 49 3B D2 4C 0F 42 D2 49 03 CA 4C 3B C9 }

        /* Function Address: 0x7ff83da34ae4 : sub_7FF83DA34AE4
        41 55                               push    r13                   
        41 56                               push    r14                   
        41 57                               push    r15                   
        48 83 EC 30                         sub     rsp, 30h              
        33 C0                               xor     eax, eax              
        49 63 E8                            movsxd  rbp, r8d              
        45 85 C0                            test    r8d, r8d              
        45 8A E9                            mov     r13b, r9b             
        4C 8B FA                            mov     r15, rdx              
        48 8B F9                            mov     rdi, rcx              
        0F 4F C5                            cmovg   eax, ebp              
        83 C0 09                            add     eax, 9                
        48 98                               cdqe                          
        48 3B D0                            cmp     rdx, rax              
        */
        $func5 = { 41 55 41 56 41 57 48 83 EC 30 33 C0 49 63 E8 45 85 C0 45 8A E9 4C 8B FA 48 8B F9 0F 4F C5 83 C0 09 48 98 48 3B D0 }

        /* Function Address: 0x7ff83da3ddd0 : sub_7FF83DA3DDD0
        44 8B D0                            mov     r10d, eax             
        44 8B C8                            mov     r9d, eax              
        41 C1 E9 03                         shr     r9d, 3                
        41 83 E1 10                         and     r9d, 10h              
        44 8B C0                            mov     r8d, eax              
        41 BE 00 02 00 00                   mov     r14d, 200h            
        41 8B D1                            mov     edx, r9d              
        83 CA 08                            or      edx, 8                
        45 23 C6                            and     r8d, r14d             
        41 0F 44 D1                         cmovz   edx, r9d              
        8B CA                               mov     ecx, edx              
        83 C9 04                            or      ecx, 4                
        25 00 04 00 00                      and     eax, 400h             
        0F 44 CA                            cmovz   ecx, edx              
        41 8B C2                            mov     eax, r10d             
        41 B9 00 08 00 00                   mov     r9d, 800h             
        8B D1                               mov     edx, ecx              
        83 CA 02                            or      edx, 2                
        41 23 C1                            and     eax, r9d              
        0F 44 D1                            cmovz   edx, ecx              
        41 8B C2                            mov     eax, r10d             
        41 BB 00 10 00 00                   mov     r11d, 1000h           
        8B CA                               mov     ecx, edx              
        83 C9 01                            or      ecx, 1                
        41 23 C3                            and     eax, r11d             
        0F 44 CA                            cmovz   ecx, edx              
        41 8B C2                            mov     eax, r10d             
        BE 00 01 00 00                      mov     esi, 100h             
        8B D1                               mov     edx, ecx              
        0F BA EA 13                         bts     edx, 13h              
        23 C6                               and     eax, esi              
        0F 44 D1                            cmovz   edx, ecx              
        41 8B C2                            mov     eax, r10d             
        41 BF 00 60 00 00                   mov     r15d, 6000h           
        41 23 C7                            and     eax, r15d             
        */
        $func6 = { 44 8B D0 44 8B C8 41 C1 E9 03 41 83 E1 10 44 8B C0 41 BE 00 02 00 00 41 8B D1 83 CA 08 45 23 C6 41 0F 44 D1 8B CA 83 C9 04 25 00 04 00 00 0F 44 CA 41 8B C2 41 B9 00 08 00 00 8B D1 83 CA 02 41 23 C1 0F 44 D1 41 8B C2 41 BB 00 10 00 00 8B CA 83 C9 01 41 23 C3 0F 44 CA 41 8B C2 BE 00 01 00 00 8B D1 0F BA EA 13 23 C6 0F 44 D1 41 8B C2 41 BF 00 60 00 00 41 23 C7 }

        /* Function Address: 0x7ff83da3d7a4 : sub_7FF83DA3D7A4
        83 E2 3F                            and     edx, 3Fh              
        44 8B C2                            mov     r8d, edx              
        8B C2                               mov     eax, edx              
        83 E0 10                            and     eax, 10h              
        41 C1 E8 02                         shr     r8d, 2                
        41 83 E0 08                         and     r8d, 8                
        8B CA                               mov     ecx, edx              
        44 0B C0                            or      r8d, eax              
        83 E1 02                            and     ecx, 2                
        41 C1 E8 02                         shr     r8d, 2                
        8B C2                               mov     eax, edx              
        83 E0 08                            and     eax, 8                
        C1 E1 03                            shl     ecx, 3                
        44 0B C0                            or      r8d, eax              
        8B C2                               mov     eax, edx              
        83 E0 04                            and     eax, 4                
        41 D1 E8                            shr     r8d, 1                
        0B C8                               or      ecx, eax              
        83 E2 01                            and     edx, 1                
        03 C9                               add     ecx, ecx              
        C1 E2 04                            shl     edx, 4                
        44 0B C1                            or      r8d, ecx              
        44 0B C2                            or      r8d, edx              
        41 8B C0                            mov     eax, r8d              
        C1 E0 18                            shl     eax, 18h              
        41 0B C0                            or      eax, r8d              
        C3                                  retn                          
        */
        $func7 = { 83 E2 3F 44 8B C2 8B C2 83 E0 10 41 C1 E8 02 41 83 E0 08 8B CA 44 0B C0 83 E1 02 41 C1 E8 02 8B C2 83 E0 08 C1 E1 03 44 0B C0 8B C2 83 E0 04 41 D1 E8 0B C8 83 E2 01 03 C9 C1 E2 04 44 0B C1 44 0B C2 41 8B C0 C1 E0 18 41 0B C0 C3 }

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize < 1MB)
        and (filesize > 100KB)
        and ( 8 of ($func*) )
}


rule CryptHunter_pythonDownloader {
    meta:
        description = "1st stage python downloader in Dangerouspassword"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "e0891a1bfa5980171599dc5fe31d15be0a6c79cc08ab8dc9f09ceec7a029cbdf"

    strings:
        $str01 = "auto_interrupt_handle" ascii wide fullword
        $str02 = "aW1wb3J0IHN0cmluZw0KaW1wb3J0IHJhbmRvbQ0" ascii wide fullword

        $rot13_01 = "clguba" ascii wide fullword
        $rot13_02 = "log_handle_method" ascii wide fullword
        $rot13_03 = "rot13" ascii wide fullword
        $rot13_04 = "zfvrkrp" ascii wide fullword
        $rot13_05 = "Jvaqbjf" ascii wide fullword
        $rot13_06 = ".zfv" ascii wide fullword
        $rot13_07 = "qrirybcpber" ascii wide fullword
        $rot13_08 = "uggc://ncc." ascii wide fullword
        $rot13_09 = "cat_file_header_ops" ascii wide fullword

    condition:
        (filesize > 10KB)
        and (filesize < 5MB)
        and ( 1 of ($str*) or ( 3 of ($rot13*) ))
}

rule CryptHunter_pythonSimpleRAT {
    meta:
        description = "2nd stage python simple rat in Dangerouspassword"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
        hash2 = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"

    strings:
        $domain01 = "www.git-hub.me" ascii wide fullword
        $domain02 = "nivyga.com" ascii wide fullword
        $domain03 = "tracking.nivyga.com" ascii wide fullword
        $domain04 = "yukunmaoyi.com" ascii wide fullword
        $domain05 = "gameofwarsite.com" ascii wide fullword
        $domain06 = "togetherwatch.com" ascii wide fullword
        $domain07 = "9d90-081d2f-vultr-los-angeles-boxul.teridions.net" ascii wide fullword
        $domain08 = "8dae-77766a-vultr-los-angeles-egnyte-sj.d1.teridioncloud.net" ascii wide fullword
        $domain09 = "www.jacarandas.top" ascii wide fullword
        $domain10 = "cleargadgetwinners.top" ascii wide fullword
        $domain11 = "ns1.smoothieking.info" ascii wide fullword
        $domain12 = "ns2.smoothieking.info" ascii wide fullword

        $str01 = "Jvaqbjf" ascii wide fullword
        $str02 = "Yvahk" ascii wide fullword
        $str03 = "Qnejva" ascii wide fullword
        $str04 = "GITHUB_REQ" ascii wide fullword
        $str05 = "GITHUB_RES" ascii wide fullword
        $str06 = "BasicInfo" ascii wide fullword
        $str07 = "CmdExec" ascii wide fullword
        $str08 = "DownExec" ascii wide fullword
        $str09 = "KillSelf" ascii wide fullword
        $str10 = "pp -b /gzc/.VPR-havk/tvg" ascii wide fullword
        $str11 = "/gzc/.VPR-havk/tvg" ascii wide fullword
        $str12 = "NccyrNppbhag.gtm" ascii wide fullword
        $str13 = "/GrzcHfre/NccyrNppbhagNffvfgnag.ncc" ascii wide fullword
        $str14 = "Pheerag Gvzr" ascii wide fullword
        $str15 = "Hfreanzr" ascii wide fullword
        $str16 = "Ubfganzr" ascii wide fullword
        $str17 = "BF Irefvba" ascii wide fullword
        $str18 = "VQ_YVXR=qrovna" ascii wide fullword
        $str19 = "VQ=qrovna" ascii wide fullword
        $str20 = "/rgp/bf-eryrnfr" ascii wide fullword
        $str21 = " -yafy -ycguernq -yerfbyi -fgq=tah99" ascii wide fullword

    condition:
        (filesize > 1KB) 
        and (filesize < 5MB)
        and ( 1 of ($domain*) or ( 5 of ($str*) ))
}

rule CryptHunter_jsDownloader {
    meta:
        description = "1st stage js downloader in Dangerouspassword"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "67a0f25a20954a353021bbdfdd531f7cc99c305c25fb03079f7abbc60e8a8081"

    strings:
        $code01 = "UID + AgentType + SessionType + OS;" ascii wide fullword
        $code02 = "received_data.toString().startsWith" ascii wide fullword
        $str01 = "GITHUB_RES" ascii wide fullword
        $str02 = "GITHUB_REQ" ascii wide fullword

    condition:
        (filesize > 1KB)
        and (filesize < 5MB)
        and ( 1 of ($code*) or ( 2 of ($str*) ))
}

rule CryptHunter_JokerSpy_macos {
     meta:
        description = "Mach-O malware using CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
        hash = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
        hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"

     strings:
        $db = "/Library/Application Support/com.apple.TCC/TCC.db" ascii
        $path = "/Users/joker/Downloads/Spy/XProtectCheck/XProtectCheck/" ascii
        $msg1 = "The screen is currently LOCKED!" ascii
        $msg2 = "Accessibility: YES" ascii
        $msg3 = "ScreenRecording: YES" ascii
        $msg4 = "FullDiskAccess: YES" ascii
        $msg5 = "kMDItemDisplayName = *TCC.db" ascii

     condition:
       (uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xcafebabe or
        uint32(0) == 0xbebafeca or
        uint32(0) == 0xcafebabf or
        uint32(0) == 0xbfbafeca) and
       5 of them
}
