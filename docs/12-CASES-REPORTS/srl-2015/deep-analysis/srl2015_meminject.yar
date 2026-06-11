rule SRL2015_MemInject_VB_Family
{
    meta:
        case        = "SRL-2015-APT-ENTERPRISE"
        author      = "agentropix"
        date        = "2026-06-10"
        description = "Detects the SRL-2015 (Stark Research Labs / SANS FOR508) VB6 injected shellcode family recovered via Volatility malfind. Anchors: 8-byte length header + E9 JMP loader stub, msvbvm60 (VB6 runtime) reference, and the OpenProcess/GetModuleHandleA/VirtualProtect injection API cluster (RWX self-modify). Two byte-variants: A (pid 23476/26340) EBP frame, B (pid 145896/151132 femc / nfury pid328) ESP frame. STATIC family signature for memory-injected pages."
        reference   = "Volatility malfind injected RWX VAD; F-Response process masquerade"
        // SHA-256 of the 5 confirmed malfind payloads (8192 bytes each):
        sha256_17_pid23476  = "42f33a83da0cecb9ddf53741423895221fca55060ade80e47ecd2a0ea2fe10c3"
        sha256_18_pid26340  = "73cb9ad706455f0a115338784f5bf9c24e7ea22dcfd69f93dd9b3f375fe00231"
        sha256_19_pid145896 = "e855864aba934e143745fe6e6ba2a08a75bdbe5a32ff0e27e00a852d00d264d7"
        sha256_20_pid151132 = "dd8ac01d1d5e8865592443dc07faf1034fcc515f6522b2918ec7dc8bfe203ebd"
        sha256_21_pid328    = "a8f9a2103327bbc2bda06ff2db02ffe628978b115139f2b06d26a69dd79233f3"

    strings:
        // Stable loader header: 8-byte little-endian length field (0x08) then E9 (near JMP rel32) loader stub.
        $hdr     = { 08 00 00 00 00 00 00 00 E9 }

        // Variant-specific JMP targets (kept for cluster discrimination, not required to fire).
        $jmp_A   = { 08 00 00 00 00 00 00 00 E9 F7 07 00 00 }   // cluster A (17,18)
        $jmp_B   = { 08 00 00 00 00 00 00 00 E9 60 08 00 00 }   // cluster B (19,20,21)

        // VB6 runtime origin.
        $vb      = "msvbvm" ascii

        // Injection / RWX API name cluster (resolved by name at runtime, stored as plain strings).
        $api1    = "OpenProcess" ascii
        $api2    = "GetModuleHandleA" ascii
        $api3    = "VirtualProtect" ascii
        $api4    = "kernel32" ascii

        // VB runtime-error string artifacts carried in the injected page.
        $err1    = "Application error" ascii
        $err2    = "The procedure %s could not be located in the DLL %s." ascii

        // Contiguous API table as laid out in the page (high-confidence).
        $apitab  = "OpenProcess\x00GetModuleHandleA\x00VirtualProtect" ascii

    condition:
        // Memory-injected pages are small; bound to keep this fast on malfind dumps.
        filesize < 256KB
        and $hdr at 0
        and $vb
        and $api4                       // "kernel32" import-resolver target
        and all of ($api1, $api2, $api3)
        and ( $apitab or $err1 or $err2 )
        // Cluster discriminators referenced here so YARA does not flag them unused;
        // detection does NOT require a specific variant (a third recompile would still fire above).
        and ( $jmp_A at 0 or $jmp_B at 0 or $hdr at 0 )
}
