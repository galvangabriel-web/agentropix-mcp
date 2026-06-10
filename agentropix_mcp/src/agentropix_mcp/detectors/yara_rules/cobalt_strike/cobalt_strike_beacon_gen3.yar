/*
   Agentropix-SIFT — W-052-T2 Cobalt Strike Beacon Detection (Gen 3)
   --------------------------------------------------------------------
   Targets Cobalt Strike beacons of generation 3.x (CS 3.0 - 3.14).
   These beacons share a common configuration pattern (XOR-encoded
   beacon settings, fixed magic markers) that pre-dates the Gen 4
   protocol overhaul.

   Reference samples: SRL-2018 corpus (DC and admin workstation memory
   dumps). Rule names are stable identifiers; downstream HuntAgent
   correlates on the rule name as a token.
*/

rule CS_Beacon_Gen3_XOR_Config
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike Gen3 beacon — XOR-encoded config"
        family        = "cobalt_strike"
        generation    = "3"
        confidence    = "high"
        mitre         = "T1055"
        ticket        = "W-052-T2"

    strings:
        // XOR-encoded config marker observed across CS 3.0-3.14
        $cfg_marker_a = { 69 6E 64 6F 77 73 }                       // "indows" (Windows env strings)
        $xor_key_a    = { 2E 2E 2E 2E 2E 2E 2E 2E }                 // common 0x2E XOR key footprint
        $beacon_str_a = "%s as %s\\%s: %d" ascii wide
        $beacon_str_b = "beacon.x64.dll" ascii wide nocase
        $beacon_str_c = "beacon.x86.dll" ascii wide nocase
        $beacon_str_d = "ReflectiveLoader" ascii wide

    condition:
        uint16(0) == 0x5A4D and    // PE header (MZ)
        filesize < 5MB and
        2 of ($beacon_str_*) and
        any of ($cfg_marker_*, $xor_key_*)
}

rule CS_Beacon_Gen3_Stager_RUNDLL32
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike Gen3 beacon stager — RUNDLL32 LOLBin invocation"
        family        = "cobalt_strike"
        generation    = "3"
        confidence    = "high"
        mitre         = "T1218.011"
        ticket        = "W-052-T2"

    strings:
        $rundll_a     = "rundll32.exe" ascii wide nocase
        $rundll_b     = "RUNDLL32.EXE" ascii wide
        $stager_a     = "StartW" ascii wide                          // CS stager export
        $stager_b     = "ReflectiveLoader" ascii wide
        $artifact_a   = "artifact.exe" ascii wide nocase             // CS default beacon name
        $artifact_b   = "beacon.exe"  ascii wide nocase
        $loader_a     = "LoadLibraryA" ascii
        $loader_b     = "VirtualAlloc" ascii
        $loader_c     = "WinExec" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($rundll_*) and
        any of ($stager_*) and
        any of ($artifact_*, $loader_*)
}
