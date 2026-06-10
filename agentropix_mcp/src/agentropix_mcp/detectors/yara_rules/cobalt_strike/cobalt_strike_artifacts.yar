/*
   Agentropix-SIFT — W-052-T2 Cobalt Strike Auxiliary Artifact Detection
   --------------------------------------------------------------------
   Catches CS artefacts that aren't beacons or loaders themselves but
   appear in CS-toolkit deployments: SMB named-pipe templates, sleep
   masking dlls, and the "post-ex" toolset (mimikatz, hashdump).

   These are *secondary* indicators; combined with a beacon/loader hit
   they raise the analyst's confidence that a CS toolkit is present
   rather than an unrelated XOR-loaded binary.
*/

rule CS_Auxiliary_NamedPipe
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike SMB beacon — default named pipe templates"
        family        = "cobalt_strike"
        component     = "auxiliary"
        confidence    = "medium"
        mitre         = "T1071.002"
        ticket        = "W-052-T2"

    strings:
        // Default malleable SMB named pipe formats
        $pipe_a = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe_b = "\\\\.\\pipe\\MSSE-"     ascii wide
        $pipe_c = "\\\\.\\pipe\\status_"   ascii wide
        $pipe_d = "\\\\.\\pipe\\postex_"   ascii wide
        $pipe_e = "\\\\.\\pipe\\mojo."     ascii wide
        $pipe_f = "\\\\.\\pipe\\ntsvcs"    ascii wide
        $pipe_g = "\\\\.\\pipe\\InitShutdown" ascii wide
        $pipe_h = "\\\\.\\pipe\\lsarpc"    ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule CS_PostEx_Toolkit
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike post-exploitation kit — mimikatz / hashdump artefacts"
        family        = "cobalt_strike"
        component     = "post-exploitation"
        confidence    = "medium"
        mitre         = "T1003.001"
        ticket        = "W-052-T2"

    strings:
        $tool_a = "mimikatz"           ascii wide nocase
        $tool_b = "hashdump"           ascii wide nocase
        $tool_c = "logonpasswords"     ascii wide nocase
        $tool_d = "sekurlsa"           ascii wide nocase
        $tool_e = "kerberos::tgt"      ascii wide nocase
        $tool_f = "lsadump::"          ascii wide nocase
        $tool_g = "privilege::debug"   ascii wide nocase

    condition:
        2 of them
}

rule CS_Beaconing_Sleep_Mask
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike sleep-mask DLL — defensive evasion via heap encryption"
        family        = "cobalt_strike"
        component     = "evasion"
        confidence    = "medium"
        mitre         = "T1027.005"
        ticket        = "W-052-T2"

    strings:
        $api_a = "BeaconSleep"   ascii
        $api_b = "BeaconAddValue" ascii
        $api_c = "BeaconHeap"    ascii
        $api_d = "BeaconRevertToken" ascii
        $sleep_keyword_a = "evasive"  ascii nocase
        $sleep_keyword_b = "sleep_mask" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($api_*) and
        any of ($sleep_keyword_*)
}
