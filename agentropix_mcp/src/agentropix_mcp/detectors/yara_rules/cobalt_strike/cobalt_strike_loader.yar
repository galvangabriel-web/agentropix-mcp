/*
   Agentropix-SIFT — W-052-T2 Cobalt Strike Loader Detection
   --------------------------------------------------------------------
   Catches the loader stage shipped with Cobalt Strike "artifact.exe"
   and similar staged droppers. These loaders typically use:
     * VirtualAlloc + WriteProcessMemory + CreateThread sequence
     * In-memory PE reflective loading
     * "MZARUH" or "MZ" stub at non-standard offsets

   Difficulty rating: yara_hit (per docs/samples/ground_truth_dc.yaml).
*/

rule CS_Loader_ReflectivePE
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike loader — reflective PE injection sequence"
        family        = "cobalt_strike"
        component     = "loader"
        confidence    = "high"
        mitre         = "T1055.002"
        ticket        = "W-052-T2"

    strings:
        $api_a = "VirtualAlloc"        ascii
        $api_b = "WriteProcessMemory"  ascii
        $api_c = "CreateRemoteThread"  ascii
        $api_d = "CreateThread"        ascii
        $api_e = "VirtualProtect"      ascii
        $loader_marker_a = "ReflectiveLoader" ascii
        $loader_marker_b = "ReflectiveLoader@" ascii          // vararg stub
        $loader_marker_c = { 4D 5A 41 52 55 48 }              // "MZARUH"
        $stager_a = "artifact.exe" ascii wide nocase
        $stager_b = "stager"      ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of ($api_*) and
        (
            any of ($loader_marker_*) or
            any of ($stager_*)
        )
}

rule CS_Loader_PowerShell_Stager
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike PowerShell stager — IEX-encoded payload"
        family        = "cobalt_strike"
        component     = "loader"
        confidence    = "medium"
        mitre         = "T1059.001"
        ticket        = "W-052-T2"

    strings:
        $ps_a = "powershell" ascii wide nocase
        $ps_b = "-NoP -NonI -W Hidden" ascii wide nocase
        $iex_a = "Invoke-Expression" ascii wide nocase
        $iex_b = "IEX(" ascii wide nocase
        $b64_a = "FromBase64String" ascii wide
        $b64_b = "[Convert]::FromBase64" ascii wide nocase
        $unmgd_a = "System.Runtime.InteropServices" ascii wide
        $vmsa_a = "VirtualAlloc" ascii wide
        $cs_indicator_a = "$DoIt" ascii wide                   // common CS PS-stager variable

    condition:
        any of ($ps_*) and
        (
            (any of ($iex_*) and any of ($b64_*)) or
            ($unmgd_a and $vmsa_a) or
            $cs_indicator_a
        )
}
