/*
   Agentropix-SIFT — W-052-T2 Cobalt Strike Beacon Detection (Gen 4)
   --------------------------------------------------------------------
   Targets Cobalt Strike beacons of generation 4.x (CS 4.0 - 4.11).
   Gen 4 introduced AES-encrypted comms and adjusted the configuration
   block layout. We match on:
     * the embedded AES IV scaffolding ("....i....I" pattern)
     * the new "MZARUH" stager artefact
     * SettingsKey markers visible in the PE .data section
*/

rule CS_Beacon_Gen4_AES_HTTPS
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike Gen4 beacon — AES HTTPS C2"
        family        = "cobalt_strike"
        generation    = "4"
        confidence    = "high"
        mitre         = "T1071.001"
        ticket        = "W-052-T2"

    strings:
        $aes_marker_a = "Mozilla/5.0 (compatible;" ascii          // CS default UA prefix
        $aes_marker_b = { 4D 5A 41 52 55 48 }                     // "MZARUH" CS Gen4 stager magic
        $beacon_export_a = "Beacon" ascii wide
        $beacon_export_b = "BeaconUseToken" ascii
        $beacon_export_c = "BeaconErrorD" ascii
        $api_unhook_a = "AmsiScanBuffer" ascii
        $api_unhook_b = "EtwEventWrite" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // Either the magic stub plus a beacon export
            ($aes_marker_b and any of ($beacon_export_*)) or
            // Or AES UA + multiple beacon evasion API references
            ($aes_marker_a and 2 of ($beacon_export_*, $api_unhook_*))
        )
}

rule CS_Beacon_Gen4_HTTP_Profile
{
    meta:
        author        = "Agentropix-SIFT"
        description   = "Cobalt Strike Gen4 beacon — HTTP malleable C2 profile artifacts"
        family        = "cobalt_strike"
        generation    = "4"
        confidence    = "medium"
        mitre         = "T1071.001"
        ticket        = "W-052-T2"

    strings:
        // Common CS malleable profile defaults observed in 4.0-4.11
        $profile_a    = "/__utm.gif"   ascii wide                 // amazon profile
        $profile_b    = "/cm/jquery-3.3.1.slim.min.js" ascii wide // jquery profile
        $profile_c    = "/api/v1/visit" ascii wide
        $profile_d    = "X-RequestSession" ascii wide
        $profile_e    = "X-Identifier"     ascii wide
        $cookie_a     = "__cfduid"     ascii wide
        $cookie_b     = "__utma"       ascii wide
        $b64_marker_a = "i_padding="   ascii wide
        $b64_marker_b = "id="          ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            2 of ($profile_*) or
            (any of ($profile_*) and any of ($cookie_*, $b64_marker_*))
        )
}
