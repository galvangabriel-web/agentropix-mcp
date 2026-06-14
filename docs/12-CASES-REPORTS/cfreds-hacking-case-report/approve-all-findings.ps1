<#
================================================================================
 approve-all-findings.ps1
 Batch-approve the 35 DRAFT findings for CFReDS case CFREDS-HACKING-CASE-4DELL
 via the Agentropix W-288 human-approval sidecar.

 SECURITY MODEL (read this):
   * Approval is a HUMAN action. This script is meant to be run BY THE EXAMINER.
   * Your approver password is read with a SECURE PROMPT (or env var) and is
     sent ONLY to the sidecar over TLS. It is never written to disk, never
     logged, and never passed through the LLM/agent context.
   * The agent CANNOT self-approve (W-286 draft-gate). This script does not
     bypass that control; it just automates the repetitive per-finding POSTs
     that you, the authenticated examiner, are entitled to make.

 USAGE:
   # Dry run (lists what would be approved, makes no changes):
   pwsh ./approve-all-findings.ps1 -DryRun

   # Real run (prompts securely for your examiner password):
   pwsh ./approve-all-findings.ps1 -ApproverId victor.galvan

   # Non-interactive (CI): set $env:AGENTROPIX_APPROVER_PASSWORD first.

   # Unattended via DPAPI credential file (create ONCE, as the same user, on this machine):
   #   Read-Host -AsSecureString "Examiner password" | ConvertFrom-SecureString | Set-Content -NoNewline .\approver.cred
   #   icacls .\approver.cred /inheritance:r /grant:r "$env:USERNAME:(R)"   # lock down ACL
   # Then run:
   #   pwsh ./approve-all-findings.ps1 -ApproverId victor.galvan -PasswordFile .\approver.cred
   # The .cred blob is DPAPI-encrypted: it can ONLY be decrypted by the same Windows
   # user on the same machine. It is NOT portable and is useless if copied elsewhere.

 NOTE ON ENDPOINT/ENVELOPE:
   The sidecar base URL defaults to the deployment value from case memory
   (W-288). Confirm the exact route + JSON field names against your sidecar's
   API doc; the POST body below follows the documented approve_finding contract
   (finding_id, approver_id, case_id, from_status->to_status, reason). Adjust
   $ApprovePath / body keys if your sidecar differs.
================================================================================
#>

[CmdletBinding()]
param(
  [string]$CaseId       = 'CFREDS-HACKING-CASE-4DELL',
  [string]$ApproverId   = 'victor.galvan',
  [string]$SidecarUrl   = 'https://siftworkstation.taile7c9ca.ts.net:8443',
  [string]$ApprovePath  = '/api/v1/approve',          # <-- confirm against sidecar API
  [string]$Reason       = 'Examiner review complete - CFReDS Mr. Evil case',
  [string]$PasswordFile = '',                         # DPAPI-encrypted credential file (see header)
  [switch]$DryRun
)

# --- The 34 finding IDs (authoritative, from agentropix-findings index) ---
$FindingIds = @(
  'CFREDS-001-hacking-toolkit',
  'CFREDS-002-sniffing-wardriving',
  'CFREDS-003-suspect-account-evasion',
  'CFREDS-004-ioc-carve',
  'CFREDS-EXT-01-suspect-identity-greg-schardt',
  'CFREDS-EXT-02-oe-email-whoknowsme',
  'CFREDS-EXT-03-irc-identity-undernet',
  'CFREDS-EXT-04-removable-optical-disc-ghostware',
  'CFREDS-EXT-05-remote-share-4-12-220-254',
  'CFREDS-EXT-06-exec-hashes-toolkit',
  'CFREDS-EXT-07-pcap-wireless-services',
  'CFREDS-EXT-08-userassist-execution',
  'CFREDS-EXT-09-wardriving-intent-typedurls',
  'CFREDS-EXT-10-ethereal-interception-capture',
  'CFREDS-EXT-11-additional-hacking-tools',
  'CFREDS-EXT-12-newsgroups-subscribed',
  'CFREDS-EXT-13-host-config-timezone',
  'CFREDS-EXT-14-recycler-deleted-execs',
  'CFREDS-EXT-15-intercepted-pocketpc-hotmail',
  'CFREDS-EXT-16-mirc-undernet-identity',
  'CFREDS-EXT-17-lookatlan-realname',
  'CFREDS-EXT-18-inbox-dbx-recovery',
  'CFREDS-EXT-19-newsgroup-content-recovered',
  'CFREDS-EXT-20-oe-account-whoknowsme',
  'CFREDS-EXT-21-master-correlation',
  'CFREDS-EXT-22-threat-intel-enrichment',
  'CFREDS-EXT-23-toolkit-hash-enrichment',
  'CFREDS-EXT-24-irc-chatlogs',
  'CFREDS-EXT-25-ie-history-wardriving',
  'CFREDS-EXT-26-anonymizer-ghostware',
  'CFREDS-EXT-27-recycler-installers-identified',
  'CFREDS-EXT-28-lookatlan-noscan-extra-irc',
  'CFREDS-EXT-29-wireless-nic-wardriving-hw',
  'CFREDS-EXT-30-new-ioc-enrichment',
  'CFREDS-EXT-31-network-lateral-summary'
)

Write-Host "Case        : $CaseId"
Write-Host "Approver    : $ApproverId"
Write-Host "Sidecar     : $SidecarUrl$ApprovePath"
Write-Host "Findings    : $($FindingIds.Count)"
Write-Host ("DryRun      : {0}" -f $DryRun.IsPresent)
Write-Host ('-' * 60)

if ($DryRun) {
  $n = 0
  foreach ($id in $FindingIds) { $n++; "{0,2}. WOULD APPROVE  {1}" -f $n, $id }
  Write-Host ('-' * 60)
  Write-Host "Dry run complete. $($FindingIds.Count) findings would be approved. No changes made."
  return
}

# --- Securely obtain the approver password (never logged / never to the agent) ---
# Precedence: -PasswordFile (DPAPI)  >  $env:AGENTROPIX_APPROVER_PASSWORD  >  interactive prompt
$plain = $null
if (-not [string]::IsNullOrEmpty($PasswordFile)) {
  if (-not (Test-Path -LiteralPath $PasswordFile)) { throw "PasswordFile not found: $PasswordFile" }
  try {
    # File holds the output of ConvertFrom-SecureString (DPAPI: decryptable only by the
    # SAME Windows user on the SAME machine that created it). See header for how to make it.
    $sec   = (Get-Content -LiteralPath $PasswordFile -Raw).Trim() | ConvertTo-SecureString
    $plain = [System.Net.NetworkCredential]::new('', $sec).Password
    Write-Host "Password loaded from DPAPI file: $PasswordFile"
  } catch {
    throw "Failed to decrypt PasswordFile (wrong user/machine, or not a ConvertFrom-SecureString blob): $($_.Exception.Message)"
  }
}
if ([string]::IsNullOrEmpty($plain)) { $plain = $env:AGENTROPIX_APPROVER_PASSWORD }
if ([string]::IsNullOrEmpty($plain)) {
  $sec = Read-Host -AsSecureString "Examiner password for '$ApproverId'"
  $plain = [System.Net.NetworkCredential]::new('', $sec).Password
}
if ([string]::IsNullOrEmpty($plain)) { throw 'No password provided; aborting.' }

$ok = 0; $fail = 0
foreach ($id in $FindingIds) {
  $body = @{
    target_type = 'finding'
    finding_id  = $id
    case_id     = $CaseId
    approver_id = $ApproverId
    from_status = 'DRAFT'
    to_status   = 'APPROVED'
    reason      = $Reason
    password    = $plain          # consumed by sidecar; TLS only
  } | ConvertTo-Json -Compress

  try {
    $resp = Invoke-RestMethod -Method Post -Uri "$SidecarUrl$ApprovePath" `
              -ContentType 'application/json' -Body $body -TimeoutSec 30
    $ok++
    Write-Host ("OK    {0}  -> {1}" -f $id, ($resp.status ?? 'APPROVED'))
  }
  catch {
    $fail++
    Write-Warning ("FAIL  {0}  -> {1}" -f $id, $_.Exception.Message)
  }
}

# Scrub the password from memory
$plain = $null; [System.GC]::Collect()

Write-Host ('-' * 60)
Write-Host "Done. Approved: $ok   Failed: $fail   Total: $($FindingIds.Count)"
Write-Host "Next: run promote_iocs + report_export to render the populated case report."
