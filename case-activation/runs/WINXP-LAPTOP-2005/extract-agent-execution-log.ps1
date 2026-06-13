<#
  extract-agent-execution-log.ps1
  Derives an agent execution log (single-agent submission) from a Claude Code
  session transcript. Produces:
    *.session-transcript.raw.jsonl  - verbatim copy of the source (Option 3, lossless)
    *.execution-log.full.jsonl      - per-turn derived view w/ full tool inputs + token usage (Option 1)
    *.execution-log.summary.md      - human-readable summary + token totals
    *.execution-log.manifest.json   - source SHA-256, record/tool counts, token totals (chain of custody)
  Usage:
    .\extract-agent-execution-log.ps1 -Transcript <path.jsonl> -OutDir C:\xp -Prefix WINXP-LAPTOP-2005
#>
param(
  [string]$Transcript = "C:\Users\admin\.claude\projects\C--xp\bd54dc37-ffdb-4835-8378-42b74ce3fdef.jsonl",
  [string]$OutDir = "C:\xp",
  [string]$Prefix = "WINXP-LAPTOP-2005"
)

$lines = Get-Content $Transcript
$recs  = $lines | ForEach-Object { $_ | ConvertFrom-Json }

# classify a tool result: protocol error (is_error), logical error (non-empty
# JSON "error" field), or Volatility/Python traceback in the body/stderr.
function Get-ErrKind([bool]$isErr, [string]$txt) {
  if ($isErr) { return 'ERROR' }
  if ($txt -match '"error"\s*:\s*"(?:\\.|[^"\\])+"') { return 'LOGICAL_ERROR' }   # requires >=1 char => skips "error":""
  if ($txt -match 'Traceback \(most recent call last\)') { return 'TRACEBACK' }
  return 'ok'
}
function Get-ErrMsg([string]$txt) {
  $m = [regex]::Match($txt, '"error"\s*:\s*"((?:\\.|[^"\\])+)"')
  if ($m.Success) { return $m.Groups[1].Value }
  if ($txt -match 'Traceback \(most recent call last\)') { return 'python traceback in tool stderr' }
  return ''
}

# ---- 1. index tool_result blocks by tool_use_id ----
$results = @{}
foreach ($r in $recs | Where-Object { $_.type -eq 'user' }) {
  $c = $r.message.content
  if ($c -is [array]) {
    foreach ($b in $c) {
      if ($b.type -eq 'tool_result') {
        $txt = if ($b.content -is [array]) { ($b.content | ForEach-Object { $_.text }) -join '' } else { [string]$b.content }
        $kind = Get-ErrKind ([bool]$b.is_error) $txt
        $results[$b.tool_use_id] = [pscustomobject]@{
          is_error  = [bool]$b.is_error
          err_kind  = $kind
          failed    = ($kind -ne 'ok')
          err_msg   = if ($kind -ne 'ok') { Get-ErrMsg $txt } else { '' }
          bytes     = $txt.Length
          preview   = if ($txt.Length -gt 240) { $txt.Substring(0,240) } else { $txt }
        }
      }
    }
  }
}

# ---- 2. build per-turn records ----
$turn = 0; $seq = 0
$log = New-Object System.Collections.Generic.List[object]
foreach ($r in $recs) {
  if ($r.type -ne 'assistant' -and $r.type -ne 'user') { continue }
  $c = $r.message.content
  $texts = @(); $tools = @()
  if ($c -is [array]) {
    foreach ($b in $c) {
      switch ($b.type) {
        'text'        { $texts += $b.text }
        'tool_use'    {
          $seq++
          $res = $results[$b.id]
          $tools += [pscustomobject]@{
            seq=$seq; name=$b.name; input=$b.input
            result_status= if($res){$res.err_kind} else {'(none)'}
            result_failed= if($res){$res.failed} else {$false}
            result_error = if($res){$res.err_msg} else {''}
            result_bytes = if($res){$res.bytes} else {0}
            result_preview = if($res){$res.preview} else {''}
          }
        }
        'tool_result' { } # handled in pass 1
      }
    }
  } elseif ($c -is [string]) { $texts += $c }
  if ($texts.Count -eq 0 -and $tools.Count -eq 0) { continue }
  $turn++
  $u = $r.message.usage
  $log.Add([pscustomobject]@{
    turn=$turn; role=$r.type; ts=$r.timestamp
    text=($texts -join "`n")
    tools=$tools
    usage= if($u){ [pscustomobject]@{
      input=$u.input_tokens; output=$u.output_tokens
      cache_read=$u.cache_read_input_tokens; cache_creation=$u.cache_creation_input_tokens } } else { $null }
  })
}

# ---- 3. emit artifacts ----
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory $OutDir | Out-Null }
$raw  = Join-Path $OutDir "$Prefix.session-transcript.raw.jsonl"
$full = Join-Path $OutDir "$Prefix.execution-log.full.jsonl"
$md   = Join-Path $OutDir "$Prefix.execution-log.summary.md"
$man  = Join-Path $OutDir "$Prefix.execution-log.manifest.json"

Copy-Item $Transcript $raw -Force
$log | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 } | Set-Content $full -Encoding utf8

$asst = $recs | Where-Object { $_.type -eq 'assistant' }
$tok = [pscustomobject]@{
  output_tokens   = ($asst.message.usage | Measure-Object output_tokens -Sum).Sum
  input_tokens    = ($asst.message.usage | Measure-Object input_tokens -Sum).Sum
  cache_read      = ($asst.message.usage | Measure-Object cache_read_input_tokens -Sum).Sum
  cache_creation  = ($asst.message.usage | Measure-Object cache_creation_input_tokens -Sum).Sum
}
$toolCalls = $log | ForEach-Object { $_.tools } | Where-Object { $_ }
$hist = $toolCalls | Group-Object name | Sort-Object Count -Descending

$sourceHash = (Get-FileHash $Transcript -Algorithm SHA256).Hash
$failed = $toolCalls | Where-Object { $_.result_failed }
$errBreakdown = $failed | Group-Object result_status | ForEach-Object { @{ $_.Name = $_.Count } }
[pscustomobject]@{
  prefix=$Prefix; source_transcript=$Transcript; source_sha256=$sourceHash
  total_records=$recs.Count; turns=$log.Count; tool_calls=$toolCalls.Count
  tool_errors=$failed.Count
  error_breakdown=($failed | Group-Object result_status | ForEach-Object { [pscustomobject]@{ kind=$_.Name; count=$_.Count } })
  token_totals=$tok
  generated_from="single-agent Claude Code session"
} | ConvertTo-Json -Depth 6 | Set-Content $man -Encoding utf8

# markdown summary
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# Agent Execution Log — $Prefix (single-agent submission)")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Source transcript: ``$Transcript``  ")
[void]$sb.AppendLine("Source SHA-256: ``$sourceHash``  ")
[void]$sb.AppendLine("Records: $($recs.Count) | Turns: $($log.Count) | Tool calls: $($toolCalls.Count) (failed: $($failed.Count))")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Token usage (summed across assistant turns)")
[void]$sb.AppendLine("| output | input | cache_read | cache_creation |")
[void]$sb.AppendLine("|---|---|---|---|")
[void]$sb.AppendLine("| $($tok.output_tokens) | $($tok.input_tokens) | $($tok.cache_read) | $($tok.cache_creation) |")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Tool-call histogram")
[void]$sb.AppendLine("| count | tool |")
[void]$sb.AppendLine("|---|---|")
foreach ($g in $hist) { [void]$sb.AppendLine("| $($g.Count) | $($g.Name) |") }
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Failed / self-corrected tool calls")
[void]$sb.AppendLine("| seq | tool | kind | error |")
[void]$sb.AppendLine("|---|---|---|---|")
foreach ($t in ($log | ForEach-Object { $_.tools } | Where-Object { $_ -and $_.result_failed })) {
  $em = ($t.result_error -replace '\|','\').Trim(); if ($em.Length -gt 90) { $em = $em.Substring(0,90)+'...' }
  [void]$sb.AppendLine("| $($t.seq) | $($t.name) | $($t.result_status) | $em |")
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Ordered tool-execution sequence")
[void]$sb.AppendLine("| seq | ts | tool | status | result_bytes |")
[void]$sb.AppendLine("|---|---|---|---|---|")
foreach ($t in ($log | ForEach-Object { $turnTs=$_.ts; $_.tools | ForEach-Object { [pscustomobject]@{seq=$_.seq;ts=$turnTs;name=$_.name;status=$_.result_status;bytes=$_.result_bytes} } })) {
  [void]$sb.AppendLine("| $($t.seq) | $($t.ts) | $($t.name) | $($t.status) | $($t.bytes) |")
}
$sb.ToString() | Set-Content $md -Encoding utf8

"Wrote:"
$raw,$full,$md,$man | ForEach-Object { "  $_" }
