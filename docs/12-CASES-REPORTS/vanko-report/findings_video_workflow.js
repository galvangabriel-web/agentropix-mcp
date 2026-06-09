export const meta = {
  name: 'vanko-findings-video-storyboard',
  description: 'Turn the 10 confirmed VANKO findings into an annotated evidence-video storyboard (Opus 4.8 agents)',
  phases: [
    { title: 'Storyboard cards', detail: 'one Opus agent per finding -> evidence card + red-box target', model: 'opus' },
    { title: 'Sequence', detail: 'order into kill-chain narrative + title/intro/outro', model: 'opus' },
  ],
}
const DIR='/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report'
const IDS = (Array.isArray(args) && args.length) ? args
  : ["VANKO-P1-001","VANKO-P2-001","VANKO-P2-003","VANKO-P2-004","VANKO-P2-005","VANKO-P3-002","VANKO-P3-003","VANKO-P3-005","VANKO-P4-003","VANKO-P4-004"]

const CARD_SCHEMA = { type:'object', additionalProperties:false, properties:{
  finding_id:{type:'string'}, technique:{type:'string'},
  kill_chain_step:{type:'integer'},
  headline:{type:'string'},        // <=8 words, plain language, true to the finding
  proves:{type:'string'},          // one plain sentence: what it means to the case
  evidence_source:{type:'string'}, // the artifact/file it came from
  proof_locator:{type:'string'},   // EXACT short substring of the finding's evidence locator (to be red-boxed)
  confidence:{type:'number'}
}, required:['finding_id','technique','kill_chain_step','headline','proves','evidence_source','proof_locator','confidence'] }

const cardPrompt = (id)=>`You are a forensic-visualization specialist building a COURTROOM evidence video for the VANKO insider intellectual-property-theft case (system STARKSURFACE, subject anthony.vanko).

Read ${DIR}/confirmed-findings.json and locate the single finding whose finding_id is "${id}". Optionally cross-read ${DIR}/VANKO-DFIR-REPORT.md for phrasing.

Produce ONE evidence card for that finding. STRICT RULES:
- Plain language a jury understands, but EVERY word must be true to the finding — do not exaggerate, soften, or invent.
- "headline": <=8 words, the punchy fact (e.g. "Secrets hidden in 'vacation photos.7z'").
- "proves": ONE plain sentence on what it means to the case.
- "proof_locator": a SHORT, EXACT substring copied from the finding's evidence locator — the precise artifact reference (event ID, path, hash, byte count, timestamp) that the video will frame with a RED BOX to mark where the proof lives. Keep it under ~70 chars; do not paraphrase it.
- "kill_chain_step": 1 = earliest setup/motive ... 10 = cover-up/impact (your best ordering for this finding).
Return the card object.`

phase('Storyboard cards')
const cards = (await parallel(IDS.map(id => () =>
  agent(cardPrompt(id), { label:`card:${id}`, phase:'Storyboard cards', model:'opus', schema:CARD_SCHEMA })
))).filter(Boolean)
log(`built ${cards.length}/${IDS.length} evidence cards`)

const STORY_SCHEMA = { type:'object', additionalProperties:false, properties:{
  title:{type:'string'}, subtitle:{type:'string'}, intro_line:{type:'string'}, outro_line:{type:'string'},
  cards:{ type:'array', items: CARD_SCHEMA }
}, required:['title','subtitle','intro_line','outro_line','cards'] }

phase('Sequence')
const story = await agent(
`You are the lead editor sequencing a forensic EVIDENCE video for case VANKO-ABDUCTED-ZEBRAFISH. Below are ${cards.length} evidence cards (JSON). 
Tasks: order them into a coherent kill-chain narrative — motive/setup -> file-server collection -> masquerade staging -> archive/disguise -> cloud exfil -> foreign-recruiter coordination -> anti-forensic cover-up -> scope/impact. Keep each card object INTACT (do not alter proof_locator); you may lightly tighten a headline for flow only. Add a title, a one-line subtitle, a one-line intro, and a one-line outro. Invent no new facts.
CARDS:
${JSON.stringify(cards, null, 1)}`,
  { label:'sequence-editor', phase:'Sequence', model:'opus', schema:STORY_SCHEMA })

return story
