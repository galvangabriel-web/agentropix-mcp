export const meta = {
  name: 'vanko-presentation-video',
  description: 'Read the 3 VANKO reports and build a technical, correlated, jury-grade presentation storyboard (Opus 4.8)',
  phases: [
    { title: 'Outline', detail: 'select the 7-9 key facts that prove the case', model: 'opus' },
    { title: 'Scene build', detail: 'one Opus agent per fact -> correlated multi-artifact scene', model: 'opus' },
    { title: 'Narrative edit', detail: 'order, cross-correlate, add framing scenes', model: 'opus' },
  ],
}
const DIR='/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report'
const SRC=`Read ALL THREE source reports for full technical depth:
- ${DIR}/VANKO-FORENSIC-REPORT.md  (presentation report — lifecycle, IOCs, 10 findings)
- ${DIR}/VANKO-DFIR-REPORT.md      (full 7-section legally-defensible report — timeline, technical narrative, IOCs, §8 validation)
- ${DIR}/report.md                 (synthesis — kill chain, IOC lists, evidence gaps)
GROUND EVERYTHING in these reports. Do NOT invent or exaggerate. Honor the honest negatives (no malware C2, iPhone-vector down-ranked, timestomp/NTP/Windows.old refuted, macOS staging NOT asserted) — never present a refuted item as proof.`

const ART = { type:'object', additionalProperties:false, properties:{
  source:{type:'string'},   // exact forensic source/engine (e.g. 'Security.evtx (EvtxECmd)')
  locator:{type:'string'},  // EXACT proof string (event id, path, hash, bytes, timestamp) — to be red-boxed
  shows:{type:'string'}     // one line: what THIS artifact demonstrates
}, required:['source','locator','shows'] }

const SCENE = { type:'object', additionalProperties:false, properties:{
  scene_no:{type:'integer'},
  title:{type:'string'},                 // the key-fact headline (<=9 words)
  mitre:{type:'string'},                 // comma-separated ATT&CK ids
  key_fact:{type:'string'},              // 1-2 sentences: the fact, technically precise
  artifacts:{ type:'array', items: ART },// 2-3 CORRELATED artifacts proving the fact
  correlation:{type:'string'},           // how these artifacts corroborate each other (the technical 'why it holds')
  what_it_means:{type:'string'}          // significance to the case, jury-facing, accurate
}, required:['scene_no','title','mitre','key_fact','artifacts','correlation','what_it_means'] }

phase('Outline')
const OUTLINE_SCHEMA={type:'object',additionalProperties:false,properties:{facts:{type:'array',items:{type:'object',additionalProperties:false,properties:{n:{type:'integer'},title:{type:'string'},scope:{type:'string'}},required:['n','title','scope']}}},required:['facts']}
const outline = await agent(
`You are the lead DFIR examiner planning a 5-10 minute evidence presentation for case VANKO-ABDUCTED-ZEBRAFISH (insider IP theft).
${SRC}
Select the **7 to 9 KEY FACTS** that most convincingly prove the case to a judge/jury — each fact must be a distinct pillar of the kill chain (motive, collection from the server, masquerade staging, archive/disguise, cloud exfil, foreign-recruiter coordination, anti-forensics defeated by VSS, scope/Level-12). For each fact give: n (order, 1=earliest), a <=9-word title, and a one-line scope of which artifacts/findings it draws on. Return {facts:[...]}.`,
  {label:'outline', phase:'Outline', model:'opus', schema:OUTLINE_SCHEMA})
log(`outline: ${outline.facts.length} key facts`)

phase('Scene build')
const scenes = (await parallel(outline.facts.map(f => () =>
  agent(`You are a DFIR examiner building ONE presentation scene for case VANKO-ABDUCTED-ZEBRAFISH.
${SRC}
Build the scene for KEY FACT #${f.n}: "${f.title}" (scope: ${f.scope}).
Requirements for a TECHNICAL, jury-convincing scene:
- key_fact: 1-2 technically precise sentences.
- artifacts: 2-3 CORRELATED artifacts (different sources where possible — e.g. an event log + an MFT/$I record + an Amcache hash) each with its EXACT locator string (will be red-boxed) and a one-line 'shows'.
- correlation: explain HOW the artifacts corroborate each other (the technical reason the conclusion holds — timestamps lining up, copy-signature, byte counts matching, cross-source agreement).
- what_it_means: plain, accurate significance to the case.
- mitre: the ATT&CK id(s). scene_no = ${f.n}.
Be precise and true to the reports.`,
    {label:`scene:${f.n}`, phase:'Scene build', model:'opus', schema:SCENE})
))).filter(Boolean)
log(`built ${scenes.length} scenes`)

phase('Narrative edit')
const STORY={type:'object',additionalProperties:false,properties:{
  title:{type:'string'},subtitle:{type:'string'},intro_line:{type:'string'},
  kill_chain_summary:{type:'array',items:{type:'string'}},  // 6-8 short steps for the overview frame
  scenes:{type:'array',items:SCENE},
  closing_fact:{type:'string'},   // 'what it all proves' synthesis
  outro_line:{type:'string'}
},required:['title','subtitle','intro_line','kill_chain_summary','scenes','closing_fact','outro_line']}
const story = await agent(
`You are the lead editor finalizing a technical evidence presentation for case VANKO-ABDUCTED-ZEBRAFISH. Below are ${scenes.length} scene specs (JSON).
Tasks: order scenes into the kill-chain narrative; verify cross-scene correlation (no contradictions; artifacts reinforce across scenes); keep each scene object INTACT (do not alter locator strings). Add: a title, one-line subtitle, one-line intro, a kill_chain_summary of 6-8 short ordered steps for an overview frame, a 'closing_fact' that synthesizes what all the evidence proves together (and honestly notes this is insider misuse — no malware — establishing credibility), and a one-line outro. Invent no new facts.
SCENES:
${JSON.stringify(scenes,null,1)}`,
  {label:'editor', phase:'Narrative edit', model:'opus', schema:STORY})
return story
