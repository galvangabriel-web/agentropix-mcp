# VANKO-ABDUCTED-ZEBRAFISH — Chat Clients Source Report

**Source:** Chat clients on host STARKSURFACE (`C:\Users\PC User`)
**Analyst:** DFIR subagent (Opus 4.8)
**Evidence:** `/cases/vanko/surface_physical.E01`, C: volume sector offset `1411072`
**Tooling:** agentropix MCP (`fls`, `extract_files`), host `sqlite3` + `strings`
**Extracted artifacts:** `/tmp/agentropix-sift-vanko/chat/{skype,telegram,whatsapp}`

---

## TL;DR / verdict

- **NO Dropbox share link** (`dropbox.com/s/...` or `/sh/...`) was found in any chat client.
- **NO QQ negotiation with `nina_kwai@qq.com`** exists locally. **No Tencent QQ / WeChat client is installed** on STARKSURFACE at all — the QQ recipient was reached over **email**, not a local chat client.
- **Skype** is the only chat client with recoverable plaintext message history (329 messages / `main.db`). It contains rich espionage-narrative context (Vanko bragging about his "V-Gen" breakthrough, plans to leave Stark for "Vladimir/Vlad" at company "Titan", moving overseas, offering a "super soldier" formula to a foreign military) **but no exfil link, no archive transfer, and no `nina_kwai@qq.com`.** The "Nina" in Skype is a *personal/dating* contact set up by coworker Kylie Normandy — the cover-story human, not the QQ handle.
- **Telegram Desktop** was installed and active (2016-06-18 → 2016-06-27) but its `tdata` is fully encrypted; **no plaintext messages, handles, or links are recoverable.**
- **WhatsApp Desktop** was installed and launched but never linked to a phone — `Databases.db` is empty, **no chats exist.**

**Clean negative for the assigned objectives (A: wiped files / B: share link & QQ negotiation) on this source.** The strongest corroborating finding is the Skype line where Vanko tells Merrick to "keep the updates coming but either on **skype or gmail**" — pointing the exfil away from chat clients and toward gmail, consistent with the established Gmail/Dropbox exfil chain.

---

## 1. Enumeration — what chat clients are installed

Full recursive `fls` of the C: volume produced **310,582 entries** (`/tmp/agentropix-sift-vanko/chat/allpaths.tsv`).

`C:\Users\PC User\AppData\Roaming` (inode 263024-144-5) contained:

```
d  Dropbox
d  Skype                 <- chat client
d  Telegram Desktop      <- chat client
d  WhatsApp              <- chat client
d  uTorrent  VeraCrypt  vlc  Adobe  Apple Computer  Macromedia  Microsoft
```

`...\AppData\Local` mirrored: `Skype`, `WhatsApp`, `Dropbox` (plus Google/MicrosoftEdge/Temp).

**Tencent / QQ / WeChat negative check** (grep over all 310k paths):
```
grep -iE "tencent files|wechat files|MicroMsg|MSG[0-9]+\.db|QQ[0-9]{5,}|tencent/|/wechat/"  -> (no matches)
```
The only `qq`-leaf hits (`qquicklayoutsplugin.dll`, `qqSAP408AmWay...swf`) are unrelated Office/ad artifacts, not a QQ client. **No QQ/WeChat install exists.**

No chat client found under `Program Files*` or `Documents` either.

---

## 2. Skype — `live#3aanthony.vanko` (account: anthony.vanko)

Profile: `C:\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\`
Extracted DBs (host sqlite3):

| file | inode | size | sha256 (head) |
|---|---|---|---|
| main.db | 233685 | 1,064,960 | c0361fe1dcad7099… |
| bistats.db | 233700 | 122,880 | f8785884ea37a9a5… |
| msn.db | 233768 | 53,248 | 87c517bc9f1a3740… |
| keyval.db | 233708 | 57,344 | ee0c388d00a9234c… |
| config.xml | 65254 | 17,940 | 60ad2e7564150a96… |

`main.db` → **329 messages** across these contacts/conversations:

```
Contacts:   echo123, fuzzygopher, merrick_mike (Michael Merrick), k.normandy (Kylie Normandy)
Conversations: echo123, fuzzygopher, merrick_mike, k.normandy,
               19:754fb1f0…@thread.skype (group: Michael Merrick + Kylie Normandy),
               + several US phone numbers (+1808…, +1202…, +1301…)
```

### 2.1 Keyword sweep — NEGATIVE for exfil indicators

```sql
SELECT ... FROM Messages
WHERE body_xml LIKE '%dropbox%' OR '%nina%' OR '%vacation%' OR '%photos%'
   OR '%im.cas.cn%' OR '%984347879%' OR '%qq.com%' OR '%http%';
```
Returned only: Google/Bing **maps** links (directions to a DC bar), Skype's own `api.asm.skype.com` photo-share fallback URLs (personal photos IMG_0130/0133/0893.JPG), and the personal "Nina" date thread. **No dropbox.com, no /s/ or /sh/, no nina_kwai, no QQ, no 984347879, no im.cas.cn.**

`strings -a` over main.db/bistats.db/msn.db/keyval.db/config.xml for `dropbox.com|nina_kw|984347879|im.cas.cn|vacation photos|qq.com|/s/|/sh/` → **zero hits.**

`Transfers` table (Skype file transfers) → **empty** — the 35 MB `vacation photos.7z` was NOT sent over Skype.

### 2.2 What Skype DOES corroborate (espionage narrative)

The "Nina" in Skype is a personal date, not the QQ recipient — established via the k.normandy/group thread:
- 2016-06-17 00:41:33 Kylie Normandy: *"Yeah I'll bring **Nina** if YOU want. She's Asian ;)"*
- Kylie: *"She's finishing a **biotech degree** somewhere in VA … something about **rare genetic type stuff**"* (note: a plausible elicitation cover for a biotech-research target).
- 2016-06-17 22:08 Vanko: *"I'm going to try to pull Nina away so I can spend some alone time with her."*
- 2016-06-25 Kylie: *"Hey how was your date with Nina??"* → Vanko forgot to confirm the date.

Insider-threat / motive & intent (merrick_mike + k.normandy threads), verbatim highlights:
- 2016-03-04 → 03-06: Vanko describes a regenerative-DNA "salamander" breakthrough — *"if I can find a way to weave two or three strands of DNA together this could be world changing."*
- 2016-03-06/07: motive — *"he peeked years ago and now he just takes credit for other people's discoveries"*; *"I almost think I would have to find something **outside the US** that I could make my life's fortune."*
- 2016-06-24: Merrick reports a real physiological "treatment" effect (benched 350, no recovery time) — Vanko coaching him as a test subject (*"your blood cells can now carry nearly 10x or more oxygen per cell"*).
- 2016-06-25: *"BTW, I forwarded you an email - keep it quiet."* / *"I worry a bit about saying it online but … I think I am on to something HUGE."*
- 2016-07-01: *"I am leaving to go to a new company that wants to fully fund my research … **DOUBLE my salary**"*; *"your gym buddy made an offer I could not refuse … **Vladimir**"*; *"**Vlad** says **V-Gen** is going to be worth at least a billion"*; *"I might be moving **overseas** for a while … for a potential public release of V-Gen"*; *"I am going to try to offer first to **military** … I think I have the formula for a **super soldier**"*; *"so that when I start with **Titan** I start with a BANG."*
- **Channel-pivot tell** — 2016-07-01 23:11:53 Vanko: *"keep the updates coming but either on **skype or gmail**."*

Full dumps saved: `/tmp/agentropix-sift-vanko/chat/skype_all_msgs.txt`, `…/skype_text_msgs.txt`.

**New leads from Skype (not in established facts):** recruiter/new-employer aliases **"Vladimir" / "Vlad"**, company **"Titan"**, product codename **"V-Gen"** (the regenerative/super-soldier formula); contacts **merrick_mike (Michael Merrick)** as a willing human test subject, **k.normandy (Kylie Normandy)** as the introducer of "Nina." These corroborate intent/overseas-sale but are distinct from the gmail→Dropbox→nina_kwai@qq.com exfil channel.

---

## 3. Telegram Desktop — installed, active, ENCRYPTED (clean negative for content)

Profile: `C:\Users\PC User\AppData\Roaming\Telegram Desktop\` (+ `tdata\`).
`log.txt` shows it launched **2016-06-18 16:43:59** (the day after the bar meeting; 2 days before the 06-30 exfil) and stayed active with MTProto traffic through **2016-06-27** (`bad message notification … error_code 17`, i.e. a live connected session), interleaved with long "Host unreachable" runs on 06-19.

`tdata` key/data files (`settings1`, `D877F783D5D3EF8C1`, `usertag`, map files) are **fully encrypted** — `strings` over them yields only binary noise; no handle, phone, link, or message text is recoverable without the local key/passcode. Telegram Desktop stores ALL message history encrypted in `tdata`, so **no chat content can be extracted from this image.** Telegram was a live channel during the operational window but is forensically opaque here.

Extracted: `/tmp/agentropix-sift-vanko/chat/telegram/`.

---

## 4. WhatsApp Desktop — installed, launched, NEVER LINKED (clean negative)

Profile: `C:\Users\PC User\AppData\Roaming\WhatsApp\`.
`main-process.log` shows WhatsApp Desktop 0.2.936 launching on **2016-06-25** and **2016-07-01** but only doing auto-update checks (and failing DNS for `web.whatsapp.com`). `databases\Databases.db` (the IndexedDB registry) is **empty** — no chat databases were ever created, meaning the app was never successfully linked to a phone. `Local Storage\file__0.localstorage` is an empty SQLite shell. **No WhatsApp message data exists.**

Extracted: `/tmp/agentropix-sift-vanko/chat/whatsapp/`.

---

## 5. Assessment

| Objective | Chat-clients result |
|---|---|
| (A) Recover SDelete-wiped/deleted classified files | Out of scope for this source; **not found** in chat data (Skype Transfers empty; no archive in any client). |
| (B) Dropbox share link | **NOT FOUND** in any chat client. |
| (B) QQ negotiation with nina_kwai@qq.com | **NOT FOUND**; no QQ/WeChat client is installed. Recipient was contacted by email, not a local chat app. |

**Why this is a credible negative, not a coverage gap:** all four AppData chat footprints were enumerated and the two with plaintext stores (Skype, WhatsApp) were fully parsed; Skype's keyword + Transfers sweeps are exhaustive and clean, and WhatsApp has no data. The only opaque store is Telegram's encrypted `tdata`, which cannot be brute-forced here — that is an honest limitation, not a missed artifact. The Skype "skype or **gmail**" instruction independently steers the share-link hunt toward the Gmail/Dropbox chain (covered by other source agents), consistent with the established facts (email thread carried the negotiation; Dropbox account 984347879 received the archive).

### IOCs / leads surfaced
- Skype account: `live:anthony.vanko`
- Skype contacts: `merrick_mike` (Michael Merrick), `k.normandy` (Kylie Normandy), `fuzzygopher`
- Recruiter/new employer aliases: **Vladimir / "Vlad"**, company **"Titan"**, product **"V-Gen"** (super-soldier/regen formula)
- Telegram Desktop active 2016-06-18 → 2016-06-27 (encrypted; channel-of-interest, content unrecoverable)
- Group thread id `19:754fb1f0335240cdb65acbde06e4e6db@thread.skype`
