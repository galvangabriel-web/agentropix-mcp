# Video playback on GitHub — diagnosis & troubleshooting plan (2026-06-11)

**Symptom (operator report):** none of the repo's videos play on github.com — not automatically,
not manually — e.g. `case-activation/runs/memdump-raw-2014/EXECUTED-RUN.mp4`.

## Diagnosis (Playwright + ffprobe, 2026-06-11)

**The files are not the problem.** All 10 committed MP4s probe clean:

| Check | Result |
|---|---|
| Codec / profile / pixel format | `h264 / High / yuv420p` on all 10 — browser-decodable everywhere |
| Box order (`faststart`) | `ftyp/moov` on all 10 — streamable before full download |
| Direct stream test | a `<video>` element pointed at the `raw.githubusercontent.com` URL **plays immediately** (verified headless-Chromium, `currentTime` advancing) |

**The GitHub UI is the problem**, in three layers (all Playwright-verified):

1. **Blob pages render no `<video>` player for repo-committed MP4s — at any size.** Probed all of
   369 KB → 29 MB: zero `<video>` elements. Files over ~20 MB additionally show
   *"Sorry about that, but we can't show files that are this big right now"* with only a
   **View raw** link.
2. **`raw.githubusercontent.com` forces a download**, never in-tab playback: it serves
   `Content-Type: application/octet-stream` with `X-Content-Type-Options: nosniff`, so the browser
   may not sniff it as video.
3. **Markdown cannot embed a player for repo files.** `![](x.mp4)` renders a broken image and
   `<video>` tags are sanitized; GitHub's inline players exist only for *user-attachment* uploads
   (issues/PRs), not for files committed to the repo.

## Fix applied (commit this file ships in)

**GitHub Pages** now serves the repository (`https://galvangabriel-web.github.io/agentropix-mcp/`,
legacy build from `main` `/`, `.nojekyll` committed so every path is served verbatim). Pages serves
`*.mp4` with a real `video/mp4` content type, so the **browser's native player plays them in-tab**.

- Every 🎬 poster/GIF click-through in the run and case-report READMEs now targets the **Pages URL**
  of its video (12 links rewritten) instead of the unplayable blob page.
- The `raw.githubusercontent.com` links are kept as the explicit **download** option.

## If a video still doesn't play — checklist

1. **Pages build finished?** `gh api repos/galvangabriel-web/agentropix-mcp/pages/builds/latest -q .status`
   must be `built`; a new push needs ~1–2 min to redeploy.
2. **Probe the served copy:** `curl -sI https://galvangabriel-web.github.io/agentropix-mcp/<path>.mp4`
   → expect `HTTP 200` + `content-type: video/mp4` + `accept-ranges: bytes`. A 404 right after
   enabling Pages = build not done (or the file exceeds the Pages 100 MB/file limit).
3. **Probe the file itself:** `ffprobe -v error -select_streams v:0 -show_entries stream=codec_name,profile,pix_fmt -of csv=p=0 <file>`
   → must be `h264,High|Main|Baseline,yuv420p`. Anything else (e.g. `yuv444p`, hevc): re-encode with
   `ffmpeg -i in.mp4 -c:v libx264 -pix_fmt yuv420p -movflags +faststart out.mp4`.
4. **Check faststart:** first two boxes must be `ftyp/moov` (re-mux with `-movflags +faststart` if `mdat` comes first).
5. **New videos:** keep ≤ 100 MB (Pages per-file limit; also keep repo lean — consider Git LFS past
   that, noting LFS files need `?raw=true`-style media URLs on Pages).
6. **Want auto-playing inline previews in a README?** Only animated **GIFs** auto-play on github.com
   (the SRL-2015 pattern: GIF preview + click-through to the MP4). Generate ~10 s preview GIFs with
   `ffmpeg -t 10 -i in.mp4 -vf "fps=8,scale=900:-1" out.gif`.

**Verification record:** after the Pages deploy, headless Chromium navigated to the Pages URL of
`memdump-raw-2014/EXECUTED-RUN.mp4` and confirmed the native player starts and `currentTime`
advances (see the session log for this commit).
