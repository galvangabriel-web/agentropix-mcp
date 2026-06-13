// Deterministic CDP virtual-time renderer for deck.html
// Usage: node render.js [maxFrames]
// Env: FPS (default 12), OUT (frames dir)
const path = require('path');
const fs = require('fs');
const puppeteer = require('/usr/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/puppeteer');

const FPS = parseInt(process.env.FPS || '12', 10);
const frameMs = 1000 / FPS;
const DECK = 'file://' + path.resolve(__dirname, 'deck.html');
const OUT = process.env.OUT || path.resolve(__dirname, 'frames');
const MAXF = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const CHROME = process.env.PUPPETEER_EXECUTABLE_PATH ||
  (process.env.HOME + '/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome');

function pad(n){ return String(n).padStart(6,'0'); }

(async () => {
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, {recursive:true});
  // clean prior frames
  for (const f of fs.readdirSync(OUT)) if (f.endsWith('.jpg')) fs.unlinkSync(path.join(OUT,f));

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'shell',
    args: ['--no-sandbox','--disable-gpu','--force-device-scale-factor=1','--hide-scrollbars']
  });
  const page = await browser.newPage();
  await page.setViewport({width:1920, height:1080, deviceScaleFactor:1});
  await page.goto(DECK, {waitUntil:'load'});
  // wait fonts + images
  await page.evaluate(async () => {
    await document.fonts.ready;
    const imgs = Array.from(document.images);
    await Promise.all(imgs.map(im => im.complete ? Promise.resolve()
      : new Promise(r => { im.onload = r; im.onerror = r; })));
  });
  const totalMs = await page.evaluate(() => window.__totalMs);
  let nFrames = Math.ceil(totalMs / frameMs) + 1;
  if (MAXF) nFrames = Math.min(nFrames, MAXF);
  console.log(`totalMs=${totalMs} fps=${FPS} frames=${nFrames} out=${OUT}`);

  const client = await page.target().createCDPSession();
  // pause virtual time, then kick the deck timeline
  await client.send('Emulation.setVirtualTimePolicy', {policy:'pause'});
  await page.evaluate(() => window.__start());

  function advance(budget){
    return new Promise(async (resolve) => {
      const onExpire = () => { client.off('Emulation.virtualTimeBudgetExpired', onExpire); resolve(); };
      client.on('Emulation.virtualTimeBudgetExpired', onExpire);
      await client.send('Emulation.setVirtualTimePolicy',
        {policy:'advance', budget: budget});
    });
  }

  const t0 = Date.now();
  for (let i=0; i<nFrames; i++){
    // capture current state, then advance one frame for the next iteration
    const buf = await page.screenshot({type:'jpeg', quality:90});
    fs.writeFileSync(path.join(OUT, `frame_${pad(i+1)}.jpg`), buf);
    await advance(frameMs);
    if (i % 120 === 0) {
      const el = ((Date.now()-t0)/1000).toFixed(0);
      console.log(`  frame ${i+1}/${nFrames}  (${el}s elapsed)`);
    }
  }
  console.log(`done: ${nFrames} frames in ${((Date.now()-t0)/1000).toFixed(0)}s`);
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
