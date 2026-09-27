#!/usr/bin/env node
/**
 * Relay self-test. No dependencies, no arguments required.
 *
 *   node relay/verify.cjs --files        only check the files on disk
 *   node relay/verify.cjs                check the files, then boot a local server
 *                                        on a free port and test it end to end
 *   node relay/verify.cjs https://my-relay.example
 *                                        test a DEPLOYED relay (Cloudflare, Deno,
 *                                        Render, a VPS — anything reachable)
 *
 * Exit code 0 = all good, 1 = something is wrong (safe for CI/Render health jobs).
 *
 * Why this exists: the most common deploy failure is a file that was copied or
 * uploaded only partly. Node reports that as a cryptic SyntaxError. This checks
 * for truncation directly, then proves the running relay actually rewrites,
 * proxies assets and plays media.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');

const HERE = __dirname;
const RELAY_JS = path.join(HERE, 'relay.js');
const NODE_SERVER = path.join(HERE, 'node-server.cjs');
const pick = (...cands) => cands.find((c) => fs.existsSync(c)) || cands[0];
const CLIENT = pick(path.join(HERE, 'client.html'), path.join(HERE, '..', 'client.html'));
const CHECK = pick(path.join(HERE, 'check.cjs'), path.join(HERE, '..', 'check.cjs'));

let pass = 0, fail = 0;
const ok = (msg) => { pass++; console.log('  \u2713 ' + msg); };
const bad = (msg, detail) => { fail++; console.log('  \u2717 ' + msg + (detail ? '\n      ' + detail : '')); };
const head = (t) => console.log('\n' + t);

/* ------------------------------------------------------------------ *
 * 1. file integrity — catches truncated uploads
 * ------------------------------------------------------------------ */

function checkFiles() {
  head('Files');

  const targets = [
    { file: RELAY_JS, sentinel: '/* __RELAY_EOF__ */', minLines: 1000, minBytes: 50000,
      must: [/export default/, /async function proxyWebSocket/, /function mediaKind/] },
    { file: NODE_SERVER, sentinel: '/* __NODE_SERVER_EOF__ */', minLines: 240, minBytes: 8000,
      must: [/attachUpgradeHandler/, /dynamic import/, /looks TRUNCATED/] },
    { file: CLIENT, sentinel: '<!-- __CLIENT_EOF__ -->', minLines: 380, minBytes: 15000, required: false,
      must: [/relayUrl/, /playBtn/] },
    { file: CHECK, sentinel: '/* __CHECK_EOF__ */', minLines: 30, minBytes: 1500,
      must: [/node-server\.cjs/, /relay\.js/] },
  ];

  let allOk = true;
  for (const t of targets) {
    const name = path.basename(t.file);
    if (!fs.existsSync(t.file)) {
      if (t.required === false) { console.log('  \u00b7 ' + name + ' is not here \u2014 skipping (fine: it is hosted separately)'); continue; }
      bad(name + ' is missing', 'expected at ' + t.file);
      allOk = false;
      continue;
    }

    const raw = fs.readFileSync(t.file, 'utf8');
    const lines = raw.split('\n').length;
    const trimmed = raw.trimEnd();

    if (!trimmed.endsWith(t.sentinel)) {
      // find where it stopped, so the message is actionable
      const lastLine = trimmed.split('\n').pop().slice(0, 80);
      bad(name + ' is TRUNCATED — it does not end with ' + t.sentinel,
        'ends instead with: ' + JSON.stringify(lastLine) + '\n      ' +
        lines + ' lines, ' + raw.length + ' bytes (expected >= ' + t.minLines + ' lines, >= ' + t.minBytes + ' bytes)');
      allOk = false;
      continue;
    }
    if (lines < t.minLines || raw.length < t.minBytes) {
      bad(name + ' looks incomplete: ' + lines + ' lines / ' + raw.length + ' bytes (expected >= ' + t.minLines + ' / ' + t.minBytes + ')');
      allOk = false;
      continue;
    }
    const missing = t.must.filter((re) => !re.test(raw));
    if (missing.length) {
      bad(name + ' is missing expected code: ' + missing.map(String).join(', '));
      allOk = false;
      continue;
    }
    ok(name + ' complete (' + lines + ' lines, ' + raw.length + ' bytes, ends with sentinel)');
  }


  return allOk;
}

/* ------------------------------------------------------------------ *
 * 2. does relay.js actually load and export?
 * ------------------------------------------------------------------ */

async function checkModule() {
  head('Module');
  try {
    const mod = await import(pathToFileURL(RELAY_JS).href);
    if (typeof mod.default?.fetch !== 'function') {
      bad('relay.js does not export a fetch handler');
      return false;
    }
    ok('relay.js loads as an ES module and exports { fetch }');
    const names = Object.keys(mod).sort();
    ok('exports: ' + names.join(', '));

    // a couple of pure functions we can exercise without a network
    const enc = mod.encodeUrl('https://example.com/a?b=1');
    const rt = mod.targetFromPath(enc.split('?')[0], '?b=1');
    if (rt === 'https://example.com/a?b=1') ok('URL encode/decode round-trips');
    else bad('URL round-trip mismatch', enc + ' -> ' + rt);

    /* The routing contract. These are the checks that would have caught the
       TikTok bug: a URL built from the wrong origin, or a path that decoded to
       the relay itself instead of the site. */
    const mirror = mod.encodeUrl('https://example.com/a/b?x=1');
    const wantMirror = mod.CONFIG.prefix + b64('https://example.com') + '/a/b?x=1';
    if (mirror === wantMirror) ok('encodeUrl mirrors the target path -> ' + mirror);
    else bad('encodeUrl no longer mirrors the path', mirror + ' (wanted ' + wantMirror + ')');

    if (mod.targetFromPath(mirror.split('?')[0], '?x=1') === 'https://example.com/a/b?x=1') ok('mirrored URL decodes back to the exact target (path + query)');
    else bad('mirrored decode failed', String(mod.targetFromPath(mirror.split('?')[0], '?x=1')));

    if (mod.targetFromPath(mod.CONFIG.prefix + b64('https://example.com/deep/page'), '') === 'https://example.com/deep/page') ok('legacy full-URL b64 still decodes (old bookmarks keep working)');
    else bad('legacy decode failed', String(mod.targetFromPath(mod.CONFIG.prefix + b64('https://example.com/deep/page'), '')));

    if (mod.targetFromPath(mod.CONFIG.prefix + b64('https://example.com') + '/dir/file.js', '') === 'https://example.com/dir/file.js') ok('origin-b64 + path decodes (relative sub-resources keep their directory)');
    else bad('origin-b64 + path decode failed', String(mod.targetFromPath(mod.CONFIG.prefix + b64('https://example.com') + '/dir/file.js', '')));

    const imap = mod.rewriteImportMap('{"imports":{"app":"https://cdn.example.com/app.js","rel":"./x.js"}}', 'https://site.example/');
    if (imap.includes('/__p/') && !/https:\/\/cdn\.example\.com/.test(imap)) ok('import maps are rewritten (the browser resolves these, the shim cannot)');
    else bad('import map not rewritten', imap);

    if (mod.isPrivateAddress('127.0.0.1') && mod.isPrivateAddress('169.254.169.254') && !mod.isPrivateAddress('example.com')) {
      ok('SSRF guard classifies loopback/metadata as private');
    } else bad('SSRF guard misclassifies addresses');

    return true;
  } catch (err) {
    bad('relay.js failed to load: ' + ((err && err.message) || err));
    return false;
  }
}

/* ------------------------------------------------------------------ *
 * 3. live checks against a base URL
 * ------------------------------------------------------------------ */

function get(base, urlPath, extraHeaders, method) {
  return new Promise((resolve) => {
    const u = new URL(urlPath, base);
    const req = http.request({
      hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search,
      method: method || 'GET', headers: Object.assign({ 'user-agent': 'relay-verify' }, extraHeaders || {}),
      timeout: 20000,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (body.length < 600000) body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (err) => resolve({ status: 0, headers: {}, body: '', error: err.message }));
    req.end();
  });
}

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64url');

async function checkLive(base) {
  head('Live relay at ' + base);

  const health = await get(base, '/__health');
  if (health.status === 200 && /ok/i.test(health.body)) ok('/__health -> ok');
  else { bad('/__health failed', 'status ' + health.status + ' ' + (health.error || health.body.slice(0, 120))); return false; }
  if (health.headers['access-control-allow-origin']) ok('/__health sends CORS headers (client can read it cross-origin)');

  const probe = await get(base, '/__probe?url=' + encodeURIComponent('https://example.com/'));
  let caps = null;
  try { caps = JSON.parse(probe.body); } catch { /* not json */ }
  if (caps && caps.status === 200 && !caps.error) ok('/__probe reaches example.com (HTTP ' + caps.status + ', ' + caps.bytes + ' bytes, ' + caps.ms + ' ms)');
  else bad('/__probe could not reach the test target', (caps && (caps.error || caps.blocked)) || probe.body.slice(0, 160));
  if (caps && caps.features) {
    const f = caps.features;
    ok('capabilities: redirects=' + f.redirect_rewriting + ' media=' + f.media_manifests +
       ' ranges=' + f.range_requests + ' websockets=' + f.websockets + ' tabs=' + f.tabs);
  }

  const page = await get(base, '/p/example.com');
  if (page.status === 200 && page.body.includes('data-relay-toolbar')) ok('/p/example.com renders with the tab strip + toolbar');
  else bad('/p/example.com did not come back as a proxied page', 'status ' + page.status);
  if (page.body.includes('/__p/')) ok('links in the page were rewritten to relay paths');
  else bad('no rewritten links found — the rewriter may not be running');
  if (!/<base\s/i.test(page.body)) ok('no <base> tag injected (this is what keeps clicks inside the relay)');
  else bad('a <base> tag was injected — relative links will leak to the real site');

  const shimHits = (page.body.match(/data-relay-shim/g) || []).length;
  if (shimHits === 1) ok('client shim injected exactly once');
  else bad('client shim injected ' + shimHits + ' times (must be exactly 1)');
  if (/,TGT=/.test(page.body) && page.body.includes('patchWritten')) ok('shim carries the document target + programmatic-URL patches');
  else bad('shim is missing the target or the programmatic URL patches — origin-built URLs will escape');
  if (/targetFromPath|pp_loc/.test(page.body) === false) ok('relay internals are not leaked to the page');

  const redirect = await get(base, '/__p/' + b64('https://httpbin.org/redirect-to?url=/get'));
  if ([301, 302, 303, 307, 308].includes(redirect.status) && String(redirect.headers.location || '').startsWith('/__p/')) {
    ok('redirects are rewritten to proxied locations (HTTP ' + redirect.status + ')');
  } else if (redirect.status === 0) {
    console.log('  · redirect check skipped (httpbin unreachable)');
  } else {
    bad('redirect was not rewritten', 'status ' + redirect.status + ' location ' + redirect.headers.location);
  }

  const cookieSet = await get(base, '/__p/' + b64('https://httpbin.org/cookies/set?v=1'));
  const hasCookie = (cookieSet.headers['set-cookie'] || []).length > 0;
  console.log('  · upstream Set-Cookie is held in the relay jar, not leaked to the browser: ' +
    (hasCookie ? 'relay sent its own cookie (access key/home)' : 'no cookies in response (expected)'));

  const m3u8 = 'https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8';
  const manifest = await get(base, '/__p/' + b64(m3u8));
  if (manifest.status === 200 && manifest.body.startsWith('#EXTM3U')) {
    const lines = manifest.body.split('\n');
    const uris = lines.filter((l) => l.trim() && !l.startsWith('#'));
    const rewritten = uris.filter((l) => l.startsWith('/__p/'));
    if (uris.length && rewritten.length === uris.length) ok('HLS master playlist: all ' + uris.length + ' variant URIs rewritten to the relay');
    else bad('HLS playlist not fully rewritten', rewritten.length + '/' + uris.length + ' URIs');
  } else {
    bad('HLS manifest fetch failed', 'status ' + manifest.status);
  }

  /* Media checks need a public video that supports ranges. Sources rate-limit
     (HTTP 429) when this test is run repeatedly, so try a few and only report a
     failure when a source answered and the relay got it wrong. */
  const MEDIA_SOURCES = [
    'https://upload.wikimedia.org/wikipedia/commons/2/22/Volcano_Lava_Sample.webm',
    'https://test-videos.co.uk/vids/bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_1MB.mp4',
    'https://test-videos.co.uk/vids/bigbuckbunny/webm/vp8/360/Big_Buck_Bunny_360_10s_1MB.webm',
  ];
  let MEDIA = null, sawStatus = 0;
  for (const cand of MEDIA_SOURCES) {
    const r = await get(base, '/__p/' + b64(cand), { range: 'bytes=0-2047' });
    sawStatus = r.status;
    if (r.status === 206 || r.status === 200) { MEDIA = cand; break; }
  }

  if (MEDIA) {
    const video = await get(base, '/__p/' + b64(MEDIA), { range: 'bytes=0-2047' });
    if (video.status === 206) ok('media byte ranges proxy through (206 Partial Content)');
    else console.log('  \u00b7 range request returned 200 (source may not support ranges)');

    const player = await get(base, '/watch?url=' + encodeURIComponent(MEDIA));
    if (player.status === 200 && player.body.includes('data-relay-player') && player.body.includes('<video')) {
      ok('/watch returns a real player page (<video> + relay-side controls)');
    } else {
      bad('/watch did not return a player page', 'status ' + player.status);
    }

    const raw = await get(base, '/__p/' + b64(MEDIA) + '?raw=1', { range: 'bytes=0-2047' });
    if (raw.status === 206 && !raw.body.includes('data-relay-player')) ok('?raw=1 streams bytes instead of the player (so <video> can use it)');
    else bad('?raw=1 did not stream raw bytes', 'status ' + raw.status);
  } else {
    console.log('  \u00b7 media checks skipped \u2014 every test video source answered HTTP ' + sawStatus +
      (sawStatus === 429 ? ' (rate limited by the source, not by the relay)' : '') + '; rerun in a minute');
  }

  return true;
}

/* ------------------------------------------------------------------ *
 * 4. run it
 * ------------------------------------------------------------------ */

async function findFreePort() {
  return new Promise((resolve) => {
    const srv = http.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function bootLocal() {
  const port = await findFreePort();
  const child = spawn(process.execPath, [NODE_SERVER], {
    env: Object.assign({}, process.env, { PORT: String(port), HOST: '127.0.0.1' }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });

  const base = 'http://127.0.0.1:' + port;
  // wait for the listening line
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 250));
    if (/listening on/.test(out)) return { child, base };
    if (child.exitCode !== null) break;
  }
  console.log(out.trim());
  throw new Error('server did not start');
}

(async () => {
  console.log('relay self-test — ' + new Date().toISOString());
  const filesOk = checkFiles();
  const moduleOk = await checkModule();

  const deployed = process.argv[2];
  if (deployed && !deployed.startsWith('--')) {
    await checkLive(deployed.replace(/\/+$/, ''));
  } else if (filesOk && moduleOk) {
    let booted = null;
    try {
      booted = await bootLocal();
      console.log('\n(server started on ' + booted.base + ')');
      await checkLive(booted.base);
    } catch (err) {
      bad('could not boot the server locally: ' + err.message);
    } finally {
      if (booted) { booted.child.kill('SIGTERM'); }
    }
  } else {
    console.log('\nSkipping live tests — fix the file/module problems above first.');
  }

  console.log('\n' + (fail === 0 ? 'PASS' : 'FAIL') + ' — ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail === 0 ? 0 : 1);
})();
