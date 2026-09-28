#!/usr/bin/env node
/**
 * Node 18+ entry point for the relay — written as CommonJS on purpose.
 *
 * WHY .cjs
 *   Node decides whether a ".js" file is ESM or CommonJS from the nearest
 *   package.json ("type": "module") — or, on Node 20.19+/22+, by sniffing the
 *   syntax. That is exactly the ambiguity that produced
 *   "SyntaxError: Unexpected end of input" and similar module-type errors on
 *   deploy. A ".cjs" file is ALWAYS CommonJS, and it loads the ESM relay with a
 *   dynamic import(), which works in every Node version, in any package.json
 *   context, and whether or not package.json exists at all.
 *
 * RUN
 *   node relay/node-server.cjs
 *   PORT=3000 node relay/node-server.cjs
 *   ACCESS_KEY=letmein node relay/node-server.cjs
 *   ALLOW_HOSTS=nas.local,192.168.1.10 node relay/node-server.cjs
 *
 * SELF-CHECK
 *   node relay/verify.cjs                 # files + a live end-to-end test
 *   node relay/verify.cjs https://my-relay.example     # test a deployment
 *
 * All proxy logic lives in relay.js; this file is transport only.
 */

'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const path = require('node:path');
const { Readable } = require('node:stream');
const { pathToFileURL } = require('node:url');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const RELAY_MODULE = path.join(__dirname, 'relay.js');

/* Set once main() has loaded the relay; handlers read it at call time. */
let R = null;

const env = {
  ACCESS_KEY: process.env.ACCESS_KEY || undefined,
  BLOCK_HOSTS: process.env.BLOCK_HOSTS || undefined,
  ALLOW_HOSTS: process.env.ALLOW_HOSTS || undefined,   // your own private-network hosts
};

/* Node compatibility shim: AbortSignal.timeout is missing before Node 17.3. */
if (typeof AbortSignal.timeout !== 'function') {
  AbortSignal.timeout = (ms) => {
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(new Error('timeout')), ms);
    return ctl.signal;
  };
}

/* ------------------------------------------------------------------ *
 *  HTTP: Node request -> Web Request, Web Response -> Node response
 * ------------------------------------------------------------------ */

function toWebRequest(req) {
  const host = req.headers.host || 'localhost';
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else headers.set(key, value);
  }

  const init = { method: req.method, headers, redirect: 'manual' };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = Readable.toWeb(req);
    init.duplex = 'half';
  }
  return new Request('http://' + host + (req.url || '/'), init);
}

async function sendWebResponse(webResponse, res) {
  const headers = {};
  let cookieLines = null;
  try {
    if (typeof webResponse.headers.getSetCookie === 'function') cookieLines = webResponse.headers.getSetCookie();
  } catch { /* older runtime */ }

  for (const [key, value] of webResponse.headers) {
    if (key.toLowerCase() === 'set-cookie') continue;
    headers[key] = value;
  }
  if (cookieLines && cookieLines.length) headers['set-cookie'] = cookieLines;

  res.writeHead(webResponse.status, headers);
  if (!webResponse.body) return res.end();

  const stream = Readable.fromWeb(webResponse.body);
  stream.on('error', () => { try { res.destroy(); } catch { /* ignore */ } });
  stream.pipe(res);
}

/* ------------------------------------------------------------------ *
 *  WebSocket tunnel
 *
 *  The shim rewrites wss://site/path to wss://relay/__p/<base64 of the original>.
 *  We decode that, open a TCP/TLS socket to the real server, replay the
 *  handshake with a corrected Host/Origin, then pipe both directions raw —
 *  which preserves text frames, binary frames, ping/pong and compression
 *  without parsing anything. Workers and Deno do this themselves.
 * ------------------------------------------------------------------ */

function attachUpgradeHandler(server) {
  server.on('upgrade', async (req, socket, head) => {
    const deny = (code, message) => {
      try {
        socket.write('HTTP/1.1 ' + code + ' ' + message + '\r\nConnection: close\r\n\r\n');
        socket.destroy();
      } catch { /* ignore */ }
    };

    let url;
    try {
      url = new URL(req.url || '/', 'http://' + (req.headers.host || 'localhost'));
    } catch {
      return deny(400, 'Bad Request');
    }

    if (env.ACCESS_KEY) {
      const fromQuery = url.searchParams.get('key');
      const fromCookie = (req.headers.cookie || '').split(/;\s*/)
        .map((p) => p.split('='))
        .filter((p) => p[0] === 'pp_key')
        .map((p) => p.slice(1).join('='))[0];
      if (fromQuery !== env.ACCESS_KEY && fromCookie !== env.ACCESS_KEY) return deny(401, 'Unauthorized');
    }

    if (!url.pathname.startsWith(R.CONFIG.prefix)) return deny(404, 'Not Found');
    const rest = url.pathname.slice(R.CONFIG.prefix.length);
    const slash = rest.indexOf('/');
    const wsTarget = R.decodeUrl(slash < 0 ? rest : rest.slice(0, slash));
    if (!wsTarget || !/^wss?:\/\//i.test(wsTarget)) return deny(400, 'Bad WebSocket target');

    const httpTarget = wsTarget.replace(/^ws/i, 'http');
    const blocked = await R.guardTarget(httpTarget, env);
    if (blocked) return deny(403, 'Blocked');

    const target = new URL(httpTarget);
    const useTls = target.protocol === 'https:';
    const port = Number(target.port || (useTls ? 443 : 80));

    const upstream = useTls
      ? tls.connect({ host: target.hostname, port, servername: target.hostname })
      : net.connect({ host: target.hostname, port });

    const cleanup = () => {
      try { upstream.destroy(); } catch { /* ignore */ }
      try { socket.destroy(); } catch { /* ignore */ }
    };
    const bail = setTimeout(cleanup, 15000);

    upstream.once(useTls ? 'secureConnect' : 'connect', () => {
      clearTimeout(bail);
      const lines = [];
      lines.push(req.method + ' ' + (target.pathname + target.search || '/') + ' HTTP/1.1');
      const forward = { ...req.headers };
      forward.host = target.host;
      forward.origin = target.origin;                                  // the site checks this
      forward['user-agent'] = req.headers['user-agent'] || R.CONFIG.userAgent;
      delete forward.cookie;                                           // relay-held cookies stay here
      for (const [k, v] of Object.entries(forward)) {
        if (v === undefined) continue;
        if (Array.isArray(v)) for (const item of v) lines.push(k + ': ' + item);
        else lines.push(k + ': ' + v);
      }
      try {
        upstream.write(lines.join('\r\n') + '\r\n\r\n');
        if (head && head.length) upstream.write(head);
      } catch {
        return cleanup();
      }
      upstream.pipe(socket);
      socket.pipe(upstream);
      for (const s of [upstream, socket]) {
        s.on('error', cleanup);
        s.on('close', cleanup);
      }
    });
    upstream.once('error', () => deny(502, 'Bad Gateway'));
  });
}

/* ------------------------------------------------------------------ *
 *  Boot
 * ------------------------------------------------------------------ */

/**
 * Load the ESM relay from CommonJS.
 *
 *  1. Normal dynamic import. Works on every Node when package.json says
 *     "type": "module", and on Node 20.19+/22+ even without it (syntax sniffing).
 *  2. Node 18/19 without that package.json refuses to parse a .js file as ESM
 *     ("Unexpected token 'export'"). relay.js imports nothing, so the exact same
 *     source can be loaded as a data: URL module — no config, no renaming, no
 *     copying files, just a slower one-off compile.
 */
async function loadRelay() {
  /* A file cut short by a copy/paste or a partial upload normally surfaces as
     "SyntaxError: Unexpected end of input" pointing at a line the real file does
     not end at. Read it as TEXT first so the log says what actually happened. */
  try {
    const text = fs.readFileSync(RELAY_MODULE, 'utf8');
    if (!text.includes('__RELAY_EOF__')) {
      console.error('');
      console.error('[relay] relay.js looks TRUNCATED: ' + RELAY_MODULE);
      console.error('        found ' + text.split('\n').length + ' lines (' +
        Buffer.byteLength(text) + ' bytes) and no  /* __RELAY_EOF__ */  at the end.');
      console.error('[relay] Re-send the whole file AS A FILE (download it, then drag it into');
      console.error('        GitHub). Pasting from a preview window can stop after a few KB.');
      console.error('[relay] Check every file at once with:  node check.cjs');
      console.error('');
      process.exit(1);
    }
  } catch { /* a missing file is reported by the import below */ }
  try {
    return { mod: await import(pathToFileURL(RELAY_MODULE).href), via: 'import' };
  } catch (err) {
    const msg = String((err && err.message) || err);
    const moduleTypeProblem = /Unexpected token 'export'|Cannot use import statement|set "type": "module"/i.test(msg);
    if (!moduleTypeProblem) {
      if (/ENOENT|Cannot find module/.test(msg)) {
        console.error('');
        console.error('[relay] Cannot find relay.js next to node-server.cjs.');
        console.error('        Expected at: ' + RELAY_MODULE);
        console.error('[relay] Both files must sit in the same folder. Check with: node check.cjs');
        console.error('');
      } else {
        console.error('[relay] relay.js could not be loaded: ' + msg);
      }
      process.exit(1);
    }
    const source = fs.readFileSync(RELAY_MODULE, 'utf8');
    const mod = await import('data:text/javascript;base64,' + Buffer.from(source, 'utf8').toString('base64'));
    return { mod, via: 'data-url' };
  }
}

async function main() {
  const loaded = await loadRelay();
  const mod = loaded.mod;
  if (loaded.via === 'data-url') {
    console.log('[relay] note: this Node build will not parse an ES module without "type":"module",');
    console.log('[relay]       so relay.js was loaded as a data-URL module. Adding a package.json');
    console.log('[relay]       containing  { "type": "module" }  removes this workaround.');
  }

  R = mod;
  if (!R || typeof R.default?.fetch !== 'function') {
    console.error('[relay] relay.js loaded but does not export a fetch handler — the file is probably truncated.');
    console.error('[relay] Check it with:  node check.cjs');
    process.exit(1);
  }

  // Real DNS resolution before fetching, so a hostname pointing into private
  // space (DNS rebinding) is refused instead of fetched. Platform builds skip
  // this because their runtimes already block private-network egress.
  R.setDnsResolver(async (hostname) => {
    const dns = await import('node:dns/promises');
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    return records.map((r) => r.address);
  });

  const server = http.createServer((req, res) => {
    let webRequest;
    try {
      webRequest = toWebRequest(req);
    } catch (err) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      return res.end('Bad request: ' + err.message);
    }
    R.default.fetch(webRequest, env, { waitUntil: () => {} })
      .then((webResponse) => sendWebResponse(webResponse, res))
      .catch((err) => {
        if (res.headersSent) return res.end();
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('Relay failure: ' + ((err && err.message) || err));
      });
  });

  attachUpgradeHandler(server);

  server.listen(PORT, HOST, () => {
    console.log('[relay] listening on http://' + HOST + ':' + PORT);
    console.log('[relay] start page:    /            (type an address — no http:// needed)');
    console.log('[relay] proxied:       /p/<address>  or  /__p/<base64url>');
    console.log('[relay] media player:  /watch?url=<address>   (any video/audio/stream URL)');
    console.log('[relay] passthrough:   /raw?url=<address>     diagnostics: /__probe?url=<address>');
    console.log('[relay] health:        /__health');
    console.log('[relay] self-test:     node relay/verify.cjs   (or: verify.cjs https://your-deployment)');
    console.log('[relay] websockets:    tunnel enabled on this build');
    if (env.ACCESS_KEY) console.log('[relay] ACCESS_KEY set — every request needs ?key=…');
    if (env.BLOCK_HOSTS) console.log('[relay] BLOCK_HOSTS: ' + env.BLOCK_HOSTS);
    if (env.ALLOW_HOSTS) console.log('[relay] ALLOW_HOSTS (private addresses allowed): ' + env.ALLOW_HOSTS);
  });

  server.on('clientError', (err, socket) => {
    try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch { /* ignore */ }
  });
  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      console.error('[relay] port ' + PORT + ' is already in use. Set PORT=<other> and try again.');
      process.exit(1);
    }
    console.error('[relay] server error: ' + ((err && err.message) || err));
  });

  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      console.log('[relay] shutting down');
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 3000);
    });
  }
}

main().catch((err) => {
  console.error('[relay] fatal: ' + ((err && err.stack) || err));
  process.exit(1);
});

/* __NODE_SERVER_EOF__ */
