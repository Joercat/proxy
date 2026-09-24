/**
 * Node 18+ adapter for the relay.
 *
 * The relay itself lives in relay.js and speaks the standard Web `Request`/
 * `Response` API, which is exactly what Cloudflare Workers and Deno Deploy hand
 * you. This file only translates Node's `http` objects to and from that API, so
 * all three targets run byte-identical proxy logic — there is no second
 * implementation to keep in sync.
 *
 *   node relay/node-server.js                 # http://0.0.0.0:8080
 *   PORT=3000 node relay/node-server.js
 *   ACCESS_KEY=letmein node relay/node-server.js
 *   BLOCK_HOSTS=example.com,internal.corp node relay/node-server.js
 *
 * Node-specific extras over the Workers/Deno build:
 *   • a real DNS resolver, so a hostname that resolves into private space
 *     (rebinding) is refused before we fetch it
 *   • Content-Length is emitted where it is known, for accurate progress bars
 */

import http from 'node:http';
import { Readable } from 'node:stream';
import dns from 'node:dns/promises';

import relay, { setDnsResolver } from './relay.js';

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';

/* Give the guard a DNS resolver: returns every address a name points at. */
setDnsResolver(async (hostname) => {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((r) => r.address);
});

const env = {
  ACCESS_KEY: process.env.ACCESS_KEY || undefined,
  BLOCK_HOSTS: process.env.BLOCK_HOSTS || undefined,
};

/** Minimal shims for the globals Workers provides but older Node builds may not. */
if (typeof AbortSignal.timeout !== 'function') {
  AbortSignal.timeout = (ms) => {
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(new Error('timeout')), ms);
    return ctl.signal;
  };
}

/** Node IncomingMessage -> Web Request. */
function toWebRequest(req) {
  const scheme = 'http';
  const host = req.headers.host || 'localhost';
  const url = scheme + '://' + host + (req.url || '/');

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
  return new Request(url, init);
}

/** Web Response -> whatever Node needs on the wire. */
async function sendWebResponse(webResponse, res) {
  const headers = {};
  let cookieLines = null;
  try {
    if (typeof webResponse.headers.getSetCookie === 'function') cookieLines = webResponse.headers.getSetCookie();
  } catch { /* ignore */ }

  for (const [key, value] of webResponse.headers) {
    if (key.toLowerCase() === 'set-cookie') continue;   // handled as an array below
    headers[key] = value;
  }
  if (cookieLines && cookieLines.length) headers['set-cookie'] = cookieLines;

  res.writeHead(webResponse.status, headers);
  if (!webResponse.body) return res.end();
  Readable.fromWeb(webResponse.body).pipe(res);
}

const server = http.createServer((req, res) => {
  let webRequest;
  try {
    webRequest = toWebRequest(req);
  } catch (err) {
    res.writeHead(400, { 'content-type': 'text/plain' });
    return res.end('Bad request: ' + err.message);
  }

  const abort = new AbortController();
  res.on('close', () => { if (!res.writableEnded) abort.abort(); });   // browser hit Stop

  relay.fetch(webRequest, env, { waitUntil: () => {} })
    .then((webResponse) => sendWebResponse(webResponse, res))
    .catch((err) => {
      if (res.headersSent) return res.end();
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Relay failure: ' + ((err && err.message) || err));
    });
});

server.listen(PORT, HOST, () => {
  console.log('[relay] listening on http://' + HOST + ':' + PORT);
  console.log('[relay] proxied pages:  /__p/<base64url>');
  console.log('[relay] passthrough:    /raw?url=<absolute url>');
  console.log('[relay] diagnostics:    /__probe?url=<absolute url>   health: /__health');
  console.log('[relay] status page:    /');
  if (env.ACCESS_KEY) console.log('[relay] ACCESS_KEY is set: every request needs ?key=…');
  if (env.BLOCK_HOSTS) console.log('[relay] BLOCK_HOSTS: ' + env.BLOCK_HOSTS);
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch { /* ignore */ }
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
