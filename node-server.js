/**
 * Node 18+ adapter for the relay.
 *
 * relay.js speaks the Web Request/Response API, which is what Cloudflare Workers
 * and Deno Deploy hand you. This file only translates Node's http objects to and
 * from that API — plus one thing the other platforms do for us and Node does not:
 * a raw WebSocket tunnel, so live pages (chat, dashboards, presence) work here
 * too. All proxy logic lives in relay.js; nothing is duplicated.
 *
 *   node relay/node-server.js
 *   PORT=3000 node relay/node-server.js
 *   ACCESS_KEY=letmein node relay/node-server.js
 *   BLOCK_HOSTS=example.com,internal.corp node relay/node-server.js
 */

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { Readable } from 'node:stream';
import dns from 'node:dns/promises';

import relay, { setDnsResolver, guardTarget, decodeUrl, CONFIG, isPrivateAddress } from './relay.js';

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';

/* Real DNS resolution before fetching, so a hostname pointing into private
   space (DNS rebinding) is refused rather than fetched. */
setDnsResolver(async (hostname) => {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((r) => r.address);
});

const env = {
  ACCESS_KEY: process.env.ACCESS_KEY || undefined,
  BLOCK_HOSTS: process.env.BLOCK_HOSTS || undefined,
  // hosts you own that live on a private network (a NAS, a router, a dev box)
  ALLOW_HOSTS: process.env.ALLOW_HOSTS || undefined,
};

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
  const url = 'http://' + host + (req.url || '/');

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

async function sendWebResponse(webResponse, res) {
  const headers = {};
  let cookieLines = null;
  try {
    if (typeof webResponse.headers.getSetCookie === 'function') cookieLines = webResponse.headers.getSetCookie();
  } catch { /* ignore */ }


