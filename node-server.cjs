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



