/**
 * ============================================================================
 *  Web Relay — a standalone, self-hostable proxy relay
 * ============================================================================
 *
 *  WHAT THIS IS
 *    A single ES module that fetches a web page on behalf of a client, rewrites
 *    every URL in it so the page keeps working, and streams everything else
 *    through untouched. The *client's browser* does all rendering (layout, CSS,
 *    JS, painting). This server never renders anything and is not a browser.
 *
 *    Assets (CSS, images, fonts, JS, video) are proxied too — not loaded from
 *    the origin — which is what makes a page behave like the real thing:
 *    cookies keep a session, hotlink protection is satisfied, mixed content and
 *    Cross-Origin-Resource-Policy cannot break it, and the site's own
 *    same-origin XHR/fetch calls resolve against this relay and work.
 *
 *  DEPLOY TARGETS (this file is the whole relay in every case)
 *    • Cloudflare Workers — dashboard → Workers & Pages → Create → paste → Deploy
 *    • Deno Deploy        — dash.deno.com → New Playground → paste → Deploy
 *    • Node 18+           — `node relay/node-server.js`  (thin adapter, same logic)
 *
 *  ROUTES
 *    GET  /__p/<base64url of target>   the proxied page (HTML rewritten, assets relayed)
 *    ALL  /raw?url=<target>            fetch without rewriting, permissive CORS
 *                                      (for the client's own fetches / reader mode)
 *    GET  /__probe?url=<target>        JSON diagnostics: status, type, size, time, redirects
 *    GET  /__health                    "ok"
 *    GET  /                            small status page (NOT the client UI)
 *
 *  OPTIONAL ENVIRONMENT
 *    ACCESS_KEY   if set, every request must carry ?key=<value> (or the pp_key
 *                 cookie, which is set automatically on the first valid request).
 *                 Use this so a public deployment is yours alone.
 *    SESSIONS     a Cloudflare KV binding (optional). Persists the cookie jar so
 *                 logins survive isolate restarts. Without it the jar lives in
 *                 memory per isolate — fine for browsing, lossy across restarts.
 *    BLOCK_HOSTS  comma-separated hostnames to refuse.
 *
 *  Deliberate design choices
 *    • No <base> tag is injected. Every rewritten URL is absolute, because a
 *      <base> makes relative JS navigations resolve against the *target site*
 *      and silently leaks the user out of the proxy.
 *    • Upstream Set-Cookie never reaches the browser. Cookies are held in a
 *      per-host jar here, which is also what stops one relayed site from
 *      reading another's session.
 *    • CSP, HSTS, X-Frame-Options, CORP/COEP/COOP, Report-To and friends are
 *      stripped from relayed responses so the proxy's own client script and
 *      the site's own assets can run.
 *    • SRI `integrity` and `nonce` attributes are removed, since neither can
 *      survive being proxied (the hashes belong to the origin's bytes).
 * ============================================================================
 */

'use strict';

/* ==========================================================================
 * 1. Configuration
 * ========================================================================== */

export const CONFIG = {
  prefix: '/__p/',
  fetchTimeoutMs: 30000,
  maxRewriteBytes: 24 * 1024 * 1024,
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  corsHeaders: {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
    'access-control-allow-headers': '*',
    'access-control-expose-headers': '*',
    'access-control-max-age': '600',
  },
};

/* Header handling:
 *  copy  — safe to pass straight through to the browser
 *  drop  — must never reach the client (would break the proxy or leak the origin)
 */
const COPY_HEADERS = new Set([
  'content-type', 'accept-ranges', 'content-range', 'cache-control', 'expires',
  'etag', 'last-modified', 'content-language', 'content-disposition', 'vary',
  'age', 'date',
]);

const DROP_HEADERS = new Set([
  'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'set-cookie', 'set-cookie2', 'content-security-policy', 'content-security-policy-report-only',
  'strict-transport-security', 'x-frame-options', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'clear-site-data',
  'alt-svc', 'report-to', 'nel', 'expect-ct', 'permissions-policy', 'origin-trial',
  'speculation-rules', 'server-timing', 'www-authenticate', 'proxy-authenticate', 'link',
]);

/* ==========================================================================
 * 2. URL encoding + small helpers
 * ========================================================================== */

/** base64url target -> '/__p/<b64>'  (short, filesystem-safe, no escaping worries) */
export function encodeUrl(url) {
  const bytes = new TextEncoder().encode(String(url));
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return CONFIG.prefix + b64;
}

/** '/__p/<b64>' or bare b64 -> target URL, or null when it isn't a usable http(s) URL */
export function decodeUrl(input) {
  try {
    const cleaned = String(input).replace(/-/g, '+').replace(/_/g, '/');
    const padded = cleaned + '='.repeat((4 - (cleaned.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const url = new TextDecoder().decode(bytes);
    return /^https?:\/\//i.test(url) ? url : null;
  } catch {
    return null;
  }
}

const isHttpUrl = (u) => /^https?:\/\//i.test(String(u || ''));

/* Anything that is not a network fetch: leave exactly as authored. */
const SKIP_SCHEME =
  /^(?:\s*)(?:data|blob|javascript|mailto|tel|sms|callto|about|chrome|chrome-extension|moz-extension|file|ws|wss|magnet|intent|market|itms|view-source|android-app):/i;

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* Attribute values arrive entity-encoded (?a=1&amp;b=2). Decode before parsing a
 * URL, and re-encode on the way out, or links silently gain a literal "amp;". */
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", '#x27': "'", nbsp: ' ' };
const unescapeHtml = (s) =>
  String(s).replace(/&(amp|lt|gt|quot|apos|#39|#x27|nbsp);/gi, (m, e) => {
    const v = ENTITIES[e.toLowerCase()];
    return v === undefined ? m : v;
  });

/** Build a proxied URL for `raw` as resolved against `base`. */
export function proxify(raw, base) {
  if (raw == null) return raw;
  const s = String(raw);
  if (!s.trim()) return raw;
  if (SKIP_SCHEME.test(s)) return raw;
  if (s.charAt(0) === '#') return raw;                  // same-document fragment
  if (s.startsWith(CONFIG.prefix)) return raw;          // already proxied
  try {
    const abs = new URL(s, base).href;
    return isHttpUrl(abs) ? encodeUrl(abs) : raw;
  } catch {
    return raw;
  }
}

/* ==========================================================================
 * 3. Access control + SSRF guard
 * ========================================================================== */

/** Private / link-local / metadata addresses we refuse to fetch. */
export function isPrivateAddress(host) {
  const h = String(host).replace(/^\[|\]$/g, '').toLowerCase();

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;
    const [a, b] = o;
    if (a === 0 || a === 127 || a === 10) return true;               // this-host / loopback / private
    if (a === 169 && b === 254) return true;                         // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;                // private
    if (a === 192 && b === 168) return true;                         // private
    if (a === 100 && b >= 64 && b <= 127) return true;               // carrier-grade NAT
    if (a >= 224) return true;                                       // multicast / reserved
    return false;
  }

  if (h.includes(':')) {
    if (h === '::' || h === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;                   // unique local
    if (/^fe80:/.test(h)) return true;                               // link local
    if (h.startsWith('::ffff:')) return isPrivateAddress(h.slice(7));
    return false;
  }

  return /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.home\.arpa|metadata\.google\.internal|instance-data)$/i.test(h);
}

/* Node's adapter installs a real resolver here so DNS names that point at
 * private space are caught too. Workers/Deno can't resolve manually; their
 * platforms already block private-network egress, so name checks are enough. */
let dnsResolver = null;
export function setDnsResolver(fn) { dnsResolver = fn; }

const dnsCache = new Map(); // host -> { verdict, expires }

export async function guardTarget(target, env) {
  let url;
  try { url = new URL(target); } catch { return 'Not a valid URL.'; }
  if (!isHttpUrl(url.href)) return 'Only http:// and https:// can be relayed.';
  if (isPrivateAddress(url.hostname)) return 'Refused: ' + url.hostname + ' is a private, loopback or metadata address.';

  const block = String((env && env.BLOCK_HOSTS) || '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (block.some((b) => url.hostname.toLowerCase() === b || url.hostname.toLowerCase().endsWith('.' + b))) {
    return 'Refused: ' + url.hostname + ' is on this relay\'s block list.';
  }

  if (dnsResolver && isHttpUrl(url.href)) {
    const cached = dnsCache.get(url.hostname);
    if (cached && cached.expires > Date.now()) return cached.verdict;
    let verdict = null;
    try {
      const list = await dnsResolver(url.hostname);
      if (list.some((ip) => isPrivateAddress(ip))) {
        verdict = 'Refused: ' + url.hostname + ' resolves to a private address.';
      }
    } catch { /* let the fetch report DNS failure itself */ }
    dnsCache.set(url.hostname, { verdict, expires: Date.now() + 60000 });
    return verdict;
  }
  return null;
}

/** Optional shared-secret gate so a public deployment stays private. */
function checkAccess(url, request, env, secure) {
  const key = env && env.ACCESS_KEY;
  if (!key) return { ok: true, cookie: null };
  const supplied = url.searchParams.get('key') || readCookie(request, 'pp_key');
  if (supplied === key) {
    const cookie = url.searchParams.get('key')
      ? 'pp_key=' + key + '; Path=/; SameSite=Lax; Max-Age=2592000' + (secure ? '; Secure' : '')
      : null;
    return { ok: true, cookie };
  }
  return { ok: false };
}

function readCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/* ==========================================================================
 * 4. Cookie jar
 *
 *    Keyed by the *final* host after redirects (so a login redirect that sets
 *    cookies on app.example.com files them under app.example.com). Honours
 *    Expires and Max-Age. Backed by Cloudflare KV when a SESSIONS binding
 *    exists, otherwise a per-isolate Map.
 * ========================================================================== */

const memoryJar = new Map();

async function jarLoad(env, host) {
  if (env && env.SESSIONS && typeof env.SESSIONS.get === 'function') {
    try {
      const raw = await env.SESSIONS.get('ck:' + host, 'json');
      return new Map(Object.entries(raw || {}));
    } catch { /* fall through to memory */ }
  }
  return memoryJar.get(host) || new Map();
}

async function jarSave(env, host, jar) {
  const now = Date.now();
  for (const [name, entry] of jar) if (entry.exp <= now) jar.delete(name);
  if (env && env.SESSIONS && typeof env.SESSIONS.put === 'function') {
    try {
      await env.SESSIONS.put('ck:' + host, JSON.stringify(Object.fromEntries(jar)), { expirationTtl: 86400 });
      return;
    } catch { /* fall through to memory */ }
  }
  memoryJar.set(host, jar);
}

/** Fold upstream Set-Cookie lines into the jar. */
function jarAbsorb(jar, setCookies) {
  const now = Date.now();
  for (const line of setCookies) {
    const parts = String(line).split(';');
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const name = parts[0].slice(0, eq).trim();
    const value = parts[0].slice(eq + 1).trim();
    let exp = Infinity;
    for (const attr of parts.slice(1)) {
      const i = attr.indexOf('=');
      const k = (i < 0 ? attr : attr.slice(0, i)).trim().toLowerCase();
      const v = i < 0 ? '' : attr.slice(i + 1).trim();
      if (k === 'max-age') { const n = Number(v); if (!isNaN(n)) exp = now + n * 1000; }
      else if (k === 'expires') { const t = Date.parse(v); if (!isNaN(t)) exp = t; }
    }
    if (exp <= now || /^deleted$/i.test(value)) jar.delete(name);
    else jar.set(name, { value, exp });
  }
}

const jarHeader = (jar) => {
  const now = Date.now();
  const out = [];
  for (const [name, e] of jar) { if (e.exp <= now) jar.delete(name); else out.push(name + '=' + e.value); }
  return out.length ? out.join('; ') : null;
};

function getSetCookies(headers) {
  try {
    if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  } catch { /* older runtimes */ }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

/* ==========================================================================
 * 5. HTML rewriter
 * ========================================================================== */

const URL_ATTRS = new Set([
  'href', 'src', 'action', 'formaction', 'poster', 'background', 'cite', 'longdesc',
  'manifest', 'data', 'itemid', 'ping', 'usemap', 'profile', 'icon', 'xlink:href',
  // lazy-loading and JS-hook attributes used by countless themes
  'data-src', 'data-href', 'data-url', 'data-lazy', 'data-lazy-src', 'data-original',
  'data-background', 'data-video', 'data-image', 'data-thumb', 'data-full', 'data-file',
  'data-path', 'data-download-url', 'data-hi-res-src', 'data-srcset',
]);

const ATTR_RE = /([a-zA-Z_:@][-a-zA-Z0-9_:.]*)(\s*=\s*)("([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;

/** Rewrite url()/image-set()/@import inside a CSS string. */
export function rewriteCss(css, base) {
  return String(css)
    .replace(/@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/gi,
      (m, q1, u1, q2, u2) => {
        const u = u1 !== undefined ? u1 : u2;
        if (!u) return m;
        const n = proxify(u, base);
        return n === u ? m : m.replace(u, n);
      })
    .replace(/url\(\s*(['"]?)([^'")]*)\1\s*\)/gi, (m, q, u) => {
      if (!u) return m;
      const n = proxify(u, base);
      return n === u ? m : 'url(' + (q || '') + n + (q || '') + ')';
    });
}

function proxifySrcset(value, base) {
  return String(value)
    .split(',')
    .map((part) => {
      const t = part.trim();
      if (!t) return '';
      const bits = t.split(/\s+/);
      bits[0] = proxify(bits[0], base);
      return bits.join(' ');
    })
    .filter(Boolean)
    .join(', ');
}

/** Rewrite one tag's attributes. */
function rewriteTag(tagText, base) {
  const nameMatch = /^<\s*([a-zA-Z][-a-zA-Z0-9:]*)/.exec(tagText);
  const tagName = nameMatch ? nameMatch[1].toLowerCase() : '';

  return tagText.replace(ATTR_RE, (match, rawName, eq, _q, dq, sq, uq) => {
    const name = rawName.toLowerCase();
    const raw = dq !== undefined ? dq : sq !== undefined ? sq : uq;
    const value = unescapeHtml(raw);
    const emit = (next) => rawName + eq + '"' + escapeHtml(next) + '"';

    // SRI hashes belong to the origin's exact bytes and can never survive a proxy.
    if (name === 'integrity' || name === 'nonce') return '';

    if (name === 'srcset' || name === 'imagesrcset' || name === 'data-srcset') {
      const next = proxifySrcset(value, base);
      return next === value ? match : emit(next);
    }
    if (URL_ATTRS.has(name)) {
      const next = proxify(value, base);
      return next === value ? match : emit(next);
    }
    if (name === 'style') {
      const next = rewriteCss(value, base);
      return next === value ? match : emit(next);
    }
    if (name === 'content' && tagName === 'meta' && /http-equiv/i.test(tagText)) {
      // <meta http-equiv="refresh" content="0;url=/next">
      const next = value.replace(/url\s*=\s*(['"]?)([^'";]+)\1/i,
        (mm, q, u) => 'url=' + (q || '') + proxify(u, base) + (q || ''));
      return next === value ? match : emit(next);
    }
    return match;
  });
}

/** Rewrite a full HTML document: attributes + <style> blocks, never <script> bodies. */
export function rewriteHtml(html, base) {
  let out = '';
  let last = 0;

  // Walk paired <script>/<style> elements so their contents are treated correctly:
  // style bodies get url() rewriting, script bodies are left byte-identical.
  const paired = /<(script|style)(\b[^>]*?)>([\s\S]*?)<\/\1\s*>/gi;
  let m;
  while ((m = paired.exec(html))) {
    out += rewriteTags(html.slice(last, m.index), base);
    const kind = m[1].toLowerCase();
    out += rewriteTag('<' + kind + m[2] + '>', base);
    out += kind === 'style' ? rewriteCss(m[3], base) : m[3];
    out += '</' + kind + '>';
    last = paired.lastIndex;
  }
  out += rewriteTags(html.slice(last), base);
  return out;
}

function rewriteTags(chunk, base) {
  return chunk.replace(/<[a-zA-Z!/?][^>]*>/g, (tag) => (tag.startsWith('<!') ? tag : rewriteTag(tag, base)));
}

/** Neutralise things that would break out of the proxy, then drop in our script. */
function finalizeHtml(html, base, extras) {
  let out = html;
  out = out.replace(/<base\b[^>]*>/gi, '');                                   // see header note
  out = out.replace(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi, ''); // handled as a link, not a jump
  return injectIntoHead(out, extras);
}

function injectIntoHead(html, block) {
  const head = /<head[^>]*>/i.exec(html);
  if (head) return html.slice(0, head.index + head[0].length) + block + html.slice(head.index + head[0].length);
  const htmlTag = /<html[^>]*>/i.exec(html);
  if (htmlTag) return html.slice(0, htmlTag.index + htmlTag[0].length) + block + html.slice(htmlTag.index + htmlTag[0].length);
  const doctype = /<!doctype[^>]*>/i.exec(html);
  if (doctype) return html.slice(0, doctype.index + doctype[0].length) + block + html.slice(doctype.index + doctype[0].length);
  return block + html;
}

/* ==========================================================================
 * 6. Client runtime shim
 *
 *    Runs in the *browser*, before any page script, and keeps URLs inside the
 *    proxy even when the page builds them at runtime: fetch, XHR, setAttribute,
 *    history.pushState, window.open, Worker, EventSource, plus a MutationObserver
 *    for markup injected after load (infinite scroll, SPA route changes).
 * ========================================================================== */

const CLIENT_SHIM = String.raw`(function(){
var P="__PREFIX__",O=location.origin;
function enc(u){var s=unescape(encodeURIComponent(u)),b=[],i;for(i=0;i<s.length;i++)b.push(s.charCodeAt(i));
return P+btoa(String.fromCharCode.apply(null,b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function dec(s){try{var t=s.replace(/-/g,"+").replace(/_/g,"/");while(t.length%4)t+="=";
return decodeURIComponent(escape(atob(t)));}catch(e){return null;}}
function base(){try{var p=location.pathname;if(p.indexOf(P)===0){var r=p.slice(P.length),j=r.indexOf("/");
var d=dec(j<0?r:r.slice(0,j));if(d&&/^https?:\/\//i.test(d))return d;}}catch(e){}return location.href;}
function abs(u){try{return new URL(u,base()).href;}catch(e){return null;}}
var PASS=/^(data:|blob:|javascript:|mailto:|tel:|sms:|about:|#|file:|ws:|wss:)/i;
function px(u){if(u==null)return u;u=String(u).trim();if(!u||PASS.test(u))return u;
if(u.indexOf(P)===0)return u;
if(u.indexOf(O+P)===0)return u;
var a=abs(u);if(!a)return u;if(a.indexOf(O+P)===0)return a;if(!/^https?:\/\//i.test(a))return u;
if(a.indexOf(P)===0)return a;
return O+enc(a);}
function fixSrcset(v){return String(v).split(",").map(function(p){var t=p.trim();if(!t)return "";
var s=t.split(/\s+/);s[0]=px(s[0]);return s.join(" ");}).filter(Boolean).join(", ");}
window.__px=px;window.__enc=enc;window.__dec=dec;window.__base=base;
var F=window.fetch;
if(F)window.fetch=function(i,init){try{
if(typeof i==="string"||(typeof URL!=="undefined"&&i instanceof URL)){i=px(i);}
else if(i&&i.url){var n=px(i.url);if(n!==i.url)i=new Request(n,i);}}catch(e){}
return F.call(this,i,init);};
var XO=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){try{if(arguments.length>1&&typeof u==="string")arguments[1]=px(u);}catch(e){}
return XO.apply(this,arguments);};
if(window.EventSource){var E=window.EventSource;var NewES=function(u,c){return new E(px(u),c);};NewES.prototype=E.prototype;window.EventSource=NewES;}
if(window.Worker){var W=window.Worker;var NewW=function(u,o){try{u=px(u);}catch(e){}return new W(u,o);};NewW.prototype=W.prototype;window.Worker=NewW;}
if(window.WebSocket){var WS=window.WebSocket;var NewWS=function(u,p){try{u=px(u);}catch(e){}return p===undefined?new WS(u):new WS(u,p);};
NewWS.prototype=WS.prototype;NewWS.CONNECTING=0;NewWS.OPEN=1;NewWS.CLOSING=2;NewWS.CLOSED=3;window.WebSocket=NewWS;}
if(navigator.serviceWorker){try{navigator.serviceWorker.register=function(){return Promise.reject(new Error("service workers are disabled by the relay"));};}catch(e){}}
["pushState","replaceState"].forEach(function(k){var o=history[k];try{history[k]=function(s,t,u){try{if(u!=null)u=px(u);}catch(e){}
return o.call(this,s,t,u);};}catch(e){}});
var WO=window.open;
if(WO)window.open=function(u){try{u=px(u);}catch(e){}return WO.call(window,u);};
var A={href:1,src:1,action:1,formaction:1,poster:1,background:1,cite:1,"xlink:href":1};
var SA=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){try{var l=String(n).toLowerCase();
if(A[l])v=px(v);else if(l==="srcset"||l==="imagesrcset")v=fixSrcset(v);}catch(e){}
return SA.call(this,n,v);};
function scan(root){try{
if(!root||root.nodeType!==1)return;
var sel="[href],[src],[srcset],[imagesrcset],[action],[poster]";
var list=root.querySelectorAll?root.querySelectorAll(sel):[];
for(var q=0;q<list.length;q++){var el=list[q];
for(var i=0;i<el.attributes.length;i++){var a=el.attributes[i],l=a.name.toLowerCase();
if(A[l]){var nv=px(a.value);if(nv!==a.value)SA.call(el,a.name,nv);}
else if(l==="srcset"||l==="imagesrcset"){var nv2=fixSrcset(a.value);if(nv2!==a.value)SA.call(el,a.name,nv2);}}}
}catch(e){}}
try{
scan(document.documentElement);
var MO=new MutationObserver(function(muts){for(var i=0;i<muts.length;i++){
var mu=muts[i];if(mu.type==="attributes"){scan(mu.target.parentNode||mu.target);}
for(var j=0;j<mu.addedNodes.length;j++){var n=mu.addedNodes[j];if(n.nodeType===1)scan(n);}}});
MO.observe(document.documentElement||document,{subtree:true,childList:true,attributes:true,
attributeFilter:["href","src","srcset","imagesrcset","action","poster","data"]});
}catch(e){}
document.addEventListener("submit",function(ev){try{var f=ev.target;if(f&&f.tagName==="FORM"){
var a=f.getAttribute("action");if(a){var nv=px(a);if(nv!==a)SA.call(f,"action",nv);}}
}catch(e){}},true);
})();`;

/* ==========================================================================
 * 7. Navigation toolbar
 *
 *    Injected by the *relay*, because once you are inside a proxied page the
 *    browser's own address bar shows the relay, not the site. Gives you back
 *    Back, an address bar, "open the real page", and a Home button when the
 *    client told us where its own UI lives (the pp_home cookie).
 * ========================================================================== */

function toolbarBlock(targetUrl, homeUrl, accessKey) {
  const cfg = JSON.stringify({ target: targetUrl, home: homeUrl || null, key: accessKey || null });
  return String.raw`<div id="__relay_bar_host" style="all:initial"></div>
<script data-relay-toolbar="1">
(function(){
var C=` + cfg + String.raw`;
var P="__PREFIX__";
var host=document.getElementById("__relay_bar_host");
if(!host)return;
var sh=host.attachShadow?host.attachShadow({mode:"open"}):host;
function enc(u){var s=unescape(encodeURIComponent(u)),b=[],i;for(i=0;i<s.length;i++)b.push(s.charCodeAt(i));
return P+btoa(String.fromCharCode.apply(null,b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function key(){return C.key?((location.search.indexOf("?")<0?"?":"&")+"key="+encodeURIComponent(C.key)):"";}
function nav(u){var s=u.trim();if(!s)return;if(!/^https?:\/\//i.test(s))s="https://"+s.replace(/^\/+/,"");
try{new URL(s);}catch(e){return;}location.href=enc(s)+key();}
sh.innerHTML="<style>"
+".b{display:flex;gap:7px;align-items:center;padding:7px 9px;background:rgba(12,15,21,.95);"
+"border-bottom:1px solid #2a3140;font:13px/1.2 ui-sans-serif,system-ui,-apple-system,sans-serif;color:#e8ebf1;box-sizing:border-box}"
+"button{all:initial;cursor:pointer;font:600 12px/1 ui-sans-serif,system-ui,sans-serif;color:#cfd7e5;background:#171c26;"
+"border:1px solid #2a3140;border-radius:9px;padding:8px 10px;white-space:nowrap}"
+"button:hover{border-color:#4b7bff;color:#fff}"
+"input{all:initial;flex:1;min-width:60px;font:12.5px/1.2 ui-monospace,Menlo,monospace;color:#e8ebf1;background:#10141c;"
+"border:1px solid #2a3140;border-radius:9px;padding:8px 10px}"
+"input:focus{outline:none;border-color:#4b7bff}"
+"span{all:initial;font:11px/1 ui-monospace,Menlo,monospace;color:#8ef0c0;background:#0f2a20;border:1px solid #1d4f3b;"
+"border-radius:999px;padding:6px 9px;white-space:nowrap}"
+".wrap{position:fixed;top:0;left:0;right:0;z-index:2147483647}"
+"</style><div class='wrap'><div class='b'>"
+(C.home?"<button id='h' title='Back to the launcher'>&#8962;</button>":"")
+"<button id='bk' title='Back'>&#8592;</button>"
+"<input id='a' spellcheck='false'>"
+"<button id='g'>Go</button><span>relay</span>"
+"<button id='o' title='Open the real page, unproxied'>&#8599;</button>"
+"<button id='x' title='Hide this bar'>&#10005;</button>"
+"</div></div>";
function $(id){return sh.getElementById?sh.getElementById(id):sh.querySelector("#"+id);}
var a=$("a");
if(a){a.value=C.target||"";a.onkeydown=function(e){if(e.key==="Enter")nav(a.value);};a.onfocus=function(){a.select();};}
if($("h"))$("h").onclick=function(){location.href=C.home;};
if($("bk"))$("bk").onclick=function(){history.back();};
if($("g"))$("g").onclick=function(){nav(a.value);};
if($("o"))$("o").onclick=function(){window.open(C.target,"_blank","noopener");};
if($("x"))$("x").onclick=function(){host.style.display="none";};
(document.documentElement||document.body).appendChild(host);
})();
</script>`.replace('__PREFIX__', CONFIG.prefix);
}

function injectionBlock(targetUrl, homeUrl, accessKey) {
  return '<script data-relay-shim="1">' + CLIENT_SHIM.replace('__PREFIX__', CONFIG.prefix) + '</script>'
    + toolbarBlock(targetUrl, homeUrl, accessKey);
}

/* ==========================================================================
 * 8. Upstream request construction
 * ========================================================================== */

/** Map a relayed Referer back to the real upstream URL it stood for. */
function refererTarget(referer) {
  if (!referer) return null;
  try {
    const u = new URL(referer);
    if (u.pathname.startsWith(CONFIG.prefix)) {
      const rest = u.pathname.slice(CONFIG.prefix.length);
      const slash = rest.indexOf('/');
      return decodeUrl(slash < 0 ? rest : rest.slice(0, slash));
    }
  } catch { /* ignore */ }
  return null;
}

function buildUpstreamHeaders(request, target, jar, accessKey) {
  const headers = new Headers();
  headers.set('user-agent', CONFIG.userAgent);
  headers.set('accept', request.headers.get('accept') || '*/*');
  headers.set('accept-language', request.headers.get('accept-language') || 'en-US,en;q=0.9');
  headers.set('accept-encoding', 'gzip, deflate, br');

  // Tell upstream where we really are, so hotlink protection and CSRF checks pass.
  const upstreamRef = refererTarget(request.headers.get('referer'));
  if (upstreamRef) {
    headers.set('referer', upstreamRef);
    const ref = new URL(upstreamRef);
    headers.set('origin', ref.origin);
    const dest = request.headers.get('sec-fetch-dest') || 'document';
    headers.set('sec-fetch-site', ref.hostname === new URL(target).hostname ? 'same-origin' : 'cross-site');
    headers.set('sec-fetch-mode', request.headers.get('sec-fetch-mode') || (dest === 'document' ? 'navigate' : 'cors'));
    headers.set('sec-fetch-dest', dest);
  } else {
    headers.set('sec-fetch-site', 'none');
    headers.set('sec-fetch-mode', 'navigate');
    headers.set('sec-fetch-dest', request.headers.get('sec-fetch-dest') || 'document');
  }
  headers.set('upgrade-insecure-requests', '1');

  const range = request.headers.get('range');
  if (range) headers.set('range', range);
  const etag = request.headers.get('if-none-match');
  if (etag) headers.set('if-none-match', etag);
  const modified = request.headers.get('if-modified-since');
  if (modified) headers.set('if-modified-since', modified);

  const cookie = jarHeader(jar);
  if (cookie) headers.set('cookie', cookie);

  const ctype = request.headers.get('content-type');
  if (ctype) headers.set('content-type', ctype);

  if (accessKey) headers.set('x-relay', '1');
  return headers;
}

/* ==========================================================================
 * 9. Response handling
 * ========================================================================== */

function charsetOf(contentType, sample) {
  const m = /charset\s*=\s*"?([\w-]+)"?/i.exec(contentType || '');
  if (m) return m[1];
  const sniff = /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(String(sample || '').slice(0, 2048));
  return sniff ? sniff[1] : 'utf-8';
}

function passthroughHeaders(upstream, extra) {
  const out = new Headers();
  for (const [k, v] of upstream.headers) {
    const key = k.toLowerCase();
    if (DROP_HEADERS.has(key)) continue;
    if (COPY_HEADERS.has(key)) out.set(k, v);
  }
  if (extra) for (const [k, v] of Object.entries(extra)) out.set(k, v);
  return out;
}

async function readAll(response, limit) {
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > limit) throw new Error('response larger than the rewrite limit');
  return buffer;
}

/* ==========================================================================
 * 10. Router
 * ========================================================================== */

export default {
  async fetch(request, env = {}, ctx = {}) {
    const url = new URL(request.url);

    try {
      // ---- health check: handy for uptime pings and deploy verification
      if (url.pathname === '/__health') {
        return new Response('ok', { headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
      }

      // ---- outgoing cookies: the access key (if configured) and the launcher's
      //      own address, which teaches the injected toolbar where "Home" is.
      const secure = url.protocol === 'https:';
      const cookies = [];

      const homeParam = url.searchParams.get('home');
      if (homeParam && /^https?:\/\//i.test(homeParam)) {
        cookies.push('pp_home=' + encodeURIComponent(homeParam) + '; Path=/; SameSite=Lax; Max-Age=604800' + (secure ? '; Secure' : ''));
      }
      const home = (homeParam && /^https?:\/\//i.test(homeParam))
        ? homeParam
        : (readCookie(request, 'pp_home') ? decodeURIComponent(readCookie(request, 'pp_home')) : null);

      // ---- access gate
      const access = checkAccess(url, request, env, secure);
      if (access.cookie) cookies.push(access.cookie);
      if (!access.ok) {
        return new Response('This relay requires an access key. Append ?key=YOUR_KEY to the URL.', {
          status: 401,
          headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' },
        });
      }

      // ---- CORS passthrough (client-side fetches, reader mode, diagnostics)
      if (url.pathname === '/raw') {
        return withCors(await rawFetch(request, url, env), cookies);
      }
      if (url.pathname === '/__probe') {
        return withCors(await probe(url, env), cookies);
      }

      // ---- status page (deliberately not the client UI)
      if (url.pathname === '/' || url.pathname === '/index.html') {
        return html(statusPage(url, env), 200, cookies);
      }
      if (url.pathname === '/favicon.ico') {
        return new Response(
          '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#4b7bff"/><path d="M9 16h14M16 9v14" stroke="#fff" stroke-width="3" stroke-linecap="round"/></svg>',
          { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'max-age=86400' } }
        );
      }
      if (url.pathname === '/robots.txt') {
        return new Response('User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain' } });
      }

      // ---- the proxied page itself
      let target = null;
      if (url.pathname.startsWith(CONFIG.prefix)) {
        const rest = url.pathname.slice(CONFIG.prefix.length);
        const slash = rest.indexOf('/');
        target = decodeUrl(slash < 0 ? rest : rest.slice(0, slash));
      }

      // Fallback for URLs the rewriter never saw (ES module imports, document.baseURI
      // relative XHR, CSS imports with odd quoting). Resolve against the referring page.
      if (!target) {
        const ref = refererTarget(request.headers.get('referer'));
        if (ref) {
          try {
            const rel = (url.pathname.startsWith(CONFIG.prefix) ? url.pathname.slice(CONFIG.prefix.length) : url.pathname) + url.search;
            target = new URL(rel, ref).href;
          } catch { target = null; }
        }
      }

      if (!target) return html(errorPage(404, 'Nothing here.', 'Enter a URL on the relay status page, or point your client at this relay.'), 404, cookies);
      return await proxy(request, target, env, cookies, home);
    } catch (err) {
      return html(errorPage(502, (err && err.message) || String(err)), 502, null);
    }
  },
};

/* -------------------------------------------------------------------------- */

async function proxy(request, target, env, cookies, home) {
  const verdict = await guardTarget(target, env);
  if (verdict) return html(errorPage(403, verdict, target), 403, cookies);

  const dest = new URL(target);
  const jar = await jarLoad(env, dest.hostname);
  const headers = buildUpstreamHeaders(request, target, jar, env && env.ACCESS_KEY);

  const init = {
    method: request.method,
    headers,
    redirect: 'follow',
    signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs),
  };
  const hasBody = !['GET', 'HEAD'].includes(request.method);
  if (hasBody) { init.body = request.body; init.duplex = 'half'; }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    const reason = (err && err.name === 'TimeoutError')
      ? 'the site took longer than ' + CONFIG.fetchTimeoutMs / 1000 + 's to answer'
      : ((err && err.message) || String(err));
    return html(errorPage(502, 'Could not reach ' + dest.hostname + ' — ' + reason, target), 502, cookies);
  }

  // ---- file any cookies under the *final* host, and never leak them outward
  const incoming = getSetCookies(upstream.headers);
  if (incoming.length) {
    const finalHost = (() => { try { return new URL(upstream.url).hostname; } catch { return dest.hostname; } })();
    const finalJar = finalHost === dest.hostname ? jar : await jarLoad(env, finalHost);
    jarAbsorb(finalJar, incoming);
    await jarSave(env, finalHost, finalJar);
  }

  const contentType = upstream.headers.get('content-type') || '';
  const finalUrl = isHttpUrl(upstream.url) ? upstream.url : target;
  const extraHeaders = {
    'x-relayed-by': 'web-relay',
    'referrer-policy': 'no-referrer-when-downgrade',
  };

  if (upstream.status === 204 || upstream.status === 304 || request.method === 'HEAD') {
    return new Response(null, { status: upstream.status, headers: passthroughHeaders(upstream, extraHeaders) });
  }

  // ---- HTML: buffer, rewrite, serve as UTF-8 (charset normalised so nothing is mangled)
  if (/^(text\/html|application\/xhtml\+xml)/i.test(contentType) && !request.headers.get('range')) {
    try {
      const bytes = await readAll(upstream, CONFIG.maxRewriteBytes);
      const text = new TextDecoder(charsetOf(contentType, new TextDecoder().decode(bytes.slice(0, 2048)))).decode(bytes);
      const key = env && env.ACCESS_KEY ? env.ACCESS_KEY : null;
      const rewritten = finalizeHtml(
        rewriteHtml(text, finalUrl),
        finalUrl,
        injectionBlock(finalUrl, home, key)
      );
      const outHeaders = passthroughHeaders(upstream, {
        ...extraHeaders,
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      });
      for (const c of cookies || []) outHeaders.append('set-cookie', c);
      return new Response(rewritten, { status: upstream.status, headers: outHeaders });
    } catch {
      // too big or unreadable — fall through and stream it untouched
    }
  }

  // ---- CSS: rewrite url() and @import
  if (/^text\/css/i.test(contentType) && !request.headers.get('range')) {
    try {
      const bytes = await readAll(upstream, CONFIG.maxRewriteBytes);
      const text = new TextDecoder(charsetOf(contentType)).decode(bytes);
      return new Response(rewriteCss(text, finalUrl), {
        status: upstream.status,
        headers: passthroughHeaders(upstream, { ...extraHeaders, 'content-type': 'text/css; charset=utf-8' }),
      });
    } catch { /* stream it */ }
  }

  // ---- everything else: byte-for-byte streaming (images, video, fonts, JS, JSON)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: passthroughHeaders(upstream, extraHeaders),
  });
}

/* -------------------------------------------------------------------------- */

async function rawFetch(request, url, env) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CONFIG.corsHeaders });

  const target = url.searchParams.get('url') || url.searchParams.get('u');
  if (!isHttpUrl(target)) {
    return new Response('usage: /raw?url=<absolute http(s) url>', { status: 400, headers: { 'content-type': 'text/plain' } });
  }
  const verdict = await guardTarget(target, env);
  if (verdict) return new Response(verdict, { status: 403, headers: { 'content-type': 'text/plain' } });

  const dest = new URL(target);
  const jar = await jarLoad(env, dest.hostname);
  const headers = new Headers({
    'user-agent': CONFIG.userAgent,
    accept: request.headers.get('accept') || '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
  });
  const cookie = jarHeader(jar);
  if (cookie) headers.set('cookie', cookie);
  const ctype = request.headers.get('content-type');
  if (ctype) headers.set('content-type', ctype);

  const init = { method: request.method, headers, redirect: 'follow', signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs) };
  if (!['GET', 'HEAD'].includes(request.method)) { init.body = request.body; init.duplex = 'half'; }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    return new Response('fetch failed: ' + ((err && err.message) || err), { status: 502, headers: { 'content-type': 'text/plain' } });
  }

  const incoming = getSetCookies(upstream.headers);
  if (incoming.length) {
    jarAbsorb(jar, incoming);
    await jarSave(env, dest.hostname, jar);
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      'content-type': upstream.headers.get('content-type') || 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

/** JSON diagnostics — the client's "Test relay" button uses this. */
async function probe(url, env) {
  const target = url.searchParams.get('url') || 'https://example.com/';
  const started = Date.now();
  const base = {
    relay: 'ok',
    probe_target: target,
    time: new Date().toISOString(),
    blocked: null,
    status: null,
    content_type: null,
    bytes: null,
    ms: null,
    final_url: null,
    cookies_set: 0,
    error: null,
    features: {
      rewrite: true,
      raw_passthrough: true,
      cookie_jar: true,
      sessions_binding: !!(env && env.SESSIONS),
      access_key: !!(env && env.ACCESS_KEY),
    },
  };
  const verdict = await guardTarget(target, env);
  if (verdict) return json({ ...base, blocked: verdict });

  try {
    const res = await fetch(target, {
      headers: { 'user-agent': CONFIG.userAgent, accept: 'text/html,*/*' },
      redirect: 'follow',
      signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs),
    });
    const reader = res.body ? res.body.getReader() : null;
    let bytes = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value ? value.byteLength : 0;
        if (bytes > 200000) { try { await reader.cancel(); } catch {} break; }
      }
    }
    return json({
      ...base,
      status: res.status,
      content_type: res.headers.get('content-type'),
      bytes: bytes >= 200000 ? '≥200000 (truncated)' : bytes,
      ms: Date.now() - started,
      final_url: res.url || null,
      cookies_set: getSetCookies(res.headers).length,
    });
  } catch (err) {
    return json({ ...base, ms: Date.now() - started, error: (err && err.message) || String(err) });
  }
}

/* ==========================================================================
 * 11. Response helpers
 * ========================================================================== */

function json(value) {
  return new Response(JSON.stringify(value, null, 2), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function withCors(response, cookies) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(CONFIG.corsHeaders)) headers.set(k, v);
  for (const c of cookies || []) headers.append('set-cookie', c);
  return new Response(response.body, { status: response.status, headers });
}

function html(body, status, cookies) {
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  for (const c of cookies || []) headers.append('set-cookie', c);
  return new Response(body, { status, headers });
}

const PAGE_STYLE = `
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0c11;color:#e6e9ef;
font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.card{max-width:680px;padding:28px 30px;border:1px solid #262b36;border-radius:16px;background:#11141b;
box-shadow:0 20px 60px rgba(0,0,0,.45);width:calc(100% - 32px);box-sizing:border-box}
h1{margin:0 0 8px;font-size:20px;letter-spacing:-.2px}
p{margin:10px 0;color:#aab2c0;word-break:break-word}
code{background:#1a1f29;padding:2px 6px;border-radius:6px;font:12.5px ui-monospace,Menlo,monospace;color:#dfe5ef}
a{color:#7cc4ff;text-decoration:none}a:hover{text-decoration:underline}
form{display:flex;gap:8px;margin:16px 0 4px;flex-wrap:wrap}
input{flex:1 1 300px;padding:12px 14px;border-radius:10px;border:1px solid #2a3140;background:#141822;color:#e8ebf1;font:inherit}
button{padding:12px 18px;border-radius:10px;border:1px solid #3f6dff;background:linear-gradient(#3f6dff,#2f55e0);
color:#fff;font:600 14px/1 inherit;cursor:pointer}
.ok{display:inline-block;font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:1.2px;color:#8ef0c0;
background:#0f2a20;border:1px solid #1d4f3b;padding:7px 10px;border-radius:999px;margin-bottom:14px}
.muted{color:#6f7888;font-size:13px}
`;

function statusPage(url, env) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>Web Relay</title><style>' + PAGE_STYLE + '</style></head><body><div class="card">'
    + '<span class="ok">● RELAY ONLINE</span>'
    + '<h1>Web Relay</h1>'
    + '<p>Fetching and URL-rewriting is handled here; rendering happens in the client\'s browser. '
    + 'This relay works on its own — it is not the client UI. Point your client at this origin:</p>'
    + '<p><code>' + escapeHtml(url.origin) + '</code></p>'
    + '<form method="get" onsubmit="this.action=\'/__p/\'+btoa(unescape(encodeURIComponent(this.u.value))).replace(/\\+/g,\'-\').replace(/\\//g,\'_\').replace(/=+$/,\'\');return true;">'
    + '<input name="u" value="https://example.com/" spellcheck="false" autocomplete="off">'
    + '<button type="submit">Open proxied</button></form>'
    + '<p class="muted">Endpoints: <code>/__p/&lt;base64url&gt;</code> · <code>/raw?url=</code> · '
    + '<code>/__probe?url=</code> · <code>/__health</code></p>'
    + '<p class="muted">' + (env && env.ACCESS_KEY ? 'Access key: <b>required</b> — append <code>?key=…</code>.' : 'Access key: not set — anyone with this URL can use the relay. Set <code>ACCESS_KEY</code> in your host\'s environment variables to lock it down.')
    + (env && env.SESSIONS ? ' Sessions: persistent (KV binding present).' : ' Sessions: in-memory per isolate.') + '</p>'
    + '</div></body></html>';
}

function errorPage(status, message, target) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>Relay error ' + status + '</title><style>' + PAGE_STYLE + '</style></head><body><div class="card">'
    + '<h1>Relay error ' + status + '</h1>'
    + '<p>' + escapeHtml(message) + '</p>'
    + (target ? '<p class="muted">target: ' + escapeHtml(String(target).slice(0, 300)) + '</p>' : '')
    + '<p><a href="/">Relay status page</a></p>'
    + '</div></body></html>';
}
