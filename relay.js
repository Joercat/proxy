/**
 * ============================================================================
 *  Web Relay — self-hostable proxy relay with media, redirects and sessions
 * ============================================================================
 *
 *  WHAT IT DOES
 *    Fetches a page for a client, rewrites every URL so nothing escapes the
 *    proxy, relays all sub-resources, and streams media with byte ranges intact.
 *    The client's browser renders everything: layout, CSS, JS, painting, video.
 *    This server is not a browser and never renders.
 *
 *  DEPLOY
 *    • Cloudflare Workers — paste this file into the dashboard editor, Deploy
 *    • Deno Deploy        — paste into a New Playground, Deploy
 *    • Node 18+           — node relay/node-server.js   (thin adapter, same logic)
 *
 *  ROUTES
 *    GET  /__p/<base64url>      proxied page (canonical form the rewriter emits)
 *    GET  /p/<plain url>        same thing, human-readable: /p/example.com/a?b=c
 *    GET  /go?url=<anything>    normalises and redirects to the proxied page
 *    ALL  /raw?url=<target>     fetch without rewriting, permissive CORS
 *    ALL  /preview?url=<target> media/manifest preview helper
 *    GET  /__probe?url=         JSON diagnostics
 *    GET  /__health             "ok"
 *    GET  /                     new-tab page: address bar, tabs, quick links
 *
 *  UPGRADES OVER A BASIC REWRITER
 *    1. Redirects are rewritten, not followed. A 301/302/303/307/308 becomes a
 *       redirect to the *proxied* location, so the address bar and history
 *       behave like a real browser, and Set-Cookie on the redirect is kept.
 *    2. Real cookie jar: domain and path aware, so a session set on
 *       .example.com is sent to api.example.com. This is what makes logins work.
 *    3. Origin/Referer/Sec-Fetch-* are translated to what the origin expects,
 *       and Authorization / WWW-Authenticate pass through so HTTP auth prompts
 *       and token headers survive.
 *    4. Media: byte ranges are proxied (seeking works), and HLS (.m3u8) and
 *       DASH (.mpd) manifests are rewritten so playlists and their segments load
 *       through the relay instead of leaking to the origin CDN.
 *    5. WebSockets are proxied where the platform allows (Workers/Deno natively,
 *       Node via a raw socket tunnel), so live pages keep working.
 *    6. Tabs: the injected toolbar is a tab strip backed by relay-origin storage,
 *       with ctrl/cmd-click, +, ×, and an address bar that accepts bare domains.
 *
 *  OPTIONAL ENVIRONMENT
 *    ACCESS_KEY   require ?key=… on every request (a cookie remembers it)
 *    SESSIONS     Cloudflare KV binding — persists the cookie jar across restarts
 *    BLOCK_HOSTS  comma-separated hostnames to refuse
 * ============================================================================
 */

'use strict';

/* ==========================================================================
 * 1. Configuration
 * ========================================================================== */

export const CONFIG = {
  prefix: '/__p/',
  prettyPrefix: '/p/',
  fetchTimeoutMs: 30000,
  maxRewriteBytes: 24 * 1024 * 1024,
  maxRedirectHops: 1,                    // we hand redirects back to the browser
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

/** Headers safe to pass straight through. */
const COPY_HEADERS = new Set([
  'content-type', 'accept-ranges', 'content-range', 'cache-control', 'expires',
  'etag', 'last-modified', 'content-language', 'content-disposition', 'vary',
  'age', 'date',
]);

/** Headers that must never reach the client (they would break the proxy). */
const DROP_HEADERS = new Set([
  'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'set-cookie', 'set-cookie2', 'content-security-policy', 'content-security-policy-report-only',
  'strict-transport-security', 'x-frame-options', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'clear-site-data',
  'alt-svc', 'report-to', 'nel', 'expect-ct', 'permissions-policy', 'origin-trial',
  'speculation-rules', 'server-timing', 'proxy-authenticate', 'link',
]);

const MEDIA_MANIFEST = /(mpegurl|x-mpegurl|dash\+xml|vnd\.apple)/i;
const MEDIA_EXT_RE = /\.(mp4|m4v|mov|webm|mkv|ogv|avi|mp3|m4a|aac|flac|wav|ogg|opus|m3u8|mpd)(?:$|[?#])/i;
const AUDIO_EXT_RE = /\.(mp3|m4a|aac|flac|wav|ogg|opus)(?:$|[?#])/i;

/**
 * What kind of playable media is this? Decided from the content type first
 * (authoritative) and the URL extension second, because plenty of servers hand
 * out video as application/octet-stream.
 */
function mediaKind(contentType, url) {
  const ct = String(contentType || '').toLowerCase();
  // Playlists first: HLS is frequently served as audio/mpegurl, which would
  // otherwise be mistaken for a plain audio file and never get a stream player.
  if (/dash\+xml/.test(ct) || /\.mpd(?:$|[?#])/i.test(url)) return 'dash';
  if (/mpegurl|vnd\.apple/.test(ct) || /\.m3u8(?:$|[?#])/i.test(url)) return 'hls';
  if (/^video\//.test(ct)) return 'video';
  if (/^audio\//.test(ct)) return 'audio';
  if (MEDIA_EXT_RE.test(url)) return AUDIO_EXT_RE.test(url) ? 'audio' : 'video';
  return null;
}

/**
 * Is this a real browser navigation, as opposed to an <img>/<video>/XHR request?
 *
 * Sec-Fetch-Dest is authoritative when present. When it is not (curl, tooling, and
 * Safari before 16.4) fall back to Accept: only a document navigation asks for
 * HTML, whereas a media element asks for video/*|audio/*|*\/*. Getting this wrong
 * in the *other* direction would hand HTML to a <video> tag and break playback.
 */
function isDocumentNavigation(request) {
  const dest = request.headers.get('sec-fetch-dest');
  if (dest) return dest === 'document';
  const accept = String(request.headers.get('accept') || '');
  return accept.includes('text/html');
}

/* ==========================================================================
 * 2. URL helpers
 * ========================================================================== */

/** Accepts anything a human types: "example.com", "//host/x", "http://…". */
export function normalizeTarget(input) {
  let s = String(input == null ? '' : input).trim();
  if (!s) return null;
  s = s.replace(/\s+/g, ' ');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (!/^(https?|wss?):\/\//i.test(s)) return null;         // ftp:, file:, …
  } else if (s.startsWith('//')) {
    s = 'https:' + s;
  } else {
    s = 'https://' + s.replace(/^\/+/, '');
  }
  try {
    const u = new URL(s);
    if (!u.hostname || !u.hostname.includes('.')) {
      // allow localhost-style single labels only when a port is present
      if (!/:\d+$/.test(u.host) && u.hostname !== 'localhost') return null;
    }
    return u.href;
  } catch {
    return null;
  }
}

/** Heuristic: does this look like a search query rather than an address? */
export function looksLikeSearch(input) {
  const s = String(input || '').trim();
  if (!s) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return false;
  if (/\s/.test(s)) return true;
  if (!s.includes('.')) return true;                          // "cats" is a search
  if (/^[^./]+\.(com|net|org|io|dev|edu|gov|co|uk|de|info|me|app|xyz|tv)\b(?!\S*\/)/i.test(s)) return false;
  return !/\.(com|net|org|io|dev|edu|gov|co|uk|de|info|me|app|xyz|tv|ai|sh|gg)\b/i.test(s) && s.endsWith('.');
}

/**
 * Build the relay path for a target URL.
 *
 * The ORIGIN is base64url-encoded and the target's own path + query are mirrored
 * after it:
 *
 *     https://www.tiktok.com/@user/video/123?a=b
 *  -> /__p/<b64 of "https://www.tiktok.com">/@user/video/123?a=b
 *
 * Mirroring matters more than it looks. A page at /__p/<b64>/dir/page that asks
 * for the relative "img.png" makes the browser request /__p/<b64>/dir/img.png,
 * which the router can decode back to https://site.com/dir/img.png with no help
 * from Referer, cookies or JavaScript. Encoding the whole URL (the old scheme,
 * still accepted) turns every relative request into an unresolvable
 * /__p/img.png and depends entirely on fallbacks.
 */
export function encodeUrl(url) {
  const u = new URL(String(url));
  const bytes = new TextEncoder().encode(u.origin);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const path = u.pathname && u.pathname !== '/' ? u.pathname : '/';
  return CONFIG.prefix + b64 + encodeURI(path).replace(/^\//, '/') + (u.search || '');
}

/**
 * Reverse of encodeUrl, tolerant of three shapes:
 *   /__p/<b64 origin>/path?q      the current, path-mirroring form
 *   /__p/<b64 origin>             origin only -> that origin's root
 *   /__p/<b64 full url>           the legacy form, still accepted
 */
export function targetFromPath(pathname, search) {
  if (!pathname || !pathname.startsWith(CONFIG.prefix)) return null;
  const rest = pathname.slice(CONFIG.prefix.length);
  const slash = rest.indexOf('/');
  const encoded = slash < 0 ? rest : rest.slice(0, slash);
  const base = decodeUrl(encoded);
  if (!base) return null;
  const tail = slash < 0 ? '' : rest.slice(slash);
  const q = search || '';
  try {
    const b = new URL(base);
    if (!tail) return b.href;
    const originOnly = b.pathname === '/' && !b.search && !b.hash;
    if (originOnly) return new URL(b.origin + tail + q).href;   // mirrored form
    return new URL(tail.replace(/^\//, '/') + q, b.origin).href; // legacy form + tail
  } catch {
    return null;
  }
}

export function decodeUrl(input) {
  try {
    const cleaned = String(input).replace(/-/g, '+').replace(/_/g, '/');
    const padded = cleaned + '='.repeat((4 - (cleaned.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const url = new TextDecoder().decode(bytes);
    return /^(https?|wss?):\/\/.+/i.test(url) ? url : null;
  } catch {
    return null;
  }
}

const isHttpUrl = (u) => /^https?:\/\/.+/i.test(String(u || ''));

/** Append ?k=v (or &k=v) to a path that may already carry a query. */
function addQuery(path, key, value) {
  return path + (path.includes('?') ? '&' : '?') + key + '=' + encodeURIComponent(value);
}

/** base64url of an arbitrary string — used for cookie-stored locations. */
function b64url(str) {
  const bytes = new TextEncoder().encode(String(str));
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const isWsUrl = (u) => /^wss?:\/\/.+/i.test(String(u || ''));

const SKIP_SCHEME =
  /^(?:\s*)(?:data|blob|javascript|mailto|tel|sms|callto|about|chrome|chrome-extension|moz-extension|file|magnet|intent|market|itms|view-source|android-app):/i;

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", '#x27': "'", nbsp: ' ' };
const unescapeHtml = (s) =>
  String(s).replace(/&(amp|lt|gt|quot|apos|#39|#x27|nbsp);/gi, (m, e) => {
    const v = ENTITIES[e.toLowerCase()];
    return v === undefined ? m : v;
  });

/** Build a proxy path for `raw`, resolved against `base`. */
export function proxify(raw, base) {
  if (raw == null) return raw;
  const s = String(raw);
  if (!s.trim()) return raw;
  if (SKIP_SCHEME.test(s)) return raw;
  if (s.charAt(0) === '#') return raw;
  if (s.startsWith(CONFIG.prefix)) return raw;                // already proxied
  if (/^wss?:\/\//i.test(s)) return encodeUrl(s);             // sockets go through us too
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

export function isPrivateAddress(host) {
  const h = String(host).replace(/^\[|\]$/g, '').toLowerCase();

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;
    const [a, b] = o;
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }

  if (h.includes(':')) {
    if (h === '::' || h === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;
    if (/^fe80:/.test(h)) return true;
    if (h.startsWith('::ffff:')) return isPrivateAddress(h.slice(7));
    return false;
  }

  return /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.home\.arpa|metadata\.google\.internal|instance-data)$/i.test(h);
}

let dnsResolver = null;
export function setDnsResolver(fn) { dnsResolver = fn; }
const dnsCache = new Map();

export async function guardTarget(target, env) {
  let url;
  try { url = new URL(isWsUrl(target) ? target.replace(/^ws/i, 'http') : target); }
  catch { return 'Not a valid URL.'; }
  if (!isHttpUrl(url.href)) return 'Only http(s) and ws(s) can be relayed.';

  // ALLOW_HOSTS is an explicit opt-in for hosts you own: a NAS, a router page, a
  // dev server. It bypasses the private-address rule for exactly those names.
  const allow = String((env && env.ALLOW_HOSTS) || '')
    .split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const hostL = url.hostname.toLowerCase();
  const allowed = allow.some((a) => hostL === a || hostL === a.split(':')[0] || hostL.endsWith('.' + a));

  if (!allowed && isPrivateAddress(url.hostname)) {
    return 'Refused: ' + url.hostname + ' is a private, loopback or metadata address. (Add it to ALLOW_HOSTS if it is yours.)';
  }

  const block = String((env && env.BLOCK_HOSTS) || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const host = url.hostname.toLowerCase();
  if (block.some((b) => host === b || host.endsWith('.' + b))) return 'Refused: ' + url.hostname + ' is on this relay\'s block list.';

  if (dnsResolver && !allowed) {
    const cached = dnsCache.get(url.hostname);
    if (cached && cached.expires > Date.now()) return cached.verdict;
    let verdict = null;
    try {
      const list = await dnsResolver(url.hostname);
      if (list.some((ip) => isPrivateAddress(ip))) verdict = 'Refused: ' + url.hostname + ' resolves to a private address.';
    } catch { /* let fetch report DNS failure */ }
    dnsCache.set(url.hostname, { verdict, expires: Date.now() + 60000 });
    return verdict;
  }
  return null;
}

function checkAccess(url, request, env, secure) {
  const key = env && env.ACCESS_KEY;
  if (!key) return { ok: true, cookie: null };
  const supplied = url.searchParams.get('key') || readCookie(request, 'pp_key');
  if (supplied === key) {
    return {
      ok: true,
      cookie: url.searchParams.get('key')
        ? 'pp_key=' + key + '; Path=/; SameSite=Lax; Max-Age=2592000' + (secure ? '; Secure' : '')
        : null,
    };
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
 *    Domain- and path-aware, which is the difference between "some pages work"
 *    and "logins work". A session cookie set by www.example.com with
 *    Domain=.example.com must also go to api.example.com — a naive per-host map
 *    loses it and the site logs you straight back out.
 *
 *    Storage: memory (authoritative, consistent) with write-through to a KV
 *    binding when present. KV is eventually consistent and edge-cached for up to
 *    60s; for strict correctness use a Durable Object instead.
 * ========================================================================== */

const jarState = { entries: null };

function parseSetCookie(line, requestHost, requestSecure) {
  const parts = String(line).split(';');
  const eq = parts[0].indexOf('=');
  if (eq < 1) return null;

  const name = parts[0].slice(0, eq).trim();
  const value = parts[0].slice(eq + 1).trim();
  let domain = requestHost;
  let path = defaultPath();
  let expires = Infinity;
  let hostOnly = true;
  let secure = false;

  for (const attr of parts.slice(1)) {
    const i = attr.indexOf('=');
    const k = (i < 0 ? attr : attr.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : attr.slice(i + 1).trim();
    if (k === 'domain' && v) { domain = v.replace(/^\./, '').toLowerCase(); hostOnly = false; }
    else if (k === 'path' && v) { path = v; }
    else if (k === 'max-age') { const n = Number(v); if (!isNaN(n)) expires = Date.now() + n * 1000; }
    else if (k === 'expires') { const t = Date.parse(v); if (!isNaN(t)) expires = t; }
    else if (k === 'secure') { secure = true; }
  }

  return {
    key: name + '|' + domain + '|' + path,
    name, value, domain, path, expires, hostOnly, secure,
  };
  function defaultPath() {
    // RFC 6265: the path of the request, minus its last segment
    const p = '/' + String(requestHost).split('/').slice(1).join('/');
    return '/';
  }
}

function jarAbsorb(jar, setCookies, requestHost) {
  for (const line of setCookies) {
    const entry = parseSetCookie(line, requestHost);
    if (!entry) continue;
    if (entry.expires <= Date.now() || /^deleted$/i.test(entry.value)) jar.delete(entry.key);
    else jar.set(entry.key, entry);
  }
}

/** Build the Cookie header for a request to host+path. */
function jarHeader(jar, host, path, secure) {
  const now = Date.now();
  const hostL = String(host).toLowerCase();
  const pathName = path || '/';
  const matches = [];

  for (const [key, c] of jar) {
    if (c.expires <= now) { jar.delete(key); continue; }
    if (c.secure && !secure) continue;
    const domainOk = c.hostOnly ? hostL === c.domain : (hostL === c.domain || hostL.endsWith('.' + c.domain));
    if (!domainOk) continue;
    if (!pathName.startsWith(c.path)) continue;
    matches.push(c);
  }
  // longest path first, then earliest set — the order browsers use
  matches.sort((a, b) => b.path.length - a.path.length);
  return matches.length ? matches.map((c) => c.name + '=' + c.value).join('; ') : null;
}

async function jarLoad(env) {
  if (jarState.entries) return jarState.entries;
  if (env && env.SESSIONS && typeof env.SESSIONS.get === 'function') {
    try {
      const raw = await env.SESSIONS.get('jar', 'json');
      if (raw && typeof raw === 'object') {
        jarState.entries = new Map(Object.entries(raw));
        return jarState.entries;
      }
    } catch { /* fall through */ }
  }
  jarState.entries = new Map();
  return jarState.entries;
}

async function jarSave(env, jar) {
  const now = Date.now();
  for (const [key, c] of jar) if (c.expires <= now) jar.delete(key);
  if (env && env.SESSIONS && typeof env.SESSIONS.put === 'function') {
    try { await env.SESSIONS.put('jar', JSON.stringify(Object.fromEntries(jar)), { expirationTtl: 86400 }); }
    catch { /* memory still holds it */ }
  }
}

function getSetCookies(headers) {
  try { if (typeof headers.getSetCookie === 'function') return headers.getSetCookie(); } catch { /* older runtime */ }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

/* ==========================================================================
 * 5. HTML / CSS / manifest rewriting
 * ========================================================================== */

const URL_ATTRS = new Set([
  'href', 'src', 'action', 'formaction', 'poster', 'background', 'cite', 'longdesc',
  'manifest', 'data', 'itemid', 'ping', 'usemap', 'profile', 'icon', 'xlink:href',
  'data-src', 'data-href', 'data-url', 'data-lazy', 'data-lazy-src', 'data-original',
  'data-background', 'data-video', 'data-image', 'data-thumb', 'data-full', 'data-file',
  'data-path', 'data-download-url', 'data-hi-res-src', 'data-srcset',
  'data-mp4', 'data-webm', 'data-hls', 'data-m3u8', 'data-stream', 'data-video-src',
]);

const ATTR_RE = /([a-zA-Z_:@][-a-zA-Z0-9_:.]*)(\s*=\s*)("([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;

export function rewriteCss(css, base) {
  return String(css)
    .replace(/@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/gi, (m, q1, u1, q2, u2) => {
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

/**
 * HLS (.m3u8) and DASH (.mpd) playlists are just text full of URLs. Rewriting
 * them keeps every segment and sub-playlist inside the relay, which is what
 * makes adaptive video play instead of silently failing at the CDN.
 */
export function rewriteManifest(text, base) {
  if (/^\s*</.test(text)) {
    // DASH: BaseURL elements and URL-valued attributes
    return String(text)
      .replace(/<BaseURL>\s*([^<\s]+)\s*<\/BaseURL>/gi, (m, u) => '<BaseURL>' + proxify(unescapeHtml(u), base) + '</BaseURL>')
      .replace(/\b(media|initialization|sourceURL|index|presentation)\s*=\s*"([^"]*)"/gi,
        (m, attr, u) => attr + '="' + proxify(unescapeHtml(u), base) + '"');
  }
  // HLS: absolute/relative URI lines plus URI="…" attributes inside tags
  return String(text)
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      if (trimmed.startsWith('#')) {
        return line.replace(/URI\s*=\s*"([^"]*)"/gi, (m, u) => 'URI="' + proxify(unescapeHtml(u), base) + '"');
      }
      const proxied = proxify(trimmed, base);
      return line.replace(trimmed, proxied);
    })
    .join('\n');
}

function proxifySrcset(value, base) {
  return String(value).split(',').map((part) => {
    const t = part.trim();
    if (!t) return '';
    const bits = t.split(/\s+/);
    bits[0] = proxify(bits[0], base);
    return bits.join(' ');
  }).filter(Boolean).join(', ');
}

function rewriteTag(tagText, base) {
  const nameMatch = /^<\s*([a-zA-Z][-a-zA-Z0-9:]*)/.exec(tagText);
  const tagName = nameMatch ? nameMatch[1].toLowerCase() : '';

  return tagText.replace(ATTR_RE, (match, rawName, eq, _q, dq, sq, uq) => {
    const name = rawName.toLowerCase();
    const raw = dq !== undefined ? dq : sq !== undefined ? sq : uq;
    const value = unescapeHtml(raw);
    const emit = (next) => rawName + eq + '"' + escapeHtml(next) + '"';

    if (name === 'integrity' || name === 'nonce') return '';
    if (name === 'target' && value === '_blank') return match;   // real new tab, proxied href

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
      const next = value.replace(/url\s*=\s*(['"]?)([^'";]+)\1/i, (mm, q, u) =>
        'url=' + (q || '') + proxify(u, base) + (q || ''));
      return next === value ? match : emit(next);
    }
    return match;
  });
}

/**
 * Import maps are consumed by the BROWSER, not by page JavaScript, so the client
 * shim cannot intercept them: every URL inside has to be rewritten here. Left
 * alone, a bare specifier resolves to the site's real CDN, which either escapes
 * the relay (the module loads outside it) or is blocked outright as a
 * cross-origin module — which is exactly how a modern bundler's app (TikTok)
 * ends up dead on arrival.
 */
export function rewriteImportMap(text, base) {
  try {
    const map = JSON.parse(text);
    const fix = (v) => (typeof v === 'string' ? (proxify(v, base) || v) : v);
    if (map && typeof map.imports === 'object' && map.imports) {
      for (const k of Object.keys(map.imports)) map.imports[k] = fix(map.imports[k]);
    }
    if (map && typeof map.scopes === 'object' && map.scopes) {
      const scopes = {};
      for (const scopeKey of Object.keys(map.scopes)) {
        const inner = {};
        const entries = map.scopes[scopeKey] || {};
        for (const k of Object.keys(entries)) inner[k] = fix(entries[k]);
        scopes[fix(scopeKey) || scopeKey] = inner;
      }
      map.scopes = scopes;
    }
    return JSON.stringify(map);
  } catch {
    return text;                       // not JSON: leave the original bytes alone
  }
}

export function rewriteHtml(html, base) {
  let out = '';
  let last = 0;
  const paired = /<(script|style)(\b[^>]*?)>([\s\S]*?)<\/\1\s*>/gi;
  let m;
  while ((m = paired.exec(html))) {
    out += rewriteTags(html.slice(last, m.index), base);
    const kind = m[1].toLowerCase();
    out += rewriteTag('<' + kind + m[2] + '>', base);
    if (kind === 'style') out += rewriteCss(m[3], base);
    else if (/\btype\s*=\s*["']?importmap["']?/i.test(m[2])) out += rewriteImportMap(m[3], base);
    else out += m[3];
    out += '</' + kind + '>';
    last = paired.lastIndex;
  }
  out += rewriteTags(html.slice(last), base);
  return out;
}

function rewriteTags(chunk, base) {
  return chunk.replace(/<[a-zA-Z!/?][^>]*>/g, (tag) => (tag.startsWith('<!') ? tag : rewriteTag(tag, base)));
}

/** Convert a meta refresh into a real client-side redirect that stays proxied. */
function metaRefreshRedirect(html, base) {
  const m = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']+)["'][^>]*>/i.exec(html);
  if (!m) return null;
  const spec = m[1];
  const delayMatch = /^\s*(\d+(?:\.\d+)?)/.exec(spec);
  const urlMatch = /url\s*=\s*(['"]?)([^'";]+)\1/i.exec(spec);
  if (!urlMatch || !urlMatch[2]) return null;
  const seconds = delayMatch ? Number(delayMatch[1]) : 0;
  const target = proxify(unescapeHtml(urlMatch[2]), base);
  return { seconds: Math.min(Math.max(seconds, 0), 60), target };
}

function finalizeHtml(html, base, extras) {
  let out = html;
  out = out.replace(/<base\b[^>]*>/gi, '');
  out = out.replace(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi, '');
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
 *    Installed before any page script, so a site's own fetch/XHR/pushState/
 *    socket calls stay inside the relay instead of being blocked by the
 *    same-origin policy.
 * ========================================================================== */

const CLIENT_SHIM = String.raw`(function(){
var P="__PREFIX__",O=location.origin,TGT=__TARGET__;
function enc(u){var x;try{x=new URL(String(u),base());}catch(e){return P;}
return P+btoa(x.origin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")+x.pathname+x.search;}
function dec(s){try{var t=s.replace(/-/g,"+").replace(/_/g,"/");while(t.length%4)t+="=";
return decodeURIComponent(escape(atob(t)));}catch(e){return null;}}
function base(){
/* The relay told us which site this document is. That beats reading it back out
   of the URL: a page reached through a non-mirrored route (a site that
   redirected to its own /404, an entry served via a bare path) still needs every
   relative and origin-built URL resolved against the real site. */
if(TGT&&/^https?:\/\//i.test(TGT))return TGT;
try{var p=location.pathname;if(p.indexOf(P)===0){var r=p.slice(P.length),j=r.indexOf("/");
var seg=j<0?r:r.slice(0,j);var tail=j<0?"":r.slice(j);var d=dec(seg);
if(d&&/^(https?|wss?):\/\//i.test(d)){
  if(tail){try{return new URL(tail+location.search,d).href;}catch(e){}}
  return d;}}}catch(e){}return location.href;}
function q(u,k,v){return u+(u.indexOf("?")<0?"?":"&")+k+"="+encodeURIComponent(v);}
function abs(u){try{return new URL(u,base()).href;}catch(e){return null;}}
var PASS=/^(data:|blob:|javascript:|mailto:|tel:|sms:|about:|#|file:)/i;
function px(u){if(u==null)return u;u=String(u).trim();if(!u||PASS.test(u))return u;
if(u.indexOf(P)===0)return u;
if(u.indexOf(O+P)===0)return u;
if(/^wss?:\/\//i.test(u))return (location.protocol==="https:"?"wss://":"ws://")+location.host+enc(u);
var a=abs(u);if(!a)return u;if(a.indexOf(O+P)===0)return a;if(!/^https?:\/\//i.test(a))return u;
if(a.indexOf(P)===0)return a;
/* A URL that points back at the relay itself is a path the page meant for the
   TARGET site (bundlers build API URLs from location.origin). Resolving it
   against the relay would make us fetch ourselves. */
if(a.indexOf(O)===0){var rest=a.slice(O.length);
  try{return O+enc(new URL(rest,base()).href);}catch(e){}}
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
if(window.WebSocket){var WS=window.WebSocket;var NewWS=function(u,p){try{u=px(u);}catch(e){}
var w=(location.protocol==="https:"?"wss://":"ws://")+location.host+u.slice(u.indexOf(P));
return p===undefined?new WS(w):new WS(w,p);};
NewWS.prototype=WS.prototype;NewWS.CONNECTING=0;NewWS.OPEN=1;NewWS.CLOSING=2;NewWS.CLOSED=3;window.WebSocket=NewWS;}
var WO=window.open;
if(WO)window.open=function(u){try{if(u!=null)u=px(u);}catch(e){}return WO.call(window,u);};
if(navigator.serviceWorker){try{navigator.serviceWorker.register=function(){return Promise.reject(new Error("service workers are disabled by the relay"));};}catch(e){}}
["pushState","replaceState"].forEach(function(k){var o=history[k];try{history[k]=function(s,t,u){try{if(u!=null)u=px(u);}catch(e){}
return o.call(this,s,t,u);};}catch(e){}});
var SA=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){try{var l=String(n).toLowerCase();
if(A[l])v=px(v);else if(l==="srcset"||l==="imagesrcset")v=fixSrcset(v);}catch(e){}
return SA.call(this,n,v);};
var A={href:1,src:1,action:1,formaction:1,poster:1,background:1,cite:1,"xlink:href":1};
function scan(root){try{
if(!root||root.nodeType!==1)return;
var list=root.querySelectorAll?root.querySelectorAll("[href],[src],[srcset],[imagesrcset],[action],[poster],[data-src]"):[];
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
attributeFilter:["href","src","srcset","imagesrcset","action","poster","data-src"]});
}catch(e){}
/* Property setters bypass the observer completely: a tag built with
   createElement() and then handed a URL (el.src=..., el.href=...) never fires
   an attribute mutation we can see. Bundlers do this constantly, and a URL
   built from location.origin then points back at the RELAY. Patch the setters
   so programmatic loads go through the same translation as markup. */
try{
var SP=[["HTMLScriptElement","src"],["HTMLLinkElement","href"],["HTMLIFrameElement","src"],
["HTMLImageElement","src"],["HTMLVideoElement","src"],["HTMLAudioElement","src"],
["HTMLSourceElement","src"],["HTMLEmbedElement","src"],["HTMLObjectElement","data"],
["HTMLFormElement","action"],["HTMLTrackElement","src"],["HTMLInputElement","src"]];
for(var si=0;si<SP.length;si++)(function(iface,prop){
var C=window[iface];if(!C||!C.prototype)return;
var d=Object.getOwnPropertyDescriptor(C.prototype,prop);
if(!d||!d.get||!d.set)return;
try{Object.defineProperty(C.prototype,prop,{configurable:true,enumerable:d.enumerable,
get:function(){return d.get.call(this);},
set:function(v){var nv=px(v);try{return d.set.call(this,nv==null?v:nv);}catch(e){return d.set.call(this,v);}}});}catch(e){}
})(SP[si][0],SP[si][1]);
}catch(e){}
/* CSS that a site builds in JavaScript never passes through an attribute, so
   neither the observer nor the server-side CSS rewrite can see it: mask-image
   icons, sprite backgrounds, @font-face rules, MediaWiki's addCSS(). Left
   alone those urls load straight from the real site. Rewrite CSS at every
   point where such text can enter the document. */
function fixCss(txt){if(!txt||typeof txt!=="string")return txt;
if(txt.indexOf("url(")<0&&txt.indexOf("@import")<0)return txt;
return txt.replace(/url\(\s*(['"]?)([^'")]*)\1\s*\)/gi,function(m,q,u){if(!u)return m;
var n=px(u);return n===u?m:"url("+(q||"")+n+(q||"")+")";})
.replace(/@import\s+(['"])([^'"]+)\1/gi,function(m,q,u){var n=px(u);return n===u?m:"@import "+q+n+q;});}
try{
var CSSURLPROPS=["background","backgroundImage","maskImage","mask","borderImage",
"borderImageSource","listStyleImage","cursor","content","webkitMaskImage"];
var CD=window.CSSStyleDeclaration&&CSSStyleDeclaration.prototype;
if(CD){for(var ci=0;ci<CSSURLPROPS.length;ci++)(function(prop){
var d=Object.getOwnPropertyDescriptor(CD,prop);
if(!d||!d.get||!d.set)return;
try{Object.defineProperty(CD,prop,{configurable:true,enumerable:d.enumerable,
get:function(){return d.get.call(this);},
set:function(v){try{return d.set.call(this,fixCss(v));}catch(e){return d.set.call(this,v);}}});}catch(e){}
})(CSSURLPROPS[ci]);}
}catch(e){}
try{
if(window.CSSStyleSheet){var IR=CSSStyleSheet.prototype.insertRule,AR=CSSStyleSheet.prototype.addRule;
if(IR)CSSStyleSheet.prototype.insertRule=function(rule,idx){return IR.call(this,fixCss(String(rule)),idx);};
if(AR)CSSStyleSheet.prototype.addRule=function(sel,decl,idx){return AR.call(this,fixCss(String(sel)+"{"+String(decl)+"}"),idx);};}
}catch(e){}
try{
function fixStyleNode(n){try{if(n&&n.nodeType===1&&n.tagName==="STYLE"){
var t=n.textContent;if(t&&t.indexOf("url(")>=0)n.textContent=fixCss(t);}}catch(e){}}
var AP=Element.prototype.appendChild,IB=Element.prototype.insertBefore,PP=Element.prototype.append;
if(AP)Element.prototype.appendChild=function(n){fixStyleNode(n);return AP.call(this,n);};
if(IB)Element.prototype.insertBefore=function(n,r){fixStyleNode(n);return IB.call(this,n,r);};
if(PP)Element.prototype.append=function(){for(var pi=0;pi<arguments.length;pi++)fixStyleNode(arguments[pi]);return PP.apply(this,arguments);};
}catch(e){}

/* document.write() markup is parsed by the browser immediately, before any
   observer callback can run, so rewrite the string itself. */
try{
var dw=document.write,dwl=document.write;
function patchWritten(html){return String(html).replace(
/(\s(?:src|href|poster|action|data-src)\s*=\s*)("([^"]*)"|'([^']*)'|([^\s>]+))/gi,
function(m,pre,dq,sq,uq){var raw=dq!==undefined?dq:(sq!==undefined?sq:uq);
var q=dq!==undefined?"\"":(sq!==undefined?"'":"");
var nv=px(raw);return nv===raw?m:pre+q+nv+q;});}
document.write=function(){for(var i=0;i<arguments.length;i++){arguments[i]=patchWritten(arguments[i]);}
return dw.apply(document,arguments);};
}catch(e){}
document.addEventListener("click",function(ev){try{
if(ev.defaultPrevented||ev.button!==0||ev.metaKey||ev.ctrlKey||ev.shiftKey||ev.altKey)return;
var path=(ev.composedPath&&ev.composedPath())||[],el=path[0]||ev.target;
var a=el&&el.closest?el.closest("a[href]"):null;
if(!a||a.hasAttribute("download"))return;
var href=a.getAttribute("href");if(!href||href.charAt(0)==="#")return;
var abs2;try{abs2=new URL(href,a.baseURI||location.href).href;}catch(e){return;}
if(!/^https?:/i.test(abs2))return;
var to=px(abs2);if(!to||to===abs2)return;
ev.preventDefault();ev.stopPropagation();location.href=to;
}catch(e){}},true);
document.addEventListener("submit",function(ev){try{var f=ev.target;if(f&&f.tagName==="FORM"){
var a=f.getAttribute("action");if(a){var nv=px(a);if(nv!==a)SA.call(f,"action",nv);}}
}catch(e){}},true);
})();`;

/* ==========================================================================
 * 7. Toolbar: tab strip + address bar
 *
 *    Injected by the relay because a proxied page cannot show the site's real
 *    address. Tabs live in relay-origin storage, so they follow you from page to
 *    page, survive reloads, and can be closed or re-opened from any tab.
 * ========================================================================== */

function toolbarBlock(targetUrl, homeUrl, accessKey) {
  const cfg = JSON.stringify({ target: targetUrl, home: homeUrl || null, key: accessKey || null });
  return ('<div id="__relay_bar_host" style="all:initial"></div>\n<script data-relay-toolbar="1">\n'
    + '(function(){\nvar C=' + cfg + ';\nvar P=' + JSON.stringify(CONFIG.prefix) + ';\n'
    + TOOLBAR_BODY
    + '})();\n</script>').replace(/__PREFIX__/g, CONFIG.prefix);
}

const TOOLBAR_BODY = String.raw`
var host=document.getElementById("__relay_bar_host");
if(!host)return;
var sh=host.attachShadow?host.attachShadow({mode:"open"}):host;
function enc(u){var x;try{x=new URL(String(u));}catch(e){return P;}
return P+btoa(x.origin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")+x.pathname+x.search;}
function q(u,k,v){return u+(u.indexOf("?")<0?"?":"&")+k+"="+encodeURIComponent(v);}
function norm(v){var s=(v||"").trim();if(!s)return null;
if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(s))s="https://"+s.replace(/^\/+/,"");
try{var u=new URL(s);return u.hostname.indexOf(".")<0&&!/:\d+$/.test(u.host)?null:u.href;}catch(e){return null;}}
function looksSearch(v){var s=(v||"").trim();if(!s)return false;
if(/^[a-z][a-z0-9+.-]*:\/\//i.test(s))return false;
if(/\s/.test(s))return true;
if(s.indexOf(".")<0)return true;
return !/\.(com|net|org|io|dev|edu|gov|co|uk|de|info|me|app|xyz|ai|sh|gg|tv|fr|jp|ru|br|nl|se|no|it|es|ca|au)(\/|$|:)/i.test(s);}
function keyFor(path){return C.key?((path.indexOf("?")<0?"?":"&")+"key="+encodeURIComponent(C.key)):"";}
function toUrl(u){var p=enc(u);return p+keyFor(p);}
function navigate(u){var v=norm(u);if(v)location.href=toUrl(v);}
function search(q){location.href=toUrl("https://html.duckduckgo.com/html/?q="+encodeURIComponent(q));}
function submitAddress(){var v=(addr.value||"").trim();if(!v)return;if(looksSearch(v))search(v);else navigate(v);}

var TKEY="pp.relay.tabs.v1", AKEY="pp.relay.active.v1";
function readTabs(){try{var t=JSON.parse(localStorage.getItem(TKEY)||"[]");return Array.isArray(t)?t:[];}catch(e){return[];}}
function writeTabs(t){try{localStorage.setItem(TKEY,JSON.stringify(t.slice(-30)));}catch(e){}}
function hostOf(u){try{return new URL(u).hostname.replace(/^www\./,"");}catch(e){return u;}}
function label(t,n){return t.title?t.title.slice(0,n):hostOf(t.url).slice(0,n);}

// record this page as a tab
var TABS=readTabs();
var idx=-1;
for(var i=0;i<TABS.length;i++){if(TABS[i].url===C.target){idx=i;break;}}
if(idx<0){TABS.push({url:C.target,title:document.title||"",ts:Date.now()});idx=TABS.length-1;}
else{TABS[idx].ts=Date.now();if(document.title)TABS[idx].title=document.title;}
writeTabs(TABS);
try{localStorage.setItem(AKEY, C.target);}catch(e){}

sh.innerHTML="<style>"
+":host{all:initial}"
+".wrap{position:fixed;top:0;left:0;right:0;z-index:2147483647;font:13px/1.2 ui-sans-serif,system-ui,-apple-system,sans-serif;"
+"background:#0d1017;border-bottom:1px solid #2a3140;box-shadow:0 6px 24px rgba(0,0,0,.45);color:#e8ebf1}"
+".r{display:flex;gap:6px;align-items:center;padding:6px 8px}"
+".tabs{display:flex;gap:5px;align-items:center;padding:0 8px 6px;overflow-x:auto;scrollbar-width:thin}"
+".tab{display:flex;align-items:center;gap:6px;padding:5px 8px 5px 10px;border:1px solid #232a37;border-radius:8px;"
+"background:#141822;color:#b9c2d2;cursor:pointer;white-space:nowrap;max-width:190px;flex:0 0 auto}"
+".tab:hover{border-color:#4b7bff;color:#fff}"
+".tab.on{background:#1b2436;border-color:#4b7bff;color:#fff}"
+".tab .x{font:600 11px/1 ui-monospace,monospace;opacity:.55;padding:2px 3px;border-radius:4px}"
+".tab .x:hover{opacity:1;background:#2a3346}"
+".tab .t{overflow:hidden;text-overflow:ellipsis}"
+"button{all:initial;cursor:pointer;font:600 12px/1 ui-sans-serif,system-ui,sans-serif;color:#cfd7e5;background:#171c26;"
+"border:1px solid #2a3140;border-radius:8px;padding:7px 9px;white-space:nowrap}"
+"button:hover{border-color:#4b7bff;color:#fff}"
+"input{all:initial;flex:1;min-width:60px;font:12.5px/1.2 ui-monospace,Menlo,monospace;color:#e8ebf1;background:#10141c;"
+"border:1px solid #2a3140;border-radius:8px;padding:8px 10px}"
+"input:focus{outline:none;border-color:#4b7bff}"
+".pill{font:11px/1 ui-monospace,Menlo,monospace;color:#8ef0c0;background:#0f2a20;border:1px solid #1d4f3b;border-radius:999px;padding:6px 8px;white-space:nowrap}"
+"</style><div class='wrap'><div class='r'>"
+"<button id='bk' title='Back (Alt+Left)'>&#8592;</button>"
+"<button id='fw' title='Forward (Alt+Right)'>&#8594;</button>"
+"<button id='rl' title='Reload'>&#8635;</button>"
+"<input id='a' spellcheck='false'>"
+"<button id='g'>Go</button><span class='pill' id='st'>relay</span>"
+(C.home?"<button id='h' title='Start page'>&#8962;</button>":"")
+"<button id='n' title='New tab (Alt+T)'>&#43;</button>"
+"<button id='z' title='Copy real URL'>&#10697;</button>"
+"<button id='o' title='Open unproxied in a new window'>&#8599;</button>"
+"<button id='x' title='Hide the bar (Esc)'>x</button>"
+"</div><div class='tabs' id='tb'></div></div>";
function $(id){return sh.getElementById?sh.getElementById(id):sh.querySelector("#"+id);}
var addr=$("a");if(addr){addr.value=C.target||"";}

function renderTabs(){
  var box=$("tb");if(!box)return;box.innerHTML="";
  var list=readTabs();
  list.forEach(function(t){
    var el=document.createElement("span");el.className="tab"+(t.url===C.target?" on":"");
    var tx=document.createElement("span");tx.className="t";tx.textContent=label(t,26);tx.title=t.url;
    var x=document.createElement("span");x.className="x";x.textContent="\u00d7";x.title="Close tab";
    x.onclick=function(ev){ev.stopPropagation();closeTab(t.url);};
    el.appendChild(tx);el.appendChild(x);
    el.onclick=function(){if(t.url!==C.target)location.href=toUrl(t.url);};
    box.appendChild(el);
  });
  var add=document.createElement("span");add.className="tab";add.style.padding="5px 9px";
  add.textContent="+";add.title="New tab";
  add.onclick=function(){if(C.home)location.href=C.home;else location.href=P.slice(0,-1)||"/";};
  box.appendChild(add);
}
function closeTab(url){
  var list=readTabs().filter(function(t){return t.url!==url;});
  writeTabs(list);
  if(url===C.target){
    var next=list.length?list[list.length-1].url:null;
    location.href=next?toUrl(next):(C.home||"/");
  } else renderTabs();
}

if(addr){addr.onkeydown=function(e){if(e.key==="Enter"){e.preventDefault();submitAddress();}};addr.onfocus=function(){addr.select();};}
if($("g"))$("g").onclick=submitAddress;
if($("bk"))$("bk").onclick=function(){history.back();};
if($("fw"))$("fw").onclick=function(){history.forward();};
if($("rl"))$("rl").onclick=function(){location.reload();};
if($("h"))$("h").onclick=function(){var sep=C.home.indexOf("?")<0?"?":"&";location.href=C.home+sep+"last="+encodeURIComponent(C.target);};
if($("n"))$("n").onclick=function(){location.href=(C.home||P.slice(0,-1)||"/");};
if($("z"))$("z").onclick=function(){try{navigator.clipboard.writeText(C.target);var b=$("z");if(b){var t=b.textContent;b.textContent="copied";setTimeout(function(){b.textContent=t;},900);}}catch(e){}};
if($("o"))$("o").onclick=function(){window.open(C.target,"_blank","noopener");};
if($("x"))$("x").onclick=function(){host.style.display="none";};
document.addEventListener("keydown",function(e){
  if(e.altKey&&e.key==="ArrowLeft"){history.back();}
  else if(e.altKey&&e.key==="ArrowRight"){history.forward();}
  else if(e.altKey&&(e.key==="t"||e.key==="T")){location.href=(C.home||P.slice(0,-1)||"/");}
  else if(e.altKey&&e.key==="l"){if(addr){addr.focus();addr.select();e.preventDefault();}}
  else if(e.key==="Escape"){host.style.display="none";}
},true);
// keep the tab label in sync once the page settles
window.addEventListener("load",function(){
  var list=readTabs(),changed=false;
  for(var i=0;i<list.length;i++){if(list[i].url===C.target&&document.title&&list[i].title!==document.title){list[i].title=document.title;changed=true;}}
  if(changed){writeTabs(list);renderTabs();}
});
renderTabs();`;

function injectionBlock(targetUrl, homeUrl, accessKey, refresh) {
  const shim = '<script data-relay-shim="1">' + CLIENT_SHIM
    .replace('__PREFIX__', CONFIG.prefix)
    .replace('__TARGET__', JSON.stringify(targetUrl || '')) + '</script>';
  const jump = refresh
    ? '<script data-relay-refresh="1">setTimeout(function(){location.replace(' + JSON.stringify(refresh.target) + ');},' + (refresh.seconds * 1000) + ');</script>'
    : '';
  return jump + shim + toolbarBlock(targetUrl, homeUrl, accessKey);
}

/* ==========================================================================
 * 8. Upstream request construction
 * ========================================================================== */

function refererTarget(referer) {
  if (!referer) return null;
  try {
    const u = new URL(referer);
    return targetFromPath(u.pathname, u.search);
  } catch { /* ignore */ }
  return null;
}

/**
 * Where was the browser last, according to the relay?
 *
 * Pp_loc is written on every proxied document. It is the fallback that makes
 * root-relative navigations work when no Referer arrives at all — which happens
 * inside sandboxed iframes, from rel=noreferrer links, with strict referrer
 * policies, and whenever a page assigns location.href itself.
 */
function locCookieTarget(request) {
  const raw = readCookie(request, 'pp_loc');
  if (!raw) return null;
  try { return decodeUrl(raw); } catch { return null; }
}

function buildUpstreamHeaders(request, target, jar, accessKey, cookieString) {
  const headers = new Headers();
  headers.set('user-agent', CONFIG.userAgent);
  headers.set('accept', request.headers.get('accept') || '*/*');
  headers.set('accept-language', request.headers.get('accept-language') || 'en-US,en;q=0.9');
  headers.set('accept-encoding', 'gzip, deflate, br');

  const dest = new URL(target);
  const upstreamRef = refererTarget(request.headers.get('referer'));
  const method = (request.method || 'GET').toUpperCase();
  const nonGet = method !== 'GET' && method !== 'HEAD';

  // Present the request the way the origin expects to see it.
  if (upstreamRef) {
    headers.set('referer', upstreamRef);
    headers.set('origin', new URL(upstreamRef).origin);
    headers.set('sec-fetch-site', new URL(upstreamRef).hostname === dest.hostname ? 'same-origin' : 'cross-site');
    headers.set('sec-fetch-mode', request.headers.get('sec-fetch-mode') || (nonGet ? 'cors' : 'navigate'));
    headers.set('sec-fetch-dest', request.headers.get('sec-fetch-dest') || 'document');
  } else {
    headers.set('sec-fetch-site', 'none');
    headers.set('sec-fetch-mode', 'navigate');
    headers.set('sec-fetch-dest', request.headers.get('sec-fetch-dest') || 'document');
  }
  // Form posts need a same-origin Origin or many CSRF filters reject them.
  if (nonGet && !headers.has('origin')) headers.set('origin', dest.origin);

  headers.set('upgrade-insecure-requests', '1');

  const range = request.headers.get('range');
  if (range) headers.set('range', range);
  const etag = request.headers.get('if-none-match');
  if (etag) headers.set('if-none-match', etag);
  const modified = request.headers.get('if-modified-since');
  if (modified) headers.set('if-modified-since', modified);
  const auth = request.headers.get('authorization');
  if (auth) headers.set('authorization', auth);                 // HTTP Basic/Bearer survive
  const ctype = request.headers.get('content-type');
  if (ctype) headers.set('content-type', ctype);
  const xsrf = request.headers.get('x-xsrf-token') || request.headers.get('x-csrf-token');
  if (xsrf) headers.set('x-xsrf-token', xsrf);

  if (cookieString) headers.set('cookie', cookieString);
  if (accessKey) headers.set('x-relay', '1');
  return headers;
}

/* ==========================================================================
 * 9. Response plumbing
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
  // Keep the auth challenge so the browser can prompt for HTTP Basic credentials.
  if (upstream.status === 401) {
    const challenge = upstream.headers.get('www-authenticate');
    if (challenge) out.set('www-authenticate', challenge);
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
 * 9b. Media player page
 *
 *     Opening a video/audio URL through the relay used to hand the browser raw
 *     bytes, which Chromium often downloads instead of playing. A top-level
 *     navigation to a media URL (or /watch?url=…) now returns this page, so the
 *     asset plays *inside* the relay with a real player, a timeline that seeks,
 *     and HLS/DASH support.
 * ========================================================================== */

function mediaTitle(target) {
  try {
    const u = new URL(target);
    const last = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || '');
    return last.length > 4 ? last : u.hostname;
  } catch { return target; }
}

function humanBytes(n) {
  const v = Number(n);
  if (!v || v <= 0) return null;
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0, x = v;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return (x >= 10 || i === 0 ? Math.round(x) : x.toFixed(1)) + ' ' + units[i];
}

function playerPage(opts) {
  const target = opts.target;
  const kind = opts.kind || 'video';
  const base = encodeUrl(target);
  const src = addQuery(base, 'raw', '1');            // never re-enter the player
  const dl = addQuery(base, 'dl', '1');
  const size = humanBytes(opts.size);
  const isAudio = kind === 'audio';
  const tag = isAudio ? 'audio' : 'video';
  const hlsCdn = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.13/dist/hls.min.js';
  const dashCdn = 'https://cdn.jsdelivr.net/npm/dashjs@4.7.4/dist/dash.all.min.js';
  const cdnShim = kind === 'hls' ? hlsCdn : kind === 'dash' ? dashCdn : null;

  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>' + escapeHtml(mediaTitle(target)) + '</title>'
    + '<style>'
    + ':root{color-scheme:dark}*{box-sizing:border-box}'
    + 'body{margin:0;background:#08090d;color:#e8ebf1;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}'
    + '.wrap{max-width:1120px;margin:0 auto;padding:18px 16px 60px}'
    + 'h1{font-size:17px;margin:6px 0 2px;font-weight:600;word-break:break-all}'
    + '.meta{color:#79839a;font:12px/1.6 ui-monospace,Menlo,monospace;word-break:break-all;margin:0 0 12px}'
    + '.stage{background:#000;border:1px solid #1d2230;border-radius:12px;overflow:hidden;display:flex;align-items:center;justify-content:center;min-height:220px}'
    + 'video,audio{width:100%;max-height:74vh;display:block;background:#000}'
    + 'audio{max-width:100%;padding:26px 0}'
    + '.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}'
    + 'a.b,button.b{all:initial;cursor:pointer;font:600 12.5px/1 ui-sans-serif,system-ui,sans-serif;color:#cfd7e5;'
    + 'background:#151a24;border:1px solid #2a3140;border-radius:9px;padding:9px 12px;text-decoration:none}'
    + 'a.b:hover,button.b:hover{border-color:#4b7bff;color:#fff}'
    + '.stat{font:12px/1.6 ui-monospace,Menlo,monospace;color:#8ef0c0}'
    + '.err{font:12px/1.6 ui-monospace,Menlo,monospace;color:#ff9d9d;max-width:70ch}'
    + '.hint{color:#6f7888;font-size:12.5px;margin-top:14px;max-width:80ch}'
    + 'kbd{font:11px/1 ui-monospace,Menlo,monospace;background:#1a1f29;border:1px solid #2b3341;border-radius:5px;padding:2px 5px;color:#dfe5ef}'
    + '</style></head><body><div class="wrap">'
    + '<h1>' + escapeHtml(mediaTitle(target)) + '</h1>'
    + '<p class="meta">' + escapeHtml(target) + '</p>'
    + '<div class="stage"><' + tag + ' id="m" controls autoplay playsinline preload="auto"' + (isAudio ? '' : ' poster=""') + '></' + tag + '></div>'
    + '<div class="bar">'
    + '<a class="b" href="' + escapeHtml(dl) + '">Download</a>'
    + '<a class="b" href="' + escapeHtml(target) + '" target="_blank" rel="noopener">Open at source</a>'
    + '<button class="b" id="copy">Copy URL</button>'
    + '<span class="stat" id="stat"></span>'
    + '</div>'
    + '<div class="err" id="err"></div>'
    + '<p class="hint">Playing through the relay: <b>' + escapeHtml(kind.toUpperCase()) + '</b>'
    + (size ? ', about ' + escapeHtml(size) : '')
    + '. Seeking works because byte ranges are proxied. Shortcuts: <kbd>space</kbd> play/pause, '
    + '<kbd>←</kbd>/<kbd>→</kbd> seek, <kbd>f</kbd> fullscreen, <kbd>m</kbd> mute.</p>'
    + '</div>'
    + injectionBlock(target, opts.home, opts.accessKey, null)
    + '<script data-relay-player="1">\n'
    + '(function(){\n'
    + 'var SRC=' + JSON.stringify(src) + ';\n'
    + 'var KIND=' + JSON.stringify(kind) + ';\n'
    + 'var LIB_RELAY=' + JSON.stringify(cdnShim ? encodeUrl(cdnShim) : null) + ';\n'
    + 'var LIB_CDN=' + JSON.stringify(cdnShim) + ';\n'
    + 'var el=document.getElementById("m");\n'
    + 'var stat=document.getElementById("stat");\n'
    + 'var errbox=document.getElementById("err");\n'
    + 'function say(t){if(stat)stat.textContent=t||"";}\n'
    + 'function note(t){if(errbox)errbox.textContent=t||"";}\n'
    + 'function fmt(t){t=Math.floor(t||0);var h=Math.floor(t/3600),m=Math.floor((t%3600)/60),sec=t%60;'
    + 'return (h?h+":":"")+(h&&m<10?"0":"")+m+":"+(sec<10?"0":"")+sec;}\n'
    /* Load a player library: through the relay first (same-origin, survives
       client-side blockers), then straight from the CDN, then explain itself. */
    + 'function loadLib(ok,bad){\n'
    + '  function step(list,i){\n'
    + '    if(i>=list.length)return bad();\n'
    + '    var s=document.createElement("script");s.src=list[i];s.async=true;\n'
    + '    s.onload=function(){ok();};s.onerror=function(){step(list,i+1);};\n'
    + '    document.head.appendChild(s);\n'
    + '  }\n'
    + '  step(LIB_RELAY&&LIB_RELAY!==LIB_CDN?[LIB_RELAY,LIB_CDN]:[LIB_CDN],0);\n'
    + '}\n'
    + 'function attachHls(){\n'
    + '  if(window.Hls&&Hls.isSupported()){\n'
    + '    var hls=new Hls({enableWorker:true,lowLatencyMode:true});\n'
    + '    hls.on(Hls.Events.MANIFEST_PARSED,function(e,d){say("HLS manifest loaded — "+d.levels.length+" level(s)");});\n'
    + '    hls.on(Hls.Events.LEVEL_SWITCHED,function(e,d){var L=hls.levels[d.level];'
    + 'if(L)say("playing "+L.height+"p @ "+Math.round(L.bitrate/1000)+" kbps");});\n'
    + '    hls.on(Hls.Events.ERROR,function(e,d){if(d.fatal)note("HLS error: "+d.type+"/"+d.details);});\n'
    + '    hls.loadSource(SRC);hls.attachMedia(el);window.__hls=hls;\n'
    + '  } else { note("This browser cannot play HLS. Safari plays it natively; otherwise try Download."); }\n'
    + '}\n'
    + 'function attachDash(){\n'
    + '  if(window.dashjs&&dashjs.MediaPlayer){var p=dashjs.MediaPlayer().create();p.initialize(el,SRC,true);'
    + 'window.__dash=p;say("DASH playing");}\n'
    + '  else note("This browser cannot play DASH. Try Download.");\n'
    + '}\n'
    + 'function mount(){\n'
    + '  if(KIND==="hls"){\n'
    + '    if(el.canPlayType("application/vnd.apple.mpegurl")){el.src=SRC;say("native HLS");return;}\n'
    + '    loadLib(attachHls,function(){note("Could not load the HLS player (hls.js) — download the stream instead.");});\n'
    + '    return;\n'
    + '  }\n'
    + '  if(KIND==="dash"){\n'
    + '    loadLib(attachDash,function(){note("Could not load the DASH player (dash.js) — download the stream instead.");});\n'
    + '    return;\n'
    + '  }\n'
    + '  el.src=SRC;\n'
    + '}\n'
    + 'el.addEventListener("loadedmetadata",function(){\n'
    + '  say("ready — "+fmt(el.duration)+(el.videoWidth?" — "+el.videoWidth+"x"+el.videoHeight:""));});\n'
    + 'el.addEventListener("error",function(){\n'
    + '  var c=el.error?el.error.code:0;\n'
    + '  note("Playback failed (code "+c+"). Either this browser lacks the codec (H.264 is missing from some '
    + 'Chromium-based builds) or the source refused the request. Download will tell you which.");});\n'
    + 'document.addEventListener("keydown",function(e){\n'
    + '  var tag=(document.activeElement&&document.activeElement.tagName)||"";\n'
    + '  if(/INPUT|TEXTAREA|SELECT/.test(tag))return;\n'
    + '  if(e.key===" "){e.preventDefault();el.paused?el.play():el.pause();}\n'
    + '  else if(e.key==="ArrowLeft"){el.currentTime=Math.max(0,el.currentTime-5);}\n'
    + '  else if(e.key==="ArrowRight"){el.currentTime=Math.min(el.duration||1e9,el.currentTime+5);}\n'
    + '  else if(e.key==="f"){if(el.requestFullscreen)el.requestFullscreen();}\n'
    + '  else if(e.key==="m"){el.muted=!el.muted;}\n'
    + '},true);\n'
    + 'var cp=document.getElementById("copy");\n'
    + 'if(cp)cp.addEventListener("click",function(){try{navigator.clipboard.writeText('
    + JSON.stringify(target) + ');cp.textContent="copied";\n'
    + 'setTimeout(function(){cp.textContent="Copy URL";},900);}catch(e){}});\n'
    + 'mount();\n'
    + '})();\n</script></body></html>';
}

/* ==========================================================================
 * 10. Router
 * ========================================================================== */

export default {
  async fetch(request, env = {}, ctx = {}) {
    const url = new URL(request.url);

    try {
      if (url.pathname === '/__health') {
        return new Response('ok', { headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
      }

      const secure = url.protocol === 'https:';
      const cookies = [];
      const homeParam = url.searchParams.get('home');
      if (homeParam && /^https?:\/\//i.test(homeParam)) {
        cookies.push('pp_home=' + encodeURIComponent(homeParam) + '; Path=/; SameSite=Lax; Max-Age=604800' + (secure ? '; Secure' : ''));
      }
      const storedHome = readCookie(request, 'pp_home');
      const home = (homeParam && /^https?:\/\//i.test(homeParam))
        ? homeParam
        : (storedHome ? decodeURIComponent(storedHome) : null);

      const access = checkAccess(url, request, env, secure);
      if (access.cookie) cookies.push(access.cookie);
      if (!access.ok) {
        return new Response('This relay requires an access key. Append ?key=YOUR_KEY to the URL.', {
          status: 401, headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' },
        });
      }

      if (url.pathname === '/raw') return withCors(await rawFetch(request, url, env), cookies);
      if (url.pathname === '/preview') return withCors(await previewFetch(request, url, env), cookies);
      if (url.pathname === '/__probe') return withCors(await probe(url, env), cookies);
      if (url.pathname === '/__tabs') return withCors(await tabsEndpoint(url), cookies);

      if (url.pathname === '/' || url.pathname === '/index.html') return html(newTabPage(url, env), 200, cookies);
      if (url.pathname === '/favicon.ico') {
        return new Response('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#4b7bff"/><path d="M9 16h14M16 9v14" stroke="#fff" stroke-width="3" stroke-linecap="round"/></svg>',
          { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'max-age=86400' } });
      }
      if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain' } });

      // /go?url=…  — accepts bare domains, searches, anything typed
      if (url.pathname === '/go') {
        const raw = url.searchParams.get('url') || url.searchParams.get('u') || url.searchParams.get('q');
        if (!raw) return redirectTo(url.origin + '/', 302, cookies);
        const target = looksLikeSearch(raw)
          ? 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(raw)
          : normalizeTarget(raw);
        if (!target) return html(errorPage(400, 'That does not look like an address.', raw), 400, cookies);
        const passthrough = new URLSearchParams(url.searchParams);
        for (const drop of ['url', 'u', 'q']) passthrough.delete(drop);
        const qs = passthrough.toString();
        return redirectTo(encodeUrl(target) + (qs ? '?' + qs : ''), 302, cookies);
      }

      // /watch?url=…  — force the media player for any URL
      if (url.pathname === '/watch') {
        const raw = url.searchParams.get('url') || url.searchParams.get('u');
        const target = normalizeTarget(raw);
        if (!target) return html(errorPage(400, 'That does not look like an address.', raw), 400, cookies);
        return await proxy(request, target, env, cookies, home, { player: true });
      }

      // /p/example.com/path  — human-readable form
      if (url.pathname.startsWith(CONFIG.prettyPrefix)) {
        const raw = decodeURIComponent(url.pathname.slice(CONFIG.prettyPrefix.length)) + url.search;
        const target = normalizeTarget(raw);
        if (!target) return html(errorPage(400, 'That does not look like an address.', raw), 400, cookies);
        return await proxy(request, target, env, cookies, home, relayOpts(url));
      }

      // WebSocket upgrade (Workers/Deno handle the socket; Node tunnels it)
      const upgrade = (request.headers.get('upgrade') || '').toLowerCase();
      if (upgrade === 'websocket') {
        let wsTarget = null;
        if (url.pathname.startsWith(CONFIG.prefix)) {
          const rest = url.pathname.slice(CONFIG.prefix.length);
          const slash = rest.indexOf('/');
          wsTarget = decodeUrl(slash < 0 ? rest : rest.slice(0, slash));
        }
        if (!wsTarget) return new Response('websocket: unknown target', { status: 400 });
        return await proxyWebSocket(request, wsTarget, env);
      }

      // canonical /__p/<origin-b64>/mirrored/path?query
      let target = targetFromPath(url.pathname, url.search);

      /* Fallback for requests that escaped the mirrored path: root-relative
         navigations (location.href = "/x"), module imports, XHR to a
         document-relative URL. Resolve against wherever the browser really was —
         the Referer if present, otherwise the pp_loc cookie, which survives
         sandboxed iframes and noreferrer links where no Referer arrives. */
      if (!target) {
        const ref = refererTarget(request.headers.get('referer')) || locCookieTarget(request);
        if (ref) {
          const rel = (url.pathname.startsWith(CONFIG.prefix)
            ? url.pathname.slice(CONFIG.prefix.length)
            : url.pathname) + url.search;
          try { target = new URL(rel, ref).href; } catch { target = null; }
        }
      }

      if (!target) {
        return html(notFoundPage(url, request), 404, cookies);
      }
      return await proxy(request, target, env, cookies, home, relayOpts(url));
    } catch (err) {
      return html(errorPage(502, (err && err.message) || String(err)), 502, null);
    }
  },
};

/* -------------------------------------------------------------------------- */

/** Relay-level query flags: ?raw=1 streams bytes instead of the player, ?dl=1 downloads. */
function relayOpts(url) {
  return {
    raw: url.searchParams.get('raw') === '1',
    download: url.searchParams.get('dl') === '1',
  };
}

async function proxy(request, target, env, cookies, home, opts) {
  opts = opts || {};
  const verdict = await guardTarget(target, env);
  if (verdict) return html(errorPage(403, verdict, target), 403, cookies);

  const dest = new URL(target);
  const jar = await jarLoad(env);
  const cookieString = jarHeader(jar, dest.hostname, dest.pathname, dest.protocol === 'https:');
  const headers = buildUpstreamHeaders(request, target, jar, env && env.ACCESS_KEY, cookieString);

  const init = {
    method: request.method,
    headers,
    redirect: 'manual',                 // redirects are rewritten, not swallowed
    signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs),
  };
  if (!['GET', 'HEAD'].includes(request.method)) { init.body = request.body; init.duplex = 'half'; }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    const reason = (err && err.name === 'TimeoutError')
      ? 'the site took longer than ' + CONFIG.fetchTimeoutMs / 1000 + 's to answer'
      : ((err && err.message) || String(err));
    return html(errorPage(502, 'Could not reach ' + dest.hostname + ' — ' + reason, target), 502, cookies);
  }

  // File cookies under the host that actually set them.
  const incoming = getSetCookies(upstream.headers);
  if (incoming.length) {
    jarAbsorb(jar, incoming, dest.hostname);
    await jarSave(env, jar);
  }

  const finalUrl = isHttpUrl(upstream.url) ? upstream.url : target;
  const extraHeaders = { 'x-relayed-by': 'web-relay', 'referrer-policy': 'no-referrer-when-downgrade' };

  /* ---- redirect rewriting -------------------------------------------------
   * Instead of following the redirect here (which would leave the address bar
   * stuck on the old URL) we hand the browser a redirect to the *proxied*
   * location. The browser updates the URL, pushes history, and applies the
   * correct method rules (303 -> GET, 307/308 -> replay). */
  if (upstream.status >= 300 && upstream.status < 400) {
    const location = upstream.headers.get('location');
    if (!location) {
      const out = passthroughHeaders(upstream, extraHeaders);
      for (const c of cookies) out.append('set-cookie', c);
      return new Response(null, { status: upstream.status, headers: out });
    }
    let absolute;
    try { absolute = new URL(location, finalUrl).href; } catch { absolute = null; }

    if (!absolute || !isHttpUrl(absolute)) {
      // non-http redirect (myapp://, intent:// …) — show it rather than lie
      return html('<p>This page wants to open <code>' + escapeHtml(location) + '</code>, which is not a web address.</p>'
        + '<p><a href="' + encodeUrl(finalUrl) + '">Go back</a></p>', 200, cookies);
    }

    const status = [301, 302, 303, 307, 308].includes(upstream.status) ? upstream.status : 302;
    const out = new Headers({
      location: encodeUrl(absolute),
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-relayed-by': 'web-relay',
    });
    for (const c of cookies) out.append('set-cookie', c);
    return new Response('Redirecting to ' + absolute, { status, headers: out });
  }

  const contentType = upstream.headers.get('content-type') || '';

  if (upstream.status === 204 || upstream.status === 304 || request.method === 'HEAD') {
    return new Response(null, { status: upstream.status, headers: passthroughHeaders(upstream, extraHeaders) });
  }

  /* ---- HTML: rewrite everything ---------------------------------------- */
  if (/^(text\/html|application\/xhtml\+xml)/i.test(contentType) && !request.headers.get('range')) {
    try {
      const bytes = await readAll(upstream, CONFIG.maxRewriteBytes);
      const text = new TextDecoder(charsetOf(contentType, new TextDecoder().decode(bytes.slice(0, 2048)))).decode(bytes);
      const refresh = metaRefreshRedirect(text, finalUrl);
      const key = env && env.ACCESS_KEY ? env.ACCESS_KEY : null;
      const rewritten = finalizeHtml(
        rewriteHtml(text, finalUrl),
        finalUrl,
        injectionBlock(finalUrl, home, key, refresh)
      );
      const outHeaders = passthroughHeaders(upstream, {
        ...extraHeaders,
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      });
      for (const c of cookies) outHeaders.append('set-cookie', c);
      /* Remember the exact page for requests that arrive with no Referer at all
         (sandboxed iframe, rel=noreferrer, strict referrer policy, or JS setting
         location.href). Without this, a root-relative navigation is
         unattributable and the relay can only answer "Nothing here". */
      outHeaders.append('set-cookie',
        'pp_loc=' + b64url(finalUrl) + '; Path=/; SameSite=Lax; Max-Age=86400');
      return new Response(rewritten, { status: upstream.status, headers: outHeaders });
    } catch { /* fall through and stream it */ }
  }

  /* ---- media: play it inside the relay instead of handing over raw bytes ---
   * A top-level navigation to a video/audio/playlist URL gets a player page, so
   * the asset plays here with a working timeline. Sub-resources (a <video> inside
   * a proxied page, an HLS segment) are never intercepted: only document
   * navigations are, and only when ?raw=1 is absent. */
  const kind = mediaKind(contentType, finalUrl);
  const wantPlayer = !opts.raw && kind && (opts.player || isDocumentNavigation(request));
  if (wantPlayer) {
    const size = upstream.headers.get('content-encoding') ? null : upstream.headers.get('content-length');
    const page = playerPage({
      target: finalUrl,
      kind,
      size,
      home: home,
      accessKey: env && env.ACCESS_KEY ? env.ACCESS_KEY : null,
    });
    const outHeaders = passthroughHeaders(upstream, {
      ...extraHeaders,
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    });
    for (const c of cookies) outHeaders.append('set-cookie', c);
    return new Response(page, { status: upstream.status === 206 ? 200 : upstream.status, headers: outHeaders });
  }

  /* ---- CSS: rewrite url()/@import -------------------------------------- */
  if (/^text\/css/i.test(contentType) && !request.headers.get('range')) {
    try {
      const bytes = await readAll(upstream, CONFIG.maxRewriteBytes);
      const text = new TextDecoder(charsetOf(contentType)).decode(bytes);
      const outHeaders = passthroughHeaders(upstream, { ...extraHeaders, 'content-type': 'text/css; charset=utf-8' });
      for (const c of cookies) outHeaders.append('set-cookie', c);
      return new Response(rewriteCss(text, finalUrl), { status: upstream.status, headers: outHeaders });
    } catch { /* stream it */ }
  }

  /* ---- HLS / DASH playlists: rewrite so segments stay proxied ---------- */
  const isManifest = MEDIA_MANIFEST.test(contentType) || /\.(m3u8|mpd)(\?|$)/i.test(finalUrl);
  if (isManifest) {
    try {
      const bytes = await readAll(upstream, CONFIG.maxRewriteBytes);
      const text = new TextDecoder(charsetOf(contentType)).decode(bytes);
      const outHeaders = passthroughHeaders(upstream, {
        ...extraHeaders,
        'content-type': /mpegurl/i.test(contentType) ? 'application/vnd.apple.mpegurl; charset=utf-8'
          : (contentType || 'application/dash+xml; charset=utf-8'),
        'cache-control': 'no-store',
      });
      for (const c of cookies) outHeaders.append('set-cookie', c);
      return new Response(rewriteManifest(text, finalUrl), { status: upstream.status, headers: outHeaders });
    } catch { /* stream it */ }
  }

  /* ---- everything else: byte-for-byte, ranges included ----------------- */
  const outHeaders = passthroughHeaders(upstream, extraHeaders);
  if (opts.download) {
    const name = mediaTitle(finalUrl).replace(/[^\w.-]+/g, '_').slice(0, 80);
    const hadType = contentType || 'application/octet-stream';
    outHeaders.set('content-disposition', 'attachment; filename="' + name + '"');
    outHeaders.set('content-type', hadType);
  }
  for (const c of cookies) outHeaders.append('set-cookie', c);
  return new Response(upstream.body, { status: upstream.status, headers: outHeaders });
}

/* -------------------------------------------------------------------------- */

/**
 * WebSocket passthrough. Cloudflare Workers and Deno Deploy perform the upgrade
 * themselves when a request carrying Upgrade: websocket is forwarded; Node does
 * it with a socket tunnel in node-server.js. Cookies and Origin are set so the
 * server accepts the connection the same way it would from the real site.
 */
async function proxyWebSocket(request, wsTarget, env) {
  const verdict = await guardTarget(wsTarget, env);
  if (verdict) return new Response(verdict, { status: 403 });

  const httpTarget = wsTarget.replace(/^ws/i, 'http');
  const dest = new URL(httpTarget);
  const jar = await jarLoad(env);
  const cookieString = jarHeader(jar, dest.hostname, dest.pathname, dest.protocol === 'https:');

  const headers = new Headers(request.headers);
  headers.set('host', dest.host);
  headers.set('origin', dest.origin);
  if (cookieString) headers.set('cookie', cookieString);
  headers.delete('x-relay');

  try {
    return await fetch(httpTarget, { method: 'GET', headers, redirect: 'manual' });
  } catch (err) {
    return new Response('websocket relay failed: ' + ((err && err.message) || err), { status: 502 });
  }
}

/* -------------------------------------------------------------------------- */

async function rawFetch(request, url, env) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CONFIG.corsHeaders });

  const raw = url.searchParams.get('url') || url.searchParams.get('u');
  const target = looksLikeSearch(raw) ? null : normalizeTarget(raw);
  if (!target) {
    return new Response('usage: /raw?url=<address or bare domain>', { status: 400, headers: { 'content-type': 'text/plain' } });
  }
  const verdict = await guardTarget(target, env);
  if (verdict) return new Response(verdict, { status: 403, headers: { 'content-type': 'text/plain' } });

  const dest = new URL(target);
  const jar = await jarLoad(env);
  const headers = new Headers({
    'user-agent': CONFIG.userAgent,
    accept: request.headers.get('accept') || '*/*',
    'accept-language': request.headers.get('accept-language') || 'en-US,en;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
  });
  const cookieString = jarHeader(jar, dest.hostname, dest.pathname, dest.protocol === 'https:');
  if (cookieString) headers.set('cookie', cookieString);
  if (request.headers.get('authorization')) headers.set('authorization', request.headers.get('authorization'));
  if (request.headers.get('content-type')) headers.set('content-type', request.headers.get('content-type'));

  const init = { method: request.method, headers, redirect: 'follow', signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs) };
  if (!['GET', 'HEAD'].includes(request.method)) { init.body = request.body; init.duplex = 'half'; }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    return new Response('fetch failed: ' + ((err && err.message) || err), { status: 502, headers: { 'content-type': 'text/plain' } });
  }

  const incoming = getSetCookies(upstream.headers);
  if (incoming.length) { jarAbsorb(jar, incoming, dest.hostname); await jarSave(env, jar); }

  const out = new Response(upstream.body, {
    status: upstream.status,
    headers: {
      'content-type': upstream.headers.get('content-type') || 'text/plain; charset=utf-8',
      'content-range': upstream.headers.get('content-range') || '',
      'accept-ranges': upstream.headers.get('accept-ranges') || 'bytes',
      'cache-control': 'no-store',
    },
  });
  if (!out.headers.get('content-range')) out.headers.delete('content-range');
  return out;
}

/**
 * Media/manifest preview: fetch a URL, and if it turns out to be an HLS or DASH
 * playlist, report the rewritten first few lines. Useful for diagnosing why a
 * video will not play without opening dev tools.
 */
async function previewFetch(request, url, env) {
  const target = normalizeTarget(url.searchParams.get('url'));
  if (!target) return json({ error: 'usage: /preview?url=<address>' });
  const verdict = await guardTarget(target, env);
  if (verdict) return json({ error: verdict });

  try {
    const res = await fetch(target, {
      headers: { 'user-agent': CONFIG.userAgent, accept: '*/*', range: 'bytes=0-65535' },
      redirect: 'follow',
      signal: AbortSignal.timeout(CONFIG.fetchTimeoutMs),
    });
    const type = res.headers.get('content-type') || '';
    const kind = MEDIA_MANIFEST.test(type) || /\.(m3u8|mpd)(\?|$)/i.test(target) ? 'manifest'
      : /^video\//i.test(type) ? 'video' : /^audio\//i.test(type) ? 'audio'
      : /^image\//i.test(type) ? 'image' : 'other';
    const body = ['manifest'].includes(kind) ? await res.text() : '';
    return json({
      target,
      status: res.status,
      kind,
      content_type: type,
      accepts_ranges: res.headers.get('accept-ranges'),
      content_range: res.headers.get('content-range'),
      proxied_url: encodeUrl(target),
      manifest_head: body ? rewriteManifest(body, target).split('\n').slice(0, 12) : undefined,
    });
  } catch (err) {
    return json({ target, error: (err && err.message) || String(err) });
  }
}

function tabsEndpoint(url) {
  return json({
    note: 'Tabs live in the client browser (relay-origin localStorage) and are rendered by the injected toolbar.',
    toolbar: true,
    storage_key: 'pp.relay.tabs.v1',
    requested: url.searchParams.get('url') || null,
  });
}

async function probe(url, env) {
  const rawTarget = url.searchParams.get('url') || 'https://example.com/';
  const target = normalizeTarget(rawTarget) || rawTarget;
  const started = Date.now();
  const base = {
    relay: 'ok',
    probe_target: target,
    time: new Date().toISOString(),
    status: null, content_type: null, bytes: null, ms: null, final_url: null,
    blocked: null, error: null,
    features: {
      rewrite: true, raw_passthrough: true, cookie_jar: 'domain+path', sessions_binding: !!(env && env.SESSIONS),
      access_key: !!(env && env.ACCESS_KEY), redirect_rewriting: true, media_manifests: 'hls+dash',
      range_requests: true, websockets: 'platform', tabs: true,
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
      bytes: bytes >= 200000 ? '>=200000 (truncated)' : bytes,
      ms: Date.now() - started,
      final_url: res.url || null,
      accepts_ranges: res.headers.get('accept-ranges'),
      cookies_set: getSetCookies(res.headers).length,
    });
  } catch (err) {
    return json({ ...base, ms: Date.now() - started, error: (err && err.message) || String(err) });
  }
}

/* ==========================================================================
 * 11. Response helpers + pages
 * ========================================================================== */

function json(value) {
  return new Response(JSON.stringify(value, null, 2), {
    status: 200, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
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

function redirectTo(location, status, cookies) {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const c of cookies || []) headers.append('set-cookie', c);
  return new Response(null, { status, headers });
}

const PAGE_STYLE = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(1100px 600px at 12% -10%,#1a2540 0%,transparent 58%),#0a0c11;
color:#e6e9ef;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{width:min(760px,100%);margin:0 auto;padding:44px 18px 64px}
h1{margin:12px 0 8px;font-size:28px;letter-spacing:-.3px}
p{margin:10px 0;color:#aab2c0}
code{background:#1a1f29;padding:2px 6px;border-radius:6px;font:12.5px ui-monospace,Menlo,monospace;color:#dfe5ef}
a{color:#7cc4ff;text-decoration:none}a:hover{text-decoration:underline}
.badge{display:inline-block;font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:1.2px;color:#8ef0c0;
background:#0f2a20;border:1px solid #1d4f3b;padding:7px 10px;border-radius:999px}
form.go{display:flex;gap:9px;flex-wrap:wrap;margin:18px 0 6px}
input{flex:1 1 320px;min-width:0;padding:14px 15px;border-radius:12px;border:1px solid #2a3140;background:#141822;
color:#e8ebf1;font:inherit}
input:focus{outline:none;border-color:#4b7bff;box-shadow:0 0 0 3px rgba(75,123,255,.18)}
button{padding:14px 20px;border-radius:12px;border:1px solid #3f6dff;background:linear-gradient(#3f6dff,#2f55e0);
color:#fff;font:600 15px/1 inherit;cursor:pointer}
button.ghost{background:#141822;border-color:#2a3140;color:#cbd3e1;font-weight:500}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px;margin-top:16px}
.grid a{display:block;padding:11px 13px;border:1px solid #222836;border-radius:11px;background:#12161f;color:#cdd5e3;font-size:13.5px}
.grid a:hover{border-color:#3a4bff;color:#fff}
.muted{color:#6f7888;font-size:13px}
.card{background:#0f1219;border:1px solid #262b36;border-radius:16px;padding:18px 20px;margin-top:20px}
`;

function newTabPage(url, env) {
  const origin = url.origin;
  const quick = [
    ['Wikipedia', 'en.wikipedia.org/wiki/Web_proxy'],
    ['Hacker News', 'news.ycombinator.com'],
    ['Example', 'example.com'],
    ['MDN', 'developer.mozilla.org'],
    ['Text CNN', 'lite.cnn.com'],
    ['Text NPR', 'text.npr.org'],
  ];
  const kq = env && env.ACCESS_KEY && url.searchParams.get('key') ? '?key=' + encodeURIComponent(url.searchParams.get('key')) : '';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Relay — start</title>'
    + '<style>' + PAGE_STYLE + '</style></head><body><div class="wrap">'
    + '<span class="badge">● RELAY ONLINE — NO http:// NEEDED</span>'
    + '<h1>Web Relay</h1>'
    + '<p>Type an address (<code>example.com</code> works) or a search. Rendering happens in your browser; '
    + 'this relay only fetches and rewrites. Once you are browsing, the tab strip and address bar appear at the top of every page.</p>'
    + '<form class="go" action="/go" method="get">'
    + '<input name="url" placeholder="example.com  ·  or search for something" autocomplete="off" spellcheck="false" autofocus'
    + (kq ? ' value=""' : '') + '><button type="submit">Go</button></form>'
    + (kq ? '<input type="hidden" name="key" value="' + escapeHtml(url.searchParams.get('key')) + '">' : '')
    + '<div class="grid">' + quick.map(([label, target]) =>
        '<a href="/p/' + escapeHtml(target) + kq + '">' + escapeHtml(label) + '</a>').join('') + '</div>'
    + '<div class="card"><p class="muted" style="margin-top:0">Endpoints</p>'
    + '<p class="muted"><code>/p/&lt;address&gt;</code> human-readable · <code>/__p/&lt;base64&gt;</code> canonical · '
    + '<code>/go?url=</code> normalises · <code>/raw?url=</code> passthrough · <code>/preview?url=</code> media check · '
    + '<code>/__probe?url=</code> diagnostics · <code>/__health</code></p>'
    + '<p class="muted">' + (env && env.ACCESS_KEY
      ? 'Access key: <b>required</b> — append <code>?key=…</code>.'
      : 'Access key: not set — anyone with this address can relay through it. Set <code>ACCESS_KEY</code> to lock it down.')
    + (env && env.SESSIONS ? ' Sessions: persistent (KV binding present).' : ' Sessions: in-memory per isolate.') + '</p>'
    + '<p class="muted">Media: byte ranges, HLS and DASH playlists are relayed, so video seeks. '
    + 'WebSockets pass through where the platform supports it.</p></div>'
    + '</div></body></html>';
}

/**
 * Reached when a request has no attributable target: usually a root-relative
 * navigation that arrived without a Referer and before pp_loc was set. Rather
 * than a dead end, offer the address box again and keep whatever path was asked
 * for, so the right URL can be retyped or guessed.
 */
function notFoundPage(url, request) {
  const asked = url.pathname + url.search;
  const loc = decodeUrl(readCookie(request, 'pp_loc') || '') ;
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Relay — address needed</title>'
    + '<style>' + PAGE_STYLE + '</style></head><body><div class="wrap">'
    + '<span class="badge" style="color:#ffd7a2;background:#2a1f10;border-color:#5b4523">RELAY — NO TARGET</span>'
    + '<h1>I don\'t know which site that path belongs to</h1>'
    + '<p>Something asked for <code>' + escapeHtml(asked.slice(0, 200)) + '</code> as a bare path, without '
    + 'telling the relay which site it was on' + (loc ? ' (the last page was <code>' + escapeHtml(loc.slice(0, 120)) + '</code>)' : '')
    + '. This usually happens when a page navigates with a root-relative URL and the browser sends no Referer.</p>'
    + '<p>Type the address (bare domains are fine) and the relay will take you there:</p>'
    + '<form class="go" action="/go" method="get">'
    + '<input name="url" placeholder="example.com" autocomplete="off" spellcheck="false" autofocus>'
    + '<button type="submit">Go</button></form>'
    + (loc ? '<p class="muted">Continue where you left off: <a href="' + escapeHtml(encodeUrl(loc)) + '">' + escapeHtml(loc.slice(0, 90)) + '</a></p>' : '')
    + '<p class="muted"><a href="/">Relay start page</a> · '
    + 'if this keeps happening, note the path above — it usually means a site builds URLs from '
    + '<code>location.origin</code> in a way the shim could not translate.</p>'
    + '</div></body></html>';
}

function errorPage(status, message, target) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Relay error ' + status + '</title>'
    + '<style>' + PAGE_STYLE + '</style></head><body><div class="wrap">'
    + '<h1>Relay error ' + status + '</h1><p>' + escapeHtml(message) + '</p>'
    + (target ? '<p class="muted">target: ' + escapeHtml(String(target).slice(0, 300)) + '</p>' : '')
    + (target && isHttpUrl(target) ? '<p><a href="' + escapeHtml(encodeUrl(target)) + '">Retry through the relay</a></p>' : '')
    + '<p><a href="/">Relay start page</a></p></div></body></html>';
}

/* __RELAY_EOF__ */
