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


