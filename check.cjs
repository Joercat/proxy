#!/usr/bin/env node
/**
 * Pocket Proxy — deploy file check.  No dependencies, no setup.
 *
 *   node check.cjs
 *
 * Put this as the Build Command on Render (and/or run it any time). It reads
 * each file as TEXT — it never executes them — so it can report a file that was
 * cut short while being copied or uploaded. That is the failure that otherwise
 * shows up in a deploy log as "SyntaxError: Unexpected end of input" pointing at
 * a line the real file does not end at, which tells you nothing.
 *
 * Exit code 0 = every file complete, 1 = something is short or missing.
 */
'use strict';

const fs = require('fs');
const path = require('path');

// sentinel = the marker each file ends with; minLines = a floor that is safely
// below the real length, so a file that is merely old is not reported as short.
const FILES = [
  { name: 'relay.js', sentinel: '/* __RELAY_EOF__ */', minLines: 1400, required: true,
    note: 'the relay itself — the big one' },
  { name: 'node-server.cjs', sentinel: '/* __NODE_SERVER_EOF__ */', minLines: 240, required: true,
    note: 'the Node entry point Render runs' },
  { name: 'client.html', sentinel: '<!-- __CLIENT_EOF__ -->', minLines: 380, required: false,
    note: 'the client (only needed if you host it from this repo)' },
];

const kb = (n) => (n / 1024).toFixed(1) + ' KB';
let bad = 0;

console.log('Pocket Proxy — checking ' + FILES.length + ' files next to ' + __filename);
console.log('');

for (const f of FILES) {
  const at = path.join(__dirname, f.name);
  if (!fs.existsSync(at)) {
    console.log((f.required ? '  MISSING ' : '  absent  ') + f.name + (f.required ? '   <- required' : '   (' + f.note + ')'));
    if (f.required) bad++;
    continue;
  }
  const src = fs.readFileSync(at, 'utf8');
  const lines = src.split('\n').length;
  const bytes = Buffer.byteLength(src, 'utf8');
  const endsWithSentinel = src.trimEnd().endsWith(f.sentinel);
  const longEnough = lines >= f.minLines;

  if (endsWithSentinel && longEnough) {
    console.log('  ok       ' + f.name.padEnd(17) + lines + ' lines, ' + kb(bytes));
  } else {
    bad++;
    console.log('  SHORT    ' + f.name.padEnd(17) + lines + ' lines, ' + kb(bytes) + '   <- truncated or incomplete');
    if (!endsWithSentinel) console.log('           it does not end with:  ' + f.sentinel);
    if (!longEnough) console.log('           expected at least ' + f.minLines + ' lines (this is ' + f.name + ', ' + f.note + ')');
  }
}

console.log('');
if (!bad) {
  console.log('All files complete — safe to start.  Start Command:  node node-server.cjs');
  process.exit(0);
}
console.log('^^^ ' + bad + ' file(s) need attention. Node will fail to start with these.');
console.log('');
console.log('How to fix a SHORT file — do NOT copy-paste it from a viewer window:');
console.log('  a preview can stop after a few KB, which is exactly how files end up');
console.log('  ending mid-sentence at line 80. Instead:');
console.log('    1. download the file (or unzip the deploy bundle)');
console.log('    2. on GitHub: Add file -> Upload files -> drag the file in -> Commit');
console.log('    3. redeploy, then run this check again');
process.exit(1);

/* __CHECK_EOF__ */
