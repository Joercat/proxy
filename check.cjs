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
    note: 'the relay itself — the big one (never paste this one; upload it)' },
  { name: 'node-server.cjs', sentinel: '/* __NODE_SERVER_EOF__ */', minLines: 240, required: true,
    note: 'the Node entry point Render runs' },
  { name: 'client.html', sentinel: '<!-- __CLIENT_EOF__ -->', minLines: 380, required: false,
    note: 'the client (only needed if you host it from this repo)' },
  { name: 'verify.cjs', sentinel: '/* __VERIFY_EOF__ */', minLines: 200, required: false,
    note: 'the end-to-end test' },
  { name: 'package.json', sentinel: null, minLines: 6, required: false, json: true,
    note: 'makes the host\'s default "npm install" build work' },
];

const kb = (n) => (n / 1024).toFixed(1) + ' KB';
let bad = 0;

console.log('Pocket Proxy — checking the deploy files in ' + __dirname);
console.log('Upload these:  relay.js, node-server.cjs, package.json, check.cjs');
console.log('');

for (const f of FILES) {
  const at = path.join(__dirname, f.name);
  if (!fs.existsSync(at)) {
    console.log((f.required ? '  MISSING ' : '  skip  ') + f.name.padEnd(17) +
      (f.required ? '<- required, upload this one' : 'optional, not needed on the relay host'));
    if (f.required) bad++;
    continue;
  }
  const src = fs.readFileSync(at, 'utf8');
  const lines = src.split('\n').length;
  const bytes = Buffer.byteLength(src, 'utf8');
  const endsWithSentinel = f.sentinel ? src.trimEnd().endsWith(f.sentinel) : true;
  const longEnough = lines >= f.minLines;

  if (endsWithSentinel && longEnough) {
    if (f.json) {
      try { JSON.parse(src); } catch (e) {
        bad++;
        console.log('  BAD JSON ' + f.name.padEnd(17) + lines + ' lines, ' + kb(bytes) + '   <- will break npm');
        console.log('           ' + String(e.message).slice(0, 120));
        console.log('           ' + f.note);
        continue;
      }
    }
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
  console.log('All files complete — safe to start.');
  console.log('  Start Command:  node node-server.cjs        (or leave the default "npm start")');
  console.log('  Build Command:  node check.cjs              (or leave the default "npm install")');
  process.exit(0);
}
console.log('NOTE: a missing package.json also fails a host\'s default "npm install" build');
console.log('      with ENOENT .../package.json. Keep it in the repo root.');
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
