// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// End-to-end test of the `webauthn` ssh-agent backend in the packaged
// extension: loads it into Chromium, attaches a CDP virtual FIDO
// authenticator, enrolls a key through the terminal UI, authorizes it on a
// real sshd, reconnects & runs a command.  Driven by run.sh.
//
// In "plain" mode it then manages keys in Options > SSH Files.  In "resident"
// mode the key is stored on the authenticator; after logging in the
// extension's storage is wiped (a new computer, in effect), the key is
// imported back from the authenticator, and we log in again.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require = createRequire(process.env.PLAYWRIGHT_DIR ?? import.meta.url);
const {chromium} = require('playwright');
const [,, extDir, userDir, authKeys, port, user, mode = 'plain'] =
    process.argv;
const resident = mode === 'resident';

const ctx = await chromium.launchPersistentContext(userDir, {
  headless: true, channel: 'chromium',
  args: ['--no-sandbox', `--disable-extensions-except=${extDir}`,
         `--load-extension=${extDir}`],
});
let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker', {timeout: 15000});
const id = new URL(sw.url()).host;
console.log('extension id', id);

const page = await ctx.newPage();
page.on('console', (m) => {
  const t = m.text();
  if (/webauthn|agent|error/i.test(t)) console.log('[console]', t.slice(0, 200));
});
const cdp = await ctx.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const {authenticatorId} = await cdp.send(
    'WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport: 'usb', hasResidentKey: resident,
      hasUserVerification: resident, isUserVerified: resident,
      automaticPresenceSimulation: true,
    }});

const screen = async () => {
  const texts = [];
  for (const f of page.frames()) {
    try {
      texts.push(await f.evaluate(() => document.body?.innerText ?? ''));
    } catch {}
  }
  return texts.join('\n');
};
const waitFor = async (re, ms = 30000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const s = await screen();
    const m = s.match(re);
    if (m) return m;
    await page.waitForTimeout(250);
  }
  console.log('---- screen ----\n' + await screen());
  throw new Error(`timeout waiting for ${re}`);
};

const uri = `ssh://${user};` + '-nassh-args=--ssh-agent%3Dwebauthn@127.0.0.1:' + port;
await page.goto(`chrome-extension://${id}/html/nassh.html#uri:${uri}`);

await waitFor(/continue connecting/);
await page.keyboard.type('yes\n');
console.log('accepted host key');

// The terminal keeps its scrollback, so count occurrences rather than search.
const count = async (re) =>
  ((await screen()).match(new RegExp(re.source, 'g')) ?? []).length;
const waitForNth = async (re, n, ms = 30000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await count(re) >= n) return;
    await page.waitForTimeout(250);
  }
  console.log('---- screen ----\n' + await screen());
  throw new Error(`timeout waiting for #${n} ${re}`);
};

const RECONNECT = /R\)econnect/;
const TOUCH_TO_LOGIN = /Touch your security key to authenticate/;

// Fill in the agent's prompt, an overlay in the terminal frame.
const answerPrompt = async (name, checkbox) => {
  for (let i = 0; i < 120; ++i) {
    for (const f of page.frames()) {
      const input = await f.$('input[aria-label^="Create a new SSH key"]');
      if (input) {
        if (checkbox) {
          await (await f.$('input[type=checkbox]')).check();
        }
        await input.fill(name);
        await input.press('Enter');
        return;
      }
    }
    await page.waitForTimeout(250);
  }
  throw new Error('no prompt input');
};

await answerPrompt('ext-e2e-key', resident);
// The terminal soft-wraps the long line; strip the wrapping.
const [wrapped] = await waitFor(
    /sk-ecdsa-sha2-nistp256@openssh\.com [\s\S]+?e[\s]*x[\s]*t-e2e-ke\s*y/);
const line = wrapped.replace(/\n/g, '');
console.log('enrolled:', line);
fs.writeFileSync(authKeys, line + '\n');

// The first attempt usually fails as sshd reads authorized_keys before we
// write it; if so, reconnect.
for (let i = 0; ; ++i) {
  if (await count(RECONNECT) >= 1) {
    await page.keyboard.type('r');
    console.log('reconnecting');
    break;
  }
  if (await count(TOUCH_TO_LOGIN) >= 1) {
    break;
  }
  if (i > 120) {
    throw new Error('neither a login nor a failure');
  }
  await page.waitForTimeout(250);
}
await waitForNth(TOUCH_TO_LOGIN, 1);
console.log('asked for touch');
await page.keyboard.type('echo EXT_E2E_$((6*7)); whoami\n');
await waitFor(/EXT_E2E_42/);
console.log('LOGGED IN via extension + WebAuthn');

if (!resident) {
  // Manage keys from Options > SSH Files.
  const prefs = await ctx.newPage();
  const prefsCdp = await ctx.newCDPSession(prefs);
  await prefsCdp.send('WebAuthn.enable');
  await prefsCdp.send('WebAuthn.addVirtualAuthenticator', {options: {
    protocol: 'ctap2', transport: 'usb', hasResidentKey: false,
    hasUserVerification: false, automaticPresenceSimulation: true,
  }});
  await prefs.goto(
      `chrome-extension://${id}/html/nassh_preferences_editor.html#ssh-files`);
  const list = prefs.locator('#ssh-files-security-keys');
  const status = prefs.locator('#ssh-files-security-keys-status');
  await list.getByText('ext-e2e-key').waitFor();

  await list.locator('li', {hasText: 'ext-e2e-key'})
      .getByRole('button', {name: 'Copy public key'}).click();
  await status.getByText('Copied the public key of "ext-e2e-key"').waitFor();

  await prefs.fill('#ssh-files-security-keys-name', 'prefs-key');
  await prefs.click('#ssh-files-security-keys-create');
  await list.getByText('prefs-key').waitFor();
  console.log('created a key in the options page');

  const trash = list.locator('li', {hasText: 'ext-e2e-key'})
      .locator('button').first();
  await trash.click();
  await status.getByText('Click again to forget the key').waitFor();
  await trash.click();
  await list.getByText('ext-e2e-key').waitFor({state: 'detached'});
  const names = await prefs.evaluate(async () => {
    const keys = (await chrome.storage.sync.get(
        '/nassh/agent/webauthn/keys'))['/nassh/agent/webauthn/keys'];
    return keys.map((key) => key.comment);
  });
  if (names.join() !== 'prefs-key') {
    throw new Error(`unexpected keys after delete: ${names}`);
  }
  console.log('managed keys in the options page');
  await prefs.close();
}

if (resident) {
  const {credentials} =
      await cdp.send('WebAuthn.getCredentials', {authenticatorId});
  if (credentials.length !== 1 || !credentials[0].isResidentCredential) {
    throw new Error(
        `expected 1 resident credential: ${JSON.stringify(credentials)}`);
  }
  console.log('credential is resident');

  // Forget the key, as on a new computer, then import it back.
  const reconnects = await count(RECONNECT);
  const touches = await count(TOUCH_TO_LOGIN);
  await page.keyboard.type('exit\n');
  await waitForNth(RECONNECT, reconnects + 1);
  await page.evaluate(() => chrome.storage.sync.clear());
  await page.keyboard.type('r');
  await answerPrompt('', false);
  await waitFor(/Using the key "ext-e2e-key" stored on your security key/);
  console.log('imported');
  await waitForNth(TOUCH_TO_LOGIN, touches + 1);
  await page.keyboard.type('echo IMPORTED_$((6*7))\n');
  await waitFor(/IMPORTED_42/);
  console.log('LOGGED IN with imported resident key');
}

console.log((await screen()).split('\n').filter((l) => l.trim()).slice(-12)
    .join('\n'));
await ctx.close();
