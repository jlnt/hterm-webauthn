// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Test suite for WebAuthn security key management.
 */

import {keyBlobToAuthorizedKeysFormat} from './nassh_agent.js';
import {Message} from './nassh_agent_message.js';
import {
  SK_ECDSA_KEY_TYPE, authorizedKeysLine, decodeDerEcdsaSignature,
  findApplication, generateSkEcdsaKeyBlob, p256PointFromSpki,
  recoverP256PublicKeys, toBase64Url, verifyP256Signature,
} from './nassh_webauthn_keys.js';

describe('nassh_webauthn_keys_tests.js', () => {

/**
 * Public key/authorized_keys pair that sshd accepted in a manual end-to-end
 * test against a WebAuthn virtual authenticator on http://localhost.
 */
const POINT = Uint8Array.fromBase64(
    'BFJXDZN53Fvox8rxBLHYxufhMiDjhQfhBf49/F+TUlycV8TgKS34PBi5mjf/YS69gcyxCebO' +
    'wrSPKiO6tIWgADs=');
const AUTHORIZED_KEY =
    'sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZA' +
    'b3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBFJXDZN53Fvox8rxBLHYxufhMiDjhQfhBf49' +
    '/F+TUlycV8TgKS34PBi5mjf/YS69gcyxCebOwrSPKiO6tIWgADsAAAAJbG9jYWxob3N0';

it('generateSkEcdsaKeyBlob', () => {
  const blob = generateSkEcdsaKeyBlob(POINT, 'localhost');
  assert.equal(keyBlobToAuthorizedKeysFormat(blob), AUTHORIZED_KEY);

  const r = new Message(/** @type {?} */ (0), blob);
  const cstring = () => new TextDecoder().decode(r.readString());
  assert.equal(cstring(), SK_ECDSA_KEY_TYPE);
  assert.equal(cstring(), 'nistp256');
  assert.deepStrictEqual(r.readString(), POINT);
  assert.equal(cstring(), 'localhost');
  assert.isTrue(r.eom());
});

it('authorizedKeysLine', () => {
  const key = {
    credentialId: 'AAAA',
    publicKey: toBase64Url(POINT),
    application: 'localhost',
    rpId: null,
    comment: 'my-key',
    created: 0,
  };
  assert.equal(authorizedKeysLine(key), `${AUTHORIZED_KEY} my-key`);
});

it('p256PointFromSpki', () => {
  const spki = Uint8Array.fromBase64(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpfYaCsnxjFWey+uzHtEXOnJyUMwKaiKCFU' +
      'Ja4XqS2EtWa9KD++j5T6zfg2cbibjHSnnNvQGj85Cl3rKU56RX7Q==');
  const point = p256PointFromSpki(spki);
  assert.equal(point.length, 65);
  assert.equal(point[0], 0x04);
  assert.deepStrictEqual(point, spki.subarray(26));

  assert.throws(() => p256PointFromSpki(spki.subarray(1)));
});

it('decodeDerEcdsaSignature', () => {
  // r has a leading zero (high bit set), s is short.
  const der = new Uint8Array([
    0x30, 0x0a,
    0x02, 0x03, 0x00, 0x80, 0x01,
    0x02, 0x03, 0x01, 0x02, 0x03,
  ]);
  const {r, s} = decodeDerEcdsaSignature(der);
  assert.deepStrictEqual(r, new Uint8Array([0x00, 0x80, 0x01]));
  assert.deepStrictEqual(s, new Uint8Array([0x01, 0x02, 0x03]));

  assert.throws(() => decodeDerEcdsaSignature(der.subarray(1)));
  assert.throws(() => decodeDerEcdsaSignature(
      new Uint8Array([...der, 0x00])));
});

it('findApplication', async () => {
  // SHA-256("chrome-extension://abcdef").
  const hash = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode('chrome-extension://abcdef')));
  assert.equal(
      await findApplication(hash, ['abcdef', 'chrome-extension://abcdef']),
      'chrome-extension://abcdef');
  assert.isNull(await findApplication(hash, ['abcdef']));
});

it('recoverP256PublicKeys', async () => {
  // Signatures from fresh WebCrypto keys must yield the real public key as one
  // of the candidates, and only the real key verifies a second signature.
  for (let i = 0; i < 5; ++i) {
    const {publicKey, privateKey} = await crypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign', 'verify']);
    const point = new Uint8Array(/** @type {!ArrayBuffer} */ (
        await crypto.subtle.exportKey('raw', publicKey)));
    const sign = async (message) => {
      // WebCrypto signatures are r || s.
      const raw = new Uint8Array(await crypto.subtle.sign(
          {name: 'ECDSA', hash: 'SHA-256'}, privateKey, message));
      return {r: raw.subarray(0, 32), s: raw.subarray(32)};
    };

    const message1 = new Uint8Array(100);
    crypto.getRandomValues(message1);
    const sig1 = await sign(message1);
    const hash1 =
        new Uint8Array(await crypto.subtle.digest('SHA-256', message1));
    const candidates = recoverP256PublicKeys(hash1, sig1.r, sig1.s);
    assert.equal(candidates.length, 2);
    assert.isTrue(candidates.some((c) => c.every((b, j) => b === point[j])));

    const message2 = new Uint8Array(100);
    crypto.getRandomValues(message2);
    const sig2 = await sign(message2);
    const verified = [];
    for (const candidate of candidates) {
      if (await verifyP256Signature(candidate, message2, sig2)) {
        verified.push(candidate);
      }
    }
    assert.equal(verified.length, 1);
    assert.deepStrictEqual(verified[0], point);
  }
});

it('recoverP256PublicKeys rejects out of range signatures', () => {
  const hash = new Uint8Array(32);
  assert.deepStrictEqual(
      recoverP256PublicKeys(hash, new Uint8Array(32), new Uint8Array([1])), []);
  assert.deepStrictEqual(
      recoverP256PublicKeys(hash, new Uint8Array([1]), new Uint8Array(32)), []);
});

});
