// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Test suite for the WebAuthn SSH agent backend.
 */

// The agent module must be evaluated before its backends (as it is in the
// app) since it registers them at load time.
import './nassh_agent.js';
import {
  WEBAUTHN_SK_ECDSA_SIG_TYPE, webauthnAssertionToSshSignature,
} from './nassh_agent_backend_webauthn.js';

/**
 * Minimal SSH wire format reader for checking our output.
 */
class WireReader {
  /** @param {!Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset);
    this.pos = 0;
  }

  /** @return {number} */
  u8() {
    return this.bytes[this.pos++];
  }

  /** @return {number} */
  u32() {
    const ret = this.view.getUint32(this.pos);
    this.pos += 4;
    return ret;
  }

  /** @return {!Uint8Array} */
  string() {
    const len = this.u32();
    const ret = this.bytes.subarray(this.pos, this.pos + len);
    this.pos += len;
    return ret;
  }

  /** @return {string} */
  cstring() {
    return new TextDecoder().decode(this.string());
  }

  /** @return {boolean} */
  eom() {
    return this.pos === this.bytes.length;
  }
}

describe('nassh_agent_backend_webauthn_tests.js', () => {

it('webauthnAssertionToSshSignature', () => {
  const authenticatorData = new Uint8Array(37 + 3);
  authenticatorData.fill(0xaa, 0, 32);
  authenticatorData[32] = 0x81;  // UP | ED
  authenticatorData.set([0x00, 0x00, 0x01, 0x02], 33);  // counter = 258
  authenticatorData.set([0xa0, 0xb0, 0xc0], 37);  // extensions
  const clientDataJSON = new TextEncoder().encode(
      '{"type":"webauthn.get","challenge":"AAEC",' +
      '"origin":"chrome-extension://abcdef","crossOrigin":false}');
  const signature = new Uint8Array([
    0x30, 0x08,
    0x02, 0x02, 0x00, 0x90,
    0x02, 0x02, 0x12, 0x34,
  ]);

  const sig = webauthnAssertionToSshSignature(
      {authenticatorData, clientDataJSON, signature});
  const r = new WireReader(sig);
  assert.equal(r.cstring(), WEBAUTHN_SK_ECDSA_SIG_TYPE);
  const inner = new WireReader(r.string());
  // mpints: 0x90 needs its leading zero kept; 0x1234 doesn't need one.
  assert.deepStrictEqual(inner.string(), new Uint8Array([0x00, 0x90]));
  assert.deepStrictEqual(inner.string(), new Uint8Array([0x12, 0x34]));
  assert.isTrue(inner.eom());
  assert.equal(r.u8(), 0x81);
  assert.equal(r.u32(), 258);
  assert.equal(r.cstring(), 'chrome-extension://abcdef');
  assert.deepStrictEqual(r.string(), clientDataJSON);
  assert.deepStrictEqual(r.string(), new Uint8Array([0xa0, 0xb0, 0xc0]));
  assert.isTrue(r.eom());
});

it('webauthnAssertionToSshSignature rejects create() client data', () => {
  assert.throws(() => webauthnAssertionToSshSignature({
    authenticatorData: new Uint8Array(37),
    clientDataJSON: new TextEncoder().encode(
        '{"type":"webauthn.create","challenge":"","origin":"x"}'),
    signature: new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
  }));
});

});
