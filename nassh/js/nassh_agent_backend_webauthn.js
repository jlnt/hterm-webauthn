// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview An SSH agent backend that uses FIDO2/U2F security keys (and
 * passkeys) via the browser's WebAuthn API.
 *
 * OpenSSH (8.2+) supports "sk-ecdsa-sha2-nistp256@openssh.com" keys backed by
 * FIDO authenticators.  In addition to the plain FIDO signature format that
 * the native `ssh` client produces, sshd also accepts the
 * "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" signature format, which was
 * designed specifically for web clients: the signature covers the WebAuthn
 * authenticatorData and a hash of the browser-generated clientDataJSON, which
 * in turn embeds the SSH challenge.  This lets us sign SSH challenges with
 * nothing more than navigator.credentials.get().
 *
 * See nassh_webauthn_keys.js for how keys are created & stored.
 *
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
 */

import {compare, concatTyped} from './lib_array.js';
import {localize} from './nassh.js';
import {UserIO} from './nassh_agent.js';
import {Backend} from './nassh_agent_backend.js';
import {
  Identity, encodeAsWireMpint, encodeAsWireString,
} from './nassh_agent_message_types.js';
import {
  StoredKey, WEBAUTHN_TIMEOUT_MS, authorizedKeysLine, createKey,
  decodeDerEcdsaSignature, encodeWireCString, fromBase64Url, importKey,
  keyBlob, loadKeys, sha256,
} from './nassh_webauthn_keys.js';

/**
 * The SSH signature type for WebAuthn assertions made by ECDSA FIDO keys.
 *
 * @const {string}
 */
export const WEBAUTHN_SK_ECDSA_SIG_TYPE =
    'webauthn-sk-ecdsa-sha2-nistp256@openssh.com';

/**
 * Turn a WebAuthn assertion into an SSH "webauthn-sk-ecdsa" signature blob.
 *
 * @see PROTOCOL.u2f "SSH U2F signatures" & the webauthn variant.
 * @param {{
 *   authenticatorData: !Uint8Array,
 *   clientDataJSON: !Uint8Array,
 *   signature: !Uint8Array,
 * }} assertion
 * @return {!Uint8Array}
 */
export function webauthnAssertionToSshSignature(
    {authenticatorData, clientDataJSON, signature}) {
  // authenticatorData = rpIdHash[32] || flags[1] || signCount[4] || exts.
  if (authenticatorData.length < 37) {
    throw new Error('authenticatorData too short');
  }
  const dv = new DataView(authenticatorData.buffer,
                          authenticatorData.byteOffset);
  const flags = authenticatorData[32];
  const counter = dv.getUint32(33);
  const extensions = authenticatorData.subarray(37);

  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (clientData.type !== 'webauthn.get' ||
      typeof clientData.origin !== 'string') {
    throw new Error('unexpected clientDataJSON');
  }

  const {r, s} = decodeDerEcdsaSignature(signature);
  const flagsAndCounter = new Uint8Array(5);
  flagsAndCounter[0] = flags;
  new DataView(flagsAndCounter.buffer).setUint32(1, counter);

  return concatTyped(
      encodeWireCString(WEBAUTHN_SK_ECDSA_SIG_TYPE),
      encodeAsWireString(concatTyped(encodeAsWireMpint(r),
                                     encodeAsWireMpint(s))),
      flagsAndCounter,
      encodeWireCString(clientData.origin),
      encodeAsWireString(clientDataJSON),
      encodeAsWireString(extensions));
}

/**
 * An SSH agent backend that uses FIDO security keys via WebAuthn.
 */
export class WebAuthn extends Backend {
  /**
   * @param {!UserIO} userIO
   * @param {boolean} isForwarded
   */
  constructor(userIO, isForwarded) {
    super(userIO);

    /**
     * Whether the agent is forwarded to the remote host.  Every signature
     * still requires a physical touch, so a forwarded agent can't be abused
     * silently, but we warn about it when prompting.
     *
     * @private {boolean}
     * @const
     */
    this.isForwarded_ = isForwarded;

    /**
     * Map a string representation of a key blob to its stored key.
     *
     * @private {!Object<string, !StoredKey>}
     */
    this.keyBlobToKey_ = {};

    /** @private {?Promise<void>} */
    this.enrollOffered_ = null;
  }

  /**
   * @return {!Promise<void>}
   * @override
   */
  async ping() {
    if (!globalThis.PublicKeyCredential || !globalThis.navigator?.credentials) {
      this.showMessage(localize('WEBAUTHN_UNAVAILABLE'));
      throw new Error('WebAuthn.ping: WebAuthn API unavailable');
    }
  }

  /**
   * Prompt the user to create (or import) a key if none is set up yet.
   *
   * More keys can be added in the options page.
   *
   * @return {!Promise<void>}
   */
  async maybeEnroll_() {
    if ((await loadKeys()).length) {
      return;
    }
    let value;
    let resident;
    try {
      ({value, checked: resident} = await this.promptUserForm(
          localize('WEBAUTHN_ENROLL_PROMPT'), {
            secret: false,
            checkboxLabel: localize('WEBAUTHN_ENROLL_RESIDENT'),
          }));
    } catch (e) {
      return;
    }

    const comment = value.trim();
    if (!comment) {
      // No name: use a key already stored on the security key instead.
      try {
        this.showMessage(localize('WEBAUTHN_IMPORT_TOUCH'));
        const key = await importKey(
            () => this.showMessage(localize('WEBAUTHN_IMPORT_TOUCH_AGAIN')));
        this.showMessage(localize('WEBAUTHN_IMPORT_DONE', [key.comment]));
        this.println(authorizedKeysLine(key));
      } catch (e) {
        this.showMessage(localize('WEBAUTHN_IMPORT_FAILED', [e.message]));
      }
      return;
    }

    try {
      this.showMessage(localize('WEBAUTHN_ENROLL_TOUCH'));
      const key = await createKey(comment, resident);
      this.showMessage(localize('WEBAUTHN_ENROLL_DONE'));
      this.println(authorizedKeysLine(key));
    } catch (e) {
      this.showMessage(localize('WEBAUTHN_ENROLL_FAILED', [e.message]));
    }
  }

  /**
   * @return {!Promise<!Array<!Identity>>}
   * @override
   */
  async requestIdentities() {
    // The ssh client may ask for identities more than once per session; only
    // offer enrollment the first time.
    if (!this.enrollOffered_) {
      this.enrollOffered_ = this.maybeEnroll_();
    }
    await this.enrollOffered_;

    this.keyBlobToKey_ = {};
    /** @type {!Array<!Identity>} */
    const identities = [];
    for (const key of await loadKeys()) {
      const blob = keyBlob(key);
      this.keyBlobToKey_[new TextDecoder('utf-8').decode(blob)] = key;
      identities.push({
        keyBlob: blob,
        comment: new TextEncoder().encode(key.comment),
      });
    }
    return identities;
  }

  /**
   * @param {!Uint8Array} keyBlob
   * @param {!Uint8Array} data
   * @param {number} flags Unused: sk-ecdsa signatures have no variants.
   * @return {!Promise<!Uint8Array>}
   * @override
   */
  async signRequest(keyBlob, data, flags) {
    const key = this.keyBlobToKey_[new TextDecoder('utf-8').decode(keyBlob)];
    if (!key) {
      throw new Error('WebAuthn.signRequest: unknown key');
    }

    this.showMessage(localize(
        this.isForwarded_ ? 'WEBAUTHN_SIGN_TOUCH_FORWARDED' :
                            'WEBAUTHN_SIGN_TOUCH',
        [key.comment]));

    /** @type {!PublicKeyCredentialRequestOptions} */
    const publicKey = {
      // The SSH session data is used verbatim as the challenge.  The browser
      // base64url encodes it into clientDataJSON, which is what sshd checks.
      challenge: data,
      allowCredentials: [{
        type: 'public-key',
        id: fromBase64Url(key.credentialId),
      }],
      userVerification: 'discouraged',
      timeout: WEBAUTHN_TIMEOUT_MS,
    };
    if (key.rpId) {
      publicKey.rpId = key.rpId;
    }
    const credential = await navigator.credentials.get({publicKey});
    if (!credential) {
      throw new Error('WebAuthn.signRequest: no assertion');
    }

    const response = /** @type {!AuthenticatorAssertionResponse} */ (
        credential.response);
    const authenticatorData = new Uint8Array(response.authenticatorData);
    if (!compare(authenticatorData.subarray(0, 32),
                 await sha256(key.application))) {
      throw new Error('WebAuthn.signRequest: RP ID hash mismatch');
    }

    return webauthnAssertionToSshSignature({
      authenticatorData,
      clientDataJSON: new Uint8Array(response.clientDataJSON),
      signature: new Uint8Array(response.signature),
    });
  }
}

/** @override */
WebAuthn.prototype.BACKEND_ID = 'webauthn';
