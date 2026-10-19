// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Management of SSH keys on FIDO2/U2F security keys (and
 * passkeys) via the browser's WebAuthn API: creating, importing, storing and
 * formatting them.  Used by the webauthn ssh-agent backend and the options
 * page, so it must not depend on the terminal or the agent.
 *
 * Keys are OpenSSH "sk-ecdsa-sha2-nistp256@openssh.com" keys.  The private
 * key never leaves the authenticator; we keep the public key & credential ID
 * in sync storage.
 *
 * The one catch is the FIDO "application" (RP ID).  Keys created by
 * `ssh-keygen -t ecdsa-sk` are bound to the application "ssh:", which a
 * browser will never let a page/extension assert.  So keys used here must be
 * created here (via navigator.credentials.create) and are bound to the
 * extension's own RP ID.  sshd does not care what the application string is;
 * it only checks that SHA256(application) matches the rpIdHash the
 * authenticator signed.
 *
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
 * @see https://www.w3.org/TR/webauthn-2/
 */

import {lib} from '../../libdot/index.js';

import {concatTyped, compare} from './lib_array.js';
import {base64ToBase64Url, base64UrlToBase64, getSyncStorage} from './nassh.js';
import {encodeAsWireString} from './nassh_agent_message_types.js';

/**
 * The SSH key type for FIDO-backed ECDSA keys.
 *
 * @const {string}
 */
export const SK_ECDSA_KEY_TYPE = 'sk-ecdsa-sha2-nistp256@openssh.com';

/**
 * COSE algorithm identifier for ECDSA w/SHA-256 on P-256.
 *
 * @const {number}
 */
const COSE_ALG_ES256 = -7;

/**
 * Storage key under which enrolled keys are saved.
 *
 * Only public data lives here (public key, credential ID & application); the
 * private key never leaves the authenticator.
 *
 * @const {string}
 */
const STORAGE_KEY = '/nassh/agent/webauthn/keys';

/**
 * How long to wait for the user to touch their key.
 *
 * @const {number}
 */
export const WEBAUTHN_TIMEOUT_MS = 60 * 1000;

/**
 * How many random bytes start the WebAuthn user handle.
 *
 * Resident credentials for the same RP & user handle replace each other, so
 * every key gets a unique handle.  The key's name follows the random bytes so
 * it can be restored when importing the key on another computer.
 *
 * @const {number}
 */
const USER_HANDLE_RANDOM_BYTES = 16;

/**
 * The maximum length of a WebAuthn user handle.
 *
 * @const {number}
 */
const USER_HANDLE_MAX_BYTES = 64;

/**
 * A key enrolled with this backend.
 *
 * All binary fields are base64url encoded so they can be stored as JSON.
 *
 * @typedef {{
 *   credentialId: string,
 *   publicKey: string,
 *   application: string,
 *   rpId: ?string,
 *   resident: (boolean|undefined),
 *   comment: string,
 *   created: number,
 * }}
 */
export let StoredKey;

/**
 * @param {!Uint8Array|!ArrayBuffer} bytes
 * @return {string}
 */
export function toBase64Url(bytes) {
  // NB: Don't use toBase64's alphabet option as libdot's polyfill ignores it.
  return base64ToBase64Url(new Uint8Array(bytes).toBase64());
}

/**
 * @param {string} str
 * @return {!Uint8Array}
 */
export function fromBase64Url(str) {
  return Uint8Array.fromBase64(base64UrlToBase64(str));
}

/**
 * @param {string} str
 * @return {!Uint8Array}
 */
export function encodeWireCString(str) {
  return encodeAsWireString(new TextEncoder().encode(str));
}

/**
 * @param {!Uint8Array|string} data
 * @return {!Promise<!Uint8Array>}
 */
export async function sha256(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', data));
}

/**
 * Generate the SSH wire format key blob for an sk-ecdsa key.
 *
 * @see PROTOCOL.u2f "SSH U2F public key format"
 * @param {!Uint8Array} publicKey The uncompressed EC point (0x04 || X || Y).
 * @param {string} application The FIDO application (RP ID) string.
 * @return {!Uint8Array}
 */
export function generateSkEcdsaKeyBlob(publicKey, application) {
  return concatTyped(
      encodeWireCString(SK_ECDSA_KEY_TYPE),
      encodeWireCString('nistp256'),
      encodeAsWireString(publicKey),
      encodeWireCString(application));
}

/**
 * Extract the raw EC point from a DER SubjectPublicKeyInfo for a P-256 key.
 *
 * @param {!Uint8Array} spki
 * @return {!Uint8Array} The 65 byte uncompressed point.
 */
export function p256PointFromSpki(spki) {
  // A P-256 SPKI is a fixed 91 bytes: 26 bytes of ASN.1 header (algorithm
  // OIDs & BIT STRING framing) followed by the uncompressed point.
  if (spki.length !== 91 || spki[26] !== 0x04) {
    throw new Error(`unexpected P-256 SPKI encoding (${spki.length} bytes)`);
  }
  return spki.slice(26);
}

/**
 * Decode a DER encoded ECDSA signature into its r & s components.
 *
 * @param {!Uint8Array} der The DER encoding of SEQUENCE { r INTEGER,
 *     s INTEGER }.
 * @return {{r: !Uint8Array, s: !Uint8Array}} Unsigned big endian integers.
 */
export function decodeDerEcdsaSignature(der) {
  let pos = 0;
  const readLength = () => {
    let len = der[pos++];
    if (len & 0x80) {
      const count = len & 0x7f;
      len = 0;
      for (let i = 0; i < count; ++i) {
        len = (len << 8) | der[pos++];
      }
    }
    return len;
  };
  const readInteger = () => {
    if (der[pos++] !== 0x02) {
      throw new Error('ECDSA signature: expected INTEGER');
    }
    const len = readLength();
    const value = der.slice(pos, pos + len);
    pos += len;
    return value;
  };

  if (der[pos++] !== 0x30) {
    throw new Error('ECDSA signature: expected SEQUENCE');
  }
  const seqLen = readLength();
  if (pos + seqLen !== der.length) {
    throw new Error('ECDSA signature: bad SEQUENCE length');
  }
  const r = readInteger();
  const s = readInteger();
  if (pos !== der.length) {
    throw new Error('ECDSA signature: trailing data');
  }
  return {r, s};
}

/**
 * NIST P-256 curve parameters.
 *
 * @see https://www.secg.org/sec2-v2.pdf (secp256r1)
 * @const
 */
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

/**
 * @param {bigint} a
 * @param {bigint} m
 * @return {bigint} a mod m in [0, m).
 */
function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/**
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} m
 * @return {bigint} base^exp mod m.
 */
function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % m;
    }
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

/**
 * @param {bigint} a
 * @param {bigint} m A prime.
 * @return {bigint} The inverse of a mod m.
 */
function modInv(a, m) {
  return modPow(a, m - 2n, m);
}

/**
 * A point on P-256 in affine coordinates.  Functions use null for the point at
 * infinity.
 *
 * @typedef {{x: bigint, y: bigint}}
 */
let P256Point;

/**
 * @param {?P256Point} p1
 * @param {?P256Point} p2
 * @return {?P256Point}
 */
function p256Add(p1, p2) {
  const p = P256.p;
  if (p1 === null) {
    return p2;
  }
  if (p2 === null) {
    return p1;
  }
  let lambda;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y, p) === 0n) {
      return null;
    }
    // Doubling; the curve's a coefficient is -3.
    lambda = mod((3n * p1.x * p1.x - 3n) * modInv(2n * p1.y, p), p);
  } else {
    lambda = mod((p2.y - p1.y) * modInv(p2.x - p1.x, p), p);
  }
  const x = mod(lambda * lambda - p1.x - p2.x, p);
  const y = mod(lambda * (p1.x - x) - p1.y, p);
  return {x, y};
}

/**
 * @param {bigint} k
 * @param {?P256Point} point
 * @return {?P256Point} k * point.
 */
function p256Multiply(k, point) {
  let result = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) {
      result = p256Add(result, addend);
    }
    addend = p256Add(addend, addend);
    k >>= 1n;
  }
  return result;
}

/**
 * @param {!Uint8Array} bytes Big endian.
 * @return {bigint}
 */
function bytesToBigInt(bytes) {
  let ret = 0n;
  for (const byte of bytes) {
    ret = (ret << 8n) | BigInt(byte);
  }
  return ret;
}

/**
 * @param {bigint} value
 * @param {number} length
 * @return {!Uint8Array} Big endian, zero padded to length bytes.
 */
function bigIntToBytes(value, length) {
  const ret = new Uint8Array(length);
  for (let i = length - 1; i >= 0; --i) {
    ret[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return ret;
}

/**
 * Recover the possible public keys that made an ECDSA P-256 signature.
 *
 * WebAuthn never returns the public key of an existing credential, so this is
 * how keys stored on a security key are imported.  Each signature yields up to
 * two candidates; verifying a second signature picks the right one.
 *
 * @see https://www.secg.org/sec1-v2.pdf section 4.1.6
 * @param {!Uint8Array} hash The SHA-256 hash of the signed message.
 * @param {!Uint8Array} r
 * @param {!Uint8Array} s
 * @return {!Array<!Uint8Array>} Uncompressed points (0x04 || X || Y).
 */
export function recoverP256PublicKeys(hash, r, s) {
  const {p, n, b, gx, gy} = P256;
  const rn = bytesToBigInt(r);
  const sn = bytesToBigInt(s);
  if (rn <= 0n || rn >= n || sn <= 0n || sn >= n) {
    return [];
  }
  const e = bytesToBigInt(hash);
  const rInv = modInv(rn, n);
  const u1 = mod(-e * rInv, n);
  const u2 = mod(sn * rInv, n);
  const g = {x: gx, y: gy};

  // R.x == r (R.x == r + n is possible in theory, but astronomically rare).
  const x = rn;
  const ySquared = mod(x * x * x - 3n * x + b, p);
  // p = 3 mod 4, so the square root is a simple exponentiation.
  const y = modPow(ySquared, (p + 1n) / 4n, p);
  if (mod(y * y, p) !== ySquared) {
    return [];
  }

  const keys = [];
  for (const ry of [y, p - y]) {
    const q = p256Add(p256Multiply(u1, g), p256Multiply(u2, {x, y: ry}));
    if (q !== null) {
      keys.push(concatTyped(new Uint8Array([0x04]), bigIntToBytes(q.x, 32),
                            bigIntToBytes(q.y, 32)));
    }
  }
  return keys;
}

/**
 * Verify an ECDSA P-256/SHA-256 signature.
 *
 * @param {!Uint8Array} publicKey Uncompressed point.
 * @param {!Uint8Array} message The signed data (hashed by WebCrypto).
 * @param {{r: !Uint8Array, s: !Uint8Array}} signature
 * @return {!Promise<boolean>}
 */
export async function verifyP256Signature(publicKey, message, {r, s}) {
  const key = await globalThis.crypto.subtle.importKey(
      'raw', publicKey, {name: 'ECDSA', namedCurve: 'P-256'}, false,
      ['verify']);
  const raw = concatTyped(bigIntToBytes(bytesToBigInt(r), 32),
                          bigIntToBytes(bytesToBigInt(s), 32));
  return globalThis.crypto.subtle.verify(
      {name: 'ECDSA', hash: 'SHA-256'}, key, raw, message);
}

/**
 * Figure out which string the authenticator hashed as the RP ID.
 *
 * Browsers differ in what they feed the authenticator for extension origins
 * (the bare extension ID, or the full chrome-extension:// origin), so rather
 * than hardcode it, check the rpIdHash that came back.
 *
 * @param {!Uint8Array} rpIdHash
 * @param {!Array<string>} candidates
 * @return {!Promise<?string>}
 */
export async function findApplication(rpIdHash, candidates) {
  for (const candidate of candidates) {
    if (compare(await sha256(candidate), rpIdHash)) {
      return candidate;
    }
  }
  return null;
}

/**
 * @return {!Promise<!Array<!StoredKey>>} The keys the user has set up.
 */
export async function loadKeys() {
  const keys = await getSyncStorage().getItem(STORAGE_KEY);
  return Array.isArray(keys) ? keys : [];
}

/**
 * @param {!Array<!StoredKey>} keys
 * @return {!Promise<void>}
 */
export async function saveKeys(keys) {
  await getSyncStorage().setItem(STORAGE_KEY, keys);
}

/**
 * @param {!StoredKey} key
 * @return {!Promise<void>}
 */
async function addKey(key) {
  const keys = await loadKeys();
  keys.push(key);
  await saveKeys(keys);
}

/**
 * Forget a key.
 *
 * A key stored on the authenticator stays there; only tools like
 * `ykman fido credentials delete` can remove it.
 *
 * @param {string} credentialId
 * @return {!Promise<void>}
 */
export async function deleteKey(credentialId) {
  const keys = await loadKeys();
  await saveKeys(keys.filter((key) => key.credentialId !== credentialId));
}

/**
 * @param {!StoredKey} key
 * @return {!Uint8Array} The SSH wire format public key.
 */
export function keyBlob(key) {
  return generateSkEcdsaKeyBlob(fromBase64Url(key.publicKey), key.application);
}

/**
 * @param {!StoredKey} key
 * @return {string} The key in authorized_keys format.
 */
export function authorizedKeysLine(key) {
  return `${SK_ECDSA_KEY_TYPE} ${keyBlob(key).toBase64()} ${key.comment}`;
}

/**
 * @param {!Uint8Array} authData authenticatorData from the authenticator.
 * @return {!Promise<string>} The application (RP ID) the authenticator
 *     hashed into authData.
 */
async function applicationFromAuthData(authData) {
  const origin = globalThis.location.origin;
  const application = await findApplication(
      authData.subarray(0, 32), [globalThis.location.hostname, origin]);
  if (application === null) {
    throw new Error(`unable to determine RP ID used for ${origin}`);
  }
  return application;
}

/**
 * Create a new key on a security key and remember it.
 *
 * @param {string} comment Human readable label for the key.
 * @param {boolean=} resident Whether to store the key on the authenticator
 *     (a discoverable credential) so it can be imported elsewhere.
 * @return {!Promise<!StoredKey>}
 */
export async function createKey(comment, resident = false) {
  const userId = concatTyped(
      globalThis.crypto.getRandomValues(
          new Uint8Array(USER_HANDLE_RANDOM_BYTES)),
      new TextEncoder().encode(comment)).subarray(0, USER_HANDLE_MAX_BYTES);

  const credential = await navigator.credentials.create({
    publicKey: {
      // Leave rp.id unset so the browser uses this extension's default RP ID.
      // We work out what it hashed below.
      rp: {name: 'Secure Shell'},
      user: {id: userId, name: comment, displayName: comment},
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)),
      // OpenSSH only supports the webauthn signature format for ECDSA.
      pubKeyCredParams: [{type: 'public-key', alg: COSE_ALG_ES256}],
      authenticatorSelection: {
        residentKey: resident ? 'required' : 'discouraged',
        userVerification: 'discouraged',
      },
      attestation: 'none',
      timeout: WEBAUTHN_TIMEOUT_MS,
    },
  });
  if (!credential) {
    throw new Error('no credential created');
  }

  const response = /** @type {!AuthenticatorAttestationResponse} */ (
      credential.response);
  if (response.getPublicKeyAlgorithm() !== COSE_ALG_ES256) {
    throw new Error('authenticator did not use ES256');
  }
  const publicKey =
      p256PointFromSpki(new Uint8Array(lib.notNull(response.getPublicKey())));
  const authData = new Uint8Array(response.getAuthenticatorData());

  /** @type {!StoredKey} */
  const key = {
    credentialId: toBase64Url(credential.rawId),
    publicKey: toBase64Url(publicKey),
    application: await applicationFromAuthData(authData),
    // Default RP ID was used for creation, so let get() default it too.
    rpId: null,
    resident,
    comment,
    created: Date.now(),
  };
  await addKey(key);
  return key;
}

/**
 * Get an assertion over a random challenge.
 *
 * @param {?string} credentialId The credential to use, or null to let the
 *     authenticator offer its discoverable credentials.
 * @return {!Promise<{
 *   credentialId: string,
 *   authenticatorData: !Uint8Array,
 *   signedData: !Uint8Array,
 *   signature: {r: !Uint8Array, s: !Uint8Array},
 *   userHandle: ?Uint8Array,
 * }>}
 */
async function getAssertion(credentialId) {
  /** @type {!PublicKeyCredentialRequestOptions} */
  const publicKey = {
    challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)),
    userVerification: 'discouraged',
    timeout: WEBAUTHN_TIMEOUT_MS,
  };
  if (credentialId !== null) {
    publicKey.allowCredentials = [{
      type: 'public-key',
      id: fromBase64Url(credentialId),
    }];
  }
  const credential = await navigator.credentials.get({publicKey});
  if (!credential) {
    throw new Error('no assertion');
  }
  const response = /** @type {!AuthenticatorAssertionResponse} */ (
      credential.response);
  const authenticatorData = new Uint8Array(response.authenticatorData);
  const clientDataHash = await sha256(new Uint8Array(response.clientDataJSON));
  return {
    credentialId: toBase64Url(credential.rawId),
    authenticatorData,
    // What the authenticator actually signed.
    signedData: concatTyped(authenticatorData, clientDataHash),
    signature: decodeDerEcdsaSignature(new Uint8Array(response.signature)),
    userHandle: response.userHandle ?
        new Uint8Array(response.userHandle) : null,
  };
}

/**
 * Import a key stored on the authenticator by createKey(comment, true), e.g.
 * when using a new computer.
 *
 * WebAuthn won't tell us the public key of an existing credential, so ask for
 * two signatures: the first yields two candidate keys and the second tells us
 * which one is right.
 *
 * @param {function()=} onSecondTouch Called before asking for the second
 *     signature, e.g. to tell the user to touch their key again.
 * @return {!Promise<!StoredKey>} The imported key, or the existing one if it
 *     was already known.
 */
export async function importKey(onSecondTouch = () => {}) {
  // No allowCredentials: the authenticator offers its stored credentials.
  const first = await getAssertion(null);

  const existing = (await loadKeys()).find(
      (key) => key.credentialId === first.credentialId);
  if (existing) {
    return existing;
  }

  const candidates = recoverP256PublicKeys(
      await sha256(first.signedData), first.signature.r, first.signature.s);

  onSecondTouch();
  const second = await getAssertion(first.credentialId);
  let publicKey = null;
  for (const candidate of candidates) {
    if (await verifyP256Signature(
            candidate, second.signedData, second.signature)) {
      publicKey = candidate;
      break;
    }
  }
  if (publicKey === null) {
    throw new Error('unable to recover public key');
  }

  const userHandle = first.userHandle ?? new Uint8Array(0);
  const comment = new TextDecoder().decode(
      userHandle.subarray(USER_HANDLE_RANDOM_BYTES)) || 'security-key';

  /** @type {!StoredKey} */
  const key = {
    credentialId: first.credentialId,
    publicKey: toBase64Url(publicKey),
    application: await applicationFromAuthData(first.authenticatorData),
    rpId: null,
    resident: true,
    comment,
    created: Date.now(),
  };
  await addKey(key);
  return key;
}
