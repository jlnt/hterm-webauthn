// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Externs for the subset of the Web Authentication API used by
 * the webauthn ssh-agent backend.  Our closure-compiler doesn't ship them.
 *
 * @see https://www.w3.org/TR/webauthn-3/
 * @externs
 */

/** @record */
function PublicKeyCredentialCreationOptions() {}

/** @record */
function PublicKeyCredentialRequestOptions() {}

/** @type {!BufferSource} */
PublicKeyCredentialRequestOptions.prototype.challenge;

/** @type {string|undefined} */
PublicKeyCredentialRequestOptions.prototype.rpId;

/** @type {!Array<{type: string, id: !BufferSource}>|undefined} */
PublicKeyCredentialRequestOptions.prototype.allowCredentials;

/** @type {string|undefined} */
PublicKeyCredentialRequestOptions.prototype.userVerification;

/** @type {number|undefined} */
PublicKeyCredentialRequestOptions.prototype.timeout;

/** @constructor */
function AuthenticatorResponse() {}

/** @type {!ArrayBuffer} */
AuthenticatorResponse.prototype.clientDataJSON;

/**
 * @constructor
 * @extends {AuthenticatorResponse}
 */
function AuthenticatorAttestationResponse() {}

/** @return {!ArrayBuffer} */
AuthenticatorAttestationResponse.prototype.getAuthenticatorData = function() {};

/** @return {?ArrayBuffer} */
AuthenticatorAttestationResponse.prototype.getPublicKey = function() {};

/** @return {number} */
AuthenticatorAttestationResponse.prototype.getPublicKeyAlgorithm =
    function() {};

/**
 * @constructor
 * @extends {AuthenticatorResponse}
 */
function AuthenticatorAssertionResponse() {}

/** @type {!ArrayBuffer} */
AuthenticatorAssertionResponse.prototype.authenticatorData;

/** @type {!ArrayBuffer} */
AuthenticatorAssertionResponse.prototype.signature;

/** @type {?ArrayBuffer} */
AuthenticatorAssertionResponse.prototype.userHandle;

/** @constructor */
function PublicKeyCredential() {}

/** @type {string} */
PublicKeyCredential.prototype.id;

/** @type {!ArrayBuffer} */
PublicKeyCredential.prototype.rawId;

/** @type {!AuthenticatorResponse} */
PublicKeyCredential.prototype.response;

/** @constructor */
function CredentialsContainer() {}

/**
 * @param {{publicKey: !PublicKeyCredentialCreationOptions}} options
 * @return {!Promise<?PublicKeyCredential>}
 */
CredentialsContainer.prototype.create = function(options) {};

/**
 * @param {{publicKey: !PublicKeyCredentialRequestOptions}} options
 * @return {!Promise<?PublicKeyCredential>}
 */
CredentialsContainer.prototype.get = function(options) {};

/** @type {!CredentialsContainer} */
Navigator.prototype.credentials;
