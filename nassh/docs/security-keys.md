# Using FIDO2/U2F security keys with Secure Shell

Secure Shell can authenticate with a FIDO2/U2F security key (YubiKey,
Titan, SoloKey, Nitrokey, …) or a passkey, using the same
`sk-ecdsa-sha2-nistp256@openssh.com` key type that native OpenSSH uses for
`ssh-keygen -t ecdsa-sk`.  No private key file is involved: the private key
lives on the authenticator, and each login requires a touch.

## Install (prebuilt)

This fork's CI builds the extension on every push.  Grab
`SecureShell-webauthn-*.zip` from the
Releases page of this repository (the rolling `latest`
pre-release), unzip it somewhere permanent, then in `chrome://extensions`
enable **Developer mode**, click **Load unpacked** and pick the unzipped
folder.

The build keeps the upstream dev-channel extension ID
(`algkcnfjnajfhgimadimbjhmpaeohhln`).  That matters for two reasons:

* Chrome only grants `chrome.sockets` (direct TCP connections) to Secure
  Shell's known IDs; a fresh ID would leave you needing a relay.
* WebAuthn credentials are bound to the extension's origin
  (`chrome-extension://algkcnfjnajfhgimadimbjhmpaeohhln`), so a stable ID keeps
  your enrolled keys working across reinstalls and machines.

As a consequence it can't be installed next to "Secure Shell (dev)" from the
Web Store, but it can sit next to the regular Secure Shell.

To build it yourself: `./nassh/bin/mkdist && ./nassh/bin/mkdist-unpacked`
produces `nassh/dist/SecureShell-unpacked-<version>.zip`.

## Quick start

1. Open Secure Shell, create a connection and set its SSH relay server
   options to `--ssh-agent=webauthn`.
2. Connect.  Since no key exists yet, you're asked to name a new one.  Type
   a name, optionally tick "Store the key on the security key" (see below),
   press Enter, then touch your security key.
3. The terminal prints a line such as:
   ```
   sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVj...ZjZGVm my-yubikey
   ```
   Append it to `~/.ssh/authorized_keys` on the server (using some other
   login method this one time).
4. Reconnect.  Touch the key when asked.

To add more keys later (e.g. a backup key), use Options → SSH Files (see
[Managing keys](#managing-keys)).  Keys are stored (public data only: public
key, credential ID and RP ID) in synced extension storage, so they follow you
to other devices where you're signed in to Chrome.

Agent forwarding (`-A`) works; every signature still needs a physical touch.

## Managing keys

Options → **SSH Files** → **Security keys (WebAuthn)** lists your keys.  From
there you can copy a key's public key (e.g. if you didn't save the line
printed when it was created), forget a key (click 🗑 twice; also remove it
from `authorized_keys` on your servers), and create or import keys without
connecting anywhere.

## Where the private key lives

The private key never leaves the security key.  What differs is where the
reference to it (the WebAuthn credential ID) lives:

* **Default:** the security key encrypts the private key with a secret that
  never leaves the device and hands the result back as the credential ID.
  Secure Shell keeps it in synced extension storage, along with the public
  key.  Nothing is stored on the security key, so this uses none of its
  slots, but if that storage is lost you have to create a new key (that's
  harmless: just add the new public key to `authorized_keys`).  This is the
  same as `ssh-keygen -t ecdsa-sk`.
* **"Store the key on the security key" ticked:** the key is created as a
  resident (discoverable) credential, like `ssh-keygen -O resident`.  It uses
  one of the security key's slots (25 on older YubiKey 5 firmware, 100 on 5.7+)
  and security keys usually require a FIDO2 PIN for it.  In return, the key
  goes wherever the security key goes: on another computer (or after wiping
  Chrome's data), leave the name empty at the prompt to import it, or use
  **Import from security key** in Options → SSH Files.  You touch
  the key twice (and may enter the PIN): WebAuthn doesn't reveal the public
  key of an existing credential, so Secure Shell recovers it from two
  signatures.  Resident keys can be listed & deleted with
  `ykman fido credentials list` / `delete`.

## Server requirements

OpenSSH 8.2 or newer on the server.  sshd must accept the
`sk-ecdsa-sha2-nistp256@openssh.com` key type, which it does by default.
Verified against OpenSSH 9.6p1 (Ubuntu 24.04) with no server config changes;
[webauthn_e2e/run.sh](../test/webauthn_e2e/run.sh) does that in CI by
logging in from the packaged extension with a virtual authenticator.

## Why can't I use my existing `ssh-keygen -t ecdsa-sk` key?

Every FIDO credential is bound to an "application" / relying party ID (RP
ID).  `ssh-keygen` always uses an application starting with `ssh:` (default
`ssh:`).  Browsers only let a page/extension use WebAuthn with an RP ID that
it owns (for an extension, its own ID), and never `ssh:`.  So the extension
can't produce signatures for keys made by `ssh-keygen`, and keys made by the
extension can't be used by native `ssh` with `ssh-sk-helper` either.

The extension therefore creates its own credential on the same hardware.  A
single YubiKey can hold any number of these alongside your `ssh-keygen` ones.

Reaching existing `ssh:` keys would need raw USB/HID access to the
authenticator (Chrome blocks FIDO devices from WebHID/WebUSB) or a native
messaging helper — i.e. running the native `ssh-agent`, which Secure Shell
can already use via `--ssh-agent=<extension id>` relays.

## How it works

OpenSSH has two signature formats for `sk-ecdsa` keys:

* `sk-ecdsa-sha2-nistp256@openssh.com`: the authenticator signs
  `SHA256(application) || flags || counter || SHA256(data)` (raw CTAP).
  Browsers can't produce this, because WebAuthn never signs caller-chosen
  data directly.
* `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`: the authenticator signs
  `authenticatorData || SHA256(clientDataJSON)`, where the browser-generated
  `clientDataJSON` embeds the base64url SSH session data as the `challenge`.
  sshd checks that `clientDataJSON` starts with
  `{"type":"webauthn.get","challenge":"<data>","origin":"<origin>"` and that
  the rpIdHash in `authenticatorData` equals `SHA256(application)` from the
  public key.  This format was added to OpenSSH specifically for web clients.

The `webauthn` agent backend
([nassh_agent_backend_webauthn.js](../js/nassh_agent_backend_webauthn.js)):

* Enrollment: `navigator.credentials.create()` with ES256, no attestation,
  and a resident key only if the user asks for one.  The user handle is 16
  random bytes (so resident keys never replace each other) followed by the
  key's name (so importing can restore it).  It reads back the rpIdHash the authenticator recorded and
  matches it against candidate strings (`location.hostname`,
  `location.origin`) to find the exact `application` value to put in the SSH
  public key.  In Chrome extensions that turns out to be the full origin,
  e.g. `chrome-extension://algkcnfjnajfhgimadimbjhmpaeohhln`.
* Import: `navigator.credentials.get()` without `allowCredentials` lets the
  user pick a resident credential.  ECDSA public key recovery (SEC 1 §4.1.6)
  on that signature gives two candidate public keys; a second assertion
  verified with WebCrypto picks the right one.
* `REQUEST_IDENTITIES`: returns the stored keys as `sk-ecdsa` key blobs.
* `SIGN_REQUEST`: calls `navigator.credentials.get()` with the SSH data as
  the challenge and the key's credential ID, then repackages
  `authenticatorData`, `clientDataJSON` and the (DER → mpint) signature as a
  `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature.

The bundled WASM OpenSSH client (10.2+) accepts agent signatures in the
webauthn format for `sk` keys (see the 10.2 `webauthn-ecdsa-sig` patch, since
merged upstream), so no client changes were needed.

## Passkeys?

Since the backend just uses WebAuthn with ES256, the same flow works with
platform authenticators and synced passkeys (Google Password Manager, iCloud
Keychain, Windows Hello) — choose one in Chrome's WebAuthn dialog during
enrollment.  sshd can't tell the difference.  Trade-off: a synced passkey is
only as strong as the account it syncs with, whereas a hardware key is
non-exportable.  Servers that want to insist on hardware can use
`authorized_keys` options/certificates with attestation, which this backend
does not collect.

## Limitations / TODO

* Only ECDSA P-256.  OpenSSH has no webauthn signature format for
  `sk-ssh-ed25519`.
* `verify-required` (PIN/biometric) keys: the backend asks for
  `userVerification: 'discouraged'`.  Making this configurable per key would
  allow sshd's `verify-required` option.
* Keys created by `ssh-keygen -O resident` can't be imported: their
  application is `ssh:`, which browsers won't let an extension use.
* RP ID is the extension's own default.  Chrome (M122+) also allows an
  extension to use any domain it holds host permissions for, which would let
  credentials be shared with a web-based SSH client on that domain.
