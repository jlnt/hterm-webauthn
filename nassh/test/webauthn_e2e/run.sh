#!/bin/bash
# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# End-to-end test of the `webauthn` ssh-agent backend: logs in to a throwaway
# sshd on 127.0.0.1:2222 as the current user from the packaged extension,
# using a virtual FIDO authenticator.  Runs once with a regular key, and once
# with a key stored on the authenticator that is then imported back.
#
# Usage: run.sh [path to SecureShell-unpacked-*.zip]
# Needs: sshd, node & playwright (set PLAYWRIGHT_DIR to its node_modules if it
# isn't resolvable from here) with its "chromium" browser installed.
set -euo pipefail
cd "$(dirname "$0")/../../.."
zip=$(realpath "${1:-$(ls nassh/dist/SecureShell-unpacked-*.zip | head -1)}")
work=$(mktemp -d)
trap 'kill $(cat "$work/sshd.pid" 2>/dev/null) 2>/dev/null; rm -rf "$work"' \
    EXIT

ssh-keygen -q -t ed25519 -N '' -f "$work/hostkey"
cat > "$work/sshd_config" <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $work/hostkey
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
PermitRootLogin yes
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
CFG
sshd=$(command -v sshd || echo /usr/sbin/sshd)
"$sshd" -f "$work/sshd_config" -E "$work/sshd.log"

unzip -q "$zip" -d "$work/ext"
for mode in plain resident; do
  echo "=== $mode"
  rm -rf "$work/profile" "$work/authorized_keys"
  : > "$work/sshd.log"
  node nassh/test/webauthn_e2e/extension_e2e.mjs "$(echo "$work"/ext/*)" \
      "$work/profile" "$work/authorized_keys" 2222 "$(id -un)" "$mode"
  grep 'Accepted publickey' "$work/sshd.log"
done
