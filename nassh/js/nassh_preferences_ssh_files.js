// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview SSH file editing helper.
 */

import {lib} from '../../libdot/index.js';

import {getSyncStorage, localize} from './nassh.js';
import {getIndexeddbFileSystem} from './nassh_fs.js';
import {
  StoredKey, authorizedKeysLine, createKey, deleteKey, importKey, loadKeys,
} from './nassh_webauthn_keys.js';

/**
 * A cached handle to the filesystem.
 *
 * @type {?IndexeddbFs}
 */
let filesystem = null;

/**
 * Utility class to bind a file to some basic UI tools.
 */
class FileWatcher {
  /**
   * @param {string} id The HTML id used to find UI elements.
   * @param {string} path The filesystem path to work with.
   */
  constructor(id, path) {
    this.element = document.getElementById(id);
    this.path = path;
    this.bindUi_(id);
    this.load();
  }

  /**
   * Bind this class to the UI elements.
   *
   * @param {string} id The HTML id used to find UI elements.
   */
  bindUi_(id) {
    const clear = document.getElementById(`${id}-clear`);
    if (clear) {
      clear.onclick = this.clear.bind(this);
    }

    const save = document.getElementById(`${id}-save`);
    save.onclick = this.save.bind(this);

    this.element.onkeyup = this.keyup.bind(this);
  }

  /**
   * Load the file.
   *
   * @return {!Promise<void>} Promise that resolves when the load finishes.
   */
  load() {
    return filesystem.readFile(this.path)
      .then((contents) => this.element.value = contents)
      .catch(() => {});
  }

  /**
   * Save the file.
   *
   * @return {!Promise<void>} Promise that resolves when the save finishes.
   */
  save() {
    return filesystem.writeFile(this.path, this.element.value).then(() => {});
  }

  /**
   * Clear the UI.
   */
  clear() {
    this.element.value = '';
  }

  /**
   * Handle keypresses in the UI.
   *
   * @param {?Event} e The keyboard event.
   */
  keyup(e) {
    switch (e.key) {
      // Escape should discard changes & reload content.
      case 'Escape':
        this.load();
        break;

      // Ctrl+Enter saves changes.
      case 'Enter':
        if (e.ctrlKey) {
          this.save();
        }
        break;
    }
  }
}

/**
 * Utility class to bind a directory to some basic UI tools.
 */
class DirWatcher {
  /**
   * @param {string} id The HTML id used to find UI elements.
   * @param {string} path The filesystem path to work with.
   */
  constructor(id, path) {
    this.element = document.getElementById(id);
    this.path = path;
    this.load();
  }

  /**
   * Load the file.
   *
   * @return {!Promise<void>} Promise that resolves when the load finishes.
   */
  load() {
    return filesystem.readDirectory(this.path)
      .then((entries) => {
        entries.files.forEach((file) => this.addFile_(file));
      })
      // The directory doesn't exist until the first connection.
      .catch(() => {});
  }

  /**
   * Add a UI element for this path.
   *
   * @param {!IndexeddbFsFileEntry} path The filesystem path to work with.
   */
  addFile_(path) {
    const li = document.createElement('li');
    const id = `ssh-files-identities:${path.name}`;
    li.id = id;

    const button = document.createElement('button');
    button.textContent = '🗑';
    button.onclick = this.deleteFile_.bind(this, li, path.fullPath);

    const a = document.createElement('a');
    a.download = path.name;
    a.textContent = path.name;
    filesystem.readFile(path.fullPath).then((data) => {
      const blob = new Blob([data], {type: 'text/plain'});
      a.href = URL.createObjectURL(blob);
    });
    a.style.paddingLeft = '1em';
    a.style.paddingRight = '1em';

    li.appendChild(button);
    li.appendChild(a);
    this.element.appendChild(li);
  }

  /**
   * Delete a path.
   *
   * @param {!Element} elementTree The elements associated with this path.
   * @param {string} path The file to delete.
   */
  deleteFile_(elementTree, path) {
    // Delete the file, and then remove the UI element.
    filesystem.removeFile(path).then(() => elementTree.remove());
  }
}

/**
 * Utility class to bind a directory to some basic UI tools.
 */
class StorageFileWatcher {
  /**
   * @param {string} id The HTML id used to find UI elements.
   * @param {!lib.Storage} storage The backing storage for file content.
   * @param {string} key The storage item name.
   */
  constructor(id, storage, key) {
    this.element = document.getElementById(id);
    this.storage = storage;
    this.key = key;
    this.bindUi_(id);
    this.load();
  }

  /**
   * Bind this class to the UI elements.
   *
   * @param {string} id The HTML id used to find UI elements.
   */
  bindUi_(id) {
    const save = document.getElementById(`${id}-save`);
    save.onclick = this.save.bind(this);

    this.element.onkeyup = this.keyup.bind(this);
  }

  /**
   * Load the file.
   *
   * @return {!Promise<void>} Promise that resolves when the load finishes.
   */
  async load() {
    const data = await this.storage.getItem(this.key) ?? '';
    this.element.value = data;
  }

  /**
   * Save the file.
   *
   * @return {!Promise<void>} Promise that resolves when the save finishes.
   */
  async save() {
    if (this.element.value.length === 0) {
      await this.storage.removeItem(this.key);
    } else {
      await this.storage.setItem(this.key, this.element.value);
    }
  }

  /**
   * Handle keypresses in the UI.
   *
   * @param {?Event} e The keyboard event.
   */
  keyup(e) {
    switch (e.key) {
      // Escape should discard changes & reload content.
      case 'Escape':
        this.load();
        break;

      // Ctrl+Enter saves changes.
      case 'Enter':
        if (e.ctrlKey) {
          this.save();
        }
        break;
    }
  }
}

/**
 * Lists the security keys (WebAuthn) set up for the webauthn ssh-agent backend
 * and lets the user create, import, copy & forget them.
 */
class SecurityKeysWatcher {
  /**
   * @param {string} id The HTML id used to find UI elements.
   * @param {!lib.Storage} storage The storage the keys are kept in.
   */
  constructor(id, storage) {
    this.element = document.getElementById(id);
    this.name = document.getElementById(`${id}-name`);
    this.resident = document.getElementById(`${id}-resident`);
    this.status = document.getElementById(`${id}-status`);
    this.createButton = document.getElementById(`${id}-create`);
    this.importButton = document.getElementById(`${id}-import`);

    this.createButton.onclick = this.create.bind(this);
    this.importButton.onclick = this.import.bind(this);
    this.name.onkeyup = (e) => {
      if (e.key === 'Enter') {
        this.create();
      }
    };

    if (!globalThis.PublicKeyCredential) {
      this.createButton.disabled = this.importButton.disabled = true;
      this.setStatus(localize('WEBAUTHN_UNAVAILABLE'));
    }

    // Keys are also added by the agent while connecting, maybe on another
    // device, so keep the list current.
    storage.addObserver(() => this.load());
    this.load();
  }

  /**
   * @param {string} message
   */
  setStatus(message) {
    this.status.textContent = message;
  }

  /**
   * Refresh the list of keys.
   *
   * @return {!Promise<void>}
   */
  async load() {
    const keys = await loadKeys();
    this.element.replaceChildren(...keys.map((key) => this.renderKey_(key)));
    if (keys.length === 0) {
      const li = document.createElement('li');
      li.textContent = localize('WEBAUTHN_KEYS_EMPTY');
      this.element.appendChild(li);
    }
  }

  /**
   * @param {!StoredKey} key
   * @return {!Element}
   */
  renderKey_(key) {
    const li = document.createElement('li');

    const remove = document.createElement('button');
    remove.textContent = '🗑';
    remove.title = localize('WEBAUTHN_KEYS_DELETE');
    remove.onclick = async () => {
      // Ask for a second click to confirm.
      if (remove.dataset.armed) {
        await this.delete(key);
        return;
      }
      remove.dataset.armed = '1';
      remove.textContent = localize('WEBAUTHN_KEYS_DELETE');
      this.setStatus(localize('WEBAUTHN_KEYS_DELETE_CONFIRM', [key.comment]));
      setTimeout(() => {
        delete remove.dataset.armed;
        remove.textContent = '🗑';
      }, 5000);
    };

    const name = document.createElement('span');
    name.textContent = key.comment;
    name.style.paddingLeft = '1em';
    name.style.paddingRight = '1em';
    name.title = authorizedKeysLine(key);

    const details = document.createElement('span');
    details.textContent = new Date(key.created).toLocaleDateString();
    if (key.resident) {
      details.textContent += ` · ${localize('WEBAUTHN_KEYS_STORED_ON_KEY')}`;
    }
    details.style.paddingRight = '1em';

    const copy = document.createElement('button');
    copy.textContent = localize('WEBAUTHN_KEYS_COPY');
    copy.onclick = this.copy.bind(this, key);

    li.append(remove, name, details, copy);
    return li;
  }

  /**
   * Copy a key's authorized_keys line to the clipboard.
   *
   * @param {!StoredKey} key
   * @return {!Promise<void>}
   */
  async copy(key) {
    await navigator.clipboard.writeText(authorizedKeysLine(key));
    this.setStatus(localize('WEBAUTHN_KEYS_COPIED', [key.comment]));
  }

  /**
   * Forget a key.
   *
   * @param {!StoredKey} key
   * @return {!Promise<void>}
   */
  async delete(key) {
    await deleteKey(key.credentialId);
    this.setStatus('');
    await this.load();
  }

  /**
   * Run a WebAuthn operation with the buttons disabled.
   *
   * @param {function(): !Promise<!StoredKey>} operation
   * @param {string} failedMessageId Message to show if the operation fails.
   * @return {!Promise<void>}
   */
  async run_(operation, failedMessageId) {
    this.createButton.disabled = this.importButton.disabled = true;
    try {
      const key = await operation();
      this.setStatus(localize('WEBAUTHN_KEYS_READY', [key.comment]));
      await this.load();
    } catch (e) {
      this.setStatus(localize(failedMessageId, [e.message]));
    } finally {
      this.createButton.disabled = this.importButton.disabled = false;
    }
  }

  /**
   * Create a new key with the name & options from the UI.
   *
   * @return {!Promise<void>}
   */
  async create() {
    const comment = this.name.value.trim();
    if (!comment) {
      this.name.focus();
      return;
    }
    this.setStatus(localize('WEBAUTHN_ENROLL_TOUCH'));
    await this.run_(async () => {
      const key = await createKey(comment, this.resident.checked);
      this.name.value = '';
      return key;
    }, 'WEBAUTHN_ENROLL_FAILED');
  }

  /**
   * Import a key stored on a security key.
   *
   * @return {!Promise<void>}
   */
  async import() {
    this.setStatus(localize('WEBAUTHN_IMPORT_TOUCH'));
    await this.run_(
        () => importKey(
            () => this.setStatus(localize('WEBAUTHN_IMPORT_TOUCH_AGAIN'))),
        'WEBAUTHN_IMPORT_FAILED');
  }
}

/**
 * Name to help with debugging in the terminal.
 */
const watched = {};

/**
 * Event when the window finishes loading.
 */
globalThis.addEventListener('DOMContentLoaded', async (event) => {
  const storage = await getSyncStorage();
  watched.etcSshConfig = new StorageFileWatcher(
      'ssh-files-etc-ssh-config', storage, '/nassh/etc/ssh/ssh_config');
  watched.etcSshKnownHosts = new StorageFileWatcher(
      'ssh-files-etc-ssh-known-hosts', storage,
      '/nassh/etc/ssh/ssh_known_hosts');
  watched.securityKeys =
      new SecurityKeysWatcher('ssh-files-security-keys', storage);

  // Load all the ~/.ssh files into the UI.
  getIndexeddbFileSystem().then((fs) => {
    filesystem = fs;
    watched.knownHosts = new FileWatcher(
        'ssh-files-known-hosts', '/.ssh/known_hosts');
    watched.sshConfig = new FileWatcher(
        'ssh-files-config', '/.ssh/config');
    watched.identities = new DirWatcher(
        'ssh-files-identities', '/.ssh/identity');
  });
});
