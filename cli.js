#!/usr/bin/env node

/**
 * sync.js — Real-Time Two-Way Folder Synchronization
 * =====================================================
 * Usage:
 *   Listen mode (Server A):
 *     node sync.js --folder ./shared_data --port 8000
 *
 *   Connect mode (Server B):
 *     node sync.js --folder ./shared_data --connect 192.168.1.1:8000
 *
 *   Silent mode (no logs):
 *     node sync.js --folder ./shared_data --port 8000 --silent
 *
 *   Encrypted mode (AES-256-GCM, both peers must share the same secret):
 *     node sync.js --folder ./shared_data --port 8000 --secret myPassphrase
 *     node sync.js --folder ./shared_data --connect 192.168.1.1:8000 --secret myPassphrase
 *
 * Only Node.js built-in modules are used: fs, net, path, crypto, events, os.
 */

'use strict';

const fs    = require('fs');
const net   = require('net');
const path  = require('path');
const crypto = require('crypto');
const os    = require('os');

// ─── CLI Argument Parsing ───────────────────────────────────────────────────

const args = process.argv.slice(2);
const getArg = (flag) => {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : null;
};

const FOLDER_ARG  = getArg('--folder');
const PORT_ARG    = getArg('--port');
const CONNECT_ARG = getArg('--connect');
const SILENT      = args.includes('--silent');
const SECRET_ARG  = getArg('--secret');

// Suppress all logs when --silent is passed
if (SILENT) {
  console.log  = () => {};
  console.warn = () => {};
  console.info = () => {};
}

if (!FOLDER_ARG) {
  console.error('ERROR: --folder <path> is required.');
  process.exit(1);
}

if (!PORT_ARG && !CONNECT_ARG) {
  console.error('ERROR: Either --port <port> (listen) or --connect <host:port> (connect) is required.');
  process.exit(1);
}

const SYNC_FOLDER   = path.resolve(FOLDER_ARG);
const NODE_ID       = crypto.randomBytes(4).toString('hex');   // Unique ID for this session
const PROTOCOL_VER  = '1';
const RECONNECT_DELAY_MS = 4000;     // ms between reconnect attempts
const DEBOUNCE_MS        = 150;      // ms to debounce fs.watch events
const ECHO_TTL_MS        = 3000;     // ms to suppress echo for a synced path

// ─── Encryption Utilities ────────────────────────────────────────────────────
// AES-256-GCM, per-session key. --secret is SERVER-ONLY.
// Clients are prompted interactively (like SSH) — passphrase never on the wire.

const ENC_IV_LEN  = 12;  // GCM IV length (bytes)
const ENC_TAG_LEN = 16;  // GCM auth tag length (bytes)
const ENC_PFX_LEN = 4;   // frame size prefix

/** Derives a 32-byte AES key from a passphrase using scrypt. */
function deriveKey(passphrase) {
  return crypto.scryptSync(passphrase, 'thesync-v1-kdf-salt', 32);
}

/** Encrypts a Buffer with given key. Frame: [4B len][12B IV][16B tag][ciphertext] */
function encryptFrameWith(key, plaintext) {
  const iv     = crypto.randomBytes(ENC_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();
  const prefix = Buffer.allocUnsafe(ENC_PFX_LEN);
  prefix.writeUInt32BE(ENC_IV_LEN + ENC_TAG_LEN + enc.length, 0);
  return Buffer.concat([prefix, iv, tag, enc]);
}

/** Decrypts one encrypted frame. Returns plaintext or null on failure. */
function decryptFrameWith(key, iv, tag, ciphertext) {
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ciphertext), d.final()]);
  } catch { return null; }
}

/**
 * Interactive passphrase prompt — masks input with '*' (like SSH).
 * The passphrase is never stored beyond this session.
 */
function promptPassphrase(promptText) {
  return new Promise((resolve) => {
    process.stdout.write(promptText);
    if (!process.stdin.isTTY) {
      process.stdin.setEncoding('utf8');
      process.stdin.resume();
      process.stdin.once('data', (d) => { process.stdout.write('\n'); resolve(d.toString().trim()); });
      return;
    }
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    let pw = '';
    const onData = (ch) => {
      if (ch === '\r' || ch === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(pw);
      } else if (ch === '\u0003') {
        process.stdout.write('\n'); process.exit(1);
      } else if (ch === '\u007f' || ch === '\b') {
        if (pw.length > 0) { pw = pw.slice(0, -1); process.stdout.write('\b \b'); }
      } else {
        pw += ch; process.stdout.write('*');
      }
    };
    process.stdin.on('data', onData);
  });
}

// ─── Ensure sync folder exists ──────────────────────────────────────────────

if (!fs.existsSync(SYNC_FOLDER)) {
  fs.mkdirSync(SYNC_FOLDER, { recursive: true });
  console.log(`[sync] Created sync folder: ${SYNC_FOLDER}`);
}

// ─── Echo Prevention ────────────────────────────────────────────────────────
// When we write a file/dir as a result of a remote sync, we mark it here so
// our local fs.watch handler ignores it for a short window.

/** @type {Map<string, number>} relativePath → timestamp */
const echoCooldown = new Map();

function markEcho(relPath) {
  echoCooldown.set(relPath, Date.now() + ECHO_TTL_MS);
}

function isEcho(relPath) {
  const exp = echoCooldown.get(relPath);
  if (!exp) return false;
  if (Date.now() < exp) return true;
  echoCooldown.delete(relPath);
  return false;
}

// ─── Message Framing ─────────────────────────────────────────────────────────
// Protocol: [4-byte BE uint32 = JSON header length][JSON header][binary body]
// The JSON header contains: { cmd, ...metadata }
// For SYNC_FILE, body = raw file bytes. For all others, body is empty.

const HEADER_BYTES = 4; // bytes reserved for the header length prefix

function encodeMessage(headerObj, body = null) {
  const headerBuf = Buffer.from(JSON.stringify(headerObj), 'utf8');
  const bodyBuf   = body ? Buffer.from(body) : Buffer.alloc(0);
  const prefix    = Buffer.allocUnsafe(HEADER_BYTES);
  prefix.writeUInt32BE(headerBuf.length, 0);
  return Buffer.concat([prefix, headerBuf, bodyBuf]);
}

// ─── Message Parser (streaming) ──────────────────────────────────────────────

class MessageParser {
  constructor(onMessage) {
    this._buf      = Buffer.alloc(0);
    this._onMessage = onMessage;
  }

  push(chunk) {
    this._buf = Buffer.concat([this._buf, chunk]);
    this._process();
  }

  _process() {
    while (true) {
      // Need at least 4 bytes for header length
      if (this._buf.length < HEADER_BYTES) break;

      const headerLen = this._buf.readUInt32BE(0);
      const totalHeaderEnd = HEADER_BYTES + headerLen;

      // Need full header
      if (this._buf.length < totalHeaderEnd) break;

      const headerJson = this._buf.slice(HEADER_BYTES, totalHeaderEnd).toString('utf8');
      let header;
      try {
        header = JSON.parse(headerJson);
      } catch (e) {
        console.error('[framing] Failed to parse header JSON:', e.message);
        this._buf = Buffer.alloc(0);
        break;
      }

      const bodyLen  = header.bodyLen || 0;
      const totalLen = totalHeaderEnd + bodyLen;

      if (this._buf.length < totalLen) break;

      const body = bodyLen > 0 ? this._buf.slice(totalHeaderEnd, totalLen) : null;
      this._buf  = this._buf.slice(totalLen);

      this._onMessage(header, body);
    }
  }
}

// ─── Safe Relative Path Helper ───────────────────────────────────────────────

function toRelative(absPath) {
  return path.relative(SYNC_FOLDER, absPath).replace(/\\/g, '/');
}

function toAbsolute(relPath) {
  return path.join(SYNC_FOLDER, relPath.replace(/\//g, path.sep));
}

function isSafeRelPath(relPath) {
  // Prevent path traversal attacks
  const abs = path.resolve(SYNC_FOLDER, relPath);
  return abs.startsWith(SYNC_FOLDER + path.sep) || abs === SYNC_FOLDER;
}

// ─── File System Watcher ─────────────────────────────────────────────────────

/** @type {Set<(relPath: string, event: string) => void>} */
const fsListeners = new Set();

/** @type {Map<string, ReturnType<typeof setTimeout>>} debounce timers */
const debounceTimers = new Map();

/** @type {Map<string, fs.FSWatcher>} Watchers keyed by absolute dir path */
const watchers = new Map();

function notifyChange(absPath, eventType) {
  const relPath = toRelative(absPath);

  if (isEcho(relPath)) {
    // This change was caused by our own sync write — ignore it.
    return;
  }

  // Debounce: reset timer for this path
  if (debounceTimers.has(relPath)) {
    clearTimeout(debounceTimers.get(relPath));
  }

  debounceTimers.set(relPath, setTimeout(() => {
    debounceTimers.delete(relPath);
    fsListeners.forEach(fn => fn(relPath, eventType));
  }, DEBOUNCE_MS));
}

function watchDir(absDir) {
  if (watchers.has(absDir)) return;

  let watcher;
  try {
    watcher = fs.watch(absDir, { recursive: false }, (eventType, filename) => {
      if (!filename) return;
      const absPath = path.join(absDir, filename);

      // Check if the path still exists to determine add/change vs delete
      fs.stat(absPath, (err, stat) => {
        if (err) {
          // File/dir no longer exists → deletion event
          notifyChange(absPath, 'unlink');
        } else if (stat.isDirectory()) {
          // New directory appeared — watch it too
          watchDir(absPath);
          notifyChange(absPath, 'addDir');
        } else {
          notifyChange(absPath, 'change');
        }
      });
    });

    watcher.on('error', (err) => {
      console.warn(`[watcher] Error on ${absDir}:`, err.message);
      watchers.delete(absDir);
    });

    watchers.set(absDir, watcher);
  } catch (e) {
    console.warn(`[watcher] Could not watch ${absDir}:`, e.message);
  }
}

function startWatching() {
  // Walk directory tree and watch each directory
  function walk(dir) {
    watchDir(dir);
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const ent of entries) {
      if (ent.isDirectory()) {
        walk(path.join(dir, ent.name));
      }
    }
  }
  walk(SYNC_FOLDER);
  console.log(`[watcher] Watching ${SYNC_FOLDER}`);
}

// ─── Sync Sender ─────────────────────────────────────────────────────────────
// Takes a change event and produces the correct message(s) to send over the socket.

/**
 * Recursively reads all files/dirs under absDir and returns encoded messages.
 * Used when a whole directory is pasted/copied in at once.
 */
async function buildDirSyncMessages(absDir) {
  const messages = [];

  async function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const ent of entries) {
      const absPath = path.join(dir, ent.name);
      const relPath = toRelative(absPath);

      if (ent.isDirectory()) {
        // Ensure new subdirs are watched
        watchDir(absPath);
        messages.push(encodeMessage({ cmd: 'CREATE_DIR', path: relPath, bodyLen: 0 }));
        await walk(absPath);
      } else {
        await new Promise((resolve) => {
          fs.readFile(absPath, (err, data) => {
            if (err) {
              if (err.code !== 'ENOENT') {
                console.warn(`[sender] Could not read ${relPath}: ${err.message}`);
              }
            } else {
              messages.push(encodeMessage({ cmd: 'SYNC_FILE', path: relPath, bodyLen: data.length }, data));
            }
            resolve();
          });
        });
      }
    }
  }

  await walk(absDir);
  return messages;
}

async function buildSyncMessages(relPath, eventType) {
  const absPath = toAbsolute(relPath);

  if (eventType === 'unlink') {
    // Could be file or directory deletion
    return [encodeMessage({ cmd: 'DELETE_FILE', path: relPath, bodyLen: 0 })];
  }

  if (eventType === 'addDir') {
    // Send CREATE_DIR for the directory itself, then recursively sync all
    // files/subdirs inside it (handles copy-paste of entire folders)
    const msgs = [encodeMessage({ cmd: 'CREATE_DIR', path: relPath, bodyLen: 0 })];
    const children = await buildDirSyncMessages(absPath);
    return msgs.concat(children);
  }

  // 'change' or 'add' — try to read the file
  return new Promise((resolve) => {
    fs.readFile(absPath, (err, data) => {
      if (err) {
        // File might have been deleted between the event and the read
        if (err.code === 'ENOENT') {
          resolve([encodeMessage({ cmd: 'DELETE_FILE', path: relPath, bodyLen: 0 })]);
        } else if (err.code === 'EBUSY' || err.code === 'EPERM') {
          // File is locked — skip silently
          console.warn(`[sender] Skipping locked file: ${relPath}`);
          resolve([]);
        } else {
          console.error(`[sender] Read error for ${relPath}:`, err.message);
          resolve([]);
        }
      } else {
        resolve([encodeMessage({ cmd: 'SYNC_FILE', path: relPath, bodyLen: data.length }, data)]);
      }
    });
  });
}

// ─── Sync Receiver ───────────────────────────────────────────────────────────
// Applies remote messages to the local filesystem.

function applyMessage(header, body) {
  const relPath = header.path;

  if (!relPath || !isSafeRelPath(relPath)) {
    console.warn(`[receiver] Rejected unsafe path: ${relPath}`);
    return;
  }

  const absPath = toAbsolute(relPath);

  switch (header.cmd) {
    case 'SYNC_FILE': {
      const dir = path.dirname(absPath);
      markEcho(relPath);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFile(absPath, body || Buffer.alloc(0), (err) => {
        if (err) {
          console.error(`[receiver] Failed to write ${relPath}:`, err.message);
          echoCooldown.delete(relPath); // unmark on failure
        } else {
          console.log(`[receiver] Synced file: ${relPath}`);
          // Watch newly created directories
          watchDir(dir);
        }
      });
      break;
    }

    case 'DELETE_FILE': {
      markEcho(relPath);
      // Try file first, then directory
      fs.rm(absPath, { recursive: true, force: true }, (err) => {
        if (err) {
          console.error(`[receiver] Failed to delete ${relPath}:`, err.message);
          echoCooldown.delete(relPath);
        } else {
          console.log(`[receiver] Deleted: ${relPath}`);
        }
      });
      break;
    }

    case 'CREATE_DIR': {
      markEcho(relPath);
      fs.mkdir(absPath, { recursive: true }, (err) => {
        if (err && err.code !== 'EEXIST') {
          console.error(`[receiver] Failed to create dir ${relPath}:`, err.message);
          echoCooldown.delete(relPath);
        } else {
          console.log(`[receiver] Created dir: ${relPath}`);
          watchDir(absPath);
        }
      });
      break;
    }

    case 'DELETE_DIR': {
      markEcho(relPath);
      fs.rm(absPath, { recursive: true, force: true }, (err) => {
        if (err) {
          console.error(`[receiver] Failed to delete dir ${relPath}:`, err.message);
          echoCooldown.delete(relPath);
        } else {
          console.log(`[receiver] Deleted dir: ${relPath}`);
        }
      });
      break;
    }

    default:
      console.warn(`[receiver] Unknown command: ${header.cmd}`);
  }
}

// ─── Peer Session ─────────────────────────────────────────────────────────────
// SSH-style asymmetric handshake:
//   1. Server sends HANDSHAKE first (with authRequired + challenge if --secret set)
//   2. Client responds:
//        - No auth needed  → plain HANDSHAKE
//        - Auth needed     → prompts user, sends HANDSHAKE + HMAC (passphrase never sent)
//   3. Encryption activates after auth completes (both sides use same derived key)

class PeerSession {
  constructor(socket, direction) {
    this.socket    = socket;
    this.direction = direction;
    this.ready     = false;
    this._encKey   = null;           // set after auth
    this._encBuf   = Buffer.alloc(0);
    this._parser   = new MessageParser((h, b) => this._onMessage(h, b));

    socket.setNoDelay(true);
    socket.on('data',  (chunk) => this._onRawData(chunk));
    socket.on('end',   () => this._onDisconnect('end'));
    socket.on('error', (err) => this._onDisconnect(`error: ${err.message}`));
    socket.on('close', () => this._onDisconnect('close'));

    // Only the server sends the handshake first (client waits)
    if (direction === 'inbound') this._sendServerHandshake();
  }

  _onRawData(chunk) {
    if (!this._encKey) {
      this._parser.push(chunk);
    } else {
      this._encBuf = Buffer.concat([this._encBuf, chunk]);
      this._drainEncrypted();
    }
  }

  _drainEncrypted() {
    while (true) {
      if (this._encBuf.length < ENC_PFX_LEN) break;
      const inner = this._encBuf.readUInt32BE(0);
      const total = ENC_PFX_LEN + inner;
      if (this._encBuf.length < total) break;
      const iv   = this._encBuf.slice(ENC_PFX_LEN, ENC_PFX_LEN + ENC_IV_LEN);
      const tag  = this._encBuf.slice(ENC_PFX_LEN + ENC_IV_LEN, ENC_PFX_LEN + ENC_IV_LEN + ENC_TAG_LEN);
      const enc  = this._encBuf.slice(ENC_PFX_LEN + ENC_IV_LEN + ENC_TAG_LEN, total);
      this._encBuf = this._encBuf.slice(total);
      const plain = decryptFrameWith(this._encKey, iv, tag, enc);
      if (plain === null) {
        console.error('[security] Decryption failed — wrong passphrase or tampered data. Disconnecting.');
        this.socket.destroy(); return;
      }
      this._parser.push(plain);
    }
  }

  // SERVER: send handshake first with optional challenge
  _sendServerHandshake() {
    const h = { cmd: 'HANDSHAKE', nodeId: NODE_ID, protoVer: PROTOCOL_VER, hostname: os.hostname(), bodyLen: 0 };
    if (SECRET_ARG) {
      this._challenge   = crypto.randomBytes(32).toString('hex');
      h.authRequired    = true;
      h.challenge       = this._challenge;
    } else {
      h.authRequired = false;
    }
    this.socket.write(encodeMessage(h));
  }

  _onMessage(header, body) {
    if (!this.ready) {
      if (header.cmd !== 'HANDSHAKE') { this.socket.destroy(); return; }
      if (header.protoVer !== PROTOCOL_VER) {
        console.error('[handshake] Protocol version mismatch.'); this.socket.destroy(); return;
      }
      if (this.direction === 'outbound') {
        this._clientHandleServerHS(header);   // client received server's HS
      } else {
        this._serverHandleClientHS(header);   // server received client's HS
      }
      return;
    }
    applyMessage(header, body);
  }

  // CLIENT: received server's handshake
  _clientHandleServerHS(sh) {
    if (!sh.authRequired) {
      // No auth: send plain handshake and we're done
      this.socket.write(encodeMessage({ cmd: 'HANDSHAKE', nodeId: NODE_ID, protoVer: PROTOCOL_VER, hostname: os.hostname(), bodyLen: 0 }));
      this._markReady(sh);
    } else {
      this._clientDoAuthPrompt(sh);
    }
  }

  async _clientDoAuthPrompt(sh) {
    const pw = await promptPassphrase(`\n[thesync] Passphrase required by ${sh.hostname}: `);
    if (!pw) { console.error('[auth] Empty passphrase.'); this.socket.destroy(); return; }
    const key  = deriveKey(pw);
    const hmac = crypto.createHmac('sha256', key).update(sh.challenge).digest('hex');
    this.socket.write(encodeMessage({ cmd: 'HANDSHAKE', nodeId: NODE_ID, protoVer: PROTOCOL_VER, hostname: os.hostname(), hmac, bodyLen: 0 }));
    this._encKey = key;   // activate encryption for all future messages
    this._markReady(sh);
  }

  // SERVER: received client's handshake response
  _serverHandleClientHS(ch) {
    if (SECRET_ARG) {
      if (!ch.hmac) {
        console.error('[auth] Client sent no passphrase proof. Disconnecting.'); this.socket.destroy(); return;
      }
      const key      = deriveKey(SECRET_ARG);
      const expected = crypto.createHmac('sha256', key).update(this._challenge).digest('hex');
      const a = Buffer.from(ch.hmac,   'hex');
      const b = Buffer.from(expected,  'hex');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        console.error('[auth] Wrong passphrase. Disconnecting.'); this.socket.destroy(); return;
      }
      console.log('[auth] Client authenticated ✓');
      this._encKey = key;  // activate encryption
    }
    this._markReady(ch);
  }

  _markReady(remoteHeader) {
    this.remoteId = remoteHeader.nodeId;
    const enc = this._encKey ? ' [AES-256-GCM encrypted]' : ' [unencrypted]';
    console.log(`[handshake] Connected to peer ${remoteHeader.nodeId} (${remoteHeader.hostname}) via ${this.direction} connection.${enc}`);
    this.ready = true;
    activePeer = this;
    if (!watcherStarted) {
      watcherStarted = true;
      startWatching();
      fsListeners.add(async (relPath, eventType) => {
        if (!activePeer || !activePeer.ready) return;
        const msgs = await buildSyncMessages(relPath, eventType);
        for (const msg of msgs) activePeer.send(msg);
      });
    }
  }

  send(buffer) {
    if (this.socket.writable) {
      const data = this._encKey ? encryptFrameWith(this._encKey, buffer) : buffer;
      this.socket.write(data);
    }
  }

  _onDisconnect(reason) {
    if (this.ready || reason !== 'close') console.log(`[peer] Disconnected (${reason})`);
    if (activePeer === this) activePeer = null;
    this.ready = false;
  }
}

// ─── Global State ─────────────────────────────────────────────────────────────

/** @type {PeerSession | null} */
let activePeer = null;
let watcherStarted = false;

// ─── Listen Mode ─────────────────────────────────────────────────────────────

function startServer(port) {
  const server = net.createServer((socket) => {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[server] Inbound connection from ${remote}`);

    if (activePeer && activePeer.ready) {
      console.log('[server] Already have an active peer. Rejecting new connection.');
      socket.destroy();
      return;
    }

    new PeerSession(socket, 'inbound');
  });

  server.on('error', (err) => {
    console.error('[server] Fatal error:', err.message);
    process.exit(1);
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`[server] Listening on port ${port}. Waiting for peer to connect...`);
    console.log(`[server] Sync folder: ${SYNC_FOLDER}`);
  });
}

// ─── Connect Mode (with auto-reconnect) ──────────────────────────────────────

function connectToPeer(host, port) {
  let reconnectTimer = null;

  function attempt() {
    console.log(`[client] Connecting to ${host}:${port} ...`);
    const socket = new net.Socket();

    socket.connect(port, host, () => {
      console.log(`[client] TCP connection established to ${host}:${port}`);
      clearTimeout(reconnectTimer);

      const session = new PeerSession(socket, 'outbound');

      // When this socket disconnects, schedule reconnect
      socket.once('close', () => {
        if (!reconnectTimer) {
          console.log(`[client] Will attempt to reconnect in ${RECONNECT_DELAY_MS / 1000}s...`);
          reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            attempt();
          }, RECONNECT_DELAY_MS);
        }
      });
    });

    socket.on('error', (err) => {
      console.warn(`[client] Connection error: ${err.message}. Retrying in ${RECONNECT_DELAY_MS / 1000}s...`);
      socket.destroy();
      if (!reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          attempt();
        }, RECONNECT_DELAY_MS);
      }
    });
  }

  attempt();
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

console.log(`[sync] Node ID: ${NODE_ID}`);
console.log(`[sync] Sync folder: ${SYNC_FOLDER}`);

if (PORT_ARG) {
  const port = parseInt(PORT_ARG, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error('ERROR: Invalid port number.');
    process.exit(1);
  }
  startServer(port);
} else {
  const parts = CONNECT_ARG.split(':');
  if (parts.length !== 2) {
    console.error('ERROR: --connect must be in <host:port> format.');
    process.exit(1);
  }
  const host = parts[0];
  const port = parseInt(parts[1], 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error('ERROR: Invalid port in --connect.');
    process.exit(1);
  }
  connectToPeer(host, port);
}

// ─── Graceful Shutdown ───────────────────────────────────────────────────────

process.on('SIGINT', () => {
  console.log('\n[sync] Shutting down...');
  for (const watcher of watchers.values()) {
    watcher.close();
  }
  if (activePeer) {
    activePeer.socket.destroy();
  }
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('[sync] Uncaught exception:', err);
  // Stay alive — don't crash the sync daemon
});
