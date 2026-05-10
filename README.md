# thesync

A minimal, real-time, two-way folder synchronization tool for Node.js. 
Zero third-party dependencies — built entirely on Node.js core modules (`net`, `fs`, `crypto`).

Perfect for instantly syncing files between two local servers, laptops, or VMs without setting up complex software or cloud accounts.

## Features

- ⚡️ **Real-time**: Uses `fs.watch` to instantly sync files the moment they change.
- 🔄 **Two-way**: Bi-directional peer-to-peer sync. Either side can add/edit/delete files.
- 🛡️ **Encrypted (Optional)**: AES-256-GCM encryption with an SSH-like interactive prompt. 
- 🪶 **Zero Dependencies**: Keeps your machine clean. Single JavaScript file under the hood.

---

## 🚀 Quick Start (No Installation Needed)

You can run `thesync` directly via `npx` on any machine with Node.js installed.

### 1. Start the Server (Machine A)
Run this on the machine that will host the connection. It will listen on port `8000`.

```bash
npx thesync --folder ./my_shared_folder --port 8000
```
*(If `./my_shared_folder` doesn't exist, it will be automatically created).*

### 2. Connect the Client (Machine B)
Run this on the other machine, pointing to Machine A's IP address.

```bash
npx thesync --folder ./my_local_folder --connect 192.168.1.50:8000
```
> *(Replace `192.168.1.50` with the actual IP address of Machine A).*

**That's it!** Any file added, edited, or deleted in either folder will instantly replicate to the other.

---

## 🔒 Security & Encryption

By default, data is transferred as unencrypted TCP (which is fast and fine for a trusted local network).
If you are syncing across an untrusted network, you can enable **AES-256-GCM encryption**.

1. Start the server with a secret passphrase:
```bash
npx thesync --folder ./data --port 8000 --secret "mySuperSecretPassphrase"
```

2. Connect with the client. It will **interactively prompt** you for the passphrase:
```bash
npx thesync --folder ./data --connect 192.168.1.50:8000
```
```text
[thesync] Passphrase required by SERVER-PC: ****
[auth] Client authenticated ✓
```

> **Security Note:** The passphrase is never stored and never transmitted over the network. Only an HMAC proof-of-knowledge is exchanged.

---

## 🤫 Silent Mode

If you want to run `thesync` in the background (like a daemon or cron job) without spamming your logs, append the `--silent` flag. Fatal errors will still be printed.

```bash
npx thesync --folder ./data --port 8000 --silent
```

---

## 📦 Global Installation (Optional)

If you use it frequently, you can install it globally so you don't need the `npx` prefix:

```bash
npm install -g thesync
```
Then use it directly:
```bash
thesync --folder ./my_data --port 8000
```

---

## Known Limitations

- **Symmetric Folders Only**: It syncs everything inside the chosen folder. You cannot filter or exclude specific sub-directories yet.
- **Whole File Transfer**: It transfers the entire file when changed, not deltas. It is not optimized for massive multi-gigabyte files that change constantly (like active database files). Perfect for source code, documents, photos, and configurations.
