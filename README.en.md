# Noctavault

*[Version française](README.md)*

A **post-quantum resistant** encrypted file cloud on a **worldwide public
network**: no central authority, anyone can run a node and join.
Anti-spam is enforced by a per-identity rate limit, not by registration
or permission.

Adding a file produces a lightweight text manifest (`.nvault`, a few KB):
the actual content is encrypted and split into chunks broadcast across
the network, unrecoverable without the owner's private key — or that of
a recipient explicitly chosen when sharing.

## Why post-quantum

Identity and encryption are built entirely on standardized (NIST)
post-quantum primitives, via the PQClean implementations:

- **ML-KEM-1024** for key encapsulation (confidentiality).
- **ML-DSA-65** for signatures (authenticity).

A file is encrypted with a random AES-256 key, itself separately
encapsulated for each recipient under their ML-KEM public key — this is
what enables multi-recipient sharing without ever moving the key in the
clear.

## How it spreads

Every transaction (encrypted chunk, published manifest, revocation) is
signed by its sender and self-authenticates — no block, no mining.
Propagation is by **gossip**: a received, valid, new transaction is
relayed to all known peers; a duplicate is dropped, which stops flooding
on its own. Anti-spam is a **per-identity rate limit** (transactions per
minute), not proof of work. Peer discovery uses mDNS on the local network
and peer exchange (PEX) for the internet.

So a brand-new node can join the network without already knowing anyone
(mDNS only works on the same local network), `nv-node` connects by
default to a public **bootstrap node** if no peer is configured. Once
connected to even a single peer, discovery (PEX) and sync take over on
their own.

## Architecture

```
crates/
  nv-core/   post-quantum identity, .nvault and .nvid file formats
  nv-chain/  ledger of signed transactions, rate limiting, revocation
  nv-net/    network: gossip, sync, mDNS/PEX
  nv-node/   CLI (init/add/get/ls/revoke/id/daemon)
apps/nv-app/ desktop GUI (Tauri; Android planned)
```

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/noctavault/noctavault-project/main/get.sh | sh
```

Detects your distro (Arch, Debian/Ubuntu, Fedora, openSUSE, Alpine),
installs system dependencies and Rust if needed, builds and installs
`nv-node`/`nv-app` into `~/.local/bin`. Or, from an existing clone:
`./get.sh`.

For a headless dedicated server (VPS), see `get-node.sh` — installs only
`nv-node` and sets up a systemd service for the daemon.

## Usage

```bash
cargo build -p nv-node -p nv-app

# Create your post-quantum identity
./target/debug/nv-node --home ~/.noctavault init

# Export your public wallet to hand to a contact
./target/debug/nv-node --home ~/.noctavault id -o me.nvid

# Add a file (encrypted for yourself, plus optional recipients)
./target/debug/nv-node --home ~/.noctavault add my-file.pdf --to alice.nvid,bob.nvid

# List the files known to the local ledger
./target/debug/nv-node --home ~/.noctavault ls

# Recover a file from its manifest
./target/debug/nv-node --home ~/.noctavault get my-file.pdf.nvault

# Revoke a file (purges the chunks on every node that applies the revocation)
./target/debug/nv-node --home ~/.noctavault revoke <file_id>

# Run a full node: network listener, mDNS, sync
./target/debug/nv-node --home ~/.noctavault daemon --listen 0.0.0.0:7777 --peers 203.0.113.7:7777
```

Or launch the GUI (available in French and English):

```bash
cargo run -p nv-app
```

It lets you view/copy your public key, share a file by pasting a
recipient's public key directly (no `.nvid` file needed), and back
up/import your full identity (private key) to switch devices.

## Using your identity on multiple devices

Your identity (`~/.noctavault/identity.nvkey`) is **the only way to
access your files** — there's no account, no password, no central
service. To use it on another device, **copy this file** (USB drive,
`scp`, password manager...) into that device's `~/.noctavault` (or
whichever `--home` you use) before launching `nv-node`/`nv-app` there.

```bash
scp ~/.noctavault/identity.nvkey other-machine:.noctavault/identity.nvkey
```

⚠️ This file is a plaintext private key: treat it like a crypto wallet
(encrypted/offline transport only, never by email or unencrypted chat).
**There is no recovery mechanism** — if `identity.nvkey` is lost, every
file meant for you becomes permanently unrecoverable. Back it up safely
as soon as you create your identity.

## Project status

| Component | Status |
|---|---|
| `nv-core` — post-quantum crypto, `.nvault`/`.nvid` formats | ✅ |
| `nv-chain` — ledger of signed transactions, rate limiting, revocation | ✅ |
| `nv-net` — gossip, sync, mDNS/PEX | ✅ |
| `nv-node` — CLI | ✅ |
| `nv-app` — desktop GUI | ✅ |
| Android | ⏳ |

## Known limitations

- Full replication: every node stores the entire ledger. Fine at the
  project's current size; sharding would need to be considered if the
  network grows significantly.
- The anti-spam rate limit is per identity; creating a new identity is
  free (just a keypair), so it's theoretically bypassable via mass
  creation of throwaway identities (Sybil). No dedicated mitigation yet.

## License

MIT.
