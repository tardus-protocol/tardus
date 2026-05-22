# TARDUS Wallet — Signing Procedure

The wallet AppImage must be cryptographically signed before release.
This document is the **one-time setup** + **per-release signing** procedure
for the project owner.

License: TARDUS-PROPRIETARY-1.0.

---

## Tool

`minisign` 0.12 is pre-staged at:

```
deploy/wallet-release/tools/minisign
```

Use that binary directly — no `apt install` required.

---

## One-time setup — generate the signing keypair

**Run this ONCE per project lifetime.** Keep the secret key offline and
backed up; rotating it later invalidates all prior verifications.

```bash
cd ~/Desktop/tardus/deploy/wallet-release
./tools/minisign -G \
  -p keys/tardus-wallet.pub \
  -s keys/tardus-wallet.key
```

`minisign` will prompt for a passphrase. **Pick a strong one and write it
down somewhere physical** (paper, password manager). If lost, the
keypair is unrecoverable.

After it finishes:

```
keys/
├── tardus-wallet.pub    ← safe to publish (paper appendix + website)
└── tardus-wallet.key    ← SECRET. Never commit. Back up offline.
```

The public key contents look like (one trusted comment line + one
base64 line — ~110 bytes total):

```
untrusted comment: minisign public key XXXXXXXXXXXX
RWQ...........base64..............=
```

---

## Per-release signing

Run this **every time** you publish a new wallet build.

```bash
cd ~/Desktop/tardus/deploy/wallet-release

./tools/minisign -S \
  -s keys/tardus-wallet.key \
  -m output/TARDUS-Wallet-0.1.0-x86_64.AppImage \
  -t "TARDUS Wallet v0.1.0 — Linux x86_64 — built $(date -u +%Y-%m-%dT%H:%MZ)" \
  -c "TARDUS Wallet v0.1.0 — Linux x86_64"
```

`minisign` will ask for your passphrase. Output:

```
output/
├── TARDUS-Wallet-0.1.0-x86_64.AppImage
├── TARDUS-Wallet-0.1.0-x86_64.AppImage.sha256
└── TARDUS-Wallet-0.1.0-x86_64.AppImage.minisig  ← created
```

---

## Verification commands users will run

Publish these three lines on the `/download` page:

```bash
# 1. Check SHA-256 (integrity)
sha256sum -c TARDUS-Wallet-0.1.0-x86_64.AppImage.sha256

# 2. Check minisign signature (authenticity)
minisign -V \
  -P "$(cat tardus-wallet.pub | tail -1)" \
  -m TARDUS-Wallet-0.1.0-x86_64.AppImage

# 3. Make it executable + run
chmod +x TARDUS-Wallet-0.1.0-x86_64.AppImage
./TARDUS-Wallet-0.1.0-x86_64.AppImage
```

---

## What to publish where

| File | Where |
|---|---|
| `TARDUS-Wallet-0.1.0-x86_64.AppImage` | Hosting (GitHub Release / Cloudflare R2) |
| `TARDUS-Wallet-0.1.0-x86_64.AppImage.sha256` | Same place |
| `TARDUS-Wallet-0.1.0-x86_64.AppImage.minisig` | Same place |
| `tardus-wallet.pub` (the **public** key) | `web/public/tardus-wallet.pub` + paper appendix |
| `tardus-wallet.key` (the **secret** key) | **Offline only**. Never on git, never on CI, never online. |

---

## After signing

Once you've completed the one-time setup + first signing, tell me:

1. **Path to `tardus-wallet.pub`** — I'll copy it into `web/public/`
2. **Confirmation that `*.minisig` exists in `output/`** — I'll integrate the
   verification command into the `/download` page

I will NOT need access to your secret key at any point.
