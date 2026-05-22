# TARDUS Web App — Security Posture

This document tracks the web-app security commitments made to Komite 2
(Q5 hardening, 2026-05-22). It is the operator-facing companion to the
CSP shipped in `index.html`.

License: TARDUS-PROPRIETARY-1.0.

---

## Current state (MVP)

| Layer | Status | Notes |
|---|---|---|
| HTTPS only | required at deploy | hosting-specific (Cloudflare / Vercel auto) |
| DNSSEC | required at deploy | DNS provider configuration |
| HSTS | required at deploy | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` |
| Content-Security-Policy | shipped via `<meta>` | production must move to HTTP header |
| X-Content-Type-Options: nosniff | shipped | `<meta>` |
| Referrer-Policy: strict-origin-when-cross-origin | shipped | `<meta>` |
| Subresource Integrity (SRI) | N/A | no external assets — everything bundled |
| Reproducible build | partial | `vite build` is deterministic given the same lockfile + node version. Container build for bit-identical artefacts is a follow-up. |
| `@solana/wallet-adapter` standard | yes | Phantom / Solflare via official adapters |
| Backend | none | static page only; user secrets never leave the browser |
| Service worker | none | no offline cache; no persisted scope |

---

## CSP in detail

The policy in `index.html`:

```
default-src 'self';
script-src  'self' 'wasm-unsafe-eval';
style-src   'self' 'unsafe-inline';
font-src    'self' data:;
img-src     'self' data: blob:;
connect-src 'self'
            https://api.devnet.solana.com
            wss://api.devnet.solana.com
            http://localhost:* ws://localhost:*
            https://* wss://*;
frame-ancestors 'none';
base-uri 'self';
form-action 'none';
object-src 'none';
```

**Why each directive:**

- `script-src 'wasm-unsafe-eval'` — `@noble/curves` runs in pure JS today, but
  future Solana SDK paths may load WebAssembly modules; explicit allow.
- `style-src 'unsafe-inline'` — Tailwind 4 emits inline styles for some
  utilities. Pre-prod hardening: switch to nonce or hash pin via Vite.
- `font-src 'self' data:` — IBM Plex bundled at `/assets/*.woff2`; some
  wallet adapter icons use `data:` URIs.
- `img-src data: blob:` — wallet adapter renders the connected wallet's
  icon from a `data:` URI; `blob:` is for any future image upload flow.
- `connect-src` — Solana RPC + WSS + the relay endpoint. The wildcard
  `https://*` is **explicitly too broad for production**; replace with
  the canonical relay URL(s) before launch.
- `frame-ancestors 'none'` — the dApp cannot be embedded; defends against
  clickjacking via off-domain iframes.
- `form-action 'none'` — no form submissions ever; the dApp is JS-driven.
- `object-src 'none'` — no Flash / Java / legacy plugins ever.

---

## Pre-production hardening checklist

These are the items Komite 2 wants fixed before the dApp is announced on
the public TARDUS site.

- [ ] Move CSP from `<meta>` to HTTP `Content-Security-Policy` header.
- [ ] Narrow `connect-src` from `https://* wss://*` to the canonical
      production RPC + relay endpoints (e.g.
      `https://api.devnet.solana.com`,
      `https://relay.tardus.<domain>`).
- [ ] Replace `style-src 'unsafe-inline'` with hash-pinning of the small
      set of inline styles Tailwind emits, or move to nonce-based.
- [ ] Add `Strict-Transport-Security` response header with `preload`.
- [ ] Add `Permissions-Policy` denying clipboard / camera / microphone /
      geolocation / payment for the dApp origin.
- [ ] Reproducible build via container image with pinned Node version
      and `--frozen-lockfile`; commit hash visible in the UI footer.
- [ ] DNSSEC enabled on the production domain.
- [ ] HSTS preload submission.
- [ ] Optional: Sigstore / cosign signature on the built artefact
      manifest, published alongside the deploy.

---

## What this dApp does NOT do

These are explicit non-features that bound the attack surface:

- **No persistent secret storage** in V0. Receiving identity mnemonic
  lives in browser memory only; closing the tab loses it. The committee
  Q1 "hybrid" plan (opt-in encrypted IndexedDB) is W-MVP-A+1, not yet
  shipped.
- **No user accounts.** No server. No login. No email. No analytics.
- **No third-party scripts.** Everything bundled by Vite.
- **No external CDN.** Fonts, icons, wallet adapter assets — all served
  from the dApp origin.
- **No service worker.** No offline cache, no background sync.
- **No iframes.** Neither hosted in one, nor hosting one.
- **No clipboard read.** Only `clipboard.writeText` for "copy" buttons;
  user opt-in via gesture.

---

## Audit log

| Date | Reviewer | Finding | Status |
|---|---|---|---|
| 2026-05-22 | Komite 2 (10 reviewers) | "Approve current CSP for MVP; tighten before prod announce" | Captured in checklist above |
