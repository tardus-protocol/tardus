# GUI v1 Screenshot Capture Procedure + ASCII Mockups

**Status:** Screenshot capture procedure documented + ASCII
mockups for each of the 7 GUI v1 tabs. Actual PNG capture
requires an interactive X11 / Wayland session and is left to a
maintainer with display access; this doc tells them exactly
what to capture and where to commit it.

License: TARDUS-PROPRIETARY-1.0.

---

## Capture procedure

### 1. Build + launch the GUI

```bash
# Linux with X11 or Wayland:
sudo apt-get install -y libxkbcommon-dev libwayland-dev libxcb1-dev libgl1-mesa-dev
cargo build --release -p tardus-wallet-gui
./target/release/tardus-wallet-gui
```

### 2. Capture each tab

Recommended capture tool: GNOME Screenshot (`gnome-screenshot
-w -d 1`, window mode with 1s delay) or `flameshot gui`. Resize
the window to **1280 × 800** before each capture for consistent
framing.

For each of the 7 tabs (Balance, Keysets, Pay, Receive, Refresh,
Withdraw, Invoice), capture a screenshot in three states:

| State | Filename | What to set up |
|---|---|---|
| Empty / new wallet | `<tab>-empty.png` | Fresh wallet, no keysets, no coins |
| Mid-flow | `<tab>-active.png` | Realistic in-progress state (e.g. Pay tab with denom + relay filled) |
| Post-success | `<tab>-success.png` | After a successful op (e.g. Refresh result panel populated) |

For tabs that don't have a meaningful 3-state distinction (e.g.
Balance, Invoice), one capture is fine.

### 3. Commit the captures

```bash
mkdir -p docs/screenshots/gui-v1
cp ~/Pictures/*.png docs/screenshots/gui-v1/
# Optimise PNGs:
optipng -o3 docs/screenshots/gui-v1/*.png
```

Then add to `README.md`'s Quick Start section:

```markdown
### Screenshots

| Tab | Empty | Active | Success |
|---|---|---|---|
| Balance | ![Balance empty](docs/screenshots/gui-v1/balance-empty.png) | — | — |
| Keysets | ![Keysets empty](docs/screenshots/gui-v1/keysets-empty.png) | ![Keysets active](docs/screenshots/gui-v1/keysets-active.png) | — |
...
```

---

## ASCII mockups (reference for review)

These are what each tab should look like at first glance. Use
these to verify a capture is showing the right state before
committing.

### Tab 1 — Balance

```
┌────────────────────────────────────────────────────────────────┐
│ TARDUS Wallet v1                                  [_][□][×]    │
├────────────────────────────────────────────────────────────────┤
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
│           [Invoice]                                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Wallet:  ~/Documents/tardus-wallet.toml         [Open…]       │
│  Status:  unlocked                                             │
│                                                                │
│  ──────────────────────────────────────────                    │
│  Total balance:   42 000 000 lamports (0.042 SOL)              │
│  ──────────────────────────────────────────                    │
│                                                                │
│  Active coins:                                                 │
│   • from-relay-abc123  denom 1 000 000   Cp 8e76ba…            │
│   • salary-2025-05-22  denom 5 000 000   Cp e4563…             │
│   • split-change-3     denom 100 000     Cp 4a8b2…             │
│                                                                │
│  Spent coins:    18                                            │
│  Refreshed:       7                                            │
│                                                                │
│ Status: wallet loaded; 3 Active coins                          │
└────────────────────────────────────────────────────────────────┘
```

### Tab 2 — Keysets

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
├────────────────────────────────────────────────────────────────┤
│ Keysets file: ~/.config/tardus/keysets.toml  [Open…]           │
│                                                                │
│  ┌────────────────────────────────────────────────────┐        │
│  │ Name        │ Denom      │ joint_pk         │ Op  │        │
│  ├────────────────────────────────────────────────────┤        │
│  │ devnet-01   │ 1 000 000  │ 17f7b138bd5a…    │ [×] │        │
│  │ devnet-02   │ 5 000 000  │ a9aa60ee9ba2…    │ [×] │        │
│  └────────────────────────────────────────────────────┘        │
│                                                                │
│  Add new:                                                      │
│    Name:      [__________________]                             │
│    Denom:     [__________]                                     │
│    joint_pk:  [____________________________________]           │
│    Validators (URL list, one per line):                        │
│    ┌─────────────────────────────────────────────┐             │
│    │ https://validator-1.tardus.example.com:443  │             │
│    │ https://validator-2.tardus.example.com:443  │             │
│    └─────────────────────────────────────────────┘             │
│    [Add keyset]                                                │
└────────────────────────────────────────────────────────────────┘
```

### Tab 3 — Pay

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
├────────────────────────────────────────────────────────────────┤
│  Pay invoice:                                                  │
│    Invoice URI:                                                │
│    ┌─────────────────────────────────────────────────┐         │
│    │ tardus://6d9bccB2…?denom=1000000&relay=…        │         │
│    └─────────────────────────────────────────────────┘         │
│    [Parse]                                                     │
│                                                                │
│  Parsed:                                                       │
│    Recipient: 6d9bccB2hPNq6Loq2ZgEVuHECPufVnsFVfAWRqg7gKKa     │
│    Denom:     1 000 000 lamports (0.001 SOL)                   │
│    Relay:     https://relay-eu-west-1.tardus.example.com:9799  │
│    Memo:      "thanks for the coffee"                          │
│                                                                │
│  Spend from keyset: [devnet-01            ▼]                   │
│  Coin to spend:     [salary-2025-05-22    ▼]                   │
│                                                                │
│  [Pay invoice]                                                 │
│                                                                │
│ Status: invoice parsed; ready to pay                           │
└────────────────────────────────────────────────────────────────┘
```

### Tab 4 — Receive

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
├────────────────────────────────────────────────────────────────┤
│  Your receiving identity:                                      │
│    pubkey:  4afa35d830995da7258326a60256406d1bc1faf6f7c7a563   │
│             b55fdd6e9dcd0824                            [📋]   │
│                                                                │
│  Generate invoice:                                             │
│    Denom: [1000000]                                            │
│    Relay: [https://relay-eu-west-1.tardus.example.com:9799]    │
│    Memo:  [coffee tab]                                         │
│                                                                │
│    Invoice URI:                                                │
│    ┌─────────────────────────────────────────────────┐         │
│    │ tardus://4afa35d830995da7258326a60256406d1bc1   │         │
│    │ faf6f7c7a563b55fdd6e9dcd0824?denom=1000000&     │         │
│    │ relay=https%3A%2F%2Frelay-eu-west-1.tardus…     │         │
│    └─────────────────────────────────────────────────┘         │
│    [📋 Copy invoice]                                           │
│                                                                │
│  Inbox poll:  [Poll now]   last poll: 2 min ago, 0 new         │
└────────────────────────────────────────────────────────────────┘
```

### Tab 5 — Refresh

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
├────────────────────────────────────────────────────────────────┤
│  Refresh an Active coin via κ-fold cut-and-choose:             │
│                                                                │
│  Coin: [salary-2025-05-22 (denom 5M, Cp e4563…)   ▼]           │
│  Keyset: [devnet-01                                ▼]          │
│                                                                │
│  [Refresh]                                                     │
│                                                                │
│  ────────────────────────────────────────────────              │
│  Last refresh result:                                          │
│    old coin Cp prefix:  e4563375be1562f2…                      │
│    new coin Cp prefix:  9c3afe71a2b8d401… ← UNLINKABLE         │
│    elapsed:             821 ms                                 │
│    κ used:              32                                     │
│    new coin label:      salary-2025-05-22-refresh-1            │
└────────────────────────────────────────────────────────────────┘
```

### Tab 6 — Withdraw (with Faz 9 privacy stack)

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
├────────────────────────────────────────────────────────────────┤
│  Withdraw — convert coin to real SOL on devnet                 │
│  (Faz 9.6: GUI submits the TX directly via solana-client)      │
│                                                                │
│  Coin: [salary-2025-05-22 (denom 5M, Cp e4563…) ▼]             │
│  Recipient: [6d9bccB2hPNq6Loq2ZgEVuHECPufVnsFVfAWRqg7gKKa]     │
│  Will withdraw 5 000 000 lamports (0.005 SOL).                 │
│                                                                │
│  Devnet submission                                             │
│    RPC URL:             [https://api.devnet.solana.com]        │
│    Program ID:          [AmY1ysgQyCC6CmorXkrNkogBSHmomy4…]     │
│    Solana keypair path: [~/.config/solana/id.json]             │
│                                                                │
│  Privacy options (Faz 9 stack)                                 │
│    [✓] Use ephemeral payer (Faz 9.1)                           │
│      [✓]  └ Fund ephemeral from on-chain SponsorPool (9.4)     │
│                                                                │
│  [Submit Withdraw TX]                                          │
│                                                                │
│  ────────────────────────────────────────────────              │
│  Last withdraw result                                          │
│    coin label:       salary-2025-05-22                         │
│    denom:            5 000 000                                 │
│    recipient:        6d9bccB2hPNq…                       [📋]  │
│    tx signature:     3UVkfK5tt671FDJ…                    [📋]  │
│    explorer:         https://explorer.solana.com/tx/3U…        │
│    payer strategy:   ephemeral-from-pool       ← GREEN         │
│    ephemeral signer: B3mFCD2qdedYd2nYuTcwZFZS1ghCs7DwKQ…       │
│    elapsed:          1 247 ms                                  │
└────────────────────────────────────────────────────────────────┘
```

### Tab 7 — Invoice

```
┌────────────────────────────────────────────────────────────────┐
│ [Balance] [Keysets] [Pay] [Receive] [Refresh] [Withdraw]       │
│ [Invoice]                                                      │
├────────────────────────────────────────────────────────────────┤
│  Parse / inspect a tardus:// invoice URI:                      │
│                                                                │
│  URI: [tardus://6d9bcc…?denom=1000000&relay=…&memo=Y29mZmVl]   │
│  [Parse]                                                       │
│                                                                │
│  Parsed:                                                       │
│    Recipient pk:  6d9bccB2hPNq6Loq2ZgEVuHECPufVnsFVfAWRqg7gKKa │
│    Denom:         1 000 000 lamports (0.001 SOL)               │
│    Relays:                                                     │
│      1.  https://relay-eu-west-1.tardus.example.com:9799       │
│      2.  https://relay-us-east-1.tardus.example.com:9799       │
│    Memo (b64):    Y29mZmVl                                     │
│    Memo (utf-8):  "coffee"                                     │
└────────────────────────────────────────────────────────────────┘
```

---

## Layout commitments

The above ASCII mockups reflect the actual v1 GUI layout
implemented in `src/main.rs::tab_*`. Reviewers can grep for
each tab's `egui::ComboBox`, `egui::Grid`, `egui::TextEdit`
calls to map the mockup elements to source line numbers:

```bash
grep -n "ComboBox\|Grid::new\|TextEdit::singleline" src/main.rs | grep -E "balance|keysets|pay|receive|refresh|withdraw|invoice"
```

If the rendered screenshot diverges from these mockups in a way
that's not a pure cosmetic difference (font, dark mode), one of
two things is true: the GUI changed since 2026-05-22 and these
mockups need an update, or the screenshot was taken at a state
the mockups don't cover. Either way, file an issue before
committing the divergent capture.
