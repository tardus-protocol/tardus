# tardus-infra — Private Infrastructure Repository

This document describes how to split the `deploy/` directory from this public monorepo into the private `tardus-org/tardus-infra` repository.

## Why a Separate Private Repo?

The `deploy/` directory contains operationally sensitive material:

- **HSM vendor capability matrix** — reveals which HSM hardware is in use
- **Key rotation runbooks** — step-by-step procedures that could aid targeted attacks
- **Mainnet ship-gate checklist** — internal release criteria
- **Relay / validator operator guides** — network topology hints
- **systemd service files** — reveals deployment paths and user accounts
- **Light Protocol / Token-2022 integration designs** — pre-announcement roadmap

None of this should be public before mainnet launch and security audit completion.

## Repository Structure

```
tardus-org/tardus-infra   (PRIVATE)
├── deploy/
│   ├── monitoring/
│   │   └── health-probe.sh
│   ├── runbooks/
│   │   ├── README.md
│   │   ├── hsm-vendor-capability-matrix.md
│   │   ├── key-rotation.md
│   │   ├── light-protocol-integration-design.md
│   │   ├── mainnet-ship-gate-checklist.md
│   │   ├── relay-operator.md
│   │   ├── token-2022-confidential-mint-design.md
│   │   ├── v2.13-hsm-resident-share-roadmap.md
│   │   └── validator-operator.md
│   ├── systemd/
│   │   ├── tardus-relayd.service
│   │   └── tardus-validator.service
│   └── wallet-release/
│       ├── SIGNING.md
│       └── AppDir/
└── README.md
```

## Migration Steps

### 1. Create the private repo

```bash
gh repo create tardus-org/tardus-infra --private --description "Tardus infrastructure, runbooks, and deployment configuration"
```

### 2. Extract deploy/ history (optional — preserves git blame)

```bash
# In a fresh clone of this repo
git clone https://github.com/tardus-org/tardus.git tardus-extract
cd tardus-extract
git filter-repo --path deploy/ --force

# Push to new private repo
git remote set-url origin https://github.com/tardus-org/tardus-infra.git
git push origin main
```

### 3. Remove deploy/ from this public repo

```bash
cd /path/to/tardus
git filter-repo --path deploy/ --invert-paths --force
git push origin main --force-with-lease
```

> ⚠️ Force-pushing rewrites history. Coordinate with all contributors and update any open PRs.

### 4. Add a stub in this repo

Replace `deploy/` with a pointer file so contributors know where to look:

```bash
mkdir -p deploy
cat > deploy/README.md << 'EOF'
# Deployment & Infrastructure

Deployment runbooks, systemd service files, and HSM configuration are maintained
in the private repository: **tardus-org/tardus-infra**

Access is restricted to operators and core maintainers.
Contact @tardus-org/infra-reviewers for access.
EOF
git add deploy/README.md
git commit -m "chore: replace deploy/ with pointer to tardus-infra private repo"
```

### 5. Update .gitignore

Ensure `deploy/wallet-release/output/` remains ignored in the infra repo:

```
deploy/wallet-release/output/
*.AppImage
*.deb
*.rpm
```

## Access Control

| Role | Access |
|------|--------|
| Core maintainers | Admin |
| Relay operators | Read |
| Validator operators | Read |
| Security auditors | Read (temporary, during audit) |
| External contributors | No access |

## CI/CD Integration

The infra repo can reference workflow artifacts from the public `tardus` repo via:

```yaml
# In tardus-infra CI
- uses: actions/download-artifact@v4
  with:
    repository: tardus-org/tardus
    run-id: ${{ inputs.run_id }}
    github-token: ${{ secrets.CROSS_REPO_TOKEN }}
```

## What Stays in This Public Repo

The following deployment-adjacent files remain **public** in `tardus`:

- `.github/workflows/` — CI/CD pipeline definitions (no secrets)
- `deploy/wallet-release/SIGNING.md` — public release signing instructions
- `crates/tardus-wallet-gui/SCREENSHOTS.md` — user-facing documentation