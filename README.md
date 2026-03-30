# zenv

**Zero-config developer secret injection runtime with end-to-end encryption.**

Replace `.env` files with an encrypted local vault. Secrets are sealed with ChaCha20-Poly1305, keys live in your OS keychain, and your process receives them as environment variables at runtime — with zero plaintext ever written to disk.

[![Crates.io](https://img.shields.io/crates/v/zenv.svg)](https://crates.io/crates/zenv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

---

## Why zenv?

| Problem with `.env` files | How zenv fixes it |
|---|---|
| Plaintext on disk | ChaCha20-Poly1305 encrypted vault |
| Shared via Slack / email | Never needs to leave your machine |
| Accidentally committed to git | Vault file is opaque binary — nothing to leak |
| No audit trail | Every access is logged locally |
| Static credentials that never rotate | Dynamic short-lived credential providers (AWS STS, Stripe) |
| Different secrets per machine | OS keychain per device, sync coming soon |

---

## Install

### From crates.io (recommended)

```bash
cargo install zenv
```

### From source

```bash
git clone https://github.com/arvytechnolgies/zenv
cd zenv
cargo install --path .
```

### Requirements

- Rust 1.75+
- macOS, Linux, or Windows
- OS keychain access (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows)

---

## Quickstart

### 1. Initialize a project

```bash
cd your-project
zenv init
```

This creates a `.zenv.toml` in your project root and generates a master key stored in your OS keychain. Nothing is written to disk in plaintext.

### 2. Add secrets

```bash
zenv vault add DATABASE_URL "postgres://localhost:5432/mydb"
zenv vault add STRIPE_SECRET_KEY "sk_live_..."
zenv vault add API_SECRET "supersecretvalue"
```

### 3. Or import your existing .env

```bash
zenv vault import .env
# ✓ imported 12 secrets
```

### 4. Run your app with secrets injected

```bash
zenv run -- npm start
zenv run -- python manage.py runserver
zenv run -- go run .
zenv run -- ./my-binary
```

Secrets are injected as environment variables. On Unix, `zenv` calls `exec()` — replacing itself with your process entirely. Zero wrapper overhead.

---

## Commands

### Vault

```bash
zenv vault add <NAME> <VALUE>       # add or update a secret
zenv vault get <NAME>               # print a secret
zenv vault list                     # list all secret names
zenv vault rm <NAME>                # remove a secret
zenv vault import <file>            # bulk import from .env file
zenv vault export                   # export to stdout (plaintext — use carefully)
```

### Run

```bash
zenv run -- <command> [args...]     # inject secrets and exec your process
```

### Shell integration

```bash
zenv shell install                  # add auto-load hook to your shell rc file
zenv shell hook                     # print the raw hook script
zenv shell export                   # print export statements for current project
```

After `zenv shell install`, secrets auto-load when you `cd` into any project with a `.zenv.toml`.

### Secret scanner

```bash
zenv scan                           # scan codebase for potential secret leaks
zenv scan --path ./src              # scan a specific directory
```

Uses three detection signals: vendor prefix matching (`AKIA...`, `sk_live_...`), Shannon entropy analysis, and keyword heuristics (`SECRET`, `TOKEN`, `PASSWORD` near high-entropy values).

### Status

```bash
zenv status                         # show project info and loaded secrets count
zenv device id                      # show this device's unique ID
zenv device reset                   # rotate the master key (re-encrypts all secrets)
```

### Sync (cloud targets)

```bash
zenv sync push vercel               # push secrets to Vercel project env
zenv sync push github               # push secrets to GitHub Actions secrets
```

---

## How the encryption works

```
Your secret (plaintext)
        │
        ▼
ChaCha20-Poly1305 seal
  ├── Key:   HKDF-SHA256(master_key, "zenv.v1.storage:{project_id}")
  ├── Nonce: random 12 bytes
  └── AAD:   "{project_id}:{secret_name}"   ← prevents ciphertext substitution
        │
        ▼
base64(nonce ‖ ciphertext ‖ tag)
        │
        ▼
~/.zenv/cache/{project_id[:8]}.sealed
```

**Master key** is generated once per device and stored in the OS keychain — never on disk. The sealed cache file is safe to back up; without the keychain entry it's useless.

**Per-secret AAD** means swapping ciphertexts between secrets fails authentication. An attacker who modifies the vault file cannot substitute one secret's value for another.

**Memory safety**: the master key type (`MasterKey([u8; 32])`) implements `ZeroizeOnDrop` — the key bytes are overwritten in memory as soon as the value goes out of scope.

---

## Shell hook example

After running `zenv shell install`, your `.zshrc` (or `.bashrc` / `config.fish`) gets:

```bash
# zenv shell hook
_zenv_hook() {
  if [ -f .zenv.toml ]; then
    eval "$(zenv shell export 2>/dev/null)"
  fi
}
add-zsh-hook chpwd _zenv_hook
_zenv_hook  # run on shell start
```

---

## Environment variables

| Variable | Description |
|---|---|
| `ZENV_MASTER_KEY` | Override keychain — use a base64 master key directly (CI/CD environments) |
| `ZENV_LOG` | Set log level: `error`, `warn`, `info`, `debug`, `trace` |
| `ZENV_CACHE_DIR` | Override default cache directory (`~/.zenv/cache/`) |

For CI/CD, export `ZENV_MASTER_KEY` from your secrets manager and zenv will use it instead of the OS keychain:

```yaml
# GitHub Actions example
env:
  ZENV_MASTER_KEY: ${{ secrets.ZENV_MASTER_KEY }}
```

---

## Security model

- **E2EE by design**: the server (when sync is enabled) stores only encrypted blobs. Plaintext never leaves your machine.
- **Per-device keys**: each device has its own master key. Revoking a device revokes its key.
- **No telemetry**: zenv makes no network requests unless you explicitly run `zenv sync`.
- **Audit log**: every vault access is recorded in `~/.zenv/audit.log` with timestamp, project, and secret name.

### Threat model

zenv protects against:
- Secrets committed to version control
- Secrets leaked via process lists (`ps aux` shows no plaintext args)
- Vault file theft (encrypted, useless without keychain)
- Ciphertext substitution attacks (per-secret AAD)

zenv does **not** protect against:
- A fully compromised OS (attacker with keychain access)
- Memory forensics on a running process (secrets are in env after injection)

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large PR.

```bash
git clone https://github.com/arvytechnolgies/zenv
cd zenv
cargo build
cargo test
```

**Maintainer**: [arvytechnolgies](https://github.com/arvytechnolgies)

---

## Roadmap

- [ ] Encrypted secret sync across machines (E2EE, server sees only blobs)
- [ ] Team vaults with role-based access
- [ ] 1Password / HashiCorp Vault backend
- [ ] Audit log export (JSON, structured)
- [ ] GitHub Actions native integration
- [ ] `zenv diff` — compare local vault against deployed env

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built by <a href="https://github.com/arvytechnolgies">arvytechnolgies</a> &nbsp;·&nbsp;
  <a href="https://zeroconfig.netlify.app">zeroconfig.netlify.app</a>
</p>
