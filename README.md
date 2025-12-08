# Entra Credentials Validator

Test OAuth 2.0 / OIDC flows with Microsoft Entra. Implements PKCE security and provides two workflows:

- **CLI** (`pixi run report`) – Interactive prompts with PASS/SKIP/FAIL results
- **Browser Helper** (`pixi run browser-helper`) – Local SPA that redeems auth codes in the browser (solves `AADSTS9002327` error)

## Quick Start

```bash
# 1. Install pixi (if needed): https://pixi.sh
pixi install

# 2. Configure
cp .env.example .env
# Edit .env with: client_id, redirect_uri, discovery_url, client_secret (optional)

# 3. Run
pixi run browser-helper  # Recommended: Web UI at localhost:5000
# OR
pixi run report         # CLI with interactive prompts
```

## Workflows

**CLI:**
```bash
pixi run report
# Follow prompts: open auth URL, login, paste redirect URL with code
```

**Browser Helper:**
```bash
pixi run browser-helper          # Opens browser automatically
pixi run browser-helper-firefox  # With Firefox
pixi run browser-helper-chromium # With Chromium
# Fill form, click "Start OAuth Flow", login, view tokens
```

**Tests:**
```bash
pixi run test  # Unit tests

# E2E tests (requires credentials)
python -m playwright install
ENTRA_E2E_PLAYWRIGHT=1 python -m pytest tests/test_browser_helper_playwright.py
```

## Configuration

**Public Client (SPA/Mobile):**
```bash
client_id="..."
client_secret=""  # Leave empty
redirect_uri="..."
discovery_url="https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
```

**Confidential Client (Backend):**
```bash
client_id="..."
client_secret="your-secret"
redirect_uri="..."
discovery_url="..."
```

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** – Setup guides for different Entra configs (Generic, B2C, Custom)
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** – Technical design and OAuth flow details
- **[docs/TESTING.md](docs/TESTING.md)** – Testing guide (unit, E2E, manual)
- **[CONTRIBUTING.md](CONTRIBUTING.md)** – Development setup and contribution guidelines
- **[docs/credential-testing.md](docs/credential-testing.md)** – Troubleshooting and enterprise constraints

## Common Issues

| Error | Solution |
|-------|----------|
| `AADSTS9002327` | Use `pixi run browser-helper` |
| `AADSTS700016` | Check client_id and tenant match |
| `AADSTS650052` | Verify redirect_uri matches registration exactly |
