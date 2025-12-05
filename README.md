# Entra Credentials Validator

Small helper utility for exercising the NIH Microsoft Entra (OIDC) registration that powers the fmrif scheduler. It loads the same `.env` values used in the Flask app, enforces PKCE, and exposes:

- `entra_test_cli.py report` – CLI workflow that walks through discovery, authorization, token, refresh, and userinfo calls while printing PASS/SKIP/FAIL results.
- `entra_test_cli.py browser-helper` – a local SPA that satisfies Microsoft’s “cross-origin only” restriction for public/SPA registrations by redeeming the authorization code in the browser. Useful when Entra returns `AADSTS9002327`.

## Setup
1. Install [uv](https://github.com/astral-sh/uv) if you do not already have it.
2. From this directory run:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install -e .
   ```
3. Copy the example environment file and fill in the NIH-provided values:
   ```bash
   cp .env.example .env
   # edit client_id, redirect_uri, discovery_url, and (optional) client_secret
   ```

## Usage
### CLI flow
```bash
python entra_test_cli.py report --public-client --open-browser
```
- Follow the prompts to launch the authorization URL, sign in with your NIH PIV/credentials, and paste the redirect URL back into the CLI.
- If the app is configured as a confidential client, omit `--public-client` (or pass `--no-public-client`) and ensure the client secret is set in `.env`.
- Every step prints PASS/SKIP/FAIL; failures suggest whether you should switch to the browser helper.

### Browser helper
```bash
python entra_test_cli.py browser-helper --public-client
# visit the printed http://127.0.0.1:8765 URL
```
- Click “Launch authorization URL,” complete the NIH login, copy the redirect URL (even if the page errors), and paste it into the helper.
- The page immediately redeems the code in the browser, attempts a refresh token exchange, and calls the Microsoft Graph userinfo endpoint. A report panel mirrors the CLI’s output.
- The helper shares the same `.env` configuration and PKCE verifier values, so you can copy/paste tokens or codes between the browser and CLI workflows if needed.

### Tests
```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_entra_test_cli.py
```

For troubleshooting notes and NIH-specific constraints, see `credential-testing.md`.
