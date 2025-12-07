# Entra Credentials Validator

Small helper utility for exercising the NIH Microsoft Entra (OIDC) registration that powers the fmrif scheduler. It loads the same `.env` values used in the Flask app, enforces PKCE, and exposes:

- `entra-credentials-validator report` – CLI workflow that walks through discovery, authorization, token, refresh, and userinfo calls while printing PASS/SKIP/FAIL results.
- `entra-credentials-validator browser-helper` – a local SPA that satisfies Microsoft’s “cross-origin only” restriction for public/SPA registrations by redeeming the authorization code in the browser. Useful when Entra returns `AADSTS9002327`.

## Setup
### Using pixi (recommended for local/dev)
1. Install [pixi](https://pixi.sh) if you do not already have it.
2. From this directory, create the environment:
   ```bash
   pixi install
   ```
3. Copy the example environment file and fill in the NIH-provided values:
   ```bash
   cp .env.example .env
   # edit client_id, redirect_uri, discovery_url, and (optional) client_secret
   ```

## Usage
### CLI flow
```bash
pixi run report
```
- Follow the prompts to launch the authorization URL, sign in with your NIH PIV/credentials, and paste the redirect URL back into the CLI.
- If the app is configured as a confidential client, omit `--public-client` (or pass `--no-public-client`) and ensure the client secret is set in `.env`.
- Every step prints PASS/SKIP/FAIL; failures suggest whether you should switch to the browser helper.

### Browser helper
```bash
pixi run browser-helper
```
- To automatically launch the helper UI in a browser (useful over X forwarding), add:
```bash
pixi run browser-helper-firefox
```
- Click “Launch authorization URL,” complete the NIH login, copy the redirect URL (even if the page errors), and paste it into the helper.
- The page immediately redeems the code in the browser, attempts a refresh token exchange, and calls the Microsoft Graph userinfo endpoint. A report panel mirrors the CLI’s output.
- The helper shares the same `.env` configuration and PKCE verifier values, so you can copy/paste tokens or codes between the browser and CLI workflows if needed.

### Tests
```bash
pixi run test
```

### Optional Playwright browser tests
- The pixi environment includes `playwright` and `pytest-playwright`, but the browsers
  themselves are not installed by default.
- To prepare Playwright for E2E checks (e.g., using Chromium instead of Firefox), run:
  ```bash
  pixi run python -m playwright install
  ```
- A placeholder test lives in `tests/test_browser_helper_playwright.py`; you can replace
  it with real Playwright tests that drive the browser-helper UI once browsers are installed.

For troubleshooting notes and NIH-specific constraints, see `credential-testing.md`.
