# Architecture - Entra Credentials Validator

This document explains the technical design and architecture of the Entra Credentials Validator tool.

---

## High-Level Overview

The tool provides two complementary workflows for testing OAuth 2.0 / OpenID Connect flows:

```
┌─────────────────────────────────────────────────────┐
│     Entra Credentials Validator                     │
│                                                     │
│  ┌──────────────────┐      ┌──────────────────┐   │
│  │   CLI Workflow   │      │  Browser Helper  │   │
│  │   (entra_test    │      │  SPA Workflow    │   │
│  │    report)       │      │  (localhost:5000)│   │
│  │                  │      │                  │   │
│  │ • User prompts   │      │ • Web UI         │   │
│  │ • Copy/paste URLs│      │ • Direct browser │   │
│  │ • Token exchange │      │ • PKCE in JS     │   │
│  │   (Python)       │      │ • Automatic flow │   │
│  └──────────────────┘      └──────────────────┘   │
│           │                         │              │
│           └─────────────────────────┘              │
│                      │                            │
│                      ▼                            │
│         Configuration (.env) & Shared             │
│         OAuth 2.0 / OIDC Logic                    │
└─────────────────────────────────────────────────────┘
```

## OAuth 2.0 Flow (Authorization Code + PKCE)

```
1. DISCOVERY
   └─> Fetch OIDC metadata from discovery_url
       (endpoints, token formats, etc.)

2. AUTHORIZATION
   └─> Generate PKCE verifier (64-char random)
       └─> SHA-256 hash = code_challenge
           └─> Build authorization URL
               └─> User opens in browser

3. LOGIN
   └─> User authenticates (password, MFA, PIV, etc.)
       └─> Entra redirects with authorization code

4. CODE EXCHANGE
   └─> Extract code from redirect URL
       └─> POST to token endpoint with:
           • client_id
           • code
           • code_verifier (PKCE)
           • client_secret (if confidential client)
           └─> Receive access_token + refresh_token (optional)

5. USERINFO
   └─> Call Microsoft Graph userinfo endpoint
       └─> Validate token works

6. REFRESH (if offline_access scope granted)
   └─> Exchange refresh_token for new access_token
       └─> Verify token refresh capability
```

---

## Code Structure

**Main File:** `entra_test_cli.py` (~2000 lines)

```
1. Imports & Configuration
2. Utility Functions
   • generate_pkce_verifier/challenge, generate_state
   • build_authorization_url, exchange_code_for_token
   • refresh_access_token, call_userinfo_endpoint
3. CLI Workflow (run_report)
   • Interactive prompts, manual copy/paste
   • Python handles token exchanges
4. Browser Helper (Flask SPA)
   • Routes: GET / (serve UI), POST /api/exchange (proxy)
   • Embedded HTML/CSS/JS with client-side PKCE
   • Satisfies Entra's "SPA-only" requirement
```

## Public vs. Confidential Clients

| Type | Secret | PKCE | Token Redemption |
|------|--------|------|------------------|
| **Public (SPA/Mobile)** | None | Required | Browser |
| **Confidential (Backend)** | Has secret | Optional | Backend |

```python
# Public client
token_request = {
    'grant_type': 'authorization_code',
    'client_id': client_id,
    'code': code,
    'code_verifier': verifier,  # PKCE required
    'redirect_uri': redirect_uri
}

# Confidential client
token_request = {
    'grant_type': 'authorization_code',
    'client_id': client_id,
    'client_secret': client_secret,  # Secret included
    'code': code,
    'code_verifier': verifier,  # PKCE optional but recommended
    'redirect_uri': redirect_uri
}
```

## Configuration (.env)

```bash
client_id="..."        # App ID from Entra
client_secret=""       # Leave empty for public clients
redirect_uri="..."     # Registered callback URL
discovery_url="..."    # OIDC metadata endpoint
scopes="..."           # Optional: custom scopes
```

All secrets in `.env` (never in code), `.env` is gitignored.

## Error Handling

**Status Codes:**
- ✅ **PASS** (green): Step succeeded
- ⏭️ **SKIP** (orange): Not applicable (e.g., no refresh token)
- ❌ **FAIL** (red): Error occurred

**Common Entra Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `AADSTS9002327` | CLI can't redeem code | Use browser-helper |
| `AADSTS700016` | Client not found | Check client_id and tenant |
| `AADSTS650052` | Invalid redirect URI | Match exact registration |
| `AADSTS65001` | Consent required | Grant permissions in browser |

## Security

**PKCE (Proof Key for Code Exchange):**
1. Generate 64-char random verifier
2. SHA-256 hash → base64url encode = challenge
3. Send challenge in auth request
4. Exchange code WITH verifier
5. Entra verifies: SHA256(verifier) == challenge

**Token Security:**
- Access tokens: short-lived (~1 hour)
- Refresh tokens: longer-lived, can get new access tokens
- Tokens displayed for inspection but NOT stored
- Tool is stateless

**Input Validation:**
- Discovery URL must use HTTPS
- client_id must be valid GUID
- redirect_uri must be valid URL

## Testing

**Unit Tests** (`tests/test_entra_test_cli.py`):
- PKCE generation, code challenge, URL building
- Discovery document parsing, GUID validation
- Run: `pixi run test`

**E2E Tests** (`tests/test_browser_helper_playwright.py`):
- Browser helper UI, form submission, token exchange
- Run: `ENTRA_E2E_PLAYWRIGHT=1 pixi run test` (requires credentials)

See [TESTING.md](TESTING.md) for details.

## Performance

**CLI Workflow:** ~2-3 minutes total (includes user login time)
**Browser Helper:** ~3-5 seconds to interactive, ~1-2s token exchange
**Network:** 4-5 HTTP calls per flow (discovery, auth, token, userinfo, refresh)

## Extensibility

**New Entra Setups:** Works with any OIDC provider. Add setup guide to [USAGE.md](USAGE.md), update `.env.example`. No code changes needed.

**New Workflows:** Create new function, implement steps, add tests, update docs.

**Reusable Components:**
```python
from entra_test_cli import generate_pkce_verifier, exchange_code_for_token
```

## Deployment

**Local (default):** `pixi run browser-helper` → http://localhost:5000

**Docker:** Containerize Flask app (not yet implemented)

**PaaS:** Deploy to Railway/Render/Heroku with env vars

## Limitations

- No token caching/persistence
- No JWT decoding/inspection
- No MFA automation
- No proxy support
- Single tenant per .env

## Summary

Focused, self-contained tool emphasizing:
- **Simplicity**: Single file, minimal dependencies
- **Flexibility**: CLI and browser workflows
- **Security**: PKCE, no stored credentials
- **Compatibility**: Any OIDC provider
