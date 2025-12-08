# Usage Guide - Entra Credentials Validator

This guide provides step-by-step instructions for validating OAuth 2.0 / OIDC flows with different Microsoft Entra setups.

**Setup:**
```bash
pixi install
cp .env.example .env
# Edit .env with your Entra app registration details
```

**Workflows:**
```bash
pixi run report                 # CLI (interactive prompts, copy/paste)
pixi run browser-helper         # Web UI (recommended)
pixi run browser-helper-chromium # With Chromium
pixi run browser-helper-firefox  # With Firefox
```

## Setup Guides

### Microsoft Entra (Generic Tenant)

**Get Registration Details:**
1. Azure Portal → Azure AD → App registrations → Your app
2. Copy Application (client) ID → `client_id`
3. Certificates & secrets → New secret (if confidential) → `client_secret`
4. Authentication → Redirect URIs → `redirect_uri`
5. Overview → Directory (tenant) ID → Use in discovery URL

**Discovery URL:**
```
https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration
```

**Configure .env:**
```bash
client_id="12345678-1234-1234-1234-123456789012"
client_secret="your-secret"  # Empty for public/SPA apps
redirect_uri="https://your-app.example.com/callback"
discovery_url="https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration"
```

**Run:**
```bash
pixi run browser-helper
```

### Azure AD B2C

**Get Registration Details:**
1. Azure Portal → Azure AD B2C → App registrations
2. Copy client_id, create client_secret, add redirect_uri

**Discovery URL:**
```
https://{TENANT_NAME}.b2clogin.com/{TENANT_ID}/v2.0/.well-known/openid-configuration?p={POLICY_NAME}
```

**Example:**
```bash
client_id="..."
client_secret="..."
redirect_uri="https://your-app.example.com/callback"
discovery_url="https://mycompany.b2clogin.com/.../v2.0/.well-known/openid-configuration?p=B2C_1_SignUpSignIn"
```

### Custom / Enterprise Entra

Use custom Entra endpoint: `{YOUR_ENTRA_URL}/v2.0/.well-known/openid-configuration`

## Report Output

| Status | Meaning | Examples |
|--------|---------|----------|
| ✅ **PASS** | Step succeeded | Discovery loaded, token exchanged |
| ⏭️ **SKIP** | Not applicable | No refresh token, optional step |
| ❌ **FAIL** | Error occurred | Invalid credentials, bad config |

## Troubleshooting

| Error | Meaning | Solution |
|-------|---------|----------|
| `AADSTS9002327` | CLI can't redeem code | Use `pixi run browser-helper` |
| `AADSTS700016` | Client not found | Check client_id and tenant |
| `AADSTS650052` | Invalid redirect URI | Match exact registration (no trailing slash) |
| Code not captured | Failed to get auth code | Copy entire redirect URL with `code=...` param |
| Token exchange fails | Can't exchange code | Verify client_secret, redirect_uri, PKCE verifier |

## Client Types

**Public (SPA/Mobile):** No secret, PKCE required
```bash
client_secret=""  # Leave empty
```

**Confidential (Backend):** Has secret, PKCE optional
```bash
client_secret="abc123..."
```

## Custom Scopes

Edit `.env` to test different scopes:
- Default: `email openid profile offline_access`
- Custom: `api://app-id/read api://app-id/write`
- Graph API: `https://graph.microsoft.com/.default`

## Next Steps

After validation:
1. Integrate with your app
2. Store tokens securely (HTTP-only cookies)
3. Implement token refresh logic
4. Handle OAuth errors
5. Test in staging before production

## Resources

- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [PKCE Spec](https://tools.ietf.org/html/rfc7636)
- [Microsoft Entra Docs](https://learn.microsoft.com/azure/active-directory/develop/)

See [credential-testing.md](credential-testing.md) for detailed troubleshooting.
