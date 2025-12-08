# Entra Credential Testing Notes

## Observations
- The NIH Microsoft Entra registration for fmrif-scheduler is configured as a **Single-Page Application** (SPA) and enforces PKCE. Tokens issued for that client can only be redeemed via browser-based/cross-origin requests (error `AADSTS9002327` if a CLI tries). The browser helper in this repo satisfies that requirement.
- NIH treats this as an internal **public client**: there is no usable client secret for delegated flows. The CLI auto-detects this (secret missing → PKCE-only) and the browser helper never sends a secret.
- All delegated tests require an NIH identity + PIV/MFA. There is no way to validate the auth flow without authenticating as an NIH staff member (VPN + smart card, or whatever factors NIH enables on the tenant). Port forwarding or vendor portals only solve network reachability; they do not bypass the PIV requirement.
- The CLI `report` command still exercises the confidential-client path (with optional client secret) for completeness. When Entra responds with the SPA-only error, it hints to switch to the browser helper.

## Manual Test Strategy
1. **Environment config** – copy `.env.example` → `.env` and fill in the NIH-provided values (`client_id`, `redirect_uri`, etc.). The CLI and browser helper both consume this file via `python-dotenv`.
2. **Metadata sanity** – run `python entra_test_cli.py well-known` or open the browser helper to confirm the `discovery_url`, issuer, and token endpoints are reachable from your machine/VPN.
3. **Authorization / Token round-trip** – run `python entra_test_cli.py browser-helper --public-client` (default when no secret) to launch the SPA UI. Click “Launch authorization URL”, sign in with your NIH PIV, copy the failing redirect URL, paste it into the page, and let the browser redeem the code. The on-page report will mark each step PASS/SKIP/FAIL.
4. **CLI report (optional)** – if you need a textual log, copy the redirect URL + PKCE verifier from the helper and run `python entra_test_cli.py report --public-client --authorization-code "<url>" --code-verifier "<verifier>" --non-interactive`.
5. **Client credentials (optional)** – only applicable if NIH adds an Application ID URI with application permissions. Provide it via `--client-credentials-scope "api://.../.default"` to verify Secrets/app-only access; otherwise, expect the step to be marked SKIP.

## Automation Gaps / Next Steps
- **Client credentials scope** – waiting on NIH to provide an Application ID URI if the scheduler backend ever needs app-only tokens. Without it, that test remains SKIP.
- **Alternate redirect URIs** – to let non-NIH developers validate without PIV hardware, CIT would need to register additional redirect URIs (e.g., `http://localhost`) and potentially enable username/password + MS Authenticator or test accounts. Until then, every delegated test must be driven by an NIH user.
- **Vendor access** – a vendor with NIH VPN/portal access can still run this helper locally. They must have valid NIH credentials and, if required, a smart card reader to satisfy the login.
