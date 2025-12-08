# Testing Guide - Entra Credentials Validator

## Quick Start

```bash
# Run all tests
pixi run test

# Run with verbose output
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_entra_test_cli.py -v

# Run specific test function
python -m pytest tests/test_entra_test_cli.py::test_generate_pkce_verifier -v
```

---

## Test Structure

```
tests/
├── test_entra_test_cli.py              # Unit tests (main)
│   ├── Test utility functions
│   ├── Test PKCE implementation
│   ├── Test URL building
│   ├── Test configuration parsing
│   └── Test error handling
│
└── test_browser_helper_playwright.py   # E2E tests (optional)
    ├── Test browser helper loads
    ├── Test UI interactions
    ├── Test token exchange flow
    └── Test with real Microsoft Entra (requires credentials)
```

---

## Unit Tests

**File:** `tests/test_entra_test_cli.py`

**Tests:**
- PKCE verifier (64 chars, valid character set)
- Code challenge (SHA-256 → base64url)
- Authorization URL (includes client_id, response_type, scope, code_challenge)
- Configuration loading (required fields, format validation)
- Discovery document parsing (extract endpoints)

**Run:**
```bash
pixi run test                                     # All tests
python -m pytest tests/test_entra_test_cli.py -v  # Verbose
python -m pytest tests/test_entra_test_cli.py --cov=entra_test_cli  # With coverage
```

## E2E Tests

**File:** `tests/test_browser_helper_playwright.py`

**Tests:**
- Browser helper loads without errors
- UI elements render (inputs, buttons)
- Form submission and auth URL display
- Full OAuth flow with real credentials (optional)

**Run:**
```bash
ENTRA_E2E_PLAYWRIGHT=1 pixi run test  # Requires credentials
python -m pytest tests/test_browser_helper_playwright.py -v -s
```

**Requirements:**
```bash
python -m playwright install chromium firefox  # Install browsers
export ENTRA_E2E_PLAYWRIGHT=1                  # Enable E2E tests
```

**Notes:**
- Optional (skipped without credentials)
- Don't use production credentials
- ~30-60 seconds per test (includes login)

## Manual Testing

**CLI Workflow:**
```bash
pixi run report
# 1. Open printed authorization URL in browser
# 2. Log in with Entra credentials
# 3. Copy full redirect URL (includes code parameter)
# 4. Paste into CLI prompt
# 5. View PASS/SKIP/FAIL report
```

**Browser Helper:**
```bash
pixi run browser-helper
# 1. Fill form (client_id, discovery_url, redirect_uri, optional client_secret)
# 2. Click "Start OAuth Flow" → login in new window
# 3. Complete login (username/password, MFA if required)
# 4. View tokens and user info on page
# 5. Click "Validate Token" to test userinfo endpoint
```

**Different Entra Setups:**
- **Azure AD B2C:** Set `discovery_url` to B2C endpoint with policy parameter
- **Custom Enterprise:** Use custom Entra discovery URL
- See [USAGE.md](USAGE.md) for specific examples

## Test Coverage

**Covered:**
- PKCE generation/validation, URL building, configuration loading
- Discovery document parsing, GUID/URL validation
- Browser helper UI rendering, basic token exchange

**Uncovered (requires real credentials):**
- Real token exchange, user login flows, refresh tokens
- Entra error responses, network timeouts
- Covered by E2E tests or manual testing

**View Coverage:**
```bash
python -m pytest tests/ --cov=entra_test_cli --cov-report=html
open htmlcov/index.html
```

## Writing New Tests

```python
import pytest
from entra_test_cli import your_function

class TestYourFeature:
    def test_basic_case(self):
        """Test the happy path"""
        result = your_function(input_data)
        assert result == expected_output

    def test_error_case(self):
        """Test error handling"""
        with pytest.raises(ValueError):
            your_function(invalid_data)
```

**Best Practices:**
- Clear test names: `test_<function>_<scenario>`
- Use fixtures for common setup
- Test error cases with `pytest.raises`
- Use `@pytest.mark.parametrize` for multiple cases

## Debugging Failed Tests

```bash
# Verbose output (shows full details)
python -m pytest tests/test_entra_test_cli.py::test_name -vv

# Print debugging (show print() output)
python -m pytest tests/test_entra_test_cli.py -s

# Use debugger
def test_my_function():
    result = my_function(data)
    breakpoint()  # Python 3.7+
    assert result == expected
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: entra_test_cli` | Run from repo root: `cd /path/to/entra-validation-app` |
| `pytest: command not found` | Use `pixi run test` |
| E2E tests hang/timeout | Set timeout: `pytest --timeout=60` or skip E2E |
| Playwright browser not found | `python -m playwright install chromium firefox` |

## Summary

| Test Type | When | Time | Requirements |
|-----------|------|------|--------------|
| Unit | Always | ~1 sec | None |
| E2E | Before deployment | ~2-3 mins | Real credentials |
| Manual (CLI) | Quick validation | ~5 mins | Entra credentials |
| Manual (Browser) | Full workflow | ~10 mins | Entra credentials |

**Workflow:**
1. Before commit: `pixi run test`
2. Before PR: `ENTRA_E2E_PLAYWRIGHT=1 pixi run test`
3. Before deployment: Manual test with `pixi run browser-helper`
