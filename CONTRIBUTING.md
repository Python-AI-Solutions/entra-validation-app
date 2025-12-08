# Contributing to Entra Credentials Validator

Thank you for your interest in contributing! This guide will help you set up your development environment and make meaningful contributions.

---

## Getting Started

### Prerequisites
- Python 3.11+
- [pixi](https://pixi.sh)
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Python-AI-Solutions/entra-credentials-validator.git
cd entra-credentials-validator

# Install dependencies using pixi
pixi install

# Copy environment template
cp .env.example .env

# Edit .env with your Microsoft Entra credentials (optional for running locally)
# Note: You only need credentials to actually test OAuth flows
```

---

## Project Structure

```
entra-validation-app/
├── entra_test_cli.py              # Main application (CLI + Flask + HTML/JS)
├── tests/
│   ├── test_entra_test_cli.py     # Unit tests for utility functions
│   └── test_browser_helper_playwright.py  # E2E browser tests
├── docs/
│   ├── ARCHITECTURE.md            # Technical design and OAuth flows
│   ├── TESTING.md                 # Testing guide and strategies
│   ├── USAGE.md                   # Setup guides (Generic, B2C, Enterprise)
│   ├── credential-testing.md      # Troubleshooting guide
│   └── nih-entra-guide.docx       # Reference documentation
├── .env.example                   # Configuration template
├── .gitignore                     # Git ignore rules
├── pixi.toml                      # Pixi configuration and task definitions
├── pyproject.toml                 # Python package metadata
├── LICENSE                        # MIT License
├── README.md                      # User-facing documentation
└── CONTRIBUTING.md                # Contribution guidelines (this file)
```

## Available Commands

```bash
pixi run report                 # CLI workflow
pixi run browser-helper         # Web UI
pixi run browser-helper-chromium # With Chromium
pixi run browser-helper-firefox  # With Firefox
pixi run test                   # Run tests
pixi run test-coverage          # Tests with coverage
```

## Code Style

- **Python**: Follow PEP 8, meaningful names, comment the "why" not the "what"
- **HTML/CSS/JS**: Keep readable, semantic HTML, vanilla JavaScript
- **Documentation**: Clear and concise with examples

## Testing Requirements

Before submitting PRs:

```bash
pixi run test                        # All tests must pass
python -m py_compile entra_test_cli.py  # Syntax check
```

- Add unit tests for utility functions
- Add E2E tests for user-facing workflows
- Aim for >80% coverage

## Security

- Never commit credentials (use `.env.example` only)
- No hardcoded secrets (all config from `.env`)
- Validate all user inputs
- Maintain PKCE implementation correctly
- Use test credentials only in CI/CD

## Pull Request Process

1. Create feature branch: `git checkout -b feature/your-feature-name`
2. Make changes with logical commits (reference issues: `Fixes #123`)
3. Run tests: `pixi run test`
4. Create PR with clear description, link issues
5. Address reviewer feedback promptly

## Reporting Issues

**Before opening an issue:**
- Check for duplicates
- Try latest version
- Review [docs/USAGE.md](docs/USAGE.md) troubleshooting

**Include:**
- Clear title and reproduction steps
- Expected vs. actual behavior
- Full error messages
- Environment: OS, Python version, pixi version
- Sanitized `.env` values

## Development Tips

**Debugging:**
```bash
# Test specific function
python -m pytest tests/test_entra_test_cli.py::test_function_name -v

# Run with coverage
pixi run test-coverage

# Test browser helper
curl http://localhost:5000/.well-known/openid-configuration
```

Use Flask debug output, browser dev tools (F12), and print statements as needed.

## Project Scope

**What this tool does:**
- Validates OAuth 2.0 / OIDC flows with Microsoft Entra
- Tests PKCE implementation
- Supports public and confidential clients

**What it does NOT do:**
- Integrate authentication into applications
- Store or cache tokens
- Provide production deployment
- Support non-OIDC flows

Keep contributions within this scope.

## License

By contributing, you agree your contributions will be licensed under the MIT License.

---

**Questions?** Check README.md, [docs/USAGE.md](docs/USAGE.md), or open an issue. Thank you for contributing!
