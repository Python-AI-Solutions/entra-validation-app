import importlib.util
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "entra_test_cli.py"
spec = importlib.util.spec_from_file_location("entra_test_cli", MODULE_PATH)
cli = importlib.util.module_from_spec(spec)
sys.modules["entra_test_cli"] = cli
assert spec.loader is not None  # for mypy/pylint
spec.loader.exec_module(cli)  # type: ignore[attr-defined]


pytestmark = pytest.mark.skipif(
    os.getenv("ENTRA_E2E_PLAYWRIGHT") != "1",
    reason=(
        "Playwright E2E tests are opt-in. Set ENTRA_E2E_PLAYWRIGHT=1 and run "
        "`pixi run python -m playwright install` to enable."
    ),
)


def _start_browser_helper_in_thread(port: int = 8790) -> str:
    args = SimpleNamespace(
        client_id="test-client-id",
        client_secret=None,
        redirect_uri=f"http://127.0.0.1:{port}/callback",
        scope=cli.DEFAULT_SCOPE,
        tenant_id=cli.DEFAULT_TENANT_ID,
        host="127.0.0.1",
        port=port,
        discovery_url=None,
        state="test-state",
        public_client=True,
        env_file=".env",
        timeout=30,
        open_browser=False,
        browser="default",
    )

    thread = threading.Thread(
        target=cli.handle_browser_helper,
        args=(args,),
        daemon=True,
    )
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    # Best-effort wait for the dev server to come up.
    time.sleep(1.5)
    return base_url


def test_browser_helper_page_loads_with_playwright() -> None:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import]
    except Exception:  # pragma: no cover - environment-specific
        pytest.skip("playwright not available in this environment")

    base_url = _start_browser_helper_in_thread()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(base_url, wait_until="load")
        title = page.title()
        assert "Microsoft Entra Browser Helper" in title
        browser.close()
