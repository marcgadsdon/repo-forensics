"""Tests for scripts/openclaw_install.py."""

import importlib.util
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
OPENCLAW_INSTALL = REPO_ROOT / "scripts" / "openclaw_install.py"


def _load_openclaw_install():
    spec = importlib.util.spec_from_file_location("openclaw_install_under_test", OPENCLAW_INSTALL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_openclaw_install_preserves_security_install_policy(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"security": {"installPolicy": "operator"}}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))

    openclaw_install = _load_openclaw_install()
    assert openclaw_install.install() == 0
    assert openclaw_install.verify() == 0

    data = json.loads(cfg.read_text())
    assert data["security"]["installPolicy"] == "operator"
    for event in openclaw_install.HOOK_EVENTS:
        assert any(openclaw_install._is_ours(entry) for entry in data["hooks"][event])


def test_openclaw_verify_fails_without_registered_hooks(monkeypatch, tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({"hooks": {}}))
    monkeypatch.setenv("OPENCLAW_HOME", str(home))

    openclaw_install = _load_openclaw_install()
    assert openclaw_install.verify() == 1
