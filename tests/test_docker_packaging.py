from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_copies_all_fritzbox_modules_declared_in_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    modules = pyproject["tool"]["setuptools"]["py-modules"]
    fritzbox_modules = {module for module in modules if module.startswith("fritzbox_")}
    top_level_modules = {path.stem for path in ROOT.glob("fritzbox_*.py")}
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY fritzbox_*.py ./" in dockerfile
    assert fritzbox_modules <= top_level_modules


def test_dockerignore_excludes_local_credentials_and_evidence() -> None:
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert ".env" in ignored
    assert ".fritzbox.env" in ignored
    assert "fritzbox-analysis.sqlite3" in ignored
    assert "*.sqlite3" in ignored
    assert "output/" in ignored
    assert "imports/" in ignored
    assert "*.zip" in ignored


def test_compose_keeps_dashboard_bound_to_loopback() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert '"127.0.0.1:8765:8765"' in compose
