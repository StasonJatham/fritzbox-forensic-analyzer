from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_env() -> None:
    load_env_file(Path(".env"))
    load_env_file(Path(".fritzbox.env"))


def fritz_connection() -> Any:
    from fritzconnection import FritzConnection

    load_env()
    password = os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS")
    if not password:
        raise SystemExit("Set FRITZBOX_PASSWORD or FRITZBOX_ADMIN_PASS in .env before running this example.")
    return FritzConnection(
        address=os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1",
        user=os.getenv("FRITZBOX_USER", ""),
        password=password,
        port=int(os.getenv("FRITZBOX_PORT", "49000") or "49000"),
        use_tls=os.getenv("FRITZBOX_TLS", "0").lower() in {"1", "true", "yes"},
        use_cache=True,
        timeout=30,
    )


def authenticated_sid(fc: Any) -> str:
    http = fc.http_interface
    try:
        sid = next(http._get_sid())
    except Exception as exc:
        raise SystemExit(f"Could not obtain Web UI SID: {type(exc).__name__}: {exc}") from exc
    if not sid or sid == "0000000000000000":
        raise SystemExit("FRITZ!Box returned an invalid Web UI SID.")
    return str(sid)
