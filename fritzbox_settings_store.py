from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

OpenDb = Callable[[Path], sqlite3.Connection]


def get_settings(path: Path, open_db: OpenDb, include_secret: bool = False) -> dict[str, Any]:
    conn = open_db(path)
    rows = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM settings")}
    conn.close()
    result: dict[str, Any] = {
        "address": rows.get("address", ""),
        "user": rows.get("user", ""),
        "port": int(rows.get("port", "49000") or "49000"),
        "tls": rows.get("tls", "0") == "1",
        "has_password": bool(rows.get("password")),
    }
    if include_secret:
        result["password"] = rows.get("password", "")
    return result


def save_settings(settings: dict[str, Any], path: Path, open_db: OpenDb) -> dict[str, Any]:
    conn = open_db(path)
    current = get_settings(path, open_db, include_secret=True)
    values = {
        "address": str(settings.get("address") or current.get("address") or "192.168.178.1"),
        "user": str(settings["user"] if "user" in settings else current.get("user") or ""),
        "port": str(int(settings.get("port") or current.get("port") or 49000)),
        "tls": "1" if bool(settings.get("tls")) else "0",
        "password": str(settings.get("password") or current.get("password") or ""),
    }
    now = datetime.now().astimezone().isoformat()
    with conn:
        for key, value in values.items():
            conn.execute(
                """
                INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, value, now),
            )
    conn.close()
    return get_settings(path, open_db)
