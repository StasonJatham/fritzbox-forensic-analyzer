from __future__ import annotations

import hashlib
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from fritzbox_store_schema import DEFAULT_DB, init_db

OpenDb = Callable[[Path], sqlite3.Connection]

SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_STATUSES = {"open", "resolved"}


def get_alert_webhook_settings(path: Path = DEFAULT_DB, open_db: OpenDb = init_db) -> dict[str, Any]:
    conn = open_db(path)
    try:
        return alert_webhook_settings_from_conn(conn)
    finally:
        conn.close()


def save_alert_webhook_settings(
    settings: dict[str, Any],
    path: Path = DEFAULT_DB,
    open_db: OpenDb = init_db,
) -> dict[str, Any]:
    enabled = bool(settings.get("enabled"))
    url = clean(settings.get("url")) or ""
    min_severity = normalize_min_severity(settings.get("min_severity"))
    if enabled:
        validate_webhook_url(url)

    values = {
        "alert_webhook_enabled": "1" if enabled else "0",
        "alert_webhook_url": url,
        "alert_webhook_min_severity": min_severity,
    }
    now = now_iso()
    conn = open_db(path)
    try:
        with conn:
            for key, value in values.items():
                conn.execute(
                    """
                    INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                    """,
                    [key, value, now],
                )
    finally:
        conn.close()
    return get_alert_webhook_settings(path, open_db)


def alert_webhook_settings_from_conn(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = {row["key"]: row["value"] for row in conn.execute("""
            SELECT key, value
            FROM settings
            WHERE key IN ('alert_webhook_enabled', 'alert_webhook_url', 'alert_webhook_min_severity')
            """)}
    url = rows.get("alert_webhook_url", "")
    return {
        "enabled": rows.get("alert_webhook_enabled", "0") == "1",
        "url": url,
        "has_url": bool(url),
        "min_severity": normalize_min_severity(rows.get("alert_webhook_min_severity")),
    }


def mark_alert_state(
    *,
    correlation_id: int,
    status: str,
    note: str = "",
    resolved_by: str = "local analyst",
    path: Path = DEFAULT_DB,
    open_db: OpenDb = init_db,
) -> dict[str, Any]:
    normalized_status = normalize_alert_status(status)
    conn = open_db(path)
    try:
        correlation = conn.execute(
            """
            SELECT id, run_id, rule_id, entity_key, window_start, window_end, correlation_type
            FROM siem_correlations
            WHERE id = ?
            """,
            [correlation_id],
        ).fetchone()
        if not correlation:
            raise KeyError(f"SIEM correlation {correlation_id} was not found")
        if correlation["correlation_type"] != "alert":
            raise ValueError("Only alert correlations can be resolved")
        identity = alert_identity(correlation)
        now = now_iso()
        resolved_at = now if normalized_status == "resolved" else None
        with conn:
            conn.execute(
                """
                INSERT INTO siem_alert_states(
                    run_id, rule_id, entity_key, window_start, window_end,
                    status, resolved_at, resolved_by, note, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, rule_id, entity_key, window_start, window_end)
                DO UPDATE SET
                    status=excluded.status,
                    resolved_at=excluded.resolved_at,
                    resolved_by=excluded.resolved_by,
                    note=excluded.note,
                    updated_at=excluded.updated_at
                """,
                [
                    identity["run_id"],
                    identity["rule_id"],
                    identity["entity_key"],
                    identity["window_start"],
                    identity["window_end"],
                    normalized_status,
                    resolved_at,
                    clean(resolved_by) or "local analyst",
                    clean(note) or "",
                    now,
                ],
            )
        return alert_state_for_correlation(conn, correlation_id) or {"status": normalized_status}
    finally:
        conn.close()


def alert_state_for_correlation(conn: sqlite3.Connection, correlation_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT s.status, s.resolved_at, s.resolved_by, s.note, s.updated_at
        FROM siem_correlations c
        JOIN siem_alert_states s
          ON s.run_id = c.run_id
         AND s.rule_id = COALESCE(c.rule_id, '')
         AND s.entity_key = c.entity_key
         AND s.window_start = COALESCE(c.window_start, '')
         AND s.window_end = COALESCE(c.window_end, '')
        WHERE c.id = ?
        """,
        [correlation_id],
    ).fetchone()
    return dict(row) if row else None


def dispatch_alert_webhooks(conn: sqlite3.Connection, run_id: int, correlations: list[dict[str, Any]]) -> int:
    settings = alert_webhook_settings_from_conn(conn)
    if not settings["enabled"] or not settings["has_url"]:
        return 0
    url = str(settings["url"])
    validate_webhook_url(url)
    min_weight = SEVERITY_WEIGHT[settings["min_severity"]]
    delivered = 0
    for correlation in correlations:
        if correlation.get("correlation_type") != "alert":
            continue
        if SEVERITY_WEIGHT.get(str(correlation.get("severity") or "info"), 0) < min_weight:
            continue
        if webhook_delivery_exists(conn, correlation, url):
            continue
        status, response_code, error = send_alert_webhook(url, webhook_payload(run_id, correlation))
        record_webhook_delivery(conn, correlation, url, status, response_code, error)
        delivered += 1
    return delivered


def webhook_delivery_exists(conn: sqlite3.Connection, correlation: dict[str, Any], url: str) -> bool:
    identity = alert_identity(correlation)
    row = conn.execute(
        """
        SELECT 1
        FROM siem_alert_webhook_deliveries
        WHERE run_id = ?
          AND rule_id = ?
          AND entity_key = ?
          AND window_start = ?
          AND window_end = ?
          AND webhook_url_hash = ?
        """,
        [
            identity["run_id"],
            identity["rule_id"],
            identity["entity_key"],
            identity["window_start"],
            identity["window_end"],
            webhook_url_hash(url),
        ],
    ).fetchone()
    return row is not None


def record_webhook_delivery(
    conn: sqlite3.Connection,
    correlation: dict[str, Any],
    url: str,
    status: str,
    response_code: int | None,
    error: str,
) -> None:
    identity = alert_identity(correlation)
    conn.execute(
        """
        INSERT OR IGNORE INTO siem_alert_webhook_deliveries(
            run_id, rule_id, entity_key, window_start, window_end,
            webhook_url_hash, delivered_at, status, response_code, error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            identity["run_id"],
            identity["rule_id"],
            identity["entity_key"],
            identity["window_start"],
            identity["window_end"],
            webhook_url_hash(url),
            now_iso(),
            status,
            response_code,
            error[:1000],
        ],
    )


def send_alert_webhook(url: str, payload: dict[str, Any]) -> tuple[str, int | None, str]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "fritzbox-forensik-siem"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            code = int(response.getcode())
        return ("delivered" if 200 <= code < 300 else "failed", code, "")
    except urllib.error.HTTPError as exc:
        return "failed", int(exc.code), str(exc)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return "failed", None, str(exc)


def webhook_payload(run_id: int, correlation: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "fritzbox-forensik-siem",
        "run_id": run_id,
        "correlation_id": correlation.get("siem_correlation_id") or correlation.get("id"),
        "rule_id": correlation.get("rule_id"),
        "severity": correlation.get("severity"),
        "confidence": correlation.get("confidence"),
        "entity_key": correlation.get("entity_key"),
        "entity_label": correlation.get("entity_label"),
        "summary": correlation.get("summary"),
        "first_seen": correlation.get("first_seen"),
        "last_seen": correlation.get("last_seen"),
        "event_count": correlation.get("event_count"),
        "fields": safe_json_dict(correlation.get("fields_json")),
        "tags": safe_json_list(correlation.get("tags_json")),
        "categories": safe_json_list(correlation.get("categories_json")),
    }


def alert_identity(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": int(row["run_id"]),
        "rule_id": str(row["rule_id"] or ""),
        "entity_key": str(row["entity_key"] or ""),
        "window_start": str(row["window_start"] or ""),
        "window_end": str(row["window_end"] or ""),
    }


def webhook_url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def validate_webhook_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Webhook URL must be an absolute http:// or https:// URL")


def normalize_min_severity(value: Any) -> str:
    severity = str(value or "high").strip().casefold()
    return severity if severity in SEVERITY_WEIGHT else "high"


def normalize_alert_status(status: str) -> str:
    normalized = str(status or "").strip().casefold()
    if normalized not in ALERT_STATUSES:
        raise ValueError("Alert status must be 'open' or 'resolved'")
    return normalized


def safe_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def safe_json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        payload = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def clean(value: Any) -> str:
    return str(value or "").strip()


def now_iso() -> str:
    return datetime.now().astimezone().isoformat()
