from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES

DEFAULT_DB = Path(os.getenv("FRITZBOX_ANALYSIS_DB", "fritzbox-analysis.sqlite3"))
SCHEMA_LOCK = threading.RLock()
SCHEMA_READY: set[Path] = set()


def restrict_db_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        return


def init_db(
    path: Path = DEFAULT_DB,
    repair_observations: Callable[[sqlite3.Connection], None] | None = None,
) -> sqlite3.Connection:
    path = Path(path)
    schema_key = path.resolve()
    existed_before_connect = path.exists()
    conn = sqlite3.connect(path, timeout=30.0)
    if not existed_before_connect:
        restrict_db_permissions(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    with SCHEMA_LOCK:
        if not existed_before_connect or schema_key not in SCHEMA_READY:
            conn.executescript("""
                PRAGMA journal_mode = WAL;

                CREATE TABLE IF NOT EXISTS export_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TEXT NOT NULL,
            router_address TEXT,
            window_hours INTEGER,
            summary_json TEXT NOT NULL,
            acquired_at TEXT,
            collector_time TEXT,
            tool_version TEXT,
            tool_git_commit TEXT,
            acquisition_mode TEXT,
            router_metadata_json TEXT,
            timestamp_assumptions_json TEXT,
            contamination_json TEXT,
            source_endpoints_json TEXT
        );

        CREATE TABLE IF NOT EXISTS raw_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, name, sha256),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            timestamp TEXT,
            category TEXT,
            mac TEXT,
            ip TEXT,
            source TEXT,
            message TEXT NOT NULL,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            searchable TEXT NOT NULL,
            UNIQUE(timestamp, message, source),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS wifi_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            derived_connected_at TEXT,
            derived_time_type TEXT,
            derived_time_confidence TEXT,
            exact_connection_time_available INTEGER NOT NULL,
            event TEXT,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            source TEXT,
            evidence TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'inferred',
            evidence_note TEXT,
            message TEXT,
            searchable TEXT NOT NULL,
            UNIQUE(derived_connected_at, event, hostname, mac, source),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            interface TEXT,
            interface_detail TEXT,
            active_now INTEGER NOT NULL,
            online INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            last_connected TEXT,
            uid TEXT,
            friendly_name TEXT,
            neighbour_name TEXT,
            ip_list TEXT,
            mac_list TEXT,
            wlan_station_type TEXT,
            wlan_uids TEXT,
            plc_uids TEXT,
            ethernet_port TEXT,
            vendor TEXT,
            model TEXT,
            speed TEXT,
            source_flags TEXT,
            parent_uid TEXT,
            flags TEXT,
            modification_flags TEXT,
            dhcp TEXT,
            static_dhcp TEXT,
            blocked TEXT,
            guest TEXT,
            vpn TEXT,
            wan_access TEXT,
            filter_profile_id TEXT,
            allow_pcp_and_upnp TEXT,
            pcp_count TEXT,
            upnp_count TEXT,
            myfritz_enabled TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'enriched_from_current_host_table',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(hostname, mac, ip),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS support_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            finding_type TEXT,
            section TEXT,
            key TEXT,
            value TEXT,
            line_number INTEGER,
            observed_at TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_text TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, line_number, raw_text),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS host_filter_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            profile_id TEXT,
            name TEXT,
            access_mode TEXT,
            time_budget TEXT,
            blocked TEXT,
            devices_json TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS mesh_topology_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            node TEXT,
            node_mac TEXT,
            interface TEXT,
            peer TEXT,
            peer_mac TEXT,
            link_type TEXT,
            state TEXT,
            last_connected TEXT,
            rx TEXT,
            tx TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS wan_port_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            protocol TEXT,
            external_port TEXT,
            internal_client TEXT,
            internal_port TEXT,
            description TEXT,
            enabled TEXT,
            remote_host TEXT,
            lease_duration TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS wlan_radios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            radio_index TEXT,
            ssid TEXT,
            enabled TEXT,
            status TEXT,
            standard TEXT,
            channel TEXT,
            total_associations TEXT,
            bytes_sent TEXT,
            bytes_received TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS wlan_associations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            observed_at TEXT,
            radio_index TEXT,
            association_index TEXT,
            mac TEXT,
            ip TEXT,
            hostname TEXT,
            auth_state TEXT,
            speed TEXT,
            signal_strength TEXT,
            channel TEXT,
            guest TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS advertisement_hints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            observed_at TEXT,
            hint_type TEXT,
            protocol TEXT,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            direction TEXT,
            confidence TEXT,
            summary TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'inferred',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS network_status_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            observed_at TEXT,
            area TEXT,
            metric TEXT,
            value TEXT,
            unit TEXT,
            source TEXT,
            confidence TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS device_risk_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            device_key TEXT,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            risk_level TEXT,
            risk_score TEXT,
            reasons_json TEXT,
            summary TEXT,
            source TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'inferred',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS security_advisories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            advisory_id TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            subject TEXT,
            status TEXT,
            recommendation TEXT,
            source TEXT,
            confidence TEXT,
            evidence_json TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'inferred',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, record_key),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS siem_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            event_time TEXT,
            event_category TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            action TEXT,
            outcome TEXT,
            severity TEXT,
            entity TEXT,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            interface TEXT,
            protocol TEXT,
            source TEXT,
            confidence TEXT,
            evidence_level TEXT,
            evidence_note TEXT,
            record_type TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            message TEXT,
            tags_json TEXT NOT NULL,
            fields_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS siem_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            correlation_type TEXT NOT NULL DEFAULT 'entity_rollup',
            rule_id TEXT,
            rule_version TEXT,
            confidence TEXT,
            window_start TEXT,
            window_end TEXT,
            entity_key TEXT NOT NULL,
            entity_label TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER NOT NULL,
            categories_json TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            severity TEXT,
            summary TEXT,
            fields_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, rule_id, entity_key, window_start, window_end),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS siem_correlation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            correlation_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            role TEXT,
            reason TEXT,
            weight INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(run_id) REFERENCES export_runs(id),
            FOREIGN KEY(correlation_id) REFERENCES siem_correlations(id),
            FOREIGN KEY(event_id) REFERENCES siem_events(id)
        );

        CREATE TABLE IF NOT EXISTS siem_alert_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            window_start TEXT NOT NULL DEFAULT '',
            window_end TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            resolved_at TEXT,
            resolved_by TEXT,
            note TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(run_id, rule_id, entity_key, window_start, window_end),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS siem_alert_webhook_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            window_start TEXT NOT NULL DEFAULT '',
            window_end TEXT NOT NULL DEFAULT '',
            webhook_url_hash TEXT NOT NULL,
            delivered_at TEXT NOT NULL,
            status TEXT NOT NULL,
            response_code INTEGER,
            error TEXT,
            UNIQUE(run_id, rule_id, entity_key, window_start, window_end, webhook_url_hash),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            record_type,
            record_id UNINDEXED,
            content
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS record_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            record_key TEXT NOT NULL,
            record_table_id INTEGER,
            observed_at TEXT NOT NULL,
            event_time TEXT,
            evidence_level TEXT NOT NULL,
            evidence_note TEXT,
            source TEXT,
            content_sha256 TEXT NOT NULL,
            content_json TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );
                """)
            ensure_schema(conn, repair_observations)
            SCHEMA_READY.add(schema_key)
    return conn


def ensure_schema(
    conn: sqlite3.Connection,
    repair_observations: Callable[[sqlite3.Connection], None] | None = None,
) -> None:
    migrate_raw_artifacts_unique_constraint(conn)
    ensure_additional_evidence_schema(conn)
    ensure_columns(
        conn,
        "export_runs",
        {
            "acquired_at": "TEXT",
            "collector_time": "TEXT",
            "tool_version": "TEXT",
            "tool_git_commit": "TEXT",
            "acquisition_mode": "TEXT",
            "router_metadata_json": "TEXT",
            "timestamp_assumptions_json": "TEXT",
            "contamination_json": "TEXT",
            "source_endpoints_json": "TEXT",
        },
    )
    ensure_columns(
        conn,
        "event_log",
        {
            "source": "TEXT",
            "evidence_level": "TEXT NOT NULL DEFAULT 'parsed_from_raw'",
            "evidence_note": "TEXT",
        },
    )
    migrate_event_log_source_unique_constraint(conn)
    ensure_columns(
        conn, "wifi_connections", {"evidence_level": "TEXT NOT NULL DEFAULT 'inferred'", "evidence_note": "TEXT"}
    )
    migrate_siem_correlations_unique_constraint(conn)
    ensure_columns(
        conn,
        "hosts",
        {
            "evidence_level": "TEXT NOT NULL DEFAULT 'enriched_from_current_host_table'",
            "evidence_note": "TEXT",
            "interface_detail": "TEXT",
            "online": "INTEGER",
            "uid": "TEXT",
            "friendly_name": "TEXT",
            "neighbour_name": "TEXT",
            "ip_list": "TEXT",
            "mac_list": "TEXT",
            "wlan_station_type": "TEXT",
            "wlan_uids": "TEXT",
            "plc_uids": "TEXT",
            "ethernet_port": "TEXT",
            "vendor": "TEXT",
            "model": "TEXT",
            "speed": "TEXT",
            "source_flags": "TEXT",
            "parent_uid": "TEXT",
            "flags": "TEXT",
            "modification_flags": "TEXT",
            "dhcp": "TEXT",
            "static_dhcp": "TEXT",
            "blocked": "TEXT",
            "guest": "TEXT",
            "vpn": "TEXT",
            "wan_access": "TEXT",
            "filter_profile_id": "TEXT",
            "allow_pcp_and_upnp": "TEXT",
            "pcp_count": "TEXT",
            "upnp_count": "TEXT",
            "myfritz_enabled": "TEXT",
            "last_activity": "TEXT",
            "last_activity_source": "TEXT",
            "last_activity_confidence": "TEXT",
            "last_activity_note": "TEXT",
        },
    )
    ensure_columns(
        conn,
        "siem_correlations",
        {
            "correlation_type": "TEXT NOT NULL DEFAULT 'entity_rollup'",
            "rule_id": "TEXT",
            "rule_version": "TEXT",
            "confidence": "TEXT",
            "window_start": "TEXT",
            "window_end": "TEXT",
        },
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS siem_correlation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            correlation_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            role TEXT,
            reason TEXT,
            weight INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(run_id) REFERENCES export_runs(id),
            FOREIGN KEY(correlation_id) REFERENCES siem_correlations(id),
            FOREIGN KEY(event_id) REFERENCES siem_events(id)
        )
        """)
    conn.execute("""
        UPDATE event_log
        SET evidence_note = 'Parsed from retained FRITZ!Box device log. The timestamp is exact for the retained log entry, not proof of full historical activity.'
        WHERE evidence_note IS NULL
        """)
    ensure_indexes(conn, repair_observations)


def ensure_additional_evidence_schema(conn: sqlite3.Connection) -> None:
    for table, spec in ADDITIONAL_EVIDENCE_TABLES.items():
        column_sql = ",\n            ".join(f"{column} TEXT" for column in spec["columns"])
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                record_key TEXT NOT NULL,
                {column_sql},
                evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
                evidence_note TEXT,
                raw_json TEXT NOT NULL,
                searchable TEXT NOT NULL,
                UNIQUE(run_id, record_key),
                FOREIGN KEY(run_id) REFERENCES export_runs(id)
            )
            """)
        ensure_columns(conn, table, {str(column): "TEXT" for column in spec["columns"]})


def migrate_raw_artifacts_unique_constraint(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'raw_artifacts'").fetchone()
    if not row or "UNIQUE(name, sha256)" not in str(row["sql"] or ""):
        return
    conn.executescript("""
        ALTER TABLE raw_artifacts RENAME TO raw_artifacts_legacy_unique;
        CREATE TABLE raw_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, name, sha256),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );
        INSERT OR IGNORE INTO raw_artifacts(id, run_id, name, sha256, content, created_at)
        SELECT id, run_id, name, sha256, content, created_at
        FROM raw_artifacts_legacy_unique;
        DROP TABLE raw_artifacts_legacy_unique;
        """)


def migrate_event_log_source_unique_constraint(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'event_log'").fetchone()
    table_sql = str(row["sql"] or "") if row else ""
    if "UNIQUE(timestamp, message)" not in table_sql or "UNIQUE(timestamp, message, source)" in table_sql:
        return
    conn.executescript("""
        ALTER TABLE event_log RENAME TO event_log_legacy_unique;
        CREATE TABLE event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            timestamp TEXT,
            category TEXT,
            mac TEXT,
            ip TEXT,
            source TEXT,
            message TEXT NOT NULL,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            searchable TEXT NOT NULL,
            UNIQUE(timestamp, message, source),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );
        INSERT OR IGNORE INTO event_log(
            id, run_id, timestamp, category, mac, ip, source, message,
            evidence_level, evidence_note, searchable
        )
        SELECT id, run_id, timestamp, category, mac, ip, COALESCE(source, 'device_log'), message,
               COALESCE(evidence_level, 'parsed_from_raw'), evidence_note, searchable
        FROM event_log_legacy_unique;
        DROP TABLE event_log_legacy_unique;
        """)


def migrate_siem_correlations_unique_constraint(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'siem_correlations'").fetchone()
    table_sql = str(row["sql"] or "") if row else ""
    if "UNIQUE(run_id, entity_key)" not in table_sql:
        return
    conn.executescript("""
        DROP TABLE IF EXISTS siem_correlation_events;
        ALTER TABLE siem_correlations RENAME TO siem_correlations_legacy_unique;
        CREATE TABLE siem_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            correlation_type TEXT NOT NULL DEFAULT 'entity_rollup',
            rule_id TEXT,
            rule_version TEXT,
            confidence TEXT,
            window_start TEXT,
            window_end TEXT,
            entity_key TEXT NOT NULL,
            entity_label TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER NOT NULL,
            categories_json TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            severity TEXT,
            summary TEXT,
            fields_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(run_id, rule_id, entity_key, window_start, window_end),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );
        INSERT OR IGNORE INTO siem_correlations(
            id, run_id, correlation_type, rule_id, rule_version, confidence,
            window_start, window_end, entity_key, entity_label, first_seen, last_seen,
            event_count, categories_json, tags_json, severity, summary, fields_json, searchable
        )
        SELECT
            id, run_id, 'entity_rollup', 'entity.timeline_rollup', '1', 'medium',
            first_seen, last_seen, entity_key, entity_label, first_seen, last_seen,
            event_count, categories_json, tags_json, severity, summary, fields_json, searchable
        FROM siem_correlations_legacy_unique;
        DROP TABLE siem_correlations_legacy_unique;
        """)


def ensure_indexes(
    conn: sqlite3.Connection,
    repair_observations: Callable[[sqlite3.Connection], None] | None = None,
) -> None:
    indexes = (
        "CREATE INDEX IF NOT EXISTS idx_record_observations_run_type_table "
        "ON record_observations(run_id, record_type, record_table_id)",
        "CREATE INDEX IF NOT EXISTS idx_record_observations_type_table "
        "ON record_observations(record_type, record_table_id)",
        "CREATE INDEX IF NOT EXISTS idx_event_log_timestamp ON event_log(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_wifi_connections_time ON wifi_connections(derived_connected_at)",
        "CREATE INDEX IF NOT EXISTS idx_hosts_activity ON hosts(last_activity, last_connected, last_seen, first_seen)",
        "CREATE INDEX IF NOT EXISTS idx_advertisement_hints_time ON advertisement_hints(observed_at)",
        "CREATE INDEX IF NOT EXISTS idx_siem_events_run_time ON siem_events(run_id, event_time)",
        "CREATE INDEX IF NOT EXISTS idx_siem_events_kind ON siem_events(event_category, event_kind, severity)",
        "CREATE INDEX IF NOT EXISTS idx_siem_events_entity ON siem_events(mac, ip, hostname)",
        "CREATE INDEX IF NOT EXISTS idx_siem_correlations_run_seen ON siem_correlations(run_id, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_siem_correlations_entity ON siem_correlations(entity_key)",
        "CREATE INDEX IF NOT EXISTS idx_siem_correlations_rule ON siem_correlations(rule_id, correlation_type)",
        "CREATE INDEX IF NOT EXISTS idx_siem_correlation_events_correlation ON siem_correlation_events(correlation_id)",
        "CREATE INDEX IF NOT EXISTS idx_siem_correlation_events_event ON siem_correlation_events(event_id)",
        "CREATE INDEX IF NOT EXISTS idx_siem_alert_states_identity "
        "ON siem_alert_states(run_id, rule_id, entity_key, window_start, window_end)",
        "CREATE INDEX IF NOT EXISTS idx_siem_alert_deliveries_identity "
        "ON siem_alert_webhook_deliveries(run_id, rule_id, entity_key, window_start, window_end)",
    )
    for sql in indexes:
        conn.execute(sql)
    for table, spec in ADDITIONAL_EVIDENCE_TABLES.items():
        time_column = str(spec["time_column"])
        if time_column:
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_{time_column} ON {table}({time_column})")
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_run ON {table}(run_id)")
    conn.execute("""
        UPDATE wifi_connections
        SET evidence_note = CASE
            WHEN exact_connection_time_available = 1 THEN 'Exact WiFi connection event parsed from a retained FRITZ!Box log entry.'
            WHEN derived_time_type = 'mesh_last_observed' THEN 'Known/current WLAN device observation from mesh data. This is not an exact WiFi association time.'
            ELSE 'Derived WiFi-related row. Treat as contextual unless backed by a retained exact connection log entry.'
        END
        WHERE evidence_note IS NULL
        """)
    conn.execute("""
        UPDATE hosts
        SET evidence_note = 'Host context from the FRITZ!Box host table at acquisition time; IP/name mappings may be stale or reassigned.'
        WHERE evidence_note IS NULL
        """)
    missing_observation_ids = int(
        conn.execute(
            "SELECT COUNT(*) FROM record_observations WHERE record_table_id IS NULL AND record_type != 'raw_artifact'"
        ).fetchone()[0]
    )
    if missing_observation_ids and repair_observations:
        repair_observations(conn)
    conn.commit()


def ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
