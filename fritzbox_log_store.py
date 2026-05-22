from __future__ import annotations

from pathlib import Path
from typing import Any

from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES as ADDITIONAL_EVIDENCE_TABLES
from fritzbox_evidence_tables import ADDITIONAL_RECORD_TYPE_ALIASES as ADDITIONAL_RECORD_TYPE_ALIASES
from fritzbox_settings_store import get_settings as load_settings
from fritzbox_settings_store import save_settings as store_settings
from fritzbox_store_constants import EXPECTED_RAW_ARTIFACTS as EXPECTED_RAW_ARTIFACTS
from fritzbox_store_constants import WIFI_DEDUPE_SQL as WIFI_DEDUPE_SQL
from fritzbox_store_ingest import add_observation as add_observation
from fritzbox_store_ingest import ingest_dataset as ingest_dataset
from fritzbox_store_ingest import init_db as init_db
from fritzbox_store_ingest import reparse_support_wlan_environment as reparse_support_wlan_environment
from fritzbox_store_queries import query_records as query_records
from fritzbox_store_queries import query_timeline as query_timeline
from fritzbox_store_queries import siem_search_facets as siem_search_facets
from fritzbox_store_query_helpers import (
    _combine_filter as _combine_filter,
)
from fritzbox_store_query_helpers import (
    _run_observation_count as _run_observation_count,
)
from fritzbox_store_query_helpers import (
    _run_observation_sql as _run_observation_sql,
)
from fritzbox_store_query_helpers import (
    _run_record_count as _run_record_count,
)
from fritzbox_store_query_helpers import (
    enrich_host_activity as enrich_host_activity,
)
from fritzbox_store_query_helpers import (
    make_fts_query as make_fts_query,
)
from fritzbox_store_query_helpers import (
    resolve_run_id as resolve_run_id,
)
from fritzbox_store_records import (
    add_fts as add_fts,
)
from fritzbox_store_records import (
    event_key as event_key,
)
from fritzbox_store_records import (
    normalize_event_log_row as normalize_event_log_row,
)
from fritzbox_store_records import (
    searchable_text as searchable_text,
)
from fritzbox_store_schema import DEFAULT_DB
from fritzbox_store_snapshots import acquisition_source_coverage as acquisition_source_coverage
from fritzbox_store_snapshots import analysis_snapshot as analysis_snapshot
from fritzbox_store_snapshots import entity_pivot as entity_pivot
from fritzbox_store_snapshots import evidence_for_record as evidence_for_record
from fritzbox_store_snapshots import investigation_snapshot as investigation_snapshot
from fritzbox_store_snapshots import latest_snapshot as latest_snapshot
from fritzbox_store_snapshots import query_entities as query_entities


def list_runs(path: Path = DEFAULT_DB) -> list[dict[str, Any]]:
    conn = init_db(path)
    rows = [dict(row) for row in conn.execute("""
            SELECT r.id, r.generated_at, r.acquired_at, r.router_address, r.window_hours,
                   COUNT(DISTINCT CASE WHEN o.record_type = 'event_log' THEN o.record_table_id END) AS event_log,
                   COUNT(DISTINCT CASE WHEN o.record_type = 'wifi_connection' THEN o.record_table_id END) AS wifi_connections,
                   COUNT(DISTINCT CASE WHEN o.record_type = 'host' THEN o.record_table_id END) AS hosts
            FROM export_runs r
            LEFT JOIN record_observations o ON o.run_id = r.id
            GROUP BY r.id
            ORDER BY r.id DESC
            """)]
    conn.close()
    for row in rows:
        timestamp = row.get("generated_at") or row.get("acquired_at") or f"run {row['id']}"
        router = row.get("router_address") or "unknown router"
        row["label"] = (
            f"Run {row['id']} - {router} - {timestamp} "
            f"({row.get('event_log') or 0} logs / {row.get('wifi_connections') or 0} wifi / {row.get('hosts') or 0} hosts)"
        )
    return rows


def get_settings(path: Path = DEFAULT_DB, include_secret: bool = False) -> dict[str, Any]:
    return load_settings(path, init_db, include_secret)


def save_settings(settings: dict[str, Any], path: Path = DEFAULT_DB) -> dict[str, Any]:
    return store_settings(settings, path, init_db)
