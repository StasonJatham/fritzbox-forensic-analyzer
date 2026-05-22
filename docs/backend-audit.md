# Backend Audit

Audit date: 2026-05-21

Scope: FastAPI dashboard routes, acquisition/import helpers, collector URL fetching, live 802.11 capture, VPN/DynDNS planner, local SQLite settings.

## Findings And Status

| Severity | Finding | Status |
|---|---|---|
| High | Dashboard APIs expose privileged local actions. Public binding can leak evidence, trigger router logins/capture, and clear profiles. | Improved: CLI now refuses non-loopback bind unless `FRITZBOX_ALLOW_PUBLIC_BIND=1`; API docs are disabled unless `FRITZBOX_ENABLE_API_DOCS=1`; `/api/*` requires `FRITZBOX_API_TOKEN` when public bind is enabled or when a token is configured. |
| High | FRITZ!Box admin password can be stored plaintext in local SQLite settings. | Improved: new DB files are chmod `0600` and forensic package export redacts the password. Residual risk remains; prefer `.env` or OS secret storage for production. |
| High | Import endpoint accepted unbounded request bodies and ZIP database members. | Fixed: request `Content-Length`, decoded payload, encrypted ZIP flag, and embedded DB size are capped. Oversized imports return 413. |
| Medium | Router-provided AVM paths could be absolute URLs and cause authenticated outbound requests to a different host. | Fixed: authenticated artifact fetches are restricted to the same router origin; unauthenticated fallback rejects absolute URLs. |
| Medium | Blocking router/network/capture work was performed inside async FastAPI handlers. | Fixed for live capture, polling, settings, and VPN planning by using sync route functions. |
| Medium | JSON request payloads were raw dicts with route-local casts, causing weak validation and possible 500s. | Fixed: Pydantic request models now validate settings, polling, live capture, and VPN/DynDNS planner payloads. |
| Low/Medium | Live capture worker could still be closing after a request returned. | Improved: capture bytes are lock-protected and partial data is discarded if the worker does not stop before timeout. |
| Low | Backend modules are broad, especially `fritzbox_log_store.py`. | Fixed: `fritzbox_log_store.py` is now a small compatibility facade. FritzBox typed-evidence table registration and aliases are split into `fritzbox_evidence_tables.py`, additional-evidence extraction/advisory derivation is split into `fritzbox_evidence_extractors.py`, local dashboard settings persistence is split into `fritzbox_settings_store.py`, SQLite schema setup/migrations are split into `fritzbox_store_schema.py`, record primitives are split into `fritzbox_store_records.py`, ingestion/write orchestration is split into `fritzbox_store_ingest.py`, search/timeline queries are split into `fritzbox_store_queries.py`, and snapshot views are split into overview, summary, investigation, and entity modules. |

## Notes

- This is a local forensic workstation app. The safest supported mode remains binding to `127.0.0.1`.
- Raw artifacts and acquisition packages are intentionally sensitive. Treat exports as evidence files and store them accordingly.
- Unofficial FRITZ!Box Web UI endpoints can change between firmware versions; raw artifacts are preserved so parser results can be validated later.
