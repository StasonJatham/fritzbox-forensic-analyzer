# Local Start

Use this when running FRITZ!Box Forensik SIEM from a fresh checkout.

## 1. Open The Project

```bash
cd /Users/karl/Code/fritzforensic
```

## 2. Create A Virtual Environment

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install -e ".[dev]"
```

## 3. Configure The Router

```bash
cp .env.example .env
```

Edit `.env` locally:

```bash
FRITZBOX_ADDRESS=192.168.178.1
FRITZBOX_USER=
FRITZBOX_PASSWORD=your-admin-password
FRITZBOX_PORT=49000
FRITZBOX_TLS=0
```

Do not commit `.env`, SQLite databases, raw artifacts, or exported evidence packages.

Acquisition now runs as a background pipeline. The dashboard starts one job at a time, shows stage progress, writes raw files first into `output/raw-acquisition-*`, and only then parses/imports into SQLite. Endpoint failures are retained as `.error.txt` files and manifest rows, so a fragile FRITZ!Box Web UI endpoint does not discard already collected evidence.

The default acquisition delay is intentionally conservative (`FRITZBOX_ACQUISITION_DELAY=0.75`). Raise it on older or busy routers; lowering it is only for controlled local testing.

The default acquisition mode uses child-process hard timeouts for each router artifact. This prevents one stuck FRITZ!Box request from blocking the whole run. `FRITZBOX_SUPPORT_HARD_TIMEOUT=180` gives support-data more time because it is the most valuable source for historical WLAN association details.

Runtime logs are written to `logs/fritzforensic.log`. For deeper acquisition debugging, set `FRITZBOX_LOG_LEVEL=DEBUG` in `.env` before starting the dashboard.

## 4. Run Tests

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/black --check .
.venv/bin/python -m mypy .
.venv/bin/pyright fritzbox_*.py tests
```

## 5. Start The Dashboard

```bash
.venv/bin/fritzbox-forensics-dashboard --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

## Optional API Token

If you intentionally bind outside localhost, set both values:

```bash
FRITZBOX_ALLOW_PUBLIC_BIND=1
FRITZBOX_API_TOKEN=change-this-token
```

Then send the token as `X-API-Token` or `Authorization: Bearer`.
