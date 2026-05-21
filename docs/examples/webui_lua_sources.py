from __future__ import annotations

import json

from common import authenticated_sid, fritz_connection


def main() -> None:
    fc = fritz_connection()
    sid = authenticated_sid(fc)
    base = str(fc.http_interface.router_url).rstrip("/")
    session = fc.http_interface.fc.session

    query = "landevice:settings/landevice/list(UID,name,ip,mac,interface,active,firstused,lastused)"
    query_response = session.get(f"{base}/query.lua", params={"landevice": query, "sid": sid}, timeout=20)
    print("query.lua status:", query_response.status_code, "bytes:", len(query_response.content))
    try:
        payload = query_response.json()
        print("query.lua top-level keys:", sorted(payload.keys()))
    except ValueError:
        print("query.lua did not return JSON")

    data_response = session.get(f"{base}/data.lua", params={"page": "homeNet", "sid": sid}, timeout=20)
    print("data.lua homeNet status:", data_response.status_code, "bytes:", len(data_response.content))
    try:
        payload = data_response.json()
        print("data.lua sample keys:", sorted(payload.keys())[:20])
        print(json.dumps({"ok": True, "keys": sorted(payload.keys())[:20]}, indent=2))
    except ValueError:
        print("data.lua did not return JSON")


if __name__ == "__main__":
    main()
