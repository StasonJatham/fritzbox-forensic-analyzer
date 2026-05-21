from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def main() -> None:
    query = sys.argv[1] if len(sys.argv) > 1 else "wifi"
    db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("fritzbox-analysis.sqlite3")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT record_type, record_id, snippet(records_fts, 2, '[', ']', '...', 12) AS match
        FROM records_fts
        WHERE records_fts MATCH ?
        LIMIT 20
        """,
        [query],
    ).fetchall()
    for row in rows:
        print(f"{row['record_type']} #{row['record_id']}: {row['match']}")
    conn.close()


if __name__ == "__main__":
    main()
