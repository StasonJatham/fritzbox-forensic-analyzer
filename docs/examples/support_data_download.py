from __future__ import annotations

from common import authenticated_sid, fritz_connection


def main() -> None:
    fc = fritz_connection()
    sid = authenticated_sid(fc)
    url = f"{fc.http_interface.router_url}/cgi-bin/firmwarecfg"
    session = fc.http_interface.fc.session
    response = session.post(url, files={"sid": (None, sid), "SupportDataEnhanced": (None, "")}, timeout=90)
    text = response.content.decode("utf-8", errors="replace")
    print("HTTP status:", response.status_code)
    print("Bytes:", len(response.content))
    print("Looks like support data:", "support" in text[:1000].casefold() and "fritz" in text[:1000].casefold())
    print("Section markers:", text.count("##### BEGIN SECTION"))
    print("Do not commit this output; support data is highly sensitive.")


if __name__ == "__main__":
    main()
