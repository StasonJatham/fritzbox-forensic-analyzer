from __future__ import annotations

from types import SimpleNamespace

from fritzbox_collectors import (
    MAX_WEBUI_ARTIFACT_BYTES,
    fetch_aha_artifacts,
    fetch_avm_path,
    fetch_support_data,
    fetch_webui_readonly_artifacts,
    fetch_webui_readonly_endpoint,
    is_read_only_action,
    is_support_data_response,
)


class FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.posts: list[dict] = []
        self.gets: list[dict] = []

    def post(self, url: str, **kwargs):
        self.posts.append({"url": url, **kwargs})
        return self.response

    def get(self, url: str, **kwargs):
        self.gets.append({"url": url, **kwargs})
        return self.response


class FakeHttp:
    router_url = "http://192.0.2.1"

    def __init__(self, session: FakeSession) -> None:
        self.fc = SimpleNamespace(session=session)

    def _get_sid(self):
        yield "0123456789abcdef"


def test_fetch_support_data_posts_sid_to_firmwarecfg() -> None:
    body = (
        "FRITZ!Box support data\nsupport device system wlan dsl mesh kernel\n" + ("diagnostic line\n" * 100)
    ).encode()
    session = FakeSession(FakeResponse(200, body))
    fc = SimpleNamespace(http_interface=FakeHttp(session))

    support_data = fetch_support_data(fc)

    assert support_data is not None
    assert support_data.startswith("FRITZ!Box support data")
    assert session.posts[0]["url"] == "http://192.0.2.1/cgi-bin/firmwarecfg"
    assert "sid" in session.posts[0]["files"]
    assert "SupportDataEnhanced" in session.posts[0]["files"]


def test_fetch_support_data_rejects_html_login_page() -> None:
    session = FakeSession(FakeResponse(200, b"<!doctype html><html>Login</html>" + (b" " * 2000)))
    fc = SimpleNamespace(http_interface=FakeHttp(session))

    assert fetch_support_data(fc) is None


def test_support_data_response_uses_content_markers() -> None:
    assert is_support_data_response("FRITZ support box wlan dsl mesh kernel\n" + ("x" * 1200))
    assert not is_support_data_response("<html>FRITZ support box wlan dsl mesh</html>" + ("x" * 1200))


def test_read_only_action_filter_blocks_mutating_actions() -> None:
    assert is_read_only_action("GetInfo")
    assert is_read_only_action("X_AVM-DE_GetMeshListPath")
    assert not is_read_only_action("SetEnable")
    assert not is_read_only_action("X_AVM-DE_GetConfigFileUpdate")
    assert not is_read_only_action("Reboot")


def test_fetch_avm_path_prefers_authenticated_session() -> None:
    session = FakeSession(FakeResponse(200, b"<root>secret</root>"))
    fc = SimpleNamespace(http_interface=FakeHttp(session))

    content = fetch_avm_path("192.0.2.1", 49000, "/secure/path.lua", fc=fc)

    assert content == "<root>secret</root>"
    assert session.gets[0]["url"] == "http://192.0.2.1/secure/path.lua"
    assert session.gets[0]["timeout"] == 15


def test_fetch_webui_readonly_artifacts_collects_structured_get_results() -> None:
    session = FakeSession(FakeResponse(200, b"<payload>state</payload>"))
    fc = SimpleNamespace(http_interface=FakeHttp(session))

    artifacts = fetch_webui_readonly_artifacts(fc)

    assert artifacts["schema_version"] == 1
    assert artifacts["endpoints"]["juis_boxinfo_xml"]["ok"]
    assert artifacts["endpoints"]["juis_boxinfo_xml"]["raw"] == "<payload>state</payload>"
    assert session.gets[0]["url"] == "http://192.0.2.1/juis_boxinfo.xml"
    assert "sid" not in session.gets[0]["params"]
    assert session.gets[1]["url"] == "http://192.0.2.1/login_sid.lua"
    assert session.gets[1]["params"]["sid"] == "0123456789abcdef"
    assert artifacts["endpoints"]["login_sid_v2"]["params"]["sid"] == "<redacted>"


def test_fetch_webui_readonly_artifacts_records_html_as_failure() -> None:
    response = FakeResponse(200, b"<!doctype html><html>Login</html>", {"content-type": "text/html"})
    session = FakeSession(response)
    fc = SimpleNamespace(http_interface=FakeHttp(session))

    artifacts = fetch_webui_readonly_artifacts(fc)

    first = artifacts["endpoints"]["juis_boxinfo_xml"]
    assert not first["ok"]
    assert first["error"] == "HTML response instead of raw API payload"
    assert "raw" not in first


def test_fetch_webui_readonly_endpoint_truncates_large_payloads() -> None:
    session = FakeSession(FakeResponse(200, b"x" * (MAX_WEBUI_ARTIFACT_BYTES + 1)))

    result = fetch_webui_readonly_endpoint(session, "http://192.0.2.1", "/juis_boxinfo.xml", {})

    assert result["ok"]
    assert result["truncated"]
    assert result["body_bytes"] == MAX_WEBUI_ARTIFACT_BYTES + 1
    assert len(result["raw"]) == MAX_WEBUI_ARTIFACT_BYTES


def test_fetch_aha_artifacts_collects_switch_stats() -> None:
    class FakeAhaConnection:
        def call_http(self, command: str, ain: str | None = None):
            if command == "getdevicelistinfos":
                return {"content": "<devicelist/>"}
            if command == "getswitchlist":
                return {"content": "AIN-1,AIN-2"}
            return {"content": f"stats-{ain}"}

    artifacts = fetch_aha_artifacts(FakeAhaConnection())

    assert artifacts["aha_device_list_xml"] == "<devicelist/>"
    assert artifacts["aha_switch_list_txt"] == "AIN-1,AIN-2"
    assert "AIN-1" in artifacts["aha_device_stats_json"]
