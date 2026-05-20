from __future__ import annotations

from types import SimpleNamespace

from fritzbox_collectors import fetch_support_data, is_support_data_response


class FakeResponse:
    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.posts: list[dict] = []

    def post(self, url: str, **kwargs):
        self.posts.append({"url": url, **kwargs})
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
