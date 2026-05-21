from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fritzbox_raw_acquisition import (
    RawAcquisitionWriter,
    collect_hosts_paced,
    collect_indexed_results_paced,
    fetch_webui_payload,
    load_raw_bundle,
)
from fritzbox_wifi_export import build_dataset_from_raw_exports


class FakeResponse:
    status_code = 200
    headers = {"content-type": "text/html"}
    text = "<!doctype html><html>Login</html>"
    content = text.encode()

    def close(self) -> None:
        pass


class FakeSession:
    def get(self, *_args, **_kwargs):
        return FakeResponse()


def test_raw_writer_preserves_successes_and_errors(tmp_path: Path) -> None:
    writer = RawAcquisitionWriter(tmp_path, "2026-05-21T08:00:00+02:00")

    writer.write_text("device_log_text", "20.05.2026 14:00:00 WLAN-Gerät angemeldet: phone", "tr064")
    writer.write_error("data_lua_page_log", "webui_data_lua", "timeout")
    writer.write_summary()

    bundle = load_raw_bundle(tmp_path)

    assert bundle["device_log_text"].startswith("20.05.2026")
    assert bundle["data_lua_page_log_error"].strip() == "timeout"
    assert "acquisition_summary_json" in bundle
    assert "acquisition_manifest_json" in bundle
    assert (tmp_path / "data_lua_page_log.error.txt").exists()


def test_load_raw_bundle_reconstructs_combined_wlan_device_lists(tmp_path: Path) -> None:
    writer = RawAcquisitionWriter(tmp_path, "2026-05-21T08:00:00+02:00")
    writer.write_text("wlan_device_list_xml_1", "<List><TotalAssociations>0</TotalAssociations></List>", "tr064")
    writer.write_text("wlan_device_list_xml_2", "<List><TotalAssociations>1</TotalAssociations></List>", "tr064")
    writer.write_summary()

    bundle = load_raw_bundle(tmp_path)

    assert "wlan_device_list_xml" in bundle
    assert '"1"' in bundle["wlan_device_list_xml"]
    assert '"2"' in bundle["wlan_device_list_xml"]


def test_build_dataset_from_raw_bundle_parses_available_data(tmp_path: Path) -> None:
    writer = RawAcquisitionWriter(tmp_path, "2026-05-21T08:00:00+02:00")
    writer.write_json(
        "hosts_tr064_generic_json",
        [{"NewHostName": "phone", "NewIPAddress": "192.0.2.10", "NewMACAddress": "aa:bb:cc:dd:ee:ff"}],
        "tr064",
    )
    writer.write_text(
        "device_log_text",
        "20.05.2026 14:00:00 WLAN-Gerät angemeldet: phone, 192.0.2.10, aa:bb:cc:dd:ee:ff",
        "tr064",
    )
    writer.write_summary()

    dataset = build_dataset_from_raw_exports(
        SimpleNamespace(address="192.0.2.1", port=49000, tls=False, hours=10000, include_disconnects=True),
        load_raw_bundle(tmp_path),
        "2026-05-21T08:00:00+02:00",
        tmp_path,
    )

    assert dataset["summary"]["wifi_events"] == 1
    assert dataset["summary"]["raw_acquisition_dir"] == str(tmp_path)
    assert "hosts_tr064_generic_json" in dataset["raw_exports"]


def test_build_dataset_merges_wlan_filtered_device_log_xml(tmp_path: Path) -> None:
    writer = RawAcquisitionWriter(tmp_path, "2026-05-21T08:00:00+02:00")
    writer.write_json("hosts_tr064_generic_json", [], "tr064")
    writer.write_text(
        "device_log_text",
        "20.05.2026 14:00:00 WLAN-Gerät angemeldet: phone, 192.0.2.10, aa:bb:cc:dd:ee:ff",
        "tr064",
    )
    writer.write_text(
        "device_log_xml_wlan",
        (
            "<DeviceLog><Event><date>20.05.26</date><time>14:05:00</time>"
            "<msg>WLAN-Anmeldung ist fehlgeschlagen: station, bb:cc:dd:ee:ff:00</msg>"
            "</Event></DeviceLog>"
        ),
        "tr064",
    )
    writer.write_summary()

    dataset = build_dataset_from_raw_exports(
        SimpleNamespace(address="192.0.2.1", port=49000, tls=False, hours=10000, include_disconnects=True),
        load_raw_bundle(tmp_path),
        "2026-05-21T08:00:00+02:00",
        tmp_path,
    )

    messages = "\n".join(row["message"] for row in dataset["event_log"])
    assert "WLAN-Gerät angemeldet" in messages
    assert "WLAN-Anmeldung ist fehlgeschlagen" in messages
    sources = {row["message"]: row["source"] for row in dataset["event_log"]}
    assert sources["WLAN-Anmeldung ist fehlgeschlagen: station, bb:cc:dd:ee:ff:00"] == "device_log_xml_wlan"


def test_webui_payload_rejects_login_html() -> None:
    fc = SimpleNamespace(http_interface=SimpleNamespace(fc=SimpleNamespace(session=FakeSession()), router_url="http://x"))

    raw, error = fetch_webui_payload(fc, "query.lua", {"sid": "bad"})

    assert raw == ""
    assert error == "HTML login/UI response instead of raw API payload"


def test_paced_hosts_collects_generic_and_specific_entries(monkeypatch) -> None:
    calls = []
    pauses = []

    class FakeFc:
        def call_action(self, service, action, arguments=None):
            calls.append((service, action, arguments))
            if action == "GetHostNumberOfEntries":
                return {"NewHostNumberOfEntries": "1"}
            if action == "GetGenericHostEntry":
                return {"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewHostName": "phone"}
            if action == "GetSpecificHostEntry":
                return {"NewIPAddress": "192.0.2.10"}
            raise AssertionError(action)

    monkeypatch.setattr("fritzbox_raw_acquisition.pause", lambda delay: pauses.append(delay))

    hosts = collect_hosts_paced(FakeFc(), 0.75)

    assert hosts == [{"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewHostName": "phone", "NewIPAddress": "192.0.2.10"}]
    assert [call[1] for call in calls] == ["GetHostNumberOfEntries", "GetGenericHostEntry", "GetSpecificHostEntry"]
    assert pauses == [0.75, 0.75]


def test_paced_indexed_results_pauses_between_items(monkeypatch) -> None:
    pauses = []

    class FakeFc:
        def call_action(self, service, action, arguments=None):
            if action in {"GetPortMappingNumberOfEntries", "GetTotalAssociations"}:
                return {}
            if action == "GetHostNumberOfEntries":
                return {"NewHostNumberOfEntries": "2"}
            if action == "GetGenericHostEntry":
                return {"NewIndex": arguments["NewIndex"]}
            return {}

    monkeypatch.setattr("fritzbox_raw_acquisition.pause", lambda delay: pauses.append(delay))

    indexed = collect_indexed_results_paced(FakeFc(), 0.75)

    assert len(indexed["hosts_generic"]["items"]) == 2
    assert len(pauses) >= 3
