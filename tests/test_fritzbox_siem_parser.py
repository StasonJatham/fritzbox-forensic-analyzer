from __future__ import annotations

from fritzbox_parsers import FritzLogEntry, classify_log_entry, entry_to_dict
from fritzbox_siem_parser import list_parser_rules, parse_fritzbox_log_message


def test_parse_hostapd_station_connection() -> None:
    parsed = parse_fritzbox_log_message("ath0: AP-STA-CONNECTED ca:04:95:b2:4c:5b")

    assert parsed["category"] == "wifi"
    assert parsed["kind"] == "wifi.ap_sta_connected"
    assert parsed["action"] == "connect"
    assert parsed["mac"] == "ca:04:95:b2:4c:5b"
    assert parsed["interface"] == "ath0"
    assert parsed["protocol"] == "802.11"
    assert parsed["fields"]["parser_rule_id"] == "wifi.ap_sta_connected"


def test_parse_fritzbox_wifi_connection_with_name_ip_and_mac() -> None:
    parsed = parse_fritzbox_log_message(
        "WLAN-Gerat angemeldet: Analyst-iPhone, 192.0.2.30, aa:bb:cc:dd:ee:ff"
    )

    assert parsed["category"] == "wifi"
    assert parsed["kind"] == "wifi.connected"
    assert parsed["hostname"] == "Analyst-iPhone"
    assert parsed["ip"] == "192.0.2.30"
    assert parsed["mac"] == "aa:bb:cc:dd:ee:ff"
    assert "connect" in parsed["tags"]


def test_parse_support_auth_failure_keeps_source_ip() -> None:
    parsed = parse_fritzbox_log_message("soap:check_async_auth failed with -1 from 192.168.178.23:54587")

    assert parsed["category"] == "auth"
    assert parsed["kind"] == "auth.login_failure"
    assert parsed["outcome"] == "failure"
    assert parsed["ip"] == "192.168.178.23"
    assert parsed["severity"] == "medium"


def test_parse_probe_request_as_nearby_discovery() -> None:
    parsed = parse_fritzbox_log_message("wifi0 probe request from de:ad:be:ef:00:01 for ssid Guest")

    assert parsed["category"] == "discovery"
    assert parsed["kind"] == "wifi.probe_request"
    assert parsed["action"] == "probe_request"
    assert parsed["mac"] == "de:ad:be:ef:00:01"
    assert parsed["interface"] == "wifi0"
    assert "nearby" in parsed["tags"]


def test_parse_hostapd_wpa_and_radius_support_lines() -> None:
    handshake = parse_fritzbox_log_message("ath1: STA aa:bb:cc:dd:ee:11 WPA: pairwise key handshake completed (RSN)")
    radius = parse_fritzbox_log_message("ath1: STA aa:bb:cc:dd:ee:11 RADIUS: starting accounting session ABC123")

    assert handshake["kind"] == "wifi.wpa_key_handshake"
    assert handshake["fields"]["handshake_kind"] == "pairwise"
    assert radius["kind"] == "wifi.radius_accounting_start"
    assert radius["fields"]["session"] == "ABC123"


def test_parse_hostapd_association_request_extracts_second_mac_group() -> None:
    parsed = parse_fritzbox_log_message("hostapd: Association Request from STA aa:bb:cc:dd:ee:44")

    assert parsed["category"] == "wifi"
    assert parsed["kind"] == "wifi.association_request"
    assert parsed["mac"] == "aa:bb:cc:dd:ee:44"


def test_parser_specific_rules_are_not_shadowed_by_broad_rules() -> None:
    exposure = parse_fritzbox_log_message("UPnP portfreigabe fuer 192.0.2.8 wurde eingerichtet")
    auth = parse_fritzbox_log_message("Login failed from 192.0.2.23")
    wifi = parse_fritzbox_log_message("ath0: AP-STA-CONNECTED ca:04:95:b2:4c:5b")

    assert exposure["kind"] == "security.exposure_event"
    assert auth["kind"] == "auth.login_failure"
    assert wifi["kind"] == "wifi.ap_sta_connected"


def test_parser_post_match_extracts_fields_from_loose_dhcp_line() -> None:
    parsed = parse_fritzbox_log_message("DHCP lease assigned for host 192.0.2.77 / AA:BB:CC:DD:EE:77")

    assert parsed["kind"] == "network.dhcp"
    assert parsed["ip"] == "192.0.2.77"
    assert parsed["mac"] == "aa:bb:cc:dd:ee:77"


def test_parser_category_is_used_by_device_log_entry_dict() -> None:
    row = entry_to_dict(FritzLogEntry(None, "ath0: AP-STA-CONNECTED ca:04:95:b2:4c:5b", "", "support_data"))

    assert row["category"] == "wifi"
    assert row["mac"] == "ca:04:95:b2:4c:5b"
    assert classify_log_entry("wifi0 probe request from de:ad:be:ef:00:01") == "discovery"


def test_parser_rule_registry_is_introspectable() -> None:
    rules = list_parser_rules()
    rule_ids = {rule["rule_id"] for rule in rules}

    assert "wifi.ap_sta_connected" in rule_ids
    assert "wifi.probe_request" in rule_ids
    assert "wifi.radius_accounting_start" in rule_ids
    assert "auth.soap_failure" in rule_ids
    assert all("priority" in rule for rule in rules)
