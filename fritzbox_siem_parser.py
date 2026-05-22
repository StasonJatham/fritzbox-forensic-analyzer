from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern
from typing import Any

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INTERFACE_RE = re.compile(r"\b(?P<interface>wlan\d+|wifi\d+|ath\d+|lan\d+|guest|mesh|radio\s+\d+)\b", re.I)


@dataclass(frozen=True)
class LogPattern:
    rule_id: str
    regex: Pattern[str]
    category: str
    kind: str
    action: str
    outcome: str
    severity: str = "info"
    protocol: str | None = None
    tags: tuple[str, ...] = ()
    fields: dict[str, Any] = field(default_factory=dict)
    priority: int = 100


def compile_pattern(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.I | re.S)


LOG_PATTERNS: tuple[LogPattern, ...] = (
    LogPattern(
        rule_id="wifi.ap_sta_connected",
        regex=compile_pattern(r"\b(?P<interface>ath\d+|wlan\d+):\s+AP-STA-CONNECTED\s+(?P<mac>[0-9a-f:]{17})\b"),
        category="wifi",
        kind="wifi.ap_sta_connected",
        action="connect",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "connect", "ap_sta"),
    ),
    LogPattern(
        rule_id="wifi.ap_sta_disconnected",
        regex=compile_pattern(r"\b(?P<interface>ath\d+|wlan\d+):\s+AP-STA-DISCONNECTED\s+(?P<mac>[0-9a-f:]{17})\b"),
        category="wifi",
        kind="wifi.ap_sta_disconnected",
        action="disconnect",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "disconnect", "ap_sta"),
    ),
    LogPattern(
        rule_id="wifi.eapol_4way_completed",
        regex=compile_pattern(r"\b(?P<interface>ath\d+|wlan\d+):\s+EAPOL-4WAY-HS-COMPLETED\s+(?P<mac>[0-9a-f:]{17})\b"),
        category="wifi",
        kind="wifi.eapol_4way_completed",
        action="wpa_handshake",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "handshake", "wpa"),
    ),
    LogPattern(
        rule_id="wifi.wpa_key_handshake",
        regex=compile_pattern(
            r"\b(?P<interface>ath\d+|wlan\d+):\s+STA\s+(?P<mac>[0-9a-f:]{17})\s+WPA:\s+"
            r"(?P<handshake_kind>pairwise|group)\s+key handshake completed(?:\s+\((?P<cipher>[^)]+)\))?"
        ),
        category="wifi",
        kind="wifi.wpa_key_handshake",
        action="wpa_handshake",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "handshake", "wpa"),
    ),
    LogPattern(
        rule_id="wifi.radius_accounting_start",
        regex=compile_pattern(
            r"\b(?P<interface>ath\d+|wlan\d+):\s+STA\s+(?P<mac>[0-9a-f:]{17})\s+RADIUS:\s+"
            r"starting accounting session\s+(?P<session>\S+)"
        ),
        category="wifi",
        kind="wifi.radius_accounting_start",
        action="accounting_start",
        outcome="observed",
        protocol="802.11",
        tags=("wifi", "radius", "accounting"),
    ),
    LogPattern(
        rule_id="wifi.association_request",
        regex=compile_pattern(
            r"\b(?P<interface>ath\d+|wlan\d+):\s+association request(?: from)?\s+(?P<mac>[0-9a-f:]{17})"
            r"(?:.*?\bssid[=:]\s*(?P<ssid>[^,;\]\n]+))?"
        ),
        category="wifi",
        kind="wifi.association_request",
        action="associate",
        outcome="observed",
        protocol="802.11",
        tags=("wifi", "association", "nearby"),
    ),
    LogPattern(
        rule_id="wifi.hostapd_association_request",
        regex=compile_pattern(
            r"\bSTA\s+(?P<mac>[0-9a-f:]{17}).*?\bAssociation Request\b|"
            r"\bAssociation Request\b.*?\bSTA\s+(?P<mac2>[0-9a-f:]{17})"
        ),
        category="wifi",
        kind="wifi.association_request",
        action="associate",
        outcome="observed",
        protocol="802.11",
        tags=("wifi", "association", "nearby"),
    ),
    LogPattern(
        rule_id="wifi.steering_history",
        regex=compile_pattern(
            r"\bOPTIMISATION\s+RCPI\s+STA\s+(?P<mac>[0-9a-f:]{17})\s+from\s+"
            r"(?P<source_bssid>[0-9a-f:]{17}).*?\bmode\s+(?P<mode>\S+).*?\bended\s+with\s+(?P<result>[^\r\n]+?)\s+at\b"
        ),
        category="wifi",
        kind="wifi.steering_history",
        action="roaming_steering",
        outcome="observed",
        protocol="802.11",
        tags=("wifi", "roaming", "steering", "nearby"),
    ),
    LogPattern(
        rule_id="wifi.probe_request",
        regex=compile_pattern(
            r"\b(?:probe[-_\s]?request|probereq|prbreq|prb_req|suchanfrage|sondierungsanfrage)\b"
            r"(?:.*?(?P<mac>[0-9a-f:]{17}))?"
            r"(?:.*?\b(?:ssid|SSID)[=:\s]+(?P<ssid>[^,;\]\n]+))?"
        ),
        category="discovery",
        kind="wifi.probe_request",
        action="probe_request",
        outcome="observed",
        severity="low",
        protocol="802.11",
        tags=("wifi", "probe", "nearby"),
    ),
    LogPattern(
        rule_id="wifi.fritz_connected",
        regex=compile_pattern(
            r"\bWLAN-Ger.?t\s+(?:angemeldet|verbunden):?\s*"
            r"(?P<hostname>[^,;\n]+)?\s*(?:,\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
            r"(?:,\s*(?P<mac>[0-9a-f:]{17}))?"
        ),
        category="wifi",
        kind="wifi.connected",
        action="connect",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "connect"),
    ),
    LogPattern(
        rule_id="wifi.fritz_disconnected",
        regex=compile_pattern(
            r"\bWLAN-Ger.?t\s+(?:abgemeldet|getrennt|disconnected):?\s*"
            r"(?P<hostname>[^,;\n]+)?\s*(?:,\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
            r"(?:,\s*(?P<mac>[0-9a-f:]{17}))?"
        ),
        category="wifi",
        kind="wifi.disconnected",
        action="disconnect",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "disconnect"),
    ),
    LogPattern(
        rule_id="wifi.fritz_connection_failed",
        regex=compile_pattern(
            r"\bWLAN-(?:Anmeldung|Verbindung).*?(?:fehlgeschlagen|failed|abgewiesen|rejected):?\s*"
            r"(?P<hostname>[^,;\n]+)?\s*(?:,\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
            r"(?:,\s*(?P<mac>[0-9a-f:]{17}))?"
        ),
        category="wifi",
        kind="wifi.connection_failed",
        action="connect",
        outcome="failure",
        severity="medium",
        protocol="802.11",
        tags=("wifi", "failure"),
    ),
    LogPattern(
        rule_id="wifi.hostapd_disconnected",
        regex=compile_pattern(
            r"\b(?P<interface>ath\d+|wlan\d+):\s+STA\s+(?P<mac>[0-9a-f:]{17}).*?"
            r"\b(?:disassociated|deauthenticated|disconnected)\b(?:.*?\breason[=:\s]+(?P<reason>\d+))?"
        ),
        category="wifi",
        kind="wifi.disconnected",
        action="disconnect",
        outcome="success",
        protocol="802.11",
        tags=("wifi", "disconnect", "hostapd"),
    ),
    LogPattern(
        rule_id="wifi.hostapd_connection_failed",
        regex=compile_pattern(
            r"\b(?P<interface>ath\d+|wlan\d+):\s+STA\s+(?P<mac>[0-9a-f:]{17}).*?"
            r"\b(?:rejected|failed|authentication failure|wrong password|invalid)\b"
        ),
        category="wifi",
        kind="wifi.connection_failed",
        action="connect",
        outcome="failure",
        severity="medium",
        protocol="802.11",
        tags=("wifi", "failure", "hostapd"),
    ),
    LogPattern(
        rule_id="auth.soap_failure",
        regex=compile_pattern(
            r"\bsoap:check_async_auth failed\b.*?(?:from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d+))?)?"
        ),
        category="auth",
        kind="auth.login_failure",
        action="login",
        outcome="failure",
        severity="medium",
        tags=("auth", "failure", "soap"),
    ),
    LogPattern(
        rule_id="auth.fritzbox_ui_failure",
        regex=compile_pattern(
            r"(?=.*\b(?:FRITZ!?Box[-\s]?(?:Benutzeroberfl(?:[aä]|ae)che|user interface)|login_sid\.lua|web(?:ui| interface))\b)"
            r"(?=.*\b(?:Anmeldung|Login|authentication|Kennwort|password)\b)"
            r"(?=.*\b(?:fehlgeschlagen|gescheitert|falsch|invalid|wrong|failed|incorrect)\b)"
            r"(?:.*?\b(?:Benutzer|user)\s+(?P<username>[^\s,;:]+))?"
            r"(?:.*?\b(?:IP-Adresse|IP address|von|from)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
        ),
        category="auth",
        kind="auth.login_failure",
        action="login",
        outcome="failure",
        severity="medium",
        tags=("auth", "failure", "fritzbox_ui"),
        priority=70,
    ),
    LogPattern(
        rule_id="auth.digest_failure",
        regex=compile_pattern(r"\bcheck_async_auth\b.*?\bfailed\b.*?(?P<method>Digest|Basic)?"),
        category="auth",
        kind="auth.login_failure",
        action="login",
        outcome="failure",
        severity="medium",
        tags=("auth", "failure"),
    ),
    LogPattern(
        rule_id="auth.login_failure",
        regex=compile_pattern(
            r"\b(?:Anmeldung|Login|Kennwort|password|authentication)\b.*?"
            r"\b(?:fehlgeschlagen|falsch|invalid|wrong|failed|incorrect)\b"
            r"(?:.*?\b(?:von|from)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
        ),
        category="auth",
        kind="auth.login_failure",
        action="login",
        outcome="failure",
        severity="medium",
        tags=("auth", "failure"),
    ),
    LogPattern(
        rule_id="auth.login_success",
        regex=compile_pattern(
            r"\b(?:Anmeldung|Login|authentication)\b.*?\b(?:erfolgreich|success|successful)\b"
            r"(?:.*?\b(?:von|from)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
        ),
        category="auth",
        kind="auth.login_success",
        action="login",
        outcome="success",
        severity="low",
        tags=("auth", "success"),
    ),
    LogPattern(
        rule_id="security.remote_admin_enabled",
        regex=compile_pattern(
            r"\b(?:remote access|internet access to (?:the )?FRITZ!?Box|"
            r"Zugriff aus dem Internet|Internetzugriff auf die FRITZ!?Box|Fernzugriff|HTTPS-Port)\b"
            r".*\b(?:enabled|aktiv|eingeschaltet|freigegeben|port\s*(?P<port>\d{2,5}))\b"
        ),
        category="security",
        kind="security.remote_admin_exposure",
        action="remote_admin_exposure",
        outcome="enabled",
        severity="high",
        tags=("security", "exposure", "remote_admin"),
        priority=70,
    ),
    LogPattern(
        rule_id="security.myfritz_enabled",
        regex=compile_pattern(
            r"\bMyFRITZ!?\b.*\b(?:enabled|aktiv|eingeschaltet|eingerichtet|registered|registriert|freigegeben)\b"
        ),
        category="security",
        kind="security.myfritz_exposure",
        action="myfritz_exposure",
        outcome="enabled",
        severity="medium",
        tags=("security", "exposure", "myfritz"),
        priority=75,
    ),
    LogPattern(
        rule_id="security.wireguard_vpn",
        regex=compile_pattern(r"\bWireGuard\b.*\b(?:enabled|aktiv|peer|handshake|connected|verbunden)\b"),
        category="security",
        kind="security.vpn_exposure",
        action="vpn_exposure",
        outcome="observed",
        severity="low",
        tags=("security", "exposure", "vpn", "wireguard"),
        priority=75,
    ),
    LogPattern(
        rule_id="security.vpn_enabled",
        regex=compile_pattern(
            r"\b(?:VPN|IPsec)\b.*\b(?:enabled|aktiv|connection|Verbindung|connected|verbunden|user)\b"
        ),
        category="security",
        kind="security.vpn_exposure",
        action="vpn_exposure",
        outcome="observed",
        severity="low",
        tags=("security", "exposure", "vpn"),
        priority=80,
    ),
    LogPattern(
        rule_id="network.dhcp",
        regex=compile_pattern(
            r"\bDHCP\b.*?(?:lease|assigned|zugewiesen|IP-Adresse|IP address)"
            r".*?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})?"
            r".*?(?P<mac>[0-9a-f:]{17})?"
        ),
        category="network",
        kind="network.dhcp",
        action="lease",
        outcome="observed",
        protocol="DHCP",
        tags=("network", "dhcp"),
    ),
    LogPattern(
        rule_id="network.arp_neighbor",
        regex=compile_pattern(r"\b(?:ARP|neigh(?:bor)?|ndisc|IPv6 neighbor)\b.*?(?P<mac>[0-9a-f:]{17})?"),
        category="network",
        kind="network.neighbor_observed",
        action="neighbor_observed",
        outcome="observed",
        protocol="ARP/ND",
        tags=("network", "neighbor", "nearby"),
    ),
    LogPattern(
        rule_id="network.discovery_advertisement",
        regex=compile_pattern(r"\b(?:SSDP|mDNS|Bonjour|LLMNR|UPnP|IGMP|multicast)\b"),
        category="discovery",
        kind="network.discovery_advertisement",
        action="advertise_or_discover",
        outcome="observed",
        protocol="discovery",
        tags=("network", "discovery", "advertisement", "nearby"),
    ),
    LogPattern(
        rule_id="internet.wan_reconnect",
        regex=compile_pattern(r"\b(?:internet|dsl|wan|ipv6-pr.?fix|external ip|reconnect|online monitor)\b"),
        category="internet",
        kind="internet.wan_event",
        action="wan_event",
        outcome="observed",
        tags=("internet", "wan"),
        priority=800,
    ),
    LogPattern(
        rule_id="security.exposure",
        regex=compile_pattern(r"\b(?:upnp|pcp|portfreigabe|port sharing|port mapping|myfritz)\b"),
        category="security",
        kind="security.exposure_event",
        action="exposure",
        outcome="observed",
        severity="medium",
        tags=("security", "exposure"),
        priority=90,
    ),
    LogPattern(
        rule_id="system.firmware_update",
        regex=compile_pattern(r"\b(?:firmware|update|FRITZ!OS)\b.*?\b(?:install|installed|update|aktualisiert)\b"),
        category="system",
        kind="system.firmware_update",
        action="update",
        outcome="observed",
        tags=("system", "firmware"),
    ),
)


def parse_fritzbox_log_message(message: str, category: str = "") -> dict[str, Any]:
    """Parse one retained FRITZ!Box/support log line into SIEM-style fields."""

    base = fallback_result(message, category)
    for pattern in sorted(LOG_PATTERNS, key=lambda rule: rule.priority):
        match = pattern.regex.search(message or "")
        if not match:
            continue
        fields = clean_fields(
            {
                **pattern.fields,
                **match.groupdict(),
                "parser_rule_id": pattern.rule_id,
                "parser_rule_priority": pattern.priority,
            }
        )
        mac = normalize_mac(first_value(fields, "mac", "mac2")) or first_mac(message) or base["mac"]
        ip = normalized_ip(fields.get("ip")) or first_ip(message) or base["ip"]
        interface = clean(fields.get("interface")) or parse_interface(message) or base["interface"]
        return {
            **base,
            "category": pattern.category,
            "kind": pattern.kind,
            "action": pattern.action,
            "outcome": pattern.outcome,
            "severity": pattern.severity,
            "hostname": normalized_hostname(fields.get("hostname")) or base["hostname"],
            "mac": mac,
            "ip": ip,
            "interface": interface,
            "protocol": pattern.protocol,
            "tags": sorted({*base.get("tags", []), *pattern.tags}),
            "fields": {**base["fields"], **fields},
        }
    return base


def fallback_result(message: str, category: str = "") -> dict[str, Any]:
    return {
        "category": category or "router",
        "kind": "router.event",
        "action": "observed",
        "outcome": "observed",
        "severity": "info",
        "hostname": None,
        "mac": first_mac(message),
        "ip": first_ip(message),
        "interface": parse_interface(message),
        "protocol": None,
        "tags": [],
        "fields": {"parser_rule_id": "router.fallback"},
    }


def list_parser_rules() -> list[dict[str, str]]:
    return [
        {
            "rule_id": pattern.rule_id,
            "category": pattern.category,
            "kind": pattern.kind,
            "action": pattern.action,
            "outcome": pattern.outcome,
            "severity": pattern.severity,
            "protocol": pattern.protocol or "",
            "priority": str(pattern.priority),
        }
        for pattern in LOG_PATTERNS
    ]


def first_value(fields: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = fields.get(key)
        if clean(value):
            return value
    return None


def clean_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return {key: value.strip() if isinstance(value, str) else value for key, value in fields.items() if clean(value)}


def first_mac(value: str) -> str | None:
    match = MAC_RE.search(value or "")
    return normalize_mac(match.group(0)) if match else None


def normalize_mac(value: Any) -> str | None:
    rendered = clean(value)
    if not rendered:
        return None
    match = MAC_RE.search(rendered)
    return match.group(0).lower() if match else None


def first_ip(value: str) -> str | None:
    match = IP_RE.search(value or "")
    return match.group(0) if match else None


def normalized_ip(value: Any) -> str | None:
    rendered = clean(value)
    if not rendered:
        return None
    match = IP_RE.search(rendered)
    return match.group(0) if match else None


def normalized_hostname(value: Any) -> str | None:
    rendered = clean(value)
    if not rendered:
        return None
    rendered = re.sub(r"\s+", " ", rendered).strip(" :,;")
    if not rendered or first_ip(rendered) or first_mac(rendered):
        return None
    if rendered.casefold() in {"none", "unknown", "wlan-geraet", "wlan-gerat", "wlan-device"}:
        return None
    if len(rendered) > 80:
        return None
    return rendered


def parse_interface(message: str) -> str | None:
    match = INTERFACE_RE.search(message or "")
    return match.group("interface") if match else None


def clean(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    if not rendered or rendered.casefold() in {"none", "null", "undefined"}:
        return None
    return rendered
