#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
import os
from pathlib import Path
import re
from typing import Any

from fritzbox_collectors import get_webui_sid
from fritzbox_wifi_export import load_env_file


DDNS_PLACEHOLDERS = ("<domain>", "<username>", "<pass>", "<ipaddr>")
SENSITIVE_URL_KEY_RE = re.compile(r"(?i)([?&][^=&]*(?:pass|password|pwd|token|secret|key)[^=]*=)([^&#]+)")
WIREGUARD_QUERY = "wireguard:settings/peer/list(name,enabled,remote_endpoint,allowed_ips,last_handshake,public_key)"
VPN_QUERY = "vpn:settings/connection/list(name,enabled,type,remote_ip,local_ip,last_connected)"
PORT_QUERY = "forwardrules:settings/rule/list(description,enabled,protocol,port,end_port,fwip,fwport,sourceip)"


@dataclass(frozen=True)
class RouterLogin:
    address: str
    user: str = ""
    password: str = ""
    port: int = 49000
    tls: bool = False


@dataclass(frozen=True)
class DynDnsIntent:
    enabled: bool = True
    provider: str = "user-defined"
    domain: str = ""
    username: str = ""
    password: str = ""
    update_url: str = ""
    replace_existing: bool = False


@dataclass(frozen=True)
class WireGuardIntent:
    client_name: str = ""
    client_public_key: str = ""
    allowed_ips: str = "192.168.178.0/24"
    dns: str = "192.168.178.1"
    endpoint_port: int = 51820
    route_all_traffic: bool = False
    replace_existing: bool = False


@dataclass(frozen=True)
class ProvisionIntent:
    dyndns: DynDnsIntent
    wireguard: WireGuardIntent


@dataclass
class ProvisionStep:
    component: str
    action: str
    status: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RouterVpnState:
    router_address: str
    collected_at: str
    app_remote_info: dict[str, Any] = field(default_factory=dict)
    wireguard_peers: list[dict[str, Any]] = field(default_factory=list)
    vpn_connections: list[dict[str, Any]] = field(default_factory=list)
    port_rules: list[dict[str, Any]] = field(default_factory=list)
    webui_pages: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class ProvisionPlan:
    dry_run: bool
    safe_to_apply: bool
    apply_supported: bool
    generated_at: str
    intent: dict[str, Any]
    state: dict[str, Any]
    steps: list[ProvisionStep]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "safe_to_apply": self.safe_to_apply,
            "apply_supported": self.apply_supported,
            "generated_at": self.generated_at,
            "intent": self.intent,
            "state": self.state,
            "steps": [asdict(step) for step in self.steps],
            "notes": self.notes,
        }


def load_router_login_from_env() -> RouterLogin:
    load_env_file(Path(".env"))
    load_env_file(Path(".fritzbox.env"))
    return RouterLogin(
        address=os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1",
        user=os.getenv("FRITZBOX_USER", ""),
        password=os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS") or "",
        port=int(os.getenv("FRITZBOX_PORT", "49000") or "49000"),
        tls=os.getenv("FRITZBOX_TLS", "0").lower() in {"1", "true", "yes"},
    )


def load_intent_from_env() -> ProvisionIntent:
    return ProvisionIntent(
        dyndns=DynDnsIntent(
            enabled=os.getenv("FRITZBOX_DYNDNS_ENABLED", "1").lower() not in {"0", "false", "no"},
            provider=os.getenv("FRITZBOX_DYNDNS_PROVIDER", "user-defined"),
            domain=os.getenv("FRITZBOX_DYNDNS_DOMAIN", ""),
            username=os.getenv("FRITZBOX_DYNDNS_USERNAME", ""),
            password=os.getenv("FRITZBOX_DYNDNS_PASSWORD", ""),
            update_url=os.getenv("FRITZBOX_DYNDNS_UPDATE_URL", ""),
            replace_existing=os.getenv("FRITZBOX_DYNDNS_REPLACE_EXISTING", "0").lower() in {"1", "true", "yes"},
        ),
        wireguard=WireGuardIntent(
            client_name=os.getenv("FRITZBOX_WG_CLIENT_NAME", ""),
            client_public_key=os.getenv("FRITZBOX_WG_CLIENT_PUBLIC_KEY", ""),
            allowed_ips=os.getenv("FRITZBOX_WG_ALLOWED_IPS", "192.168.178.0/24"),
            dns=os.getenv("FRITZBOX_WG_DNS", "192.168.178.1"),
            endpoint_port=int(os.getenv("FRITZBOX_WG_ENDPOINT_PORT", "51820") or "51820"),
            route_all_traffic=os.getenv("FRITZBOX_WG_ROUTE_ALL_TRAFFIC", "0").lower() in {"1", "true", "yes"},
            replace_existing=os.getenv("FRITZBOX_WG_REPLACE_EXISTING", "0").lower() in {"1", "true", "yes"},
        ),
    )


def discover_router_vpn_state(login: RouterLogin) -> RouterVpnState:
    try:
        from fritzconnection import FritzConnection
    except ImportError as exc:  # pragma: no cover - dependency is part of package install
        raise SystemExit("Missing dependency: fritzconnection") from exc

    if not login.password:
        raise SystemExit("Set FRITZBOX_PASSWORD or FRITZBOX_ADMIN_PASS before running the VPN provision planner.")

    fc = FritzConnection(
        address=login.address,
        user=login.user,
        password=login.password,
        port=login.port,
        use_tls=login.tls,
        use_cache=True,
        timeout=30,
    )
    return discover_router_vpn_state_from_connection(fc, login.address)


def discover_router_vpn_state_from_connection(fc: Any, router_address: str = "") -> RouterVpnState:
    state = RouterVpnState(router_address=router_address, collected_at=datetime.now().astimezone().isoformat())
    try:
        state.app_remote_info = fc.call_action("X_AVM-DE_AppSetup:1", "GetAppRemoteInfo")
    except Exception as exc:
        state.errors.append(f"AppSetup:GetAppRemoteInfo unavailable: {type(exc).__name__}: {exc}")

    state.wireguard_peers = query_lua_list(fc, "wireguard", WIREGUARD_QUERY, state.errors)
    state.vpn_connections = query_lua_list(fc, "vpn_users", VPN_QUERY, state.errors)
    state.port_rules = query_lua_list(fc, "port_sharing", PORT_QUERY, state.errors)
    state.webui_pages = fetch_vpn_related_pages(fc, state.errors)
    return state


def query_lua_list(fc: Any, name: str, query: str, errors: list[str]) -> list[dict[str, Any]]:
    try:
        response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/query.lua", {name: query})
    except Exception as exc:
        errors.append(f"query.lua {name} unavailable: {type(exc).__name__}: {exc}")
        return []
    if not isinstance(response, dict):
        return []
    data = response.get(name)
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, dict):
        return [row for row in data.values() if isinstance(row, dict)]
    return []


def fetch_vpn_related_pages(fc: Any, errors: list[str]) -> dict[str, dict[str, Any]]:
    pages: dict[str, dict[str, Any]] = {}
    try:
        http = fc.http_interface
        sid = get_webui_sid(http)
    except Exception as exc:
        errors.append(f"Web UI SID unavailable: {type(exc).__name__}: {exc}")
        return pages
    if not sid:
        errors.append("Web UI SID unavailable: login returned no valid SID")
        return pages
    for page in ("remoteAccess", "portShare", "forwardRules", "vpn", "wireguard", "dyndns", "dynDns"):
        try:
            response = http.fc.session.get(
                f"{str(http.router_url).rstrip('/')}/data.lua",
                params={"page": page, "sid": sid},
                timeout=15,
            )
            raw = response.text
            payload: dict[str, Any] | None = None
            if raw.lstrip().startswith("{"):
                try:
                    payload = response.json()
                except ValueError:
                    payload = None
            pages[page] = {
                "ok": response.status_code == 200 and payload is not None,
                "status": response.status_code,
                "json": payload is not None,
                "field_hints": vpn_field_hints(payload or {}),
            }
        except Exception as exc:
            pages[page] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return pages


def vpn_field_hints(payload: dict[str, Any]) -> list[str]:
    hints: set[str] = set()

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                dotted = f"{prefix}.{key}" if prefix else str(key)
                if any(token in dotted.casefold() for token in ("wire", "vpn", "dyn", "ddns", "remote", "forward")):
                    hints.add(dotted)
                walk(child, dotted)
        elif isinstance(value, list):
            for index, child in enumerate(value[:5]):
                walk(child, f"{prefix}[{index}]")

    walk(payload)
    return sorted(hints)[:80]


def build_plan(state: RouterVpnState, intent: ProvisionIntent, dry_run: bool = True) -> ProvisionPlan:
    steps: list[ProvisionStep] = []
    notes = [
        "Dry-run is the default. The planner does not overwrite router VPN or DynDNS settings.",
        "FRITZ!OS WireGuard peer creation is Web-UI/wizard driven and may require physical confirmation on the router.",
    ]
    steps.extend(dyndns_steps(state, intent.dyndns))
    steps.extend(wireguard_steps(state, intent.wireguard, intent.dyndns.domain))
    safe_to_apply = all(step.status in {"noop", "ready", "manual"} for step in steps)
    apply_supported = False
    return ProvisionPlan(
        dry_run=dry_run,
        safe_to_apply=safe_to_apply,
        apply_supported=apply_supported,
        generated_at=datetime.now().astimezone().isoformat(),
        intent=sanitized_intent(intent),
        state=sanitized_state(state),
        steps=steps,
        notes=notes,
    )


def dyndns_steps(state: RouterVpnState, intent: DynDnsIntent) -> list[ProvisionStep]:
    steps: list[ProvisionStep] = []
    if not intent.enabled:
        steps.append(ProvisionStep("dyndns", "disable", "manual", "Desired DynDNS state is disabled."))
        return steps
    missing = [
        name
        for name, value in {
            "FRITZBOX_DYNDNS_DOMAIN": intent.domain,
            "FRITZBOX_DYNDNS_USERNAME": intent.username,
            "FRITZBOX_DYNDNS_PASSWORD": intent.password,
            "FRITZBOX_DYNDNS_UPDATE_URL": intent.update_url,
        }.items()
        if not value
    ]
    if missing:
        steps.append(
            ProvisionStep(
                "dyndns",
                "configure",
                "blocked",
                "Missing required DynDNS environment values.",
                {"missing": missing},
            )
        )
        return steps
    missing_placeholders = [placeholder for placeholder in DDNS_PLACEHOLDERS if placeholder not in intent.update_url]
    if missing_placeholders:
        steps.append(
            ProvisionStep(
                "dyndns",
                "validate_update_url",
                "review",
                "Update URL does not contain all common FRITZ!Box placeholders; verify provider requirements.",
                {"missing_placeholders": missing_placeholders},
            )
        )
    remote_enabled = truthy(state.app_remote_info.get("NewRemoteAccessDDNSEnabled"))
    remote_domain = str(state.app_remote_info.get("NewRemoteAccessDDNSDomain") or "")
    if remote_enabled and remote_domain == intent.domain:
        steps.append(
            ProvisionStep(
                "dyndns",
                "configure",
                "noop",
                "Custom remote-access DynDNS is already enabled for the desired domain.",
                {"domain": intent.domain},
            )
        )
    elif remote_enabled and remote_domain and not intent.replace_existing:
        steps.append(
            ProvisionStep(
                "dyndns",
                "configure",
                "blocked",
                "A different custom DynDNS domain is already configured; refusing to replace it without explicit intent.",
                {"existing_domain": remote_domain, "desired_domain": intent.domain},
            )
        )
    else:
        steps.append(
            ProvisionStep(
                "dyndns",
                "configure",
                "manual",
                "Configure FRITZ!Box DynDNS as user-defined with the desired domain and update URL.",
                {
                    "provider": intent.provider,
                    "domain": intent.domain,
                    "username": intent.username,
                    "update_url": redact_url_secrets(intent.update_url, intent.password),
                },
            )
        )
    return steps


def wireguard_steps(state: RouterVpnState, intent: WireGuardIntent, endpoint_domain: str) -> list[ProvisionStep]:
    steps: list[ProvisionStep] = []
    if not intent.client_name:
        steps.append(
            ProvisionStep(
                "wireguard",
                "add_client",
                "blocked",
                "Missing FRITZBOX_WG_CLIENT_NAME.",
                {"missing": ["FRITZBOX_WG_CLIENT_NAME"]},
            )
        )
        return steps
    existing_by_name = [peer for peer in state.wireguard_peers + state.vpn_connections if peer_name(peer) == intent.client_name]
    existing_by_key = [
        peer for peer in state.wireguard_peers if intent.client_public_key and peer.get("public_key") == intent.client_public_key
    ]
    if existing_by_name or existing_by_key:
        steps.append(
            ProvisionStep(
                "wireguard",
                "add_client",
                "noop",
                "A WireGuard/VPN entry matching the desired client already exists.",
                {"client_name": intent.client_name, "matched": len(existing_by_name) + len(existing_by_key)},
            )
        )
        return steps
    udp_rules = [
        rule
        for rule in state.port_rules
        if str(rule.get("protocol", "")).upper() == "UDP" and str(rule.get("port") or rule.get("fwport")) == str(intent.endpoint_port)
    ]
    steps.append(
        ProvisionStep(
            "wireguard",
            "add_client",
            "manual",
            "Add a new FRITZ!Box WireGuard single-device connection and download the generated client config.",
            {
                "client_name": intent.client_name,
                "endpoint": endpoint_domain or state.app_remote_info.get("NewMyFritzDynDNSName") or "<dyndns-domain>",
                "endpoint_port": intent.endpoint_port,
                "allowed_ips": "0.0.0.0/0" if intent.route_all_traffic else intent.allowed_ips,
                "dns": intent.dns,
                "existing_udp_rules_on_port": len(udp_rules),
            },
        )
    )
    return steps


def peer_name(peer: dict[str, Any]) -> str:
    return str(peer.get("name") or peer.get("NewName") or peer.get("description") or "").strip()


def truthy(value: Any) -> bool:
    return str(value).casefold() in {"1", "true", "yes", "on", "enabled"}


def redact_url_secrets(value: str, known_secret: str = "") -> str:
    redacted = value.replace(known_secret, "<redacted>") if known_secret else value

    def replacement(match: re.Match[str]) -> str:
        payload = match.group(2)
        if payload in {"<pass>", "<username>", "<domain>", "<ipaddr>"}:
            return match.group(0)
        return f"{match.group(1)}<redacted>"

    return SENSITIVE_URL_KEY_RE.sub(replacement, redacted)


def sanitized_intent(intent: ProvisionIntent) -> dict[str, Any]:
    data = asdict(intent)
    data["dyndns"]["password"] = "<set>" if intent.dyndns.password else ""
    data["dyndns"]["update_url"] = redact_url_secrets(intent.dyndns.update_url, intent.dyndns.password)
    return data


def sanitized_state(state: RouterVpnState) -> dict[str, Any]:
    data = asdict(state)
    for page in data.get("webui_pages", {}).values():
        page.pop("raw", None)
    return data


def env_example() -> str:
    return """# FRITZ!Box connection
FRITZBOX_ADDRESS=192.168.178.1
FRITZBOX_USER=
FRITZBOX_PASSWORD=change-me
FRITZBOX_PORT=49000
FRITZBOX_TLS=0

# DynDNS provider. FRITZ!Box user-defined URLs support <domain>, <username>, <pass>, <ipaddr>.
FRITZBOX_DYNDNS_ENABLED=1
FRITZBOX_DYNDNS_PROVIDER=user-defined
FRITZBOX_DYNDNS_DOMAIN=vpn.example.net
FRITZBOX_DYNDNS_USERNAME=dyndns-user
FRITZBOX_DYNDNS_PASSWORD=dyndns-token-or-password
FRITZBOX_DYNDNS_UPDATE_URL=https://dyndns.example.net/update?hostname=<domain>&myip=<ipaddr>&user=<username>&pass=<pass>
FRITZBOX_DYNDNS_REPLACE_EXISTING=0

# WireGuard client intent.
FRITZBOX_WG_CLIENT_NAME=analyst-laptop
FRITZBOX_WG_ENDPOINT_PORT=51820
FRITZBOX_WG_ALLOWED_IPS=192.168.178.0/24
FRITZBOX_WG_DNS=192.168.178.1
FRITZBOX_WG_ROUTE_ALL_TRAFFIC=0
FRITZBOX_WG_REPLACE_EXISTING=0

# Optional: set when importing/merging with an externally generated client key.
FRITZBOX_WG_CLIENT_PUBLIC_KEY=
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Dry-run FRITZ!Box DynDNS + WireGuard provisioning planner.")
    parser.add_argument("--apply", action="store_true", help="Reserved for a future firmware-specific write adapter.")
    parser.add_argument("--env-example", action="store_true", help="Print a .env snippet for provisioning.")
    parser.add_argument("--output", type=Path, help="Write the plan JSON to a file.")
    args = parser.parse_args()

    if args.env_example:
        print(env_example())
        return
    if args.apply:
        raise SystemExit(
            "--apply is intentionally disabled until this FRITZ!OS version's Web UI write workflow is mapped and tested."
        )

    login = load_router_login_from_env()
    intent = load_intent_from_env()
    state = discover_router_vpn_state(login)
    plan = build_plan(state, intent, dry_run=True)
    payload = json.dumps(plan.to_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
