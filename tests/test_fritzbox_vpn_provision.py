from __future__ import annotations

from types import SimpleNamespace

from fritzbox_vpn_provision import (
    DynDnsIntent,
    ProvisionIntent,
    RouterVpnState,
    WireGuardIntent,
    build_plan,
    query_lua_list,
    redact_url_secrets,
)


def test_build_plan_blocks_missing_dyndns_values() -> None:
    state = RouterVpnState(router_address="192.0.2.1", collected_at="2026-05-20T12:00:00+02:00")
    intent = ProvisionIntent(
        dyndns=DynDnsIntent(domain="vpn.example.net"),
        wireguard=WireGuardIntent(client_name="analyst-laptop"),
    )

    plan = build_plan(state, intent)

    assert not plan.safe_to_apply
    assert plan.steps[0].component == "dyndns"
    assert plan.steps[0].status == "blocked"
    assert "FRITZBOX_DYNDNS_USERNAME" in plan.steps[0].details["missing"]


def test_build_plan_is_noop_for_existing_dyndns_and_wireguard_peer() -> None:
    state = RouterVpnState(
        router_address="192.0.2.1",
        collected_at="2026-05-20T12:00:00+02:00",
        app_remote_info={
            "NewRemoteAccessDDNSEnabled": "1",
            "NewRemoteAccessDDNSDomain": "vpn.example.net",
        },
        wireguard_peers=[{"name": "analyst-laptop", "enabled": "1"}],
    )
    intent = ProvisionIntent(
        dyndns=DynDnsIntent(
            domain="vpn.example.net",
            username="user",
            password="secret",
            update_url="https://dyn.example/update?hostname=<domain>&myip=<ipaddr>&user=<username>&pass=<pass>",
        ),
        wireguard=WireGuardIntent(client_name="analyst-laptop"),
    )

    plan = build_plan(state, intent)

    assert plan.safe_to_apply
    assert [step.status for step in plan.steps] == ["noop", "noop"]
    assert plan.intent["dyndns"]["password"] == "<set>"


def test_build_plan_redacts_dyndns_secrets_from_intent_and_steps() -> None:
    state = RouterVpnState(router_address="192.0.2.1", collected_at="2026-05-20T12:00:00+02:00")
    intent = ProvisionIntent(
        dyndns=DynDnsIntent(
            domain="vpn.example.net",
            username="user",
            password="super-secret-token",
            update_url=(
                "https://dyn.example/update?hostname=<domain>&myip=<ipaddr>&user=<username>" "&pass=super-secret-token"
            ),
        ),
        wireguard=WireGuardIntent(client_name="phone"),
    )

    plan = build_plan(state, intent)
    rendered = str(plan.to_dict())

    assert "super-secret-token" not in rendered
    assert "<redacted>" in rendered


def test_build_plan_refuses_to_replace_existing_dyndns_domain() -> None:
    state = RouterVpnState(
        router_address="192.0.2.1",
        collected_at="2026-05-20T12:00:00+02:00",
        app_remote_info={
            "NewRemoteAccessDDNSEnabled": "1",
            "NewRemoteAccessDDNSDomain": "old.example.net",
        },
    )
    intent = ProvisionIntent(
        dyndns=DynDnsIntent(
            domain="vpn.example.net",
            username="user",
            password="secret",
            update_url="https://dyn.example/update?hostname=<domain>&myip=<ipaddr>&user=<username>&pass=<pass>",
        ),
        wireguard=WireGuardIntent(client_name="phone"),
    )

    plan = build_plan(state, intent)

    assert not plan.safe_to_apply
    assert any(step.status == "blocked" and step.component == "dyndns" for step in plan.steps)


def test_query_lua_list_accepts_dict_nodes() -> None:
    class FakeHttp:
        router_url = "http://192.0.2.1"

        def call_url(self, _url, _params):
            return {
                "wireguard": {
                    "peer0": {"name": "phone"},
                    "peer1": {"name": "laptop"},
                }
            }

    errors: list[str] = []
    rows = query_lua_list(SimpleNamespace(http_interface=FakeHttp()), "wireguard", "query", errors)

    assert rows == [{"name": "phone"}, {"name": "laptop"}]
    assert errors == []


def test_redact_url_secrets_preserves_fritzbox_placeholders() -> None:
    url = "https://dyn.example/update?pass=<pass>&token=abc123&domain=<domain>"

    assert redact_url_secrets(url) == "https://dyn.example/update?pass=<pass>&token=<redacted>&domain=<domain>"
