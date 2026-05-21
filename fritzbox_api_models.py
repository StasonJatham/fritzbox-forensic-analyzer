from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PollingRequest(BaseModel):
    active: bool = False
    interval_minutes: int = Field(default=15, ge=5, le=15)


class LiveCaptureRequest(BaseModel):
    duration_seconds: int = Field(default=10, ge=1, le=60)
    interface: str = Field(default="", max_length=128)


class SettingsRequest(BaseModel):
    address: str = Field(default="192.168.178.1", min_length=1, max_length=255)
    user: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=4096)
    port: int = Field(default=49000, ge=1, le=65535)
    tls: bool = False


class DynDnsRequest(BaseModel):
    enabled: bool = True
    provider: str = Field(default="user-defined", max_length=128)
    domain: str = Field(default="", max_length=255)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=4096)
    update_url: str = Field(default="", max_length=4096)
    replace_existing: bool = False


class WireGuardRequest(BaseModel):
    client_name: str = Field(default="", max_length=255)
    client_public_key: str = Field(default="", max_length=512)
    allowed_ips: str = Field(default="192.168.178.0/24", max_length=512)
    dns: str = Field(default="192.168.178.1", max_length=255)
    endpoint_port: int = Field(default=51820, ge=1, le=65535)
    route_all_traffic: bool = False
    replace_existing: bool = False


class VpnProvisionPlanRequest(BaseModel):
    dyndns: DynDnsRequest = Field(default_factory=DynDnsRequest)
    wireguard: WireGuardRequest = Field(default_factory=WireGuardRequest)


def model_payload(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()
