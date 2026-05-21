from __future__ import annotations

from common import fritz_connection


def fetch_path(fc, path: str) -> str:
    url = f"{str(fc.http_interface.router_url).rstrip('/')}/{path.lstrip('/')}"
    response = fc.http_interface.fc.session.get(url, timeout=20)
    response.raise_for_status()
    return response.text


def main() -> None:
    fc = fritz_connection()
    specs = [
        ("Device log XML", "DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath", "NewDeviceLogPath"),
        ("Host list XML", "Hosts:1", "X_AVM-DE_GetHostListPath", "NewX_AVM-DE_HostListPath"),
        ("Mesh list JSON/XML", "Hosts:1", "X_AVM-DE_GetMeshListPath", "NewX_AVM-DE_MeshListPath"),
    ]
    for label, service, action, field in specs:
        try:
            path = fc.call_action(service, action).get(field)
            content = fetch_path(fc, str(path)) if path else ""
            print(f"{label}: path={path!r}, bytes={len(content.encode('utf-8'))}")
        except Exception as exc:
            print(f"{label}: unavailable ({type(exc).__name__}: {exc})")

    for index in range(1, 5):
        service = f"WLANConfiguration:{index}"
        try:
            response = fc.call_action(service, "X_AVM-DE_GetWLANDeviceListPath")
            path = response.get("NewX_AVM-DE_WLANDeviceListPath")
            content = fetch_path(fc, str(path)) if path else ""
            print(f"{service} device list: path={path!r}, bytes={len(content.encode('utf-8'))}")
        except Exception as exc:
            print(f"{service} device list: unavailable ({type(exc).__name__}: {exc})")


if __name__ == "__main__":
    main()
