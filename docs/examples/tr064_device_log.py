from __future__ import annotations

from common import fritz_connection


def main() -> None:
    fc = fritz_connection()
    info = fc.call_action("DeviceInfo:1", "GetInfo")
    log = fc.call_action("DeviceInfo:1", "GetDeviceLog").get("NewDeviceLog", "")
    print("Model:", info.get("NewModelName") or info.get("NewProductClass"))
    print("Firmware:", info.get("NewSoftwareVersion"))
    print("Device log lines:", len(str(log).splitlines()))
    print("First 5 lines:")
    for line in str(log).splitlines()[:5]:
        print(" ", line)


if __name__ == "__main__":
    main()
