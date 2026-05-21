# Sensitivity and Redaction

FRITZ!Box evidence is sensitive by default.

## Sensitive Fields

| Data | Examples | Risk |
|---|---|---|
| Router credentials | `.env`, saved settings, export passwords | Full router compromise. |
| Public IP / DynDNS / MyFRITZ | WAN IP, MyFRITZ domain, DDNS domain | Location and attack-surface disclosure. |
| Local topology | Hostnames, MACs, IPs, mesh links | Device/user identification. |
| WLAN data | SSIDs, BSSIDs, station MACs, signal/RSSI | Location and device tracking. |
| Telephony | Call lists, phonebooks | Personal data. |
| Smart home | AHA device IDs, switch stats | Occupancy and environment context. |
| Support data | Service state, logs, internal daemon output | Broad forensic and config exposure. |
| Config export | Encrypted settings backup | High-value evidence and potential secret material. |

## Redaction Guidelines

Before sharing docs, reports, or screenshots:

- Replace MAC addresses with stable pseudonyms.
- Replace public IPs and DDNS domains.
- Replace local hostnames if they reveal owners or locations.
- Remove account names and login SIDs.
- Do not include raw support-data excerpts unless strictly necessary.
- Do not include `.env`, SQLite databases, or acquisition packages in Git.

Example redaction:

```text
ca:04:95:b2:4c:5b -> client-mac-001
192.168.178.21 -> client-ip-001
example-id.myfritz.net -> myfritz-redacted.example
```

## Evidence Sharing

Recommended public artifacts:

- Synthetic screenshots.
- Sanitized CSV extracts.
- Parser fixtures with fake MAC/IP/host values.
- Documentation examples using RFC 5737 IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

Do not publish real router exports.
