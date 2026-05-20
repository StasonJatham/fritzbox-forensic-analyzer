# Security Policy

## Sensitive Data

This tool is designed to collect router logs, device identifiers, hostnames, IP addresses, MAC addresses, and local credential settings. Treat every SQLite database, raw artifact archive, CSV export, JSON export, and forensic package as sensitive evidence.

Do not attach real FRITZ!Box exports, screenshots, databases, forensic packages, credentials, public IP addresses, MAC addresses, hostnames, or home-network diagrams to public issues.

## Reporting Security Issues

Open a GitHub issue with a minimal description that does not include secrets or evidence data. If reproduction data is required, create a synthetic dataset with fake hostnames, fake MAC addresses, and RFC 5737 documentation IP ranges.

## Recommended Deployment

Run the dashboard on localhost or a trusted internal host only. If you expose it beyond localhost, put it behind strong authentication and TLS. The dashboard can store FRITZ!Box credentials locally in SQLite for scheduled polling and manual fetches.
