# Security

T3 is a localhost evidence collector for public HTTP/HTTPS targets. Keep the interface on 127.0.0.1. Public multi-user hosting is not supported. See [the technical reference](docs/TECHNICAL.md#egress-and-resource-boundaries) for DNS pinning, redirect policy, parser limits and deadlines.

Saved reports and target content are untrusted. Browser imports are bounded, parsed as data and rendered with textContent; import and comparison never connect to embedded targets. A report can still contain false or manipulated observations. SHA256 does not authenticate a source. Review exported URLs, queries and form actions before sharing.

Threat lookup is opt-in and sends the full normalized URL to Google. Keep API keys in the process environment and out of screenshots, issues and commits. Never add credentials to a target URL.

For a suspected vulnerability, use the repository's private vulnerability-reporting option if available. Otherwise use the maintainer's GitHub profile to request a private contact route; do not put exploit details, credentials or private targets in a public issue. This project makes no response-time commitment or bug bounty promise.
