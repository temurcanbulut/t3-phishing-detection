# Changelog

## Product workflows — 2026-10-15

- Added local saved-report import, schema/structure limits, probe overview and same-target report comparison with scope changes and JSON difference export.
- Added a real workflow GIF, Turkish quickstart and separate technical reference.

# Changes

## Evidence inspector — 2026-10-15

### Evidence collection and local tools

- Parse bounded HTML5 source with external form owners, submit overrides, template/disabled-control handling and declared character encodings.
- Keep per-probe outcomes after timeouts; share concurrent DNS pins and handle split TXT records and NAT64 destinations.
- Add offline saved-report comparison with scope differences and file fingerprints; verify mobile layout and keyboard tabs.

- Remove numeric risk scoring and introduce timestamped `t3-evidence/1` records with no safety verdict.
- Add a CLI sharing the web core, opt-in target/provider contact, bounded async deadlines, redirect/DNS guards, certificate fingerprints and limited HTML evidence.
- Add published MX/SPF/DMARC/CAA observations without converting missing records into phishing claims.
- Disable the legacy GET analysis route, enforce local Host/Origin restrictions, and add real local-server adversarial fixtures and property tests.
- Provide a separately labeled static URL-only client that can run on static hosting without pretending to inspect remote sites.

### Earlier PR revision

- Replace the opaque trust score with an explained risk-signal report and explicit incomplete checks.
- Preserve the full URL path/query for threat-list lookups; ignore fragments.
- Configure Safe Browsing through an environment variable. HTTP errors, timeouts and malformed responses remain unknown.
- Check public DNS addresses before connecting, pin the checked address for TLS, and do not follow target redirects.
- Bound network timeouts and concurrent analyses. Inspect headers without downloading target page content.
- Add a responsive Turkish interface, JSON report downloads, input/error/loading states and a strict same-origin CSP.
- Remove Alexa scraping, WHOIS owner data and age-based scoring from the active analysis. These were not reliable evidence of a phishing verdict.
- Use a local Waitress server, remove tracked bytecode, document setup and add automated regression tests on Windows/Linux.

The earlier PR API is superseded by the evidence inspector revision above: GET `/check_domain` now returns 405, POST `/api/analyze` returns evidence, and numeric scores are removed.
