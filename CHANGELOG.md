# Changes

## Unreleased

- Replace the opaque trust score with an explained risk-signal report and explicit incomplete checks.
- Preserve the full URL path/query for threat-list lookups; ignore fragments.
- Configure Safe Browsing through an environment variable. HTTP errors, timeouts and malformed responses remain unknown.
- Check public DNS addresses before connecting, pin the checked address for TLS, and do not follow target redirects.
- Bound network timeouts and concurrent analyses. Inspect headers without downloading target page content.
- Add a responsive Turkish interface, JSON report downloads, input/error/loading states and a strict same-origin CSP.
- Remove Alexa scraping, WHOIS owner data and age-based scoring from the active analysis. These were not reliable evidence of a phishing verdict.
- Use a local Waitress server, remove tracked bytecode, document setup and add automated regression tests on Windows/Linux.

The existing `/check_domain` route remains available, but its JSON response now uses `risk_score` (higher means more observed risk) and `checks`. The old `score` and WHOIS fields are no longer returned.
