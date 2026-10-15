# T3 Phishing Detection

A local web application that explains URL risk signals, shows missing evidence, and exports a JSON report. The interface is in Turkish. Development continues in this repository; earlier implementations are in the commit history.

## Run

Python 3.11 or newer:

```sh
git clone https://github.com/temurcanbulut/t3-phishing-detection.git
cd t3-phishing-detection
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` on Windows PowerShell or `source .venv/bin/activate` on Linux/macOS, then:

```sh
python -m pip install -r requirements.txt
python T3-Phishing-Detection/app.py
```

Open **http://127.0.0.1:5000**. Waitress binds to the loopback interface; debug mode is disabled. This is a local tool, not a public multi-user scanner.

## What the report contains

- HTTP/HTTPS, URL length, path depth, IP literal and internationalized domain signals.
- TLS certificate verification and HSTS response headers from the target host on port 443.
- Optional Google Safe Browsing threat-list lookup using the full normalized URL.
- A reason and state for every check: checked, warning, threat match, information, unavailable or unconfigured.
- Completed-check count, elapsed time and a downloadable JSON report. Reports are not stored by the application.

The **risk score increases with observed risk signals**. It is a rule total, not a calibrated probability. HTTPS and an empty threat-list response do not prove that a link is safe. Missing external evidence makes a low-score report **incomplete**. Page contents, redirect chains, downloads and brand impersonation are not analyzed. HSTS is informational and does not add risk points.

| Signal | Points |
|---|---:|
| HTTP URL | 10 |
| URL longer than 150 characters | 5 |
| More than 5 nonempty path segments | 5 |
| IP literal instead of a domain | 10 |
| Invalid TLS certificate | 15 |
| Safe Browsing threat match | 80 |

Scores are capped at 100. High: 60+, medium: 20–59; below 20 is incomplete if any external check is missing, otherwise low observed risk. The `incomplete` field is independent of risk level, so missing evidence remains visible even on a high-risk report.

## Optional Safe Browsing

Set `SAFE_BROWSING_API_KEY` before starting:

```powershell
$env:SAFE_BROWSING_API_KEY = 'your-key'
python T3-Phishing-Detection/app.py
```

On Linux/macOS, use `export SAFE_BROWSING_API_KEY='your-key'`. `.env.example` documents the setting; `.env` files are not automatically loaded. Never commit a key.

Enabling this sends the **full URL, including query parameters**, to Google. Avoid submitting private tokens or account links. Without a key, the check explicitly shows “Yapılandırılmadı”. Provider failures show “Tamamlanamadı”, never a clean result. Review the provider's [Lookup API documentation](https://developers.google.com/safe-browsing/v4/lookup-api) and [usage terms](https://developers.google.com/safe-browsing/v4/terms) before enabling it.

## Network behavior

Only HTTP/HTTPS URLs on their standard ports are accepted. Credentials in URLs, private/reserved/multicast IPs and DNS answers mixing public/private addresses are rejected. The target TLS connection is pinned to a checked DNS address while retaining hostname verification, preventing a second DNS lookup from changing the destination. Only a `HEAD /` request is sent; no page body is read and target redirects are not followed. HTTPS is probed on port 443 even for an HTTP input.

Target connections have a 4-second socket timeout; Google requests have 4-second connect/read timeouts. The two checks run concurrently. System DNS resolution follows the OS resolver's own timeout. These are per-operation timeouts, not a hard end-to-end deadline. At most four analyses run concurrently per process; additional requests return HTTP 429. A public deployment would additionally need authentication, per-client quotas and deployment-specific egress controls.

## API

```sh
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/path?x=1"}'
```

Response fields: `url`, `domain`, `risk_score`, `risk_level`, `incomplete`, `completed_checks`, `total_checks`, `checks`, `duration_ms`, `analyzed_at`, `methodology`.

`GET /check_domain?domain=example.com` remains available with the same **new report schema**. The previous trust `score`, domain rank, domain age and owner fields have been removed; clients must migrate to `risk_score` and per-check states. Invalid input returns 400; non-JSON POST requests 415; oversized requests 413; busy capacity 429.

## Development

```sh
python -m unittest discover -s tests -v
```

Tests mock all external probes and cover URL handling, provider failures, private-network rejection, pinned connections, request limits and report uncertainty. CI runs on Windows and Linux with Python 3.11 and 3.13.

The [original demo video](https://www.youtube.com/watch?v=6S9v_cZMzoo) shows the earlier interface and scoring behavior. See [CHANGELOG.md](CHANGELOG.md) for current changes.
