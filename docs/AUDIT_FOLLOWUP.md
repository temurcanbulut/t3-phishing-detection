# Review decisions — 2026-11-01

The product is **T3 URL & Domain Inspector**. Its historical repository URL stays
stable so existing links and stars are preserved. It collects inspectable evidence;
it does not implement or claim a trained phishing classifier.

- Installable `t3-url-inspector` distribution, `t3-inspect` entry point and
  `python -m t3core`; root `t3.py` remains a compatibility launcher.
- Browser site HTML/assets are generated from the server template/static source.
  Copies are build output ignored by Git; Pages generates and allowlists nine files.
- After TLS verification failure, a separate short-lived connection to the same
  DNS-pinned public IP/SNI records only unverified certificate metadata. No HTTP,
  cookies or credentials are sent; status stays `verification_failed` and the HTTP
  connector retains normal certificate verification. Mocked connection tests
  assert these boundaries, including a failed observation retry.
- html5lib 1.1 is intentionally retained behind byte/time/node/depth/attribute
  limits and parser regressions. A parser swap is not a security upgrade by itself;
  native lxml/selectolax would change recovery and resource behavior. The pinned
  adapter and its MIT notices are shipped in wheels. Replacement needs parity and
  adversarial tests before adoption.
- Four active inspection slots and the 12-second budget remain resource limits,
  returning 429 instead of allowing an unbounded queue. This localhost tool is not
  a multi-tenant public scanning service. No extra target/provider call was made
  to verify this review.
