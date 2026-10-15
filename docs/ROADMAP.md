# Product roadmap

The usable product today is a local evidence workspace. A checked item means implemented behavior, not a guarantee of detection.

- [x] Bounded URL/DNS/TLS/HTTP/HTML evidence with explicit probe states
- [x] CLI and localhost web interface using one analysis core
- [x] JSON export, offline reopen and same-target comparison in the browser
- [x] Browser-only static parser with clearly restricted scope
- [ ] Configured-provider integration against documented test URLs; record request/response scope
- [ ] Browser/JavaScript behavior analysis in a separate isolated worker, with resource and egress design before implementation
- [ ] Installable desktop distribution and signed releases with clean-machine startup checks

Do not collapse source matches, unavailable probes or inconclusive observations into a synthetic safety percentage. Public multi-user hosting needs authentication, quotas and deployment isolation; it is not supported by the current localhost service.
