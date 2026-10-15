# Evidence walkthrough

The README GIF contains four captioned crops from the actual localhost application: URL and options, TLS observations, HTTP observations, and report comparison. Source evidence values are browser-rendered; they were not redrawn or invented. Readable facts are derived from the same report data as the expandable technical JSON.

The target was `https://example.com/`. Active checks collected DNS, verified TLS and bounded HTTP/HTML observations. Google Safe Browsing was not enabled. The example is an observation at one time, not a guarantee of current behavior or a safety verdict.

The comparison pairs an earlier passive report with the active report. Its scope warning is intentional: newly collected network evidence reflects the changed collection scope, not proof that the website changed.

The GIF uses chapter captions and editorial holds, not real-time collection timing. It measures no phishing-detection accuracy. The static build can display saved reports and compare them; it cannot collect live TLS or HTTP evidence.

## Provenance

- Animation: `images/evidence-walkthrough.gif`, 1280 × 800, four frames, 18.5 seconds.
- GIF SHA256: `1e0bc4913dc0801e5f7d03cc6524bf6e5745e9fb61965b63a28b1b228059ccab`.
- [Screenshot hashes and source regions](images/evidence-walkthrough-source.json).

The local interface now presents TLS, DNS, URL and HTTP facts as labeled rows. Report comparisons place the readable before and after facts side by side. Full technical records remain available below the facts.
