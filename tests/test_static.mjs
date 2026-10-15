import test from 'node:test';
import assert from 'node:assert/strict';
import {analyzeLocal} from '../T3-Phishing-Detection/static/url-local.mjs';

test('static client exposes its limited scope and performs no fetch', () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => {throw new Error('Unexpected network call');};
  try {
    const report = analyzeLocal('https://bücher.de/path?x=1#fragment');
    assert.equal(report.target.host, 'xn--bcher-kva.de');
    assert.equal(report.target.registrable_domain, null);
    assert.equal(report.scope.active, false);
    assert.equal(report.conclusion, 'no_safety_verdict');
    assert.equal(report.target.url, 'https://xn--bcher-kva.de/path?x=1');
    assert.equal(report.evidence[1].status, 'not_run');
  } finally {globalThis.fetch = original;}
});

test('credentials and unsafe/ambiguous protocols fail locally', () => {
  for (const input of ['file:///etc/passwd','javascript:alert(1)','https://u:p@example.com','https://example.com:81','https://example.com\\@evil.example','https://example.com/%zz','https://example.com/\nx']) {
    assert.throws(() => analyzeLocal(input), input);
  }
});

test('hostile strings remain ordinary report data', () => {
  const report = analyzeLocal('https://example.com/%3Cscript%3E?next=%22onerror');
  assert.equal(report.target.host, 'example.com');
  assert.equal(report.findings.length, 0);
  assert.ok(report.target.url.includes('%3Cscript%3E'));
});
