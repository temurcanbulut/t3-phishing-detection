import test from 'node:test';
import assert from 'node:assert/strict';
import {analyzeLocal} from '../T3-Phishing-Detection/static/url-local.mjs';
import {parseSavedReport, compareSavedReports, MAX_REPORT_BYTES} from '../T3-Phishing-Detection/static/reports.mjs';

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

test('import validates schema, target, structure and static scope without network', () => {
  const good = analyzeLocal('example.com');
  assert.equal(parseSavedReport(JSON.stringify(good)).target.host, 'example.com');
  for (const mutate of [
    r => {r.schema = 'unknown';},
    r => {r.target.host = 'other.example';},
    r => {r.scope.active = true;},
    r => {r.evidence.push(r.evidence[0]);},
    r => {r.evidence[0].status = 'safe';},
    r => {r.findings = [{kind:'x', detail:{html:'<script>'}}];},
    r => {r.duration_ms = -1;},
  ]) {
    const bad = structuredClone(good); mutate(bad);
    assert.throws(() => parseSavedReport(JSON.stringify(bad)));
  }
  assert.throws(() => parseSavedReport(' '.repeat(MAX_REPORT_BYTES + 1)));
  assert.throws(() => parseSavedReport('{broken'));
  const deep = structuredClone(good); let inner = deep;
  for (let i=0;i<60;i++) {inner.extra = {}; inner = inner.extra;}
  assert.throws(() => parseSavedReport(JSON.stringify(deep)));
});

test('comparison ignores collection clocks and key order but retains actual changes', () => {
  const before = analyzeLocal('example.com'), after = structuredClone(before);
  after.started_at = '2026-10-16T00:00:00Z';
  after.evidence[0].collected_at = after.started_at;
  after.evidence[0].data = Object.fromEntries(Object.entries(after.evidence[0].data).reverse());
  assert.equal(compareSavedReports(before, after).changes.length, 0);
  after.evidence[0].data.path = '/new';
  assert.deepEqual(compareSavedReports(before, after).changes.map(x => x.probe), ['browser_url']);
  after.scope.extra = true;
  assert.equal(compareSavedReports(before, after).scope_changed, true);
  assert.throws(() => compareSavedReports(before, analyzeLocal('other.example')));
  const other = structuredClone(before); other.schema = 't3-evidence/1';
  assert.throws(() => compareSavedReports(before, other));
});

test('Python records support bracket-free IPv6 hosts and expanded Unicode paths', () => {
  const record = analyzeLocal('https://[2606:4700:4700::1111]/');
  record.schema = 't3-evidence/1';
  record.target.host = '2606:4700:4700::1111';
  record.target.url += '%E6%B5%8B'.repeat(300);
  assert.equal(parseSavedReport(JSON.stringify(record)).target.host, record.target.host);
});

test('import and comparison preserve hostile values as data and never fetch', () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => {throw new Error('Unexpected network call');};
  try {
    const record = analyzeLocal('example.com');
    record.evidence[0].data.title = '</script><img src=x onerror=alert(1)>';
    const parsed = parseSavedReport(JSON.stringify(record));
    assert.equal(parsed.evidence[0].data.title, record.evidence[0].data.title);
    assert.equal(compareSavedReports(parsed, parsed).changes.length, 0);
  } finally {globalThis.fetch = original;}
});
