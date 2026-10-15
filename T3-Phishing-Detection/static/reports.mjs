// Saved reports are untrusted observations. This module never contacts a target.
export const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 16384) => typeof value === 'string' && value.length <= max;
const statuses = new Set(['observed','matched','no_match','verification_failed','unavailable','limited','blocked','not_run','not_configured']);

export function parseSavedReport(source) {
  if (typeof source !== 'string' || new TextEncoder().encode(source).length > MAX_REPORT_BYTES) throw new Error('Rapor en fazla 4 MiB olabilir.');
  let report;
  try { report = JSON.parse(source); } catch { throw new Error('Dosya geçerli bir JSON raporu değil.'); }
  const stack = [[report, 0]];
  let nodes = 0;
  while (stack.length) {
    const [value, depth] = stack.pop();
    if (++nodes > 50000 || depth > 48) throw new Error('Raporun yapı sınırı aşıldı.');
    if (value && typeof value === 'object') for (const child of Object.values(value)) stack.push([child, depth + 1]);
  }
  if (!object(report) || !['t3-evidence/1','t3-browser-url/1'].includes(report.schema)) throw new Error('Desteklenen bir T3 raporu seçin.');
  const fail = () => { throw new Error('Rapor alanları eksik veya tutarsız.'); };
  if (!object(report.target) || !text(report.target.url, 4096) || !text(report.target.host, 253)) fail();
  let url;
  try { url = new URL(report.target.url); } catch { fail(); }
  const expectedHost = report.schema === 't3-evidence/1' ? url.hostname.replace(/^\[|\]$/g, '') : url.hostname;
  if (!['https:', 'http:'].includes(url.protocol) || expectedHost !== report.target.host || url.username || url.password || url.hash || url.port) fail();
  if (report.target.registrable_domain !== null && !text(report.target.registrable_domain, 253)) fail();
  if (!object(report.scope) || typeof report.scope.active !== 'boolean' || typeof report.scope.threat_lookup !== 'boolean' || typeof report.partial !== 'boolean') fail();
  if (!Number.isFinite(report.duration_ms) || report.duration_ms < 0 || !text(report.started_at, 100)) fail();
  if (!['no_safety_verdict', 'threat_source_match'].includes(report.conclusion)) fail();
  if (!Array.isArray(report.evidence) || report.evidence.length > 50 || !Array.isArray(report.findings) || report.findings.length > 256 || !Array.isArray(report.limitations) || report.limitations.length > 100) fail();
  const ids = new Set();
  for (const item of report.evidence) {
    if (!object(item) || !text(item.id, 100) || !item.id || ids.has(item.id) || !text(item.label, 200) || !text(item.note) || !statuses.has(item.status)) fail();
    ids.add(item.id);
  }
  if (!report.findings.every(item => object(item) && text(item.kind, 200) && text(item.detail)) || !report.limitations.every(item => text(item))) fail();
  // Static records cannot claim observations their producer cannot collect.
  if (report.schema === 't3-browser-url/1' && (report.scope.active || report.scope.threat_lookup || report.conclusion !== 'no_safety_verdict' || report.evidence.some(item => item.id !== 'browser_url' && item.status !== 'not_run'))) fail();
  return report;
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (object(value)) return Object.fromEntries(Object.keys(value).filter(key => key !== 'collected_at').sort().map(key => [key, stable(value[key])]));
  return value;
}

export function compareSavedReports(before, after) {
  if (before.schema !== after.schema) throw new Error('Tarayıcı ve Python raporları farklı kapsamlardadır; aynı şemadaki iki kaydı seçin.');
  if (before.target.url !== after.target.url) throw new Error('Karşılaştırma için tam olarak aynı normalleştirilmiş URL gerekir.');
  const left = new Map(before.evidence.map(item => [item.id, item]));
  const right = new Map(after.evidence.map(item => [item.id, item]));
  const changes = [];
  for (const id of [...new Set([...left.keys(), ...right.keys()])].sort()) {
    const old = stable(left.get(id) ?? null), current = stable(right.get(id) ?? null);
    if (JSON.stringify(old) !== JSON.stringify(current)) changes.push({probe:id, before:old, after:current});
  }
  return {schema:'t3-comparison/1', target:before.target.url, before_started_at:before.started_at, after_started_at:after.started_at,
    scope_changed:JSON.stringify(stable(before.scope)) !== JSON.stringify(stable(after.scope)), changes,
    interpretation:'Observed report differences only; no phishing verdict or source authenticity proof.'};
}
