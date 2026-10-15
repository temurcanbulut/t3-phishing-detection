export function analyzeLocal(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 2048 || /[\s\u0000-\u001f\u007f\\]/u.test(value.trim()) || /%(?![\da-f]{2})/iu.test(value)) throw new Error('Geçerli ve boşluk içermeyen bir URL girin.');
  const candidate = value.includes('://') ? value.trim() : `https://${value.trim()}`;
  let url;
  try { url = new URL(candidate); } catch { throw new Error('URL ayrıştırılamadı.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port) throw new Error('Yalnızca kullanıcı bilgisi içermeyen standart HTTP/HTTPS URL’leri desteklenir.');
  url.hash = '';
  const started = new Date().toISOString();
  return {
    schema: 't3-browser-url/1',
    target: {url: url.href, host: url.hostname, registrable_domain: null},
    started_at: started, finished_at: started, duration_ms: 0, partial: false,
    scope: {active: false, threat_lookup: false, runtime: 'static_browser'},
    conclusion: 'no_safety_verdict', findings: [],
    evidence: [{id: 'browser_url', label: 'Tarayıcı URL ayrıştırması', status: 'observed', collected_at: started,
      data: {host: url.hostname, scheme: url.protocol, path: url.pathname, has_query: Boolean(url.search)},
      note: 'WHATWG URL ayrıştırıcısının yerel sonucudur. Alan adı sahipliği ve genel son ek listesi doğrulanmaz.'},
      {id: 'network', label: 'Ağ ve tehdit kontrolleri', status: 'not_run', collected_at: started, data: null,
       note: 'Statik sürümde DNS, TLS, içerik ve tehdit kaynağı kontrolü yoktur.'}],
    limitations: ['Bu sürüm tamamen tarayıcıda çalışır; girilen URL hiçbir analiz servisine gönderilmez.', 'Sunucu yanıtı, site içeriği veya phishing varlığı hakkında bir sonuç çıkarılamaz.'],
  };
}
