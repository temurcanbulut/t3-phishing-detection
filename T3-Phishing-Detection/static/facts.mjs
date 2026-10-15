// Readable projections of source observations. Never synthesize a safety verdict.
const string = value => typeof value === 'string' ? value : null;
const finite = value => typeof value === 'number' && Number.isFinite(value) ? String(value) : null;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function evidenceFacts(item) {
  const facts = [];
  const add = (label, value) => {if (value !== null && value !== undefined && value !== '') facts.push([label,String(value)]);};
  const data = item?.data;
  if (item?.id === 'tls' && object(data)) {
    add('Bağlanılan sunucu', string(data.host));
    add('TLS sürümü', string(data.tls_version));
    add('Doğrulama', data.verification === 'system_trust_store_and_hostname' ? 'Sistem güven deposu ve alan adı ile doğrulandı' : string(data.verification));
    add('Sertifikayı veren', string(data.issuer));
    add('Geçerlilik sonu', string(data.valid_until));
    add('Bağlanılan IP', string(data.connected_ip));
  } else if (item?.id === 'dns' && object(data)) {
    add('Sorgulanan sunucu', string(data.host));
    if (Array.isArray(data.addresses)) add('Yanıtlanan IP adresleri',data.addresses.filter(x => string(x) !== null).slice(0,16).join(' · '));
  } else if (item?.id === 'http' && Array.isArray(data)) {
    for (const [index,hop] of data.slice(0,5).entries()) {
      if (!object(hop)) continue;
      add(`HTTP adımı ${index + 1}`,`${finite(hop.status) ?? 'Durum kaydı yok'} · ${string(hop.url) ?? 'URL kaydı yok'}`);
      if (object(hop.page)) {
        add('Sayfa başlığı',string(hop.page.title));
        if (Array.isArray(hop.page.forms)) add('Kaynak HTML’de form sayısı',hop.page.forms.length);
        add('Karakter kodlaması',string(hop.page.encoding));
      }
      add('Toplanan gövde',finite(hop.body_bytes_collected) === null ? null : `${hop.body_bytes_collected} bayt${hop.body_truncated === true ? ' · sınıra ulaşıldı' : ''}`);
    }
  } else if (['url','browser_url'].includes(item?.id) && object(data)) {
    add('Gerçek sunucu',string(data.ascii_host ?? data.host));
    add('Unicode gösterimi',string(data.unicode_host));
    add('Kayıt edilebilir alan adı',string(data.registrable_domain));
    add('Protokol',string(data.scheme));
    add('Yol',string(data.path));
  } else if (item?.id === 'dns_policy' && Array.isArray(data)) {
    for (const record of data.slice(0,8)) {
      if (!object(record)) continue;
      const values = Array.isArray(record.records) ? record.records.filter(x => string(x) !== null).slice(0,4) : [];
      add(`${string(record.name) ?? 'Alan adı'} · ${string(record.type) ?? 'Kayıt'}`,values.length ? values.join(' · ') : record.status === 'no_record' ? 'Sorguda kayıt dönmedi' : string(record.status));
    }
  }
  return facts.slice(0,24).map(([label,value]) => [label,value.length > 1200 ? value.slice(0,1200) + '… (tam değer teknik kayıtta)' : value]);
}
