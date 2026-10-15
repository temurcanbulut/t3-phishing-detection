import {analyzeLocal} from './url-local.mjs';
import {parseSavedReport, compareSavedReports, MAX_REPORT_BYTES} from './reports.mjs';
import {evidenceFacts} from './facts.mjs';

const $ = selector => document.querySelector(selector);
const staticMode = document.body.dataset.runtime === 'static';
const labels = {observed:'GÖZLENDİ', matched:'KAYNAK EŞLEŞMESİ', no_match:'EŞLEŞME YOK', verification_failed:'DOĞRULAMA BAŞARISIZ', unavailable:'TAMAMLANAMADI', limited:'SINIRA ULAŞILDI', blocked:'ENGELLENDİ', not_run:'ÇALIŞTIRILMADI', not_configured:'YAPILANDIRILMADI'};
let latest = null;
let comparison = null;
let revision = 0;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function showTab(raw) {
  $('#raw-panel').hidden = !raw;
  $('#evidence-panel').hidden = raw;
  $('#raw-tab').setAttribute('aria-selected', String(raw));
  $('#evidence-tab').setAttribute('aria-selected', String(!raw));
  $('#raw-tab').tabIndex = raw ? 0 : -1;
  $('#evidence-tab').tabIndex = raw ? -1 : 0;
}

function factList(item) {
  const list = node('dl', undefined, 'fact-list');
  for (const [label,value] of evidenceFacts(item)) list.append(node('dt',label),node('dd',value));
  return list;
}

function render(data, origin = 'Bu oturumda oluşturuldu.') {
  comparison = null;
  $('#comparison-result').replaceChildren();
  $('#compare-error').hidden = true;
  $('#export-comparison').disabled = true;
  $('#host').textContent = data.target.host;
  $('#domain').textContent = data.target.registrable_domain ? `Kayıt edilebilir alan adı: ${data.target.registrable_domain}` : 'Kayıt edilebilir alan adı bu modda belirlenmedi.';
  $('#normalized-url').textContent = data.target.url;
  $('#mode').textContent = data.schema === 't3-browser-url/1' ? 'BROWSER / OFFLINE' : data.scope.active ? 'ACTIVE' : 'PASSIVE';
  $('#duration').textContent = `${data.duration_ms} ms`;
  $('#completion').textContent = data.partial ? 'KISMİ KAYIT' : 'İSTENEN KAPSAM TAMAMLANDI';
  $('#provenance').textContent = `${origin} Başlangıç: ${data.started_at}. Kayıt, kaynağın doğruluğunu kanıtlamaz.`;
  $('#probe-overview').replaceChildren(...data.evidence.map(item => {
    const box = node('div', undefined, 'probe-tile');
    box.append(node('strong', item.label), node('span', labels[item.status] || item.status, `probe-state ${item.status}`));
    return box;
  }));
  $('#conclusion').textContent = data.conclusion === 'threat_source_match'
    ? 'Bir tehdit kaynağı URL eşleşmesi bildirdi. Kaynağı, zamanı ve eşleşme türünü aşağıdan inceleyin.'
    : 'Güvenli / zararlı kararı verilmedi. Aşağıdaki kayıt, bu incelemede gözlenen teknik bulguları gösterir.';
  $('#findings').replaceChildren(...data.findings.map(finding => {
    const box = node('article', undefined, 'finding');
    box.append(node('code', finding.kind), node('div', finding.detail));
    return box;
  }));
  $('#evidence').replaceChildren(...data.evidence.map(item => {
    const details = node('details');
    const summary = node('summary');
    summary.append(node('span', item.label, 'probe-name'), node('span', labels[item.status] || item.status, `probe-state ${item.status}`));
    details.append(summary, node('p', item.note, 'probe-note'));
    details.append(factList(item));
    if (item.data !== null && item.data !== undefined) {
      const raw = node('details',undefined,'technical-record');
      raw.append(node('summary','Teknik kaydı aç'),node('pre',JSON.stringify({collected_at:item.collected_at,data:item.data},null,2)));
      details.append(raw);
    }
    return details;
  }));
  $('#limits').replaceChildren(...data.limitations.map(text => node('li', text)));
  $('#raw').textContent = JSON.stringify(data, null, 2);
  showTab(false);
  $('#report').hidden = false;
}

$('#inspect-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('#error').hidden = true;
  $('#report').hidden = true;
  latest = null;
  const currentRevision = ++revision;
  $('#run').disabled = true;
  $('#progress').hidden = false;
  $('#inspect-form').setAttribute('aria-busy', 'true');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    let result;
    if (staticMode) result = analyzeLocal($('#target').value);
    else {
      const response = await fetch('api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, signal:controller.signal,
        body:JSON.stringify({url:$('#target').value.trim(), active:$('#active').checked, threat_lookup:$('#threat').checked})});
      let data;
      try { data = await response.json(); }
      catch { throw new Error(response.status === 413 ? 'İstek çok büyük. Daha kısa bir URL kullanın.' : `İnceleme servisi geçerli bir yanıt döndürmedi (HTTP ${response.status}).`); }
      if (!response.ok) throw new Error(data.error || 'İnceleme tamamlanamadı.');
      result = data;
    }
    if (currentRevision === revision) { latest = result; render(latest); }
  } catch (error) {
    $('#error').textContent = error.name === 'AbortError' ? 'İstek süresi doldu; sonuç alınamadı.' : error.message;
    $('#error').hidden = false;
  } finally {
    clearTimeout(timer);
    $('#run').disabled = false;
    $('#progress').hidden = true;
    $('#inspect-form').removeAttribute('aria-busy');
  }
});

$('#raw-tab').addEventListener('click', () => showTab(true));
$('#evidence-tab').addEventListener('click', () => showTab(false));
for (const selector of ['#raw-tab', '#evidence-tab']) $(selector).addEventListener('keydown', event => {
  if (['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) {
    event.preventDefault();
    const raw = event.key === 'End' || (event.key !== 'Home' && selector === '#evidence-tab');
    showTab(raw);
    $(raw ? '#raw-tab' : '#evidence-tab').focus();
  }
});
function download(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'}));
  const link = node('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('#export').addEventListener('click', () => {if (latest) download(latest, 't3-evidence.json');});

async function readFile(input) {
  const file = input.files[0];
  if (!file) return null;
  input.value = '';
  if (file.size > MAX_REPORT_BYTES) throw new Error('Rapor en fazla 4 MiB olabilir.');
  const bytes = await file.arrayBuffer();
  let source;
  try { source = new TextDecoder('utf-8', {fatal:true}).decode(bytes); }
  catch { throw new Error('UTF-8 kodlamasında bir JSON dosyası seçin.'); }
  const data = parseSavedReport(source);
  const hash = crypto.subtle ? Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), x => x.toString(16).padStart(2, '0')).join('') : null;
  return {data, hash};
}

$('#open-report').addEventListener('change', async event => {
  const currentRevision = ++revision;
  $('#file-error').hidden = true;
  try {
    const record = await readFile(event.target);
    if (!record || currentRevision !== revision) return;
    latest = record.data;
    render(latest, `Yerel dosyadan açıldı. SHA256: ${record.hash || 'bu ortamda hesaplanamadı'}.`);
  } catch (error) {
    $('#file-error').textContent = error.message;
    $('#file-error').hidden = false;
  }
});

$('#example').addEventListener('click', () => {
  ++revision;
  latest = analyzeLocal('https://example.com/account?next=%2Fsettings');
  render(latest, 'Yerel URL örneği; ağ bağlantısı yapılmadı.');
});

$('#compare-report').addEventListener('change', async event => {
  const current = latest;
  const currentRevision = revision;
  $('#compare-error').hidden = true;
  $('#comparison-result').replaceChildren();
  $('#export-comparison').disabled = true;
  comparison = null;
  try {
    const record = await readFile(event.target);
    if (!record || currentRevision !== revision || !current) return;
    comparison = compareSavedReports(record.data, current);
    comparison.before_sha256 = record.hash;
    // The current view may be freshly collected, so no original-file hash is invented.
    comparison.after_representation = 'current_report_view';
    const result = $('#comparison-result');
    result.append(node('p', `${comparison.changes.length} kontrol değişti. ${comparison.scope_changed ? 'İnceleme kapsamı da değişti; sonuçları aynı koşullar gibi yorumlamayın.' : 'İnceleme kapsamları aynı.'}`, 'notice'));
    result.append(node('p', `Önce: ${comparison.before_started_at} → Sonra: ${comparison.after_started_at}`, 'quiet'));
    for (const change of comparison.changes) {
      const detail = node('details');
      const oldState = change.before ? labels[change.before.status] || change.before.status : 'KAYIT YOK';
      const newState = change.after ? labels[change.after.status] || change.after.status : 'KAYIT YOK';
      const summary = node('summary', `${change.after?.label || change.before?.label || change.probe} · ${oldState} → ${newState}`);
      const sides = node('div',undefined,'comparison-sides');
      for (const [heading,item] of [['Önce',change.before],['Sonra',change.after]]) {
        const side = node('section');
        side.append(node('h3',heading),item ? factList(item) : node('p','Bu kayıtta yer almıyor.','quiet'));
        sides.append(side);
      }
      const raw = node('details',undefined,'technical-record');
      raw.append(node('summary','Teknik farkı aç'),node('pre',JSON.stringify({before:change.before,after:change.after},null,2)));
      detail.append(summary,sides,raw);
      result.append(detail);
    }
    if (!comparison.changes.length) result.append(node('p', 'Kayıtlı bulgular aynı. Bu, sitenin değişmediğini veya güvenli olduğunu kanıtlamaz.', 'quiet'));
    result.append(node('p', `Önceki dosyanın SHA256 özeti: ${record.hash || 'hesaplanamadı'}. Dosya özeti kaynak doğrulaması değildir.`, 'provenance'));
    $('#export-comparison').disabled = false;
  } catch (error) {
    $('#compare-error').textContent = error.message;
    $('#compare-error').hidden = false;
  }
});
$('#export-comparison').addEventListener('click', () => {if (comparison) download(comparison, 't3-comparison.json');});
