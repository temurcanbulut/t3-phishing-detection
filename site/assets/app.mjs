import {analyzeLocal} from './url-local.mjs';

const $ = selector => document.querySelector(selector);
const staticMode = document.body.dataset.runtime === 'static';
const labels = {observed:'GÖZLENDİ', matched:'KAYNAK EŞLEŞMESİ', no_match:'EŞLEŞME YOK', verification_failed:'DOĞRULAMA BAŞARISIZ', unavailable:'TAMAMLANAMADI', limited:'SINIRA ULAŞILDI', blocked:'ENGELLENDİ', not_run:'ÇALIŞTIRILMADI', not_configured:'YAPILANDIRILMADI'};
let latest = null;

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

function render(data) {
  $('#host').textContent = data.target.host;
  $('#domain').textContent = data.target.registrable_domain ? `Kayıt edilebilir alan adı: ${data.target.registrable_domain}` : 'Kayıt edilebilir alan adı bu modda belirlenmedi.';
  $('#normalized-url').textContent = data.target.url;
  $('#mode').textContent = staticMode ? 'BROWSER / OFFLINE' : data.scope.active ? 'ACTIVE' : 'PASSIVE';
  $('#duration').textContent = `${data.duration_ms} ms`;
  $('#completion').textContent = data.partial ? 'KISMİ KAYIT' : 'İSTENEN KAPSAM TAMAMLANDI';
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
    if (item.data !== null && item.data !== undefined) details.append(node('pre', JSON.stringify({collected_at:item.collected_at, data:item.data}, null, 2)));
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
  $('#run').disabled = true;
  $('#progress').hidden = false;
  $('#inspect-form').setAttribute('aria-busy', 'true');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    if (staticMode) latest = analyzeLocal($('#target').value);
    else {
      const response = await fetch('api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, signal:controller.signal,
        body:JSON.stringify({url:$('#target').value.trim(), active:$('#active').checked, threat_lookup:$('#threat').checked})});
      let data;
      try { data = await response.json(); }
      catch { throw new Error(response.status === 413 ? 'İstek çok büyük. Daha kısa bir URL kullanın.' : `İnceleme servisi geçerli bir yanıt döndürmedi (HTTP ${response.status}).`); }
      if (!response.ok) throw new Error(data.error || 'İnceleme tamamlanamadı.');
      latest = data;
    }
    render(latest);
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
$('#export').addEventListener('click', () => {
  if (!latest) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(latest, null, 2)], {type:'application/json'}));
  const link = node('a');
  link.href = url;
  link.download = 't3-evidence.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
