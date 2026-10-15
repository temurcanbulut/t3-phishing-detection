'use strict';

const form = document.querySelector('#analysis-form');
const input = document.querySelector('#url');
const button = document.querySelector('#analyze-button');
const report = document.querySelector('#report');
const errorBox = document.querySelector('#error');
const loading = document.querySelector('#loading');
let latestReport = null;

const statusLabels = {
  clear: 'Kontrol edildi', warning: 'Dikkat', danger: 'Tehdit eşleşmesi',
  unknown: 'Tamamlanamadı', disabled: 'Yapılandırılmadı', info: 'Bilgi',
};
const levelLabels = {
  high: 'Yüksek risk işareti', medium: 'Dikkat gerektiren işaretler',
  low: 'Az risk işareti gözlendi', incomplete: 'Kontroller eksik',
};

function renderReport(data) {
  document.querySelector('#risk-score').textContent = data.risk_score;
  const level = document.querySelector('#risk-level');
  level.textContent = levelLabels[data.risk_level];
  level.className = `badge ${data.risk_level}`;
  document.querySelector('#analyzed-url').textContent = data.url;
  document.querySelector('#coverage').textContent = `${data.completed_checks} / ${data.total_checks} kontrol tamamlandı · ${data.duration_ms} ms`;
  document.querySelector('#incomplete').hidden = !data.incomplete;
  document.querySelector('#methodology').textContent = data.methodology;
  const checks = document.querySelector('#checks');
  checks.replaceChildren();
  for (const check of data.checks) {
    const card = document.createElement('article');
    card.className = 'check';
    const heading = document.createElement('div');
    heading.className = 'check-heading';
    const title = document.createElement('h3');
    title.textContent = check.label;
    const status = document.createElement('span');
    status.className = `status ${check.status}`;
    status.textContent = statusLabels[check.status];
    const detail = document.createElement('p');
    detail.textContent = check.detail;
    heading.append(title, status);
    card.append(heading, detail);
    checks.append(card);
  }
  report.hidden = false;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  errorBox.hidden = true;
  input.removeAttribute('aria-invalid');
  report.hidden = true;
  latestReport = null;
  button.disabled = true;
  form.setAttribute('aria-busy', 'true');
  loading.hidden = false;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25000);
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: input.value.trim()}), signal: controller.signal,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Analiz tamamlanamadı.');
    latestReport = data;
    renderReport(data);
  } catch (error) {
    errorBox.textContent = error.name === 'AbortError'
      ? 'Kontroller zamanında tamamlanamadı. Yeniden deneyebilirsiniz.'
      : error.message;
    errorBox.hidden = false;
    input.setAttribute('aria-invalid', 'true');
  } finally {
    clearTimeout(timeout);
    button.disabled = false;
    form.removeAttribute('aria-busy');
    loading.hidden = true;
  }
});

document.querySelector('#download').addEventListener('click', () => {
  if (!latestReport) return;
  const file = new Blob([JSON.stringify(latestReport, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = url;
  link.download = 't3-analysis.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
