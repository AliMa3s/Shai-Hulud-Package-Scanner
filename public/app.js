const form = document.getElementById('scan-form');
const targetInput = document.getElementById('target');
const datasetInput = document.getElementById('dataset-url');
const resultsSection = document.getElementById('results');
const resultsSummary = document.getElementById('results-summary');
const resultsDetails = document.getElementById('results-details');
const resourcesSection = document.getElementById('resources');
const resourceList = document.getElementById('resource-list');
const matchTemplate = document.getElementById('match-template');

async function loadResources() {
  try {
    const resp = await fetch('/api/resources');
    if (!resp.ok) return;
    const data = await resp.json();
    if (Array.isArray(data.resources) && data.resources.length) {
      resourcesSection.hidden = false;
      resourceList.innerHTML = '';
      data.resources.forEach((item) => {
        const li = document.createElement('li');
        const link = document.createElement('a');
        link.href = item.url;
        link.textContent = item.name;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        li.append(link);
        resourceList.append(li);
      });
    }
  } catch (err) {
    console.warn('Unable to load resources', err);
  }
}

async function loadConfig() {
  try {
    const resp = await fetch('/api/config');
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.defaultDatasetUrl) {
      datasetInput.value = data.defaultDatasetUrl;
    }
  } catch (err) {
    console.warn('Unable to load config', err);
  }
}

function resetResults() {
  resultsSummary.innerHTML = '';
  resultsDetails.innerHTML = '';
  resultsSection.hidden = true;
}

function renderMatches(matches = []) {
  resultsDetails.innerHTML = '';
  if (!matches.length) {
    const p = document.createElement('p');
    p.textContent = 'No known indicators were detected in this file.';
    resultsDetails.append(p);
    return;
  }

  matches.forEach((match, index) => {
    const node = matchTemplate.content.cloneNode(true);
    const heading = node.querySelector('h3');
    const list = node.querySelector('dl');

    let title = `Indicator ${index + 1}`;
    if (match.kind === 'manifest-range') {
      title = `${match.dependency} (${match.section}) — range overlap`;
    } else if (match.kind === 'manifest-exact') {
      title = `${match.dependency} (${match.section}) — exact pin`;
    } else if (match.kind === 'manifest-name-only') {
      title = `${match.dependency} (${match.section}) — requires review`;
    } else if (match.kind === 'lock-installed') {
      title = `${match.name}@${match.version} — installed`;
    }

    heading.textContent = title;

    const entries = [
      ['Kind', match.kind],
      ['Target', match.target || match.name || match.dependency],
      ['Section / Location', match.section || match.location || 'n/a'],
      ['Selector / Version', match.selector || match.version || 'n/a'],
      ['Matches', Array.isArray(match.matches) ? match.matches.join(', ') : '—']
    ];

    if (match.aliasOf) {
      entries.push(['Alias of', match.aliasOf]);
    }
    if (match.pattern) {
      entries.push(['Pattern', match.pattern]);
    }

    entries.forEach(([term, value]) => {
      const dt = document.createElement('dt');
      dt.textContent = term;
      const dd = document.createElement('dd');
      dd.textContent = value;
      list.append(dt, dd);
    });

    resultsDetails.append(node);
  });
}

function describeDataset(meta = {}) {
  if (!meta.source) return 'Bundled dataset';
  if (meta.source === 'remote-default') {
    return `Default remote feed (${meta.url})`;
  }
  if (meta.source === 'remote-custom') {
    return `Custom remote feed (${meta.url})`;
  }
  if (meta.source === 'local-fallback') {
    return `Fallback to bundled list (failed to fetch ${meta.fallbackFrom})`;
  }
  return 'Bundled dataset';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resetResults();

  const file = targetInput.files?.[0];
  if (!file) {
    alert('Choose a package.json or package-lock.json first.');
    return;
  }

  const formData = new FormData();
  formData.append('target', file, file.name);
  if (datasetInput.value.trim()) {
    formData.append('datasetUrl', datasetInput.value.trim());
  }

  const submitButton = form.querySelector('button[type="submit"]');
  const originalLabel = submitButton.textContent;
  submitButton.disabled = true;
  submitButton.textContent = 'Scanning…';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      body: formData
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || 'Scan failed');
    }

    resultsSection.hidden = false;
    resultsSummary.innerHTML = '';

    const summaryLines = [
      `Target: ${payload.target?.originalName || 'uploaded file'} (${(payload.target?.size ?? 0).toLocaleString()} bytes)`,
      `Dataset: ${describeDataset(payload.dataset)} (${payload.dataset?.entries ?? 0} entries)`
    ];

    if (payload.dataset?.malformed) {
      summaryLines.push(`Ignored malformed dataset entries: ${payload.dataset.malformed}`);
    }
    if (payload.dataset?.error || payload.dataset?.lastError) {
      summaryLines.push(`Dataset fetch issue: ${payload.dataset.error || payload.dataset.lastError}`);
    }

    summaryLines.push(`Indicators found: ${payload.matches?.length ?? 0}`);

    summaryLines.forEach((text) => {
      const p = document.createElement('p');
      p.textContent = text;
      resultsSummary.append(p);
    });

    renderMatches(payload.matches || []);
  } catch (err) {
    resultsSection.hidden = false;
    const p = document.createElement('p');
    p.textContent = err.message;
    resultsSummary.append(p);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = originalLabel;
  }
});

loadConfig();
loadResources();
