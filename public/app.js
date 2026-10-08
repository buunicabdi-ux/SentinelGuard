(() => {
  'use strict';

  const HISTORY_KEY = 'sentinelguard.inspectionHistory.v1';
  const HISTORY_LIMIT = 20;
  const PREVIEW_LIMIT = 180;
  const STORAGE_LIMIT = 48000;
  const SECRET_PATTERNS = [
    /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
    /\b(authorization)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\r\n,;]+)/gi,
    /\b(password|passwd|token|api[\s_-]?key|secret)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi
  ];
  const EXAMPLES = [
    { label: 'SQL injection', mode: 'text', value: "' OR '1'='1" },
    { label: 'XSS', mode: 'text', value: '<script>alert(1)</script>' },
    { label: 'Path traversal', mode: 'text', value: '../../etc/passwd' },
    { label: 'Command injection', mode: 'text', value: '; cat /etc/passwd' },
    { label: 'Phishing', mode: 'text', value: 'Your account will be suspended today. Verify your password immediately using this login link.' },
    { label: 'Benign text', mode: 'text', value: 'Our team teaches developers how to prevent SQL injection and XSS.' },
    { label: 'JSON payload', mode: 'json', value: JSON.stringify({ username: 'admin', query: "' OR '1'='1", comment: '<script>alert(1)</script>' }, null, 2) }
  ];
  const $ = (selector) => document.querySelector(selector);
  const elements = {
    input: $('#inspection-input'),
    inputCount: $('#input-count'),
    inputLabel: $('#input-label'),
    inputHelp: $('#input-help'),
    inspect: $('#inspect-button'),
    clear: $('#clear-button'),
    error: $('#error-message'),
    examples: $('#example-list'),
    empty: $('#empty-state'),
    loading: $('#loading-state'),
    result: $('#result-content'),
    actions: $('#result-actions'),
    history: $('#history-list'),
    historyEmpty: $('#history-empty'),
    clearHistory: $('#clear-history-button'),
    export: $('#export-button'),
    print: $('#print-button'),
    aiStatus: $('#global-ai-status')
  };
  let mode = 'text';
  let currentReport = null;
  let history = readHistory();

  function safeString(value, maximum = 1000) {
    return typeof value === 'string' ? value.slice(0, maximum) : '';
  }

  function safePreview(value) {
    return value
      .replace(/\s+/g, ' ')
      .trim()
      .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
      .replace(/\b(password|passwd|token|api[_-]?key|secret)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1$2[REDACTED]')
      .slice(0, PREVIEW_LIMIT);
  }

  function redactSensitive(value) {
    return SECRET_PATTERNS.reduce(
      (text, pattern) => text.replace(pattern, (match, key, separator) =>
        key ? `${key}${separator}[REDACTED]` : '[REDACTED]'),
      value
    );
  }

  function safeNumber(value, fallback = 0) {
    return Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : fallback;
  }

  function safeResult(data) {
    if (!data || typeof data !== 'object') return null;
    const findings = Array.isArray(data.findings) ? data.findings.slice(0, 30).map((finding) => ({
      ruleId: safeString(finding?.ruleId, 40),
      category: safeString(finding?.category, 40),
      severity: safeString(finding?.severity, 20),
      description: redactSensitive(safeString(finding?.description, 500)),
      evidence: redactSensitive(safeString(finding?.evidence, 200)),
      recommendation: redactSensitive(safeString(finding?.recommendation, 500))
    })) : [];
    const ai = data.ai && typeof data.ai === 'object' ? {
      enabled: data.ai.enabled === true,
      status: data.ai.status === 'available' ? 'available' : 'unavailable',
      ...(typeof data.ai.summary === 'string' ? { summary: redactSensitive(safeString(data.ai.summary, 500)) } : {}),
      ...(typeof data.ai.explanation === 'string' ? { explanation: redactSensitive(safeString(data.ai.explanation, 1000)) } : {}),
      ...(Array.isArray(data.ai.indicators) ? { indicators: data.ai.indicators.slice(0, 8).map((item) => redactSensitive(safeString(item, 160))) } : {}),
      ...(Array.isArray(data.ai.recommendations) ? { recommendations: data.ai.recommendations.slice(0, 8).map((item) => redactSensitive(safeString(item, 240))) } : {}),
      ...(data.ai.confidence === null || Number.isFinite(data.ai.confidence)
        ? { confidence: data.ai.confidence }
        : {})
    } : { enabled: false, status: 'unavailable' };
    return {
      riskScore: safeNumber(data.riskScore),
      classification: safeString(data.classification, 40) || 'unknown_threat',
      severity: safeString(data.severity, 20) || 'informational',
      findings,
      recommendations: Array.isArray(data.recommendations)
        ? [...new Set(data.recommendations.slice(0, 20).map((item) => redactSensitive(safeString(item, 500))).filter(Boolean))]
        : [],
      ai
    };
  }

  function makeRecord(value) {
    const report = safeResult(value?.report);
    if (!report || typeof value?.timestamp !== 'string') return null;
    return {
      id: safeString(value.id, 80),
      timestamp: safeString(value.timestamp, 40),
      preview: redactSensitive(safePreview(safeString(value.preview, PREVIEW_LIMIT))),
      mode: value.mode === 'json' ? 'json' : 'text',
      report
    };
  }

  function readHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (!raw || raw.length > STORAGE_LIMIT) {
        if (raw) localStorage.removeItem(HISTORY_KEY);
        return [];
      }
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        localStorage.removeItem(HISTORY_KEY);
        return [];
      }
      return parsed.slice(0, HISTORY_LIMIT).map(makeRecord).filter(Boolean);
    } catch {
      try { localStorage.removeItem(HISTORY_KEY); } catch { /* Storage may be unavailable. */ }
      return [];
    }
  }

  function writeHistory() {
    try {
      let records = history.slice(0, HISTORY_LIMIT);
      let serialized = JSON.stringify(records);
      while (records.length && serialized.length > STORAGE_LIMIT) {
        records = records.slice(0, -1);
        serialized = JSON.stringify(records);
      }
      localStorage.setItem(HISTORY_KEY, serialized);
      history = records;
    } catch {
      showError('Browser storage is unavailable. The current result is still available, but history was not saved.');
    }
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function showError(message) {
    elements.error.textContent = message;
    elements.error.hidden = false;
  }

  function hideError() {
    elements.error.textContent = '';
    elements.error.hidden = true;
  }

  function severityClass(severity) {
    if (severity === 'critical' || severity === 'high') return 'risk-high';
    if (severity === 'medium') return 'risk-medium';
    return 'risk-low';
  }

  function scoreClass(score) {
    if (score >= 70) return 'risk-high';
    if (score >= 30) return 'risk-medium';
    return 'risk-low';
  }

  function scoreLabel(score) {
    if (score >= 90) return 'Critical risk';
    if (score >= 70) return 'High risk';
    if (score >= 30) return 'Medium risk';
    return 'Low risk';
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
  }

  function renderExamples() {
    clearNode(elements.examples);
    for (const sample of EXAMPLES) {
      const button = element('button', 'example-chip', sample.label);
      button.type = 'button';
      button.addEventListener('click', () => {
        setMode(sample.mode);
        elements.input.value = sample.value;
        updateCounter();
        hideError();
        elements.input.focus();
      });
      elements.examples.append(button);
    }
  }

  function setMode(nextMode) {
    mode = nextMode;
    document.querySelectorAll('.mode-tab').forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', String(active));
    });
    elements.inputLabel.textContent = mode === 'json' ? 'JSON PAYLOAD TO INSPECT' : 'CONTENT TO INSPECT';
    elements.input.placeholder = mode === 'json'
      ? '{\n  "query": "paste a structured payload here"\n}'
      : 'Paste a suspicious URL, message, query, or other untrusted input…';
    elements.inputHelp.textContent = mode === 'json'
      ? 'Enter a JSON object or array. Nested values are bounded and analyzed as text; nothing is executed.'
      : 'Text mode analyzes the content as provided. No code or links are executed.';
    updateCounter();
  }

  function updateCounter() {
    const maximum = mode === 'json' ? 32768 : 32000;
    elements.inputCount.textContent = `${elements.input.value.length.toLocaleString()} / ${maximum.toLocaleString()}`;
    elements.inputCount.classList.toggle('counter-over', elements.input.value.length > maximum);
  }

  function renderReport(report, timestamp, preview, recordId) {
    const data = safeResult(report);
    if (!data) return;
    elements.empty.hidden = true;
    elements.loading.hidden = true;
    elements.result.hidden = false;
    elements.actions.hidden = false;
    clearNode(elements.result);

    const scoreRow = element('div', 'score-row');
    const gauge = element('div', `score-gauge ${scoreClass(data.riskScore)}`);
    const gaugeSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    gaugeSvg.setAttribute('viewBox', '0 0 100 100');
    gaugeSvg.setAttribute('aria-hidden', 'true');
    const track = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    track.setAttribute('class', 'gauge-track');
    track.setAttribute('cx', '50');
    track.setAttribute('cy', '50');
    track.setAttribute('r', '42');
    const progress = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    progress.setAttribute('class', 'gauge-value');
    progress.setAttribute('cx', '50');
    progress.setAttribute('cy', '50');
    progress.setAttribute('r', '42');
    progress.setAttribute('stroke-dasharray', '264');
    progress.setAttribute('stroke-dashoffset', String(264 - (264 * data.riskScore / 100)));
    gaugeSvg.append(track, progress);
    const inner = element('div', 'score-inner');
    inner.append(element('span', 'score-number', String(data.riskScore)), element('span', 'score-denom', 'RISK / 100'));
    gauge.append(gaugeSvg, inner);
    const copy = element('div', 'score-copy');
    copy.append(element('p', 'eyebrow', 'DETERMINISTIC ASSESSMENT'));
    copy.append(element('h3', '', data.classification.replaceAll('_', ' ')));
    copy.append(element('p', '', data.findings.length
      ? `${data.findings.length} security indicator${data.findings.length === 1 ? '' : 's'} matched`
      : 'No configured patterns matched. This is not proof of safety.'));
    copy.append(element('span', `risk-badge ${scoreClass(data.riskScore)}`, scoreLabel(data.riskScore)));
    copy.append(element('span', `risk-badge ${severityClass(data.severity)}`, `Severity: ${data.severity}`));
    scoreRow.append(gauge, copy);
    elements.result.append(scoreRow);

    const meta = element('div', 'result-meta');
    meta.append(element('span', '', `${preview || 'Inspection'}${recordId ? ' · from local history' : ''}`));
    meta.append(element('span', '', formatDate(timestamp)));
    elements.result.append(meta);

    const findingHeading = element('div', 'subheading');
    findingHeading.append(element('h3', '', 'Deterministic findings'));
    findingHeading.append(element('span', '', `${data.findings.length} matched`));
    elements.result.append(findingHeading);

    if (data.findings.length) {
      const list = element('div', 'finding-list');
      for (const finding of data.findings) {
        const card = element('article', `finding-card ${severityClass(finding.severity)}`);
          const head = element('div', 'finding-top');
        head.append(element('span', 'finding-category', finding.category.replaceAll('_', ' ')));
        head.append(element('span', 'finding-code', finding.ruleId));
        head.append(element('span', 'finding-severity', finding.severity));
        card.append(head, element('p', '', finding.description));
        if (finding.evidence) {
          card.append(element('span', 'evidence-label', 'BOUNDED EVIDENCE'));
          card.append(element('code', 'finding-evidence', finding.evidence));
        }
        if (finding.recommendation) {
          card.append(element('span', 'recommendation-label', 'RECOMMENDED ACTION'));
          card.append(element('p', '', finding.recommendation));
        }
        list.append(card);
      }
      elements.result.append(list);
    } else {
      elements.result.append(element('div', 'clean-card', 'No configured deterministic rule matched this input. SentinelGuard does not guarantee that unflagged content is safe.'));
    }

    if (data.recommendations.length) {
      const heading = element('div', 'subheading');
      heading.append(element('h3', '', 'Recommended actions'));
      elements.result.append(heading);
      const list = element('ul', 'recommendation-list');
      data.recommendations.forEach((item) => list.append(element('li', '', item)));
      elements.result.append(list);
    }

    const aiCard = element('div', 'ai-card');
    const aiHead = element('div', 'ai-card-head');
    aiHead.append(element('span', '', 'AI ENRICHMENT'));
    aiHead.append(element('span', '', data.ai.status === 'available' ? 'SUPPLEMENTARY' : 'UNAVAILABLE'));
    aiCard.append(aiHead);
    if (data.ai.status === 'available') {
      aiCard.append(element('p', '', data.ai.summary || 'Supplementary AI context is available.'));
      if (data.ai.explanation) aiCard.append(element('p', '', data.ai.explanation));
      if (data.ai.confidence !== undefined && data.ai.confidence !== null) {
        aiCard.append(element('p', '', `AI confidence: ${Math.round(data.ai.confidence * 100)}% (non-authoritative)`));
      }
      for (const values of [data.ai.indicators || [], data.ai.recommendations || []]) {
        if (values.length) {
          const list = element('ul', 'ai-observation');
          values.forEach((item) => list.append(element('li', '', item)));
          aiCard.append(list);
        }
      }
      aiCard.append(element('p', '', 'AI context cannot change deterministic findings or risk score.'));
    } else {
      aiCard.append(element('p', '', 'No AI provider is configured. Deterministic analysis is complete and remains authoritative.'));
    }
    elements.result.append(aiCard);

    elements.aiStatus.replaceChildren();
    elements.aiStatus.append(element('span', `status-dot ${data.ai.status === 'available' ? '' : 'status-dot-muted'}`));
    elements.aiStatus.append(document.createTextNode(data.ai.status === 'available' ? 'AI supplementary' : 'AI unavailable'));
  }

  function renderHistory() {
    clearNode(elements.history);
    elements.historyEmpty.hidden = history.length > 0;
    elements.clearHistory.disabled = history.length === 0;
    for (const record of history) {
      const row = element('div', 'history-item');
      const open = element('button', 'history-open');
      open.type = 'button';
      open.append(element('span', 'history-preview', record.preview || '(empty input)'));
      open.append(element('span', 'history-time', formatDate(record.timestamp)));
      open.addEventListener('click', () => {
        currentReport = {
          timestamp: record.timestamp,
          mode: record.mode,
          input: record.preview,
          inputIsPreview: true,
          report: record.report
        };
        setMode(record.mode);
        elements.input.value = record.preview;
        updateCounter();
        renderReport(record.report, record.timestamp, record.preview, record.id);
        document.querySelector('.result-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      const score = element('span', `history-score ${scoreClass(record.report.riskScore)}`, String(record.report.riskScore));
      const category = element('span', 'history-class', record.report.classification.replaceAll('_', ' '));
      const severity = element('span', `history-severity ${severityClass(record.report.severity)}`, record.report.severity);
      const remove = element('button', 'history-delete', '×');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove inspection from history');
      remove.addEventListener('click', () => {
        history = history.filter((item) => item.id !== record.id);
        writeHistory();
        renderDashboard();
        renderHistory();
      });
      row.append(open, category, score, severity, remove);
      elements.history.append(row);
    }
  }

  function renderDashboard() {
    $('#metric-total').textContent = String(history.length);
    $('#metric-high').textContent = String(history.filter((record) => record.report.riskScore >= 70).length);
    $('#metric-medium').textContent = String(history.filter((record) => record.report.riskScore >= 30 && record.report.riskScore < 70).length);
    $('#metric-low').textContent = String(history.filter((record) => record.report.riskScore < 30).length);
    const counts = new Map();
    for (const record of history) {
      for (const finding of record.report.findings) {
        counts.set(finding.category, (counts.get(finding.category) || 0) + 1);
      }
    }
    const common = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
    $('#metric-category').textContent = common ? common[0].replaceAll('_', ' ') : '—';
  }

  async function inspect() {
    hideError();
    const raw = elements.input.value;
    if (!raw.trim()) {
      showError('Enter content to inspect or choose one of the examples.');
      elements.input.focus();
      return;
    }
    let endpoint = '/api/v1/inspect';
    let requestBody;
    if (mode === 'json') {
      try {
        const payload = JSON.parse(raw);
        if (!payload || typeof payload !== 'object') throw new Error('expected an object or array');
        requestBody = { payload };
        endpoint = '/api/v1/inspect/payload';
      } catch {
        showError('Enter valid JSON containing an object or array payload.');
        elements.input.focus();
        return;
      }
    } else {
      requestBody = { user_input: raw };
    }

    elements.inspect.disabled = true;
    elements.inspect.textContent = 'Inspecting…';
    elements.empty.hidden = true;
    elements.result.hidden = true;
    elements.actions.hidden = true;
    elements.loading.hidden = false;
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });
      const body = await response.json().catch(() => null);
      if (!response.ok || !body?.success) {
        const message = typeof body?.error?.message === 'string'
          ? body.error.message
          : 'Inspection could not be completed. Please try again.';
        throw new Error(message);
      }
      const report = safeResult(body.data);
      if (!report) throw new Error('The inspection service returned an invalid result.');
      const timestamp = new Date().toISOString();
      const preview = redactSensitive(safePreview(raw));
      const record = {
        id: globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        timestamp,
        preview,
        mode,
        report
      };
      currentReport = {
        timestamp,
        mode,
        input: redactSensitive(raw.slice(0, 2000)),
        truncated: raw.length > 2000,
        inputIsPreview: false,
        report
      };
      history = [record, ...history.filter((item) => item.id !== record.id)].slice(0, HISTORY_LIMIT);
      writeHistory();
      renderDashboard();
      renderHistory();
      renderReport(report, timestamp, preview, '');
    } catch (error) {
      elements.loading.hidden = true;
      elements.empty.hidden = false;
      showError(error instanceof TypeError
        ? 'Unable to reach SentinelGuard. Check that the service is running and try again.'
        : safeString(error.message, 240) || 'Inspection could not be completed.');
    } finally {
      elements.inspect.disabled = false;
      elements.inspect.textContent = '⌕ Inspect input →';
    }
  }

  function downloadReport() {
    if (!currentReport) return;
    const report = {
      product: 'SentinelGuard AI',
      exportedAt: new Date().toISOString(),
      inspectedAt: currentReport.timestamp,
      input: currentReport.input,
      inputTruncated: currentReport.truncated === true,
      inputIsPreview: currentReport.inputIsPreview === true,
      inputMode: currentReport.mode,
      ...currentReport.report
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `sentinelguard-report-${new Date(currentReport.timestamp).toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function clearCurrent() {
    elements.input.value = '';
    updateCounter();
    hideError();
    elements.result.hidden = true;
    elements.actions.hidden = true;
    elements.loading.hidden = true;
    elements.empty.hidden = false;
    currentReport = null;
    elements.input.focus();
  }

  elements.inspect.addEventListener('click', inspect);
  elements.input.addEventListener('input', updateCounter);
  elements.input.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') inspect();
  });
  elements.clear.addEventListener('click', clearCurrent);
  elements.export.addEventListener('click', downloadReport);
  elements.print.addEventListener('click', () => window.print());
  elements.clearHistory.addEventListener('click', () => {
    history = [];
    try { localStorage.removeItem(HISTORY_KEY); } catch { showError('Could not clear browser history storage.'); }
    renderDashboard();
    renderHistory();
  });
  document.querySelectorAll('.mode-tab').forEach((button) =>
    button.addEventListener('click', () => setMode(button.dataset.mode)));

  renderExamples();
  renderDashboard();
  renderHistory();
  updateCounter();
})();
