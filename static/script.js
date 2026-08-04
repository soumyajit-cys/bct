/**
 * NexusScan · script.js
 * Sections: Config | Scanner | QRScanner | History | Utils | Init
 *
 * Preserved 100%: All scan logic, API endpoints, QR scanning, history storage,
 *                 data flow, backend compatibility.
 */

"use strict";

/* ═══════════════════════ CONFIG ═══════════════════════ */
const CONFIG = {
  API_ENDPOINT:   '/analyze',
  HISTORY_KEY:     'nexusscan_history',
  HISTORY_MAX:     20,
};


/* ═══════════════════════ SCANNER ═══════════════════════ */
const Scanner = (() => {
  let scanning    = false;
  let gaugeChart  = null;  // Chart.js instance
  let els;

  function init() {
    els = {
      urlInput:        document.getElementById('urlInput'),
      analyzeBtn:      document.getElementById('analyzeBtn'),
      loadingState:    document.getElementById('loadingState'),
      resultContainer: document.getElementById('resultContainer'),
      errorContainer:  document.getElementById('errorContainer'),
      progressBar:     document.getElementById('progressBar'),
      // Results
      verdictBanner:   document.getElementById('verdictBanner'),
      verdictIcon:     document.getElementById('verdictIcon'),
      verdictText:     document.getElementById('verdictText'),
      riskScore:       document.getElementById('riskScoreDisplay'),
      issueCount:      document.getElementById('issueCount'),
      scanTime:        document.getElementById('scanTimeDisplay'),
      confidence:      document.getElementById('confidenceDisplay'),
      technicalData:   document.getElementById('technicalData'),
      findingsBadge:   document.getElementById('findingsBadge'),
      errorText:       document.getElementById('errorText'),
      copyBtn:         document.getElementById('copyResultBtn'),
      scanAnotherBtn:  document.getElementById('scanAnotherBtn'),
      // AI Report
      aiReportBlock:   document.getElementById('aiReportBlock'),
      aiBadge:         document.getElementById('aiBadge'),
      aiSummary:       document.getElementById('aiSummary'),
      aiWhy:           document.getElementById('aiWhy'),
      aiActions:       document.getElementById('aiActions'),
      aiTechSummary:   document.getElementById('aiTechSummary'),
      aiConfidence:    document.getElementById('aiConfidence'),
      aiFallbackNote:  document.getElementById('aiFallbackNote'),
      aiFallbackText:  document.getElementById('aiFallbackText'),
    };

    els.analyzeBtn.addEventListener('click', startScan);
    els.urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
    els.copyBtn.addEventListener('click', copyReport);
    els.scanAnotherBtn.addEventListener('click', resetToIdle);

    document.querySelectorAll('.hint-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        els.urlInput.value = btn.dataset.url;
        els.urlInput.focus();
      });
    });
  }

  /* ── Public: startScan ── */
  async function startScan() {
    if (scanning) return;

    hide(document.getElementById('qrSuccessHint'));

    let url = els.urlInput.value.trim();
    if (!url) { showError('Enter a URL to scan.'); return; }

    url = normalizeInputUrl(url);
    els.urlInput.value = url;

    if (!isValidUrl(url)) {
      showError('Please enter a valid URL (e.g. https://example.com)');
      return;
    }

    scanning = true;
    hideAll();
    setLoadingUI(true);

    try {
      const [data] = await Promise.all([
        fetchScan(url),
        fakeProgress(),
      ]);

      if (data.error) { showError(data.error); return; }

      setProgress(100);
      await sleep(400);
      setLoadingUI(false);
      displayResults(data, url);
      History.add({ url, data, ts: Date.now() });

    } catch (err) {
      showError('Scan failed — check the URL and try again.');
      console.error('[NexusScan]', err);
    } finally {
      scanning = false;
    }
  }

  async function fetchScan(url) {
    const res = await fetch(CONFIG.API_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function fakeProgress() {
    const steps = [15, 35, 60, 80, 92];
    for (const pct of steps) {
      await sleep(900);
      setProgress(pct);
    }
  }

  function setProgress(pct) {
    if (els.progressBar) els.progressBar.style.width = pct + '%';
  }

  /* ── Display Results ── */
  function displayResults(data, url) {
    const score   = data.risk_score ?? 0;
    const verdict = data.verdict ?? 'Unknown';
    const tier    = getTier(score);

    // Verdict banner
    els.verdictIcon.textContent = getVerdictEmoji(tier);
    els.verdictText.textContent = verdict;
    els.verdictText.className   = 'verdict-text ' + tier;

    // Apply tier class to banner for border color
    els.verdictBanner.className = 'verdict-banner ' + tier;

    // Gauge (Chart.js)
    animateGauge(score, tier);

    // Stats
    animateCounter(els.riskScore, 0, score, 1000);
    els.issueCount.textContent = data.technical_details ? data.technical_details.length : 0;
    els.scanTime.textContent   = data.scan_time ?? '—';
    els.confidence.textContent = getConfidence(data.score_breakdown);

    // AI report
    renderAIReport(data.ai_report ?? null);

    // Technical findings
    renderFindings(data.technical_details ?? [], score);

    // Findings badge
    const count = data.technical_details ? data.technical_details.length : 0;
    els.findingsBadge.textContent = `${count} finding${count !== 1 ? 's' : ''}`;

    // Score breakdown
    renderScoreBreakdown(data.score_breakdown ?? []);

    // Store for copy
    els.resultContainer._data = { data, url, score, verdict };

    show(els.resultContainer);
    els.resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ── Chart.js half-gauge ── */
  function animateGauge(score, tier) {
    const colorMap = {
      safe:     '#16a34a',
      low:      '#d97706',
      medium:   '#ea580c',
      high:     '#dc2626',
      critical: '#b91c1c',
    };
    const fillColor = colorMap[tier] ?? '#2563eb';

    const canvas = document.getElementById('gaugeChart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (gaugeChart) {
      gaugeChart.destroy();
      gaugeChart = null;
    }

    const ctx = canvas.getContext('2d');

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    gaugeChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [score, 100 - score],
          backgroundColor: [
            fillColor,
            'rgba(15, 23, 42, 0.07)',
          ],
          borderWidth:  0,
          borderRadius: score > 0 && score < 100 ? 3 : 0,
          hoverBackgroundColor: [fillColor, 'rgba(255,255,255,0.06)'],
        }],
      },
      options: {
        cutout:        '78%',
        rotation:      -90,
        circumference: 180,
        animation: {
          animateRotate: true,
          duration:      1100,
          easing:        'easeOutQuart',
        },
        plugins: {
          legend:  { display: false },
          tooltip: { enabled: false },
        },
        responsive:          false,
        maintainAspectRatio: false,
        events:              [],
      },
    });
  }

  /* ── Score Breakdown ── */
  function renderScoreBreakdown(breakdown) {
    const container = document.getElementById('scoreBreakdown');
    if (!container) return;

    container.innerHTML = '';

    const scored = breakdown.filter(b => b.points > 0);
    if (!scored.length) {
      container.classList.add('hidden');
      return;
    }

    scored.forEach(b => {
      const row = document.createElement('div');
      row.className = 'breakdown-row';

      const label = document.createElement('span');
      label.className  = 'breakdown-label';
      label.textContent = b.label || b.finding.slice(0, 60);

      const pts = document.createElement('span');
      pts.className  = 'breakdown-pts';
      pts.textContent = '+' + b.points;

      row.appendChild(label);
      row.appendChild(pts);
      container.appendChild(row);
    });

    container.classList.remove('hidden');
  }

  /* ── Technical Findings ── */
  function renderFindings(findings, score) {
    els.technicalData.innerHTML = '';

    if (!findings.length) {
      const empty = document.createElement('div');
      empty.className = 'finding-item ok';
      const dot = document.createElement('span');
      dot.className = 'finding-dot';
      empty.appendChild(dot);
      empty.appendChild(document.createTextNode('No issues detected — site appears clean.'));
      els.technicalData.appendChild(empty);
      return;
    }

    findings.forEach(f => {
      const text  = (typeof f === 'object' && f !== null) ? (f.text  || '') : String(f);
      const links = (typeof f === 'object' && f !== null) ? (f.links || []) : [];

      const cls = classifyFinding(text);
      const div = document.createElement('div');
      div.className = `finding-item ${cls}`;

      const dot = document.createElement('span');
      dot.className = 'finding-dot';
      div.appendChild(dot);

      if (links.length > 0) {
        let remaining = text;
        links.forEach(url => {
          const idx = remaining.indexOf(url);
          if (idx < 0) return;
          if (idx > 0) div.appendChild(document.createTextNode(remaining.slice(0, idx)));
          const a = document.createElement('a');
          a.href   = url;
          a.target = '_blank';
          a.rel    = 'noopener noreferrer';
          a.textContent = url;
          div.appendChild(a);
          remaining = remaining.slice(idx + url.length);
        });
        if (remaining) div.appendChild(document.createTextNode(remaining));
      } else {
        div.appendChild(document.createTextNode(text));
      }

      els.technicalData.appendChild(div);
    });
  }

  function classifyFinding(text) {
    if (/exposed|breach|trace|credential/i.test(text)) return 'critical';
    if (/directory|missing|HTTPS|redirect/i.test(text)) return 'warning';
    if (/no critical|clean|none/i.test(text))           return 'ok';
    return 'info';
  }

  /* ── AI Report ── */
  function renderAIReport(report) {
    if (!report || !els.aiReportBlock) return;

    if (els.aiSummary)     els.aiSummary.textContent     = report.executive_summary    ?? '';
    if (els.aiWhy)         els.aiWhy.textContent          = report.why_it_was_flagged   ?? '';
    if (els.aiTechSummary) els.aiTechSummary.textContent  = report.technical_summary    ?? '';
    if (els.aiConfidence)  els.aiConfidence.textContent   = report.confidence_note      ?? '';

    if (els.aiActions) {
      els.aiActions.innerHTML = '';
      const actions = Array.isArray(report.recommended_actions) ? report.recommended_actions : [];
      actions.forEach(action => {
        const li = document.createElement('li');
        li.textContent = action;
        els.aiActions.appendChild(li);
      });
    }

    if (els.aiFallbackNote) {
      if (report.is_fallback) {
        els.aiFallbackNote.classList.remove('hidden');
        if (els.aiFallbackText) els.aiFallbackText.textContent = resolveFallbackMessage(report);
        if (els.aiBadge) {
          els.aiBadge.style.background = 'rgba(100,116,139,0.1)';
          els.aiBadge.style.color      = 'rgba(100,116,139,0.8)';
          els.aiBadge.style.border     = '1px solid rgba(100,116,139,0.25)';
          els.aiBadge.title            = 'LLM unavailable — summary generated from scan data';
        }
      } else {
        els.aiFallbackNote.classList.add('hidden');
        if (els.aiBadge) {
          els.aiBadge.style.background = '';
          els.aiBadge.style.color      = '';
          els.aiBadge.style.border     = '';
          els.aiBadge.title            = 'Generated by AI to help non-technical users';
        }
      }
    }

    show(els.aiReportBlock);
  }

  function resolveFallbackMessage(report) {
    if (report && typeof report.fallback_message === 'string' && report.fallback_message.trim())
      return report.fallback_message.trim();
    const reason = typeof report?.fallback_reason === 'string' ? report.fallback_reason.trim() : '';
    if (!reason)                             return 'AI explanation unavailable — showing rule-based summary.';
    if (reason === 'missing_api_key')        return 'LLM API key is not configured — showing rule-based summary.';
    if (reason === 'unsupported_provider')   return 'Invalid LLM provider configuration — showing rule-based summary.';
    if (reason === 'response_unparseable')   return 'LLM returned an invalid response — showing rule-based summary.';
    if (reason === 'timeout')                return 'LLM request timed out — showing rule-based summary.';
    if (reason === 'connection_error')       return 'Could not connect to LLM provider — showing rule-based summary.';
    if (reason.startsWith('http_error_'))
      return `LLM provider returned HTTP ${reason.slice('http_error_'.length) || '?'} — showing rule-based summary.`;
    return 'AI explanation unavailable — showing rule-based summary.';
  }

  /* ── Copy Report ── */
  function copyReport() {
    const d = els.resultContainer._data;
    if (!d) return;

    const ai = d.data.ai_report;
    const aiLines = [];
    if (ai) {
      aiLines.push('── Report ──');
      if (ai.executive_summary)  aiLines.push(ai.executive_summary);
      if (ai.why_it_was_flagged) aiLines.push('\nWhy flagged: ' + ai.why_it_was_flagged);
      const acts = Array.isArray(ai.recommended_actions) ? ai.recommended_actions : [];
      if (acts.length) { aiLines.push('\nRecommended actions:'); acts.forEach(a => aiLines.push('  → ' + a)); }
      if (ai.confidence_note) aiLines.push('\n' + ai.confidence_note);
    }

    const technicalText = (d.data.technical_details ?? [])
      .map(f => (typeof f === 'object' && f !== null) ? (f.text || '') : String(f))
      .join('\n');

    const text = [
      `NexusScan Report`,
      `URL: ${d.url}`,
      `Verdict: ${d.verdict}`,
      `Risk Score: ${d.score}`,
      `Scan Time: ${d.data.scan_time}`,
      ``,
      ...(aiLines.length ? [...aiLines, ``] : []),
      `── Technical Findings ──`,
      technicalText,
    ].join('\n');

    navigator.clipboard.writeText(text).then(() => {
      const orig = els.copyBtn.innerHTML;
      els.copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> Copied!';
      setTimeout(() => { els.copyBtn.innerHTML = orig; }, 2000);
    });
  }

  /* ── UI Helpers ── */
  function setLoadingUI(on) {
    if (on) {
      show(els.loadingState);
      els.analyzeBtn.disabled = true;
      const btnText = els.analyzeBtn.querySelector('.btn-text');
      if (btnText) btnText.textContent = 'SCANNING';
      setProgress(0);
    } else {
      hide(els.loadingState);
      els.analyzeBtn.disabled = false;
      const btnText = els.analyzeBtn.querySelector('.btn-text');
      if (btnText) btnText.textContent = 'SCAN';
    }
  }

  function showError(msg) {
    setLoadingUI(false);
    hide(els.resultContainer);
    if (els.errorText) els.errorText.textContent = msg;
    show(els.errorContainer);
    scanning = false;
  }

  function resetToIdle() {
    hideAll();
    els.urlInput.value = '';
    els.urlInput.focus();
    scanning = false;
    hide(document.getElementById('qrSuccessHint'));
    // Destroy gauge chart on reset
    if (gaugeChart) { gaugeChart.destroy(); gaugeChart = null; }
  }

  function hideAll() {
    hide(els.loadingState);
    hide(els.resultContainer);
    hide(els.errorContainer);
  }

  return { init, startScan };
})();


/* ═══════════════════════ QR SCANNER ═══════════════════════ */
/**
 * QRScanner — 100% preserved from original.
 * Provides QR code scanning as an additional URL input source.
 */
const QRScanner = (() => {
  let qrInstance     = null;
  let panelOpen      = false;
  let currentTab     = 'camera';
  let cameraStarting = false;
  let scanLock       = false;
  let successHintTimer = null;

  const CAMERA_ELEMENT_ID = 'qrReaderCamera';

  function init() {
    const toggleBtn  = document.getElementById('qrScannerBtn');
    const closeBtn   = document.getElementById('qrCloseBtn');
    const imageInput = document.getElementById('qrImageInput');
    const tabs       = document.querySelectorAll('.qr-tab');

    if (!toggleBtn) return;

    toggleBtn.addEventListener('click', togglePanel);
    closeBtn?.addEventListener('click', () => closePanel());

    tabs.forEach(tab => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    imageInput?.addEventListener('change', handleImageUpload);

    const uploadArea = document.querySelector('.qr-upload-area');
    if (uploadArea) {
      uploadArea.addEventListener('dragover', e => {
        e.preventDefault(); e.stopPropagation();
        uploadArea.classList.add('qr-upload-area--dragover');
      });
      uploadArea.addEventListener('dragenter', e => {
        e.preventDefault(); e.stopPropagation();
        uploadArea.classList.add('qr-upload-area--dragover');
      });
      uploadArea.addEventListener('dragleave', e => {
        e.preventDefault(); e.stopPropagation();
        uploadArea.classList.remove('qr-upload-area--dragover');
      });
      uploadArea.addEventListener('drop', e => {
        e.preventDefault(); e.stopPropagation();
        uploadArea.classList.remove('qr-upload-area--dragover');
        const file = e.dataTransfer?.files?.[0];
        if (file) processImageFile(file);
      });
    }
  }

  /* ══ Panel ══ */

  function togglePanel() {
    if (panelOpen) { closePanel(); } else { openPanel(); }
  }

  function openPanel() {
    const panel     = document.getElementById('qrScannerPanel');
    const toggleBtn = document.getElementById('qrScannerBtn');
    if (!panel) return;

    panelOpen = true;
    panel.classList.remove('hidden');
    toggleBtn?.setAttribute('aria-expanded', 'true');

    if (currentTab === 'camera') startCameraInstance();
  }

  function closePanel(silent = false) {
    const panel     = document.getElementById('qrScannerPanel');
    const toggleBtn = document.getElementById('qrScannerBtn');
    if (!panel) return;

    panelOpen = false;
    panel.classList.add('hidden');
    toggleBtn?.setAttribute('aria-expanded', 'false');

    stopCameraInstance();
    if (!silent) clearQrStatus();
  }

  /* ══ Tabs ══ */

  function switchTab(tab) {
    if (tab === currentTab) return;
    currentTab = tab;

    document.querySelectorAll('.qr-tab').forEach(el => {
      const isActive = el.dataset.tab === tab;
      el.classList.toggle('active', isActive);
      el.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    document.querySelectorAll('.qr-tab-content').forEach(el => {
      el.classList.toggle('hidden', !el.id.toLowerCase().includes(tab));
    });

    clearQrStatus();

    if (tab === 'camera')  startCameraInstance();
    if (tab === 'upload')  stopCameraInstance();
  }

  /* ══ Camera ══ */

  async function startCameraInstance() {
    if (cameraStarting || qrInstance) return;
    if (typeof Html5Qrcode === 'undefined') {
      showQrStatus('QR library not loaded. Please refresh the page.', 'error');
      return;
    }

    cameraStarting = true;
    clearQrStatus();

    try {
      qrInstance = new Html5Qrcode(CAMERA_ELEMENT_ID);
      const config = { fps: 10, qrbox: { width: 220, height: 220 }, aspectRatio: 1.0 };
      await qrInstance.start({ facingMode: 'environment' }, config, onQrSuccess, () => {});
    } catch (err) {
      qrInstance = null;
      const msg = err?.message || String(err);
      if (/permission|denied|not allowed/i.test(msg)) {
        showQrStatus('Camera access denied. Please allow camera permissions and try again.', 'error');
      } else if (/no.*camera|not.*found|device/i.test(msg)) {
        showQrStatus('No camera detected on this device.', 'error');
      } else {
        showQrStatus('Could not start camera. Try the Upload Image tab instead.', 'error');
      }
    } finally {
      cameraStarting = false;
    }
  }

  async function stopCameraInstance() {
    if (!qrInstance) return;
    const instance = qrInstance;
    qrInstance = null;
    try {
      if (instance.isScanning) await instance.stop();
      instance.clear?.();
    } catch (_) { /* ignore */ }
  }

  /* ══ Image upload ══ */

  function handleImageUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    processImageFile(file);
    e.target.value = '';
  }

  function processImageFile(file) {
    if (!file.type.startsWith('image/') && file.type !== 'application/pdf') {
      showQrStatus('Unsupported file type. Please upload an image or PDF.', 'error');
      return;
    }

    if (typeof Html5Qrcode === 'undefined') {
      showQrStatus('QR library not loaded. Please refresh the page.', 'error');
      return;
    }

    clearQrStatus();
    showQrStatus('Scanning image…', 'info');

    const tempId = 'qr-temp-' + Date.now();
    const tempDiv = document.createElement('div');
    tempDiv.id = tempId;
    tempDiv.style.display = 'none';
    document.body.appendChild(tempDiv);

    const reader = new Html5Qrcode(tempId);
    reader.scanFile(file, false)
      .then(decoded => {
        tempDiv.remove();
        onQrSuccess(decoded);
      })
      .catch(err => {
        tempDiv.remove();
        const msg = String(err?.message || err || '');
        if (/No QR/i.test(msg) || /No barcode/i.test(msg)) {
          showQrStatus('No QR code found in this image. Please try a clearer image.', 'error');
        } else {
          showQrStatus('Could not read image. Try a higher-resolution photo.', 'error');
        }
      });
  }

  /* ══ QR decode success ══ */

  function onQrSuccess(decoded) {
    if (scanLock) return;
    scanLock = true;
    setTimeout(() => { scanLock = false; }, 2000);

    const url = normalizeQrUrl(decoded.trim());
    if (!url) {
      showQrStatus(`QR code contains non-URL data: "${decoded.slice(0, 60)}"`, 'error');
      setTimeout(() => { scanLock = false; }, 500);
      return;
    }

    const urlInput = document.getElementById('urlInput');
    if (urlInput) urlInput.value = url;

    stopCameraInstance();
    closePanel(true);
    showQrSuccessHint();

    setTimeout(() => {
      if (window.Scanner && typeof window.Scanner.startScan === 'function') {
        window.Scanner.startScan();
      } else {
        document.getElementById('analyzeBtn')?.click();
      }
    }, 300);
  }

  /* ══ URL Normalization ══ */

  function normalizeQrUrl(raw) {
    if (/^https?:\/\//i.test(raw)) {
      try {
        const u = new URL(raw);
        if (!u.hostname.includes('.')) return null;
        return u.href;
      } catch { return null; }
    }
    const stripped   = raw.replace(/^\/\//, '');
    const candidate  = 'https://' + stripped;
    try {
      const u    = new URL(candidate);
      const host = u.hostname;
      if (!host.includes('.'))             return null;
      const parts = host.split('.');
      if (parts.length < 2)                return null;
      if (parts[parts.length - 1].length < 2) return null;
      if (raw.includes(' '))               return null;
      return u.href;
    } catch { return null; }
  }

  /* ══ UI Helpers ══ */

  function showQrStatus(msg, type) {
    const el = document.getElementById('qrStatus');
    if (!el) return;
    el.textContent = msg;
    el.className   = `qr-status qr-status--${type}`;
    el.classList.remove('hidden');
  }

  function clearQrStatus() {
    const el = document.getElementById('qrStatus');
    if (el) { el.textContent = ''; el.classList.add('hidden'); }
  }

  function showQrSuccessHint() {
    const el = document.getElementById('qrSuccessHint');
    if (!el) return;
    if (successHintTimer) clearTimeout(successHintTimer);
    el.classList.remove('hidden');
    successHintTimer = setTimeout(() => {
      el.classList.add('hidden');
      successHintTimer = null;
    }, 12000);
  }

  async function destroy() { await stopCameraInstance(); }

  return { init, closePanel };
})();


/* ═══════════════════════ HISTORY ═══════════════════════ */
const History = (() => {
  let records = [];

  function init() {
    load();
    render();
    document.getElementById('clearHistoryBtn')?.addEventListener('click', clear);
    document.getElementById('navHistoryBtn')?.addEventListener('click', () => {
      document.getElementById('history')?.scrollIntoView({ behavior: 'smooth' });
    });
  }

  function load() {
    try { records = JSON.parse(localStorage.getItem(CONFIG.HISTORY_KEY)) ?? []; }
    catch { records = []; }
  }

  function save() {
    try { localStorage.setItem(CONFIG.HISTORY_KEY, JSON.stringify(records.slice(0, CONFIG.HISTORY_MAX))); }
    catch { /* quota exceeded */ }
  }

  function add(entry) {
    records.unshift(entry);
    if (records.length > CONFIG.HISTORY_MAX) records.pop();
    save();
    render();
  }

  function clear() {
    records = [];
    save();
    render();
  }

  function render() {
    const list  = document.getElementById('historyList');
    const empty = document.getElementById('historyEmpty');
    if (!list) return;

    list.querySelectorAll('.history-item').forEach(el => el.remove());

    if (!records.length) { show(empty); return; }
    hide(empty);

    records.forEach(rec => {
      const score   = rec.data?.risk_score ?? 0;
      const verdict = rec.data?.verdict    ?? '—';
      const tier    = getTier(score);
      const date    = new Date(rec.ts).toLocaleString(undefined, {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      });

      const el = document.createElement('div');
      el.className = 'history-item';
      el.innerHTML = `
        <div class="history-score ${tier}">${score}</div>
        <span class="history-url">${sanitize(rec.url)}</span>
        <span class="history-verdict">${sanitize(verdict)}</span>
        <span class="history-date">${date}</span>
      `;
      el.addEventListener('click', () => {
        const inp = document.getElementById('urlInput');
        if (inp) { inp.value = rec.url; inp.focus(); }
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
      list.appendChild(el);
    });
  }

  return { init, add };
})();


/* ═══════════════════════ UTILITIES ═══════════════════════ */

/**
 * normalizeInputUrl — prepend https:// to bare hostnames.
 * Preserved exactly from original.
 */
function normalizeInputUrl(url) {
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith('//'))       return 'https:' + url;
  return 'https://' + url;
}

function isValidUrl(url) {
  try { const u = new URL(url); return ['http:', 'https:'].includes(u.protocol); }
  catch { return false; }
}

function getTier(score) {
  if (score < 25) return 'safe';
  if (score < 50) return 'low';
  if (score < 75) return 'medium';
  if (score < 90) return 'high';
  return 'critical';
}

function getVerdictEmoji(tier) {
  return { safe: '✅', low: '🟡', medium: '🟠', high: '🔴', critical: '💀' }[tier] ?? '❓';
}

function getConfidence(breakdown) {
  const items = Array.isArray(breakdown) ? breakdown : [];
  if (!items.length) return 'High';
  const substantive = items.filter(it => (it.points ?? 0) >= 8).length;
  if (substantive >= 2) return 'High';
  if (substantive === 1) return 'Medium';
  return 'Low';
}

function sanitize(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function show(el) { if (el) el.classList.remove('hidden'); }
function hide(el) { if (el) el.classList.add('hidden'); }

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function animateCounter(el, from, to, duration) {
  if (!el) return;
  const start = performance.now();
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * ease);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}


/* ═══════════════════════ INIT ═══════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  Scanner.init();
  History.init();
  QRScanner.init();

  // Expose Scanner globally so QRScanner can trigger auto-scan
  window.Scanner = Scanner;
});
