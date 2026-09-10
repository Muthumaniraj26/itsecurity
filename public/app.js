document.addEventListener('DOMContentLoaded', () => {
  // Global State
  let threatFeeds = [];
  let selectedFeedItem = null;

  function getAuthHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const provider = localStorage.getItem('securityhelpdesk_llm_provider') || 'google';
    const userKey = localStorage.getItem('securityhelpdesk_user_api_key');
    const modelName = localStorage.getItem('securityhelpdesk_llm_model');
    const baseUrl = localStorage.getItem('securityhelpdesk_base_url');

    headers['x-llm-provider'] = provider;
    if (userKey && userKey.trim()) headers['x-api-key'] = userKey.trim();
    if (modelName && modelName.trim()) headers['x-llm-model'] = modelName.trim();
    if (baseUrl && baseUrl.trim()) headers['x-base-url'] = baseUrl.trim();
    return headers;
  }

  // Cache DOM Elements
  const tabButtons = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');
  
  // Threat Digest Elements
  const refreshFeedsBtn = document.getElementById('refresh-feeds-btn');
  const alertsCount = document.getElementById('alerts-count');
  const feedSearchInput = document.getElementById('feed-search');
  const articlesListContainer = document.getElementById('articles-list');
  const threatDetailsPanel = document.getElementById('threat-details-panel');
  const threatDetailsContent = document.getElementById('threat-details-content');

  // Phishing Sandbox Elements
  const phishingForm = document.getElementById('phishing-scan-form');
  const phishUrlInput = document.getElementById('phish-url-input');
  const phishPlaceholder = document.getElementById('phish-placeholder');
  const phishResultsArea = document.getElementById('phishing-results-area');
  const phishGaugeFill = document.getElementById('phish-gauge-fill');
  const phishRiskVal = document.getElementById('phish-risk-val');
  const phishVerdict = document.getElementById('phish-verdict');
  const phishIndicatorSsl = document.getElementById('phish-indicator-ssl');
  const phishIndicatorAge = document.getElementById('phish-indicator-age');
  const phishIndicatorPass = document.getElementById('phish-indicator-pass');
  const phishIndicatorLinks = document.getElementById('phish-indicator-links');
  const phishRiskFactors = document.getElementById('phish-risk-factors');
  const phishLayoutCheck = document.getElementById('phish-layout-check');
  const phishReasoning = document.getElementById('phish-reasoning');

  // Scam Detector Elements
  const scamForm = document.getElementById('scam-scan-form');
  const scamUrlInput = document.getElementById('scam-url-input');
  const scamPlaceholder = document.getElementById('scam-placeholder');
  const scamResultsArea = document.getElementById('scam-results-area');
  const scamGaugeFill = document.getElementById('scam-gauge-fill');
  const scamTrustVal = document.getElementById('scam-trust-val');
  const scamVerdict = document.getElementById('scam-verdict');
  const scamRegistrar = document.getElementById('scam-registrar');
  const scamCreatedDate = document.getElementById('scam-created-date');
  const scamAgeDays = document.getElementById('scam-age-days');
  const scamRedFlags = document.getElementById('scam-red-flags');
  const scamSignalsText = document.getElementById('scam-signals-text');
  const scamAssessment = document.getElementById('scam-assessment');

  // ==========================================
  // TAB NAVIGATION
  // ==========================================
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      
      // Update active nav button
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Update active content section
      tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === targetTab) {
          content.classList.add('active');
        }
      });
    });
  });

  // ==========================================
  // UTILITY FUNCTIONS
  // ==========================================
  const gaugeAnimState = new Map();

  function setGaugeValue(gaugeFillEl, valTextEl, value, isTrustMeter = false) {
    if (!gaugeFillEl || !valTextEl) return;

    const maxOffset = 251; // Circumference for r=40
    const targetScore = Math.min(Math.max(Math.round(value), 0), 100);
    const strokeOffset = maxOffset - (targetScore / 100) * maxOffset;

    // Determine gauge stroke & drop-shadow colors based on target score
    let colorHex = '#10b981'; // Green default
    let glowRgba = 'rgba(16, 185, 129, 0.5)';

    if (!isTrustMeter) {
      // Risk Meter: Higher score = Higher risk (Danger)
      if (targetScore >= 66) {
        colorHex = '#ef4444'; // Red
        glowRgba = 'rgba(239, 68, 68, 0.6)';
      } else if (targetScore >= 31) {
        colorHex = '#f59e0b'; // Amber
        glowRgba = 'rgba(245, 158, 11, 0.6)';
      } else {
        colorHex = '#10b981'; // Green
        glowRgba = 'rgba(16, 185, 129, 0.6)';
      }
    } else {
      // Trust Meter: Higher score = Higher trust (Safe)
      if (targetScore >= 70) {
        colorHex = '#10b981'; // Green
        glowRgba = 'rgba(16, 185, 129, 0.6)';
      } else if (targetScore >= 35) {
        colorHex = '#f59e0b'; // Amber
        glowRgba = 'rgba(245, 158, 11, 0.6)';
      } else {
        colorHex = '#ef4444'; // Red
        glowRgba = 'rgba(239, 68, 68, 0.6)';
      }
    }

    // Apply SVG stroke color, drop shadow filter, and offset
    gaugeFillEl.style.stroke = colorHex;
    gaugeFillEl.style.filter = `drop-shadow(0 0 8px ${glowRgba})`;
    gaugeFillEl.style.strokeDashoffset = strokeOffset;

    // Animate Text Counter Count-up / Count-down
    const elementId = valTextEl.id || 'gauge-val-text';
    if (gaugeAnimState.has(elementId)) {
      clearInterval(gaugeAnimState.get(elementId));
    }

    let currentVal = parseInt(valTextEl.textContent.replace('%', ''), 10) || 0;
    if (currentVal === targetScore) {
      valTextEl.textContent = isTrustMeter ? `${targetScore}` : `${targetScore}%`;
      return;
    }

    const duration = 800; // ms
    const steps = 25;
    const stepTime = duration / steps;
    const increment = (targetScore - currentVal) / steps;
    let stepCount = 0;

    const timer = setInterval(() => {
      stepCount++;
      currentVal += increment;
      if (stepCount >= steps) {
        currentVal = targetScore;
        clearInterval(timer);
        gaugeAnimState.delete(elementId);
      }
      valTextEl.textContent = isTrustMeter ? `${Math.round(currentVal)}` : `${Math.round(currentVal)}%`;
    }, stepTime);

    gaugeAnimState.set(elementId, timer);
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return dateStr;
    }
  }

  // ==========================================
  // 1. THREAT DIGEST WORKFLOW
  // ==========================================
  async function loadThreatFeeds() {
    articlesListContainer.innerHTML = `
      <div class="placeholder-loader">
        <div class="spinner"></div>
        <p>Querying security alert databases...</p>
      </div>
    `;
    alertsCount.textContent = 'Loading...';
    alertsCount.className = 'badge blue';

    try {
      const response = await fetch('/api/feeds');
      if (!response.ok) throw new Error('API server ingestion failed');

      threatFeeds = await response.data || await response.json();
      alertsCount.textContent = threatFeeds.length;
      alertsCount.className = 'badge red';
      
      renderThreatItems(threatFeeds);
    } catch (error) {
      articlesListContainer.innerHTML = `
        <div class="placeholder-loader">
          <span style="font-size: 2rem"></span>
          <p style="color: var(--accent-red)">Failed to fetch security feeds.</p>
          <small>${error.message}</small>
        </div>
      `;
      alertsCount.textContent = 'ERROR';
      alertsCount.className = 'badge red';
    }
  }

  function renderThreatItems(items) {
    if (items.length === 0) {
      articlesListContainer.innerHTML = `
        <div class="panel-placeholder">
          <p>No security alerts found matching filters.</p>
        </div>
      `;
      return;
    }

    articlesListContainer.innerHTML = '';
    items.forEach((item, index) => {
      const card = document.createElement('div');
      card.className = 'feed-item-card';
      if (selectedFeedItem && selectedFeedItem.link === item.link) {
        card.classList.add('selected');
      }

      card.innerHTML = `
        <div class="feed-item-header">
          <span>${item.source}</span>
          <span>${formatDateTime(item.pubDate)}</span>
        </div>
        <h4>${item.title}</h4>
        <p class="feed-item-desc">${item.description || 'No description provided.'}</p>
      `;

      card.addEventListener('click', () => {
        // Toggle selected state
        document.querySelectorAll('.feed-item-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        
        selectedFeedItem = item;
        analyzeFeedItemDetails(item);
      });

      articlesListContainer.appendChild(card);
    });
  }

  async function analyzeFeedItemDetails(item) {
    // Reveal panel details & show loading state
    threatDetailsPanel.innerHTML = `
      <div class="placeholder-loader">
        <div class="spinner"></div>
        <p>Triggering AI threat assessment framework...</p>
        <small style="font-family: var(--font-mono)">Analyzing vulnerability footprint...</small>
      </div>
    `;

    try {
      const response = await fetch('/api/analyze-feed', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(item)
      });

      if (!response.ok) throw new Error('AI analysis agent responded with error');

      const data = await response.json();
      const analysis = data.analysis;

      let severityClass = 'blue';
      let severityBadgeText = 'LOW RISK';
      if (analysis.severity === 'Critical') { severityClass = 'red'; severityBadgeText = 'CRITICAL RISK'; }
      else if (analysis.severity === 'High') { severityClass = 'orange'; severityBadgeText = 'HIGH RISK'; }
      else if (analysis.severity === 'Medium') { severityClass = 'blue'; severityBadgeText = 'MEDIUM RISK'; }
      else if (analysis.severity === 'Low') { severityClass = 'green'; severityBadgeText = 'LOW RISK'; }

      // CISA KEV Badge styling
      const isCisaKev = analysis.cisaKevStatus === 'CONFIRMED_EXPLOITED';
      const cisaKevBadgeHtml = isCisaKev 
        ? `<div class="kev-badge alert-red"><span class="badge-dot red"></span><span>🚨 CISA KEV Catalog: Active Exploitation Confirmed</span></div>`
        : `<div class="kev-badge safe-green"><span class="badge-dot green"></span><span>🛡️ CISA KEV Catalog: No Active Exploitation Reported</span></div>`;

      // MITRE ATT&CK Card
      const mitre = analysis.mitreTtp || { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' };

      // Org Asset Inventory Exposure Card
      const assetMatch = analysis.orgAssetMatch || 'NO_MATCH';
      const assetName = analysis.orgAssetName || 'Enterprise Infrastructure';
      const isExposed = analysis.internetExposed === 'YES';
      const assetExposureHtml = assetMatch === 'MATCHED'
        ? `<div class="asset-card matched">
            <div class="asset-header">
              <span class="badge red pulse-badge">MATCHED ASSET</span>
              <span class="exposure-tag ${isExposed ? 'danger' : 'warning'}">Internet Exposed: ${isExposed ? 'YES 🌐' : 'NO 🔒'}</span>
            </div>
            <div class="asset-title">${assetName}</div>
            <small style="color: var(--text-muted)">Detected in Organization Asset Inventory</small>
          </div>`
        : `<div class="asset-card safe">
            <div class="asset-header">
              <span class="badge green">NO DIRECT ASSET MATCH</span>
              <span class="exposure-tag safe">Internet Exposed: NO 🔒</span>
            </div>
            <div class="asset-title">${assetName}</div>
            <small style="color: var(--text-muted)">No matching asset found in company inventory</small>
          </div>`;

      // Investigation Trail Stepper Logs
      const trail = analysis.investigationTrail || [];
      const trailHtml = trail.map((step, idx) => `
        <div class="trail-step-item">
          <div class="trail-step-header">
            <span class="trail-capability-badge">${step.capability.toUpperCase()}</span>
            <span class="trail-tool-name">tool: <code>${step.tool}</code></span>
          </div>
          <p class="trail-step-output">${step.output}</p>
        </div>
      `).join('');

      threatDetailsPanel.innerHTML = `
        <div class="analysis-header card-sub">
          <div class="title-block">
            <span class="badge ${severityClass} pulse-badge">${severityBadgeText}</span>
            <h3 style="margin-top: 10px; font-family: var(--font-heading); font-size: 1.25rem;">${item.title}</h3>
            <div class="meta" style="margin-top: 6px; font-size: 0.8rem; color: var(--text-muted);">
              Source: <strong style="color: var(--text-white)">${item.source}</strong> &bull; Ingested: ${formatDateTime(item.pubDate)}
            </div>
          </div>
        </div>

        <!-- Deterministic Security Intelligence Grid -->
        <div class="tool-intelligence-grid">
          ${cisaKevBadgeHtml}

          <div class="intel-card-grid">
            <div class="intel-card">
              <span class="intel-card-label">MITRE ATT&amp;CK TTP</span>
              <div class="mitre-badge">
                <span class="mitre-id">${mitre.id}</span>
                <span class="mitre-name">${mitre.name}</span>
              </div>
              <small class="mitre-tactic">Tactic: ${mitre.tactic}</small>
            </div>

            <div class="intel-card">
              <span class="intel-card-label">IDENTIFIED CVE &amp; CATEGORY</span>
              <div class="cve-display">
                <span class="cve-id">${analysis.cveId || 'N/A'}</span>
                <span class="category-pill">${analysis.category}</span>
              </div>
              <small style="color: var(--text-muted)">Deterministic Entity Extraction</small>
            </div>

            <div class="intel-card">
              <span class="intel-card-label">NIST NVD CVSS &amp; WEAKNESS</span>
              <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
                <span class="cvss-score-pill ${(analysis.cvssScore || 0) >= 9.0 ? '' : 'high'}">CVSS ${analysis.cvssScore || 'N/A'}</span>
                <span class="cwe-badge">${analysis.cweId || 'N/A'}</span>
              </div>
              <small style="color: var(--text-muted); font-size: 0.72rem; display: block; margin-top: 4px;">${analysis.cweName || 'Security Flaw'}</small>
            </div>
          </div>

          <!-- Organization Asset Matching -->
          <div class="analysis-panel-section" style="margin-top: 14px;">
            <h4>Organization Asset Inventory Match</h4>
            ${assetExposureHtml}
          </div>
        </div>

        <!-- Export Actions -->
        <div class="export-btn-group">
          <button type="button" class="btn export-btn" id="export-md-btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>Export Markdown (.md)</span>
          </button>
          <button type="button" class="btn export-btn" id="export-json-btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Export JSON</span>
          </button>
        </div>

        <!-- Contextual Risk Reasoning -->
        <div class="cve-summary-box margin-top">
          <div class="cve-info">
            <p class="rationale-text"><strong>Contextual Risk Reasoning:</strong> ${analysis.severityReasoning}</p>
          </div>
        </div>

        <!-- Agent Investigation Tool Execution Trail -->
        <div class="analysis-panel-section margin-top">
          <h4>Agent Investigation Trail (7 Capabilities Execution Log)</h4>
          <div class="trail-container scrollable-trail">
            ${trailHtml}
          </div>
        </div>

        <div class="analysis-panel-section margin-top">
          <h4>Executive Intelligence Digest</h4>
          <p class="executive-summary-text">${analysis.executiveSummary}</p>
        </div>

        <div class="analysis-panel-section">
          <h4>Affected Infrastructure &amp; Systems</h4>
          <p class="affected-systems-text">${analysis.affectedSystems}</p>
        </div>

        <div class="analysis-panel-section">
          <h4>Compliance Framework Impact Audit</h4>
          <div class="compliance-badges-grid">
            ${analysis.complianceImpact && analysis.complianceImpact.length > 0
              ? analysis.complianceImpact.map(std => `<div class="compliance-card"><span class="comp-dot"></span><span>${std}</span></div>`).join('')
              : '<div class="compliance-card safe"><span class="comp-dot safe"></span><span>No Regulatory Standards Violated</span></div>'
            }
          </div>
        </div>

        <div class="analysis-panel-section">
          <h4>Engineering Remediation Action Plan</h4>
          <ul class="remediation-steps">
            ${analysis.actionPlan.map((step, idx) => `
              <li class="remediation-step-item">
                <span class="step-num-badge">0${idx + 1}</span>
                <span class="step-text">${step}</span>
              </li>
            `).join('')}
          </ul>
        </div>

        <!-- Interactive AI Security Analyst Assistant Chat Drawer -->
        <div class="analyst-chat-card">
          <div class="section-title">
            <span class="badge green">Interactive Assistant</span>
            <h4 style="margin-top: 4px; font-size: 1rem;">Ask AI Security Analyst</h4>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px;">Ask contextual questions regarding threat exposure, CVE exploitability, or custom workarounds.</p>
          <div class="chat-messages-container" id="threat-chat-messages">
            <div class="chat-bubble analyst">
              <div class="chat-bubble-author">AI Security Analyst</div>
              I have synthesized this advisory. Ask me anything about internal infrastructure exposure, mitigation alternatives, or CVE mechanics.
            </div>
          </div>
          <form id="threat-chat-form" class="chat-input-row">
            <input type="text" id="threat-chat-input" placeholder="e.g., Are our Linux servers vulnerable? What is the temporary mitigation?" required>
            <button type="submit" class="btn primary sm-btn">Ask</button>
          </form>
        </div>

        <hr class="divider">
        <a href="${item.link}" target="_blank" class="btn primary" style="text-decoration: none; width: fit-content;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          <span>View Original Security Advisory Link</span>
        </a>
      `;

      // Attach Export Listeners
      const exportMdBtn = document.getElementById('export-md-btn');
      if (exportMdBtn) {
        exportMdBtn.addEventListener('click', async () => {
          try {
            const res = await fetch('/api/export-advisory', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ type: 'threat', format: 'markdown', item, analysis })
            });
            const data = await res.json();
            triggerFileDownload(data.filename, data.content, 'text/markdown');
          } catch (e) {
            alert('Export failed: ' + e.message);
          }
        });
      }

      const exportJsonBtn = document.getElementById('export-json-btn');
      if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', async () => {
          try {
            const res = await fetch('/api/export-advisory', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ type: 'threat', format: 'json', item, analysis })
            });
            const data = await res.json();
            triggerFileDownload(data.filename, JSON.stringify(data.content, null, 2), 'application/json');
          } catch (e) {
            alert('Export failed: ' + e.message);
          }
        });
      }

      // Attach Threat Chat Listener
      const chatForm = document.getElementById('threat-chat-form');
      const chatInput = document.getElementById('threat-chat-input');
      const chatMessages = document.getElementById('threat-chat-messages');
      const chatHistory = [];

      if (chatForm && chatInput && chatMessages) {
        chatForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const userMsg = chatInput.value.trim();
          if (!userMsg) return;

          // Add user bubble
          const userBubble = document.createElement('div');
          userBubble.className = 'chat-bubble user';
          userBubble.textContent = userMsg;
          chatMessages.appendChild(userBubble);
          chatInput.value = '';
          chatMessages.scrollTop = chatMessages.scrollHeight;

          // Add loading bubble
          const loadingBubble = document.createElement('div');
          loadingBubble.className = 'chat-bubble analyst';
          loadingBubble.innerHTML = `<div class="chat-bubble-author">AI Security Analyst</div><em>Analyzing question against threat context...</em>`;
          chatMessages.appendChild(loadingBubble);
          chatMessages.scrollTop = chatMessages.scrollHeight;

          chatHistory.push({ role: 'user', content: userMsg });

          try {
            const response = await fetch('/api/threat-chat', {
              method: 'POST',
              headers: getAuthHeaders(),
              body: JSON.stringify({
                message: userMsg,
                context: {
                  title: item.title,
                  cveId: analysis.cveId,
                  cvssScore: analysis.cvssScore,
                  cvssSeverity: analysis.cvssSeverity,
                  cweId: analysis.cweId,
                  cweName: analysis.cweName,
                  cisaKevStatus: analysis.cisaKevStatus,
                  severity: analysis.severity,
                  affectedSystems: analysis.affectedSystems,
                  severityReasoning: analysis.severityReasoning,
                  actionPlan: analysis.actionPlan
                },
                history: chatHistory
              })
            });
            const resData = await response.json();
            loadingBubble.innerHTML = `<div class="chat-bubble-author">AI Security Analyst</div>${resData.answer || 'Analysis complete.'}`;
            chatHistory.push({ role: 'assistant', content: resData.answer });
          } catch (err) {
            loadingBubble.innerHTML = `<div class="chat-bubble-author">AI Security Analyst</div>[Error] Could not retrieve response: ${err.message}`;
          }
          chatMessages.scrollTop = chatMessages.scrollHeight;
        });
      }
    } catch (error) {
      threatDetailsPanel.innerHTML = `
        <div class="panel-placeholder">
          <span style="font-size: 2rem"></span>
          <h3 style="color: var(--accent-red)">AI Agent Failed</h3>
          <p>${error.message}</p>
        </div>
      `;
    }
  }

  // Filter feed items by search input
  feedSearchInput.addEventListener('input', (e) => {
    const searchVal = e.target.value.toLowerCase().trim();
    if (!searchVal) {
      renderThreatItems(threatFeeds);
      return;
    }

    const filtered = threatFeeds.filter(item => 
      item.title.toLowerCase().includes(searchVal) || 
      item.source.toLowerCase().includes(searchVal) ||
      (item.description && item.description.toLowerCase().includes(searchVal))
    );
    renderThreatItems(filtered);
  });

  refreshFeedsBtn.addEventListener('click', loadThreatFeeds);

  // ==========================================
  // 2. PHISHING URL SCANNER WORKFLOW
  // ==========================================
  phishingForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = phishUrlInput.value.trim();
    if (!url) return;

    // Transition UI: Hide placeholder, Reveal Results Area, Show loading values
    phishPlaceholder.classList.add('hidden');
    phishResultsArea.classList.remove('hidden');
    
    // Set spinner loading text in elements
    phishVerdict.textContent = 'SCANNING...';
    phishVerdict.className = 'verdict-badge warning-bg';
    setGaugeValue(phishGaugeFill, phishRiskVal, 0);
    
    phishIndicatorSsl.textContent = 'Calculating...';
    phishIndicatorSsl.className = 'indicator-value';
    phishIndicatorAge.textContent = 'Checking...';
    phishIndicatorAge.className = 'indicator-value';
    phishIndicatorPass.textContent = 'Scanning...';
    phishIndicatorPass.className = 'indicator-value';
    phishIndicatorLinks.textContent = 'Auditing...';
    phishIndicatorLinks.className = 'indicator-value';
    
    phishRiskFactors.innerHTML = `
      <div class="placeholder-loader">
        <div class="spinner"></div>
        <p>Crawling target URL and analyzing secure DOM factors...</p>
      </div>
    `;
    phishLayoutCheck.textContent = 'Scraping CSS/HTML properties...';
    phishReasoning.textContent = 'Invoking security AI agent sandbox classification...';

    try {
      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ url })
      });

      if (!response.ok) throw new Error('API server returned error scanning URL');

      const data = await response.json();
      const scraped = data.scraped;
      const analysis = data.analysis;

      // Update Gauge & Verdict Badge
      setGaugeValue(phishGaugeFill, phishRiskVal, analysis.phishingProbability);
      
      phishVerdict.textContent = analysis.dangerLevel.toUpperCase();
      if (analysis.dangerLevel === 'Safe') {
        phishVerdict.className = 'verdict-badge safe-bg';
      } else if (analysis.dangerLevel === 'Suspicious') {
        phishVerdict.className = 'verdict-badge warning-bg';
      } else {
        phishVerdict.className = 'verdict-badge'; // Defaults to Danger/Red
      }

      // Update Scraped Metadata Indicators
      phishIndicatorSsl.textContent = scraped.isHttps ? 'SECURE (HTTPS)' : 'INSECURE (HTTP)';
      phishIndicatorSsl.className = scraped.isHttps ? 'indicator-value val-success' : 'indicator-value val-danger';
      
      const ageDays = scraped.domainInfo.ageDays;
      if (ageDays === null) {
        phishIndicatorAge.textContent = 'Unknown (No record)';
        phishIndicatorAge.className = 'indicator-value val-warning';
      } else {
        phishIndicatorAge.textContent = `${ageDays} days`;
        phishIndicatorAge.className = ageDays < 90 ? 'indicator-value val-danger' : 'indicator-value val-success';
      }

      const hasPassword = scraped.pageMetadata.hasPasswordFields;
      phishIndicatorPass.textContent = hasPassword ? 'YES (High Risk)' : 'No (Standard)';
      phishIndicatorPass.className = hasPassword ? 'indicator-value val-danger' : 'indicator-value val-success';

      const totalLnk = scraped.pageMetadata.totalLinks;
      const extLnk = scraped.pageMetadata.externalLinks;
      const ratio = totalLnk > 0 ? (extLnk / totalLnk * 100).toFixed(0) : 0;
      phishIndicatorLinks.textContent = `${extLnk}/${totalLnk} (${ratio}%)`;
      phishIndicatorLinks.className = ratio > 60 ? 'indicator-value val-warning' : 'indicator-value val-success';

      // Update ML Feature Vector Chips (matching vaibhavbichave/Phishing-URL-Detection)
      const mlChipsContainer = document.getElementById('phish-ml-chips');
      if (mlChipsContainer) {
        const vec = analysis.mlFeatureVector || {};
        const chips = [];
        if (vec.ShortURL === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Short URL Service</span>');
        if (vec['Symbol@'] === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">@ Symbol Trap</span>');
        if (vec['ServerFormHandler'] === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">External/Empty Form</span>');
        if (vec.IframeRedirection === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Hidden Iframe</span>');
        if (vec.DisableRightClick === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Right-Click Blocked</span>');
        if (vec.InfoEmail === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Mailto Submission</span>');
        if (vec.NonStdPort === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Non-Std Port</span>');
        if (vec.HTTPSDomainURL === -1) chips.push('<span class="usecase-chip" style="border-color: rgba(244, 63, 94, 0.4); color: #fca5a5;">Fake HTTPS in Domain</span>');

        if (chips.length === 0) {
          chips.push('<span class="usecase-chip" style="border-color: rgba(16, 185, 129, 0.4); color: #6ee7b7;">✓ Clean Domain Structure</span>');
          chips.push('<span class="usecase-chip" style="border-color: rgba(16, 185, 129, 0.4); color: #6ee7b7;">✓ Valid Form Action</span>');
          chips.push('<span class="usecase-chip" style="border-color: rgba(16, 185, 129, 0.4); color: #6ee7b7;">✓ No Iframe / Script Traps</span>');
        }
        mlChipsContainer.innerHTML = chips.join('');
      }

      // Update Risk Factors list
      if (analysis.riskFactors && analysis.riskFactors.length > 0) {
        phishRiskFactors.innerHTML = '';
        analysis.riskFactors.forEach(factor => {
          const item = document.createElement('div');
          item.className = 'factor-item';
          item.innerHTML = `<span>-</span> <span>${factor}</span>`;
          phishRiskFactors.appendChild(item);
        });
      } else {
        phishRiskFactors.innerHTML = `
          <div class="factor-item" style="background: rgba(0, 230, 118, 0.05); border-color: rgba(0, 230, 118, 0.15); color: #B9F6CA;">
            <span>-</span> <span>No critical phishing risk indicators detected in site structure.</span>
          </div>
        `;
      }

      // Update text descriptions
      phishLayoutCheck.textContent = analysis.visualLayoutCheck || 'No layout warnings detected.';
      phishReasoning.textContent = analysis.verdictReasoning;

    } catch (error) {
      phishRiskFactors.innerHTML = `
        <div class="factor-item">
          <span>[ERROR]</span> <span>Scanner Fail: ${error.message}</span>
        </div>
      `;
      phishVerdict.textContent = 'ERROR';
      phishVerdict.className = 'verdict-badge';
    }
  });

  // ==========================================
  // 3. WEBSITE SCAM DETECTOR WORKFLOW
  // ==========================================
  scamForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = scamUrlInput.value.trim();
    if (!domain) return;

    scamPlaceholder.classList.add('hidden');
    scamResultsArea.classList.remove('hidden');

    scamVerdict.textContent = 'AUDITING...';
    scamVerdict.className = 'verdict-badge warning-bg';
    setGaugeValue(scamGaugeFill, scamTrustVal, 100, true);

    scamRegistrar.textContent = 'Querying RDAP...';
    scamCreatedDate.textContent = 'Parsing events...';
    scamAgeDays.textContent = 'Calculating age...';

    scamRedFlags.innerHTML = `
      <div class="placeholder-loader">
        <div class="spinner"></div>
        <p>Scanning registrar records & querying RDAP registry...</p>
      </div>
    `;
    scamSignalsText.textContent = 'Retrieving business terms, policies, and contacts...';
    scamAssessment.textContent = 'Running trust assessment script...';

    try {
      const response = await fetch('/api/detect-scam', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ url: domain })
      });

      if (!response.ok) throw new Error('API server returned error auditing domain');

      const data = await response.json();
      const scraped = data.scraped;
      const analysis = data.analysis;

      // Update Gauge & Verdict Badge
      setGaugeValue(scamGaugeFill, scamTrustVal, analysis.trustScore, true);

      scamVerdict.textContent = analysis.scamProbability > 50 ? 'HIGH RISK SCAM' : (analysis.scamProbability > 25 ? 'LOW TRUST' : 'TRUSTWORTHY');
      if (analysis.scamProbability > 50) {
        scamVerdict.className = 'verdict-badge';
      } else if (analysis.scamProbability > 25) {
        scamVerdict.className = 'verdict-badge warning-bg';
      } else {
        scamVerdict.className = 'verdict-badge safe-bg';
      }

      // Update domain registration metadata
      scamRegistrar.textContent = scraped.domainInfo.registrar || 'Unknown';
      
      const createdDate = scraped.domainInfo.createdDate;
      scamCreatedDate.textContent = createdDate ? new Date(createdDate).toLocaleDateString() : 'N/A';
      
      const ageDays = scraped.domainInfo.ageDays;
      scamAgeDays.textContent = ageDays !== null ? `${ageDays} days` : 'Unknown';

      // Update Red Flags
      if (analysis.redFlags && analysis.redFlags.length > 0) {
        scamRedFlags.innerHTML = '';
        analysis.redFlags.forEach(flag => {
          const item = document.createElement('div');
          item.className = 'factor-item red-flag';
          item.innerHTML = `<span>-</span> <span>${flag}</span>`;
          scamRedFlags.appendChild(item);
        });
      } else {
        scamRedFlags.innerHTML = `
          <div class="factor-item" style="background: rgba(0, 230, 118, 0.05); border-color: rgba(0, 230, 118, 0.15); color: #B9F6CA;">
            <span>-</span> <span>No scam indicators detected in registrar age or content policies.</span>
          </div>
        `;
      }

      // Update text descriptions
      scamSignalsText.textContent = analysis.riskSignalsText;
      scamAssessment.textContent = analysis.assessmentText;

    } catch (error) {
      scamRedFlags.innerHTML = `
        <div class="factor-item red-flag">
          <span>[ERROR]</span> <span>Scam Audit Fail: ${error.message}</span>
        </div>
      `;
      scamVerdict.textContent = 'ERROR';
      scamVerdict.className = 'verdict-badge';
    }
  });

  // ==========================================
  // 4. PRICING PLANS WORKFLOW
  // ==========================================
  const currencyPrices = {
    USD: { symbol: '$', proPrice: '49' },
    EUR: { symbol: '€', proPrice: '45' },
    INR: { symbol: '₹', proPrice: '3999' },
    GBP: { symbol: '£', proPrice: '39' }
  };

  const currencyButtons = document.querySelectorAll('#currency-selector .selector-btn');
  const paymentButtons = document.querySelectorAll('#payment-selector .selector-btn');
  const paymentNotification = document.getElementById('payment-notification');
  const paymentStatusTitle = document.getElementById('payment-status-title');
  const paymentStatusDesc = document.getElementById('payment-status-desc');

  // Currency selection handler
  currencyButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      // Toggle active states
      currencyButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const selectedCurrency = btn.getAttribute('data-currency');
      const pricing = currencyPrices[selectedCurrency];

      // Update Free & Pro price elements
      document.getElementById('free-symbol').textContent = pricing.symbol;
      document.getElementById('pro-symbol').textContent = pricing.symbol;
      document.getElementById('pro-price').textContent = pricing.proPrice;
    });
  });

  // Payment method selection handler
  const paymentNames = {
    credit_card: { title: 'Credit Card Channel Active', desc: 'Secure card checkout enabled via 3D-Secure 2.0.' },
    stripe: { title: 'Stripe Gateway Selected', desc: 'Payment will be securely routed through Stripe Elements.' },
    paypal: { title: 'PayPal Checkout Selected', desc: 'Login details and subscription auth will execute via PayPal Secure Sandbox.' },
    crypto: { title: 'Crypto Wallet Connected', desc: 'A custom Web3 payment prompt will request payment in BTC/ETH equivalent value.' }
  };

  paymentButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      // Toggle active states
      paymentButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const selectedPayment = btn.getAttribute('data-payment');
      const info = paymentNames[selectedPayment];

      // Reveal and populate payment notification card
      paymentNotification.classList.remove('hidden');
      paymentStatusTitle.textContent = info.title;
      paymentStatusDesc.textContent = info.desc;
    });
  });

  // Upgrade Actions
  const upgradeProBtn = document.getElementById('upgrade-pro-btn');
  if (upgradeProBtn) {
    upgradeProBtn.addEventListener('click', () => {
      const activePaymentEl = document.querySelector('#payment-selector .selector-btn.active');
      const activeCurrencyEl = document.querySelector('#currency-selector .selector-btn.active');
      const paymentMethod = activePaymentEl ? activePaymentEl.textContent.trim() : 'Credit Card';
      const currency = activeCurrencyEl ? activeCurrencyEl.getAttribute('data-currency') : 'USD';
      const priceVal = currencyPrices[currency].proPrice;
      const symbol = currencyPrices[currency].symbol;

      alert(`Redirecting to secure ${paymentMethod} checkout page for Pro Subscription (${symbol}${priceVal}/month)...`);
    });
  }

  const contactSalesBtn = document.getElementById('contact-sales-btn');
  if (contactSalesBtn) {
    contactSalesBtn.addEventListener('click', () => {
      alert("Redirecting to help desk connection portal to customize your plan...");
    });
  }

  // ==========================================
  // 5. SECRET KEYS MANAGER WORKFLOW (MULTI-LLM)
  // ==========================================
  const llmProviderSelect = document.getElementById('llm-provider-select');
  const userApiKeyInput = document.getElementById('user-api-key-input');
  const llmModelInput = document.getElementById('llm-model-input');
  const customBaseUrlInput = document.getElementById('custom-base-url-input');
  const customBaseUrlGroup = document.getElementById('custom-base-url-group');
  const toggleKeyVisibilityBtn = document.getElementById('toggle-key-visibility-btn');
  const saveKeyBtn = document.getElementById('save-key-btn');
  const testKeyBtn = document.getElementById('test-key-btn');
  const clearKeyBtn = document.getElementById('clear-key-btn');
  const keyStatusDot = document.getElementById('key-status-dot');
  const keyStatusTitle = document.getElementById('key-status-title');
  const keyStatusDesc = document.getElementById('key-status-desc');

  const providerDefaults = {
    google: { label: 'Google Gemini API Key', placeholder: 'gemini-2.5-flash' },
    openai: { label: 'OpenAI API Key', placeholder: 'gpt-4o-mini' },
    anthropic: { label: 'Anthropic Claude API Key', placeholder: 'claude-3-5-sonnet-20241022' },
    groq: { label: 'Groq Cloud API Key', placeholder: 'llama-3.3-70b-versatile' },
    custom: { label: 'Custom API Key (Optional)', placeholder: 'my-custom-model-name' }
  };

  function updateProviderUI() {
    const provider = llmProviderSelect ? llmProviderSelect.value : 'google';
    const info = providerDefaults[provider] || providerDefaults.google;

    const keyLabel = document.getElementById('key-label');
    if (keyLabel) keyLabel.textContent = info.label;
    if (llmModelInput) llmModelInput.placeholder = `e.g. ${info.placeholder}`;

    if (provider === 'custom') {
      if (customBaseUrlGroup) customBaseUrlGroup.classList.remove('hidden');
    } else {
      if (customBaseUrlGroup) customBaseUrlGroup.classList.add('hidden');
    }
  }

  function updateKeyStatusUI() {
    const provider = localStorage.getItem('securityhelpdesk_llm_provider') || 'google';
    const savedKey = localStorage.getItem('securityhelpdesk_user_api_key') || '';
    const savedModel = localStorage.getItem('securityhelpdesk_llm_model') || '';
    const savedUrl = localStorage.getItem('securityhelpdesk_base_url') || '';
    const sidebarAgentText = document.getElementById('sidebar-agent-text') || document.querySelector('.mode-text');
    const sidebarAgentDot = document.getElementById('sidebar-agent-dot') || document.querySelector('.badge-dot');

    if (llmProviderSelect) llmProviderSelect.value = provider;
    if (userApiKeyInput) userApiKeyInput.value = savedKey;
    if (llmModelInput) llmModelInput.value = savedModel;
    if (customBaseUrlInput) customBaseUrlInput.value = savedUrl;

    updateProviderUI();

    const providerDisplayNames = {
      google: 'GEMINI',
      openai: 'OPENAI',
      anthropic: 'CLAUDE',
      groq: 'GROQ',
      custom: 'CUSTOM LLM'
    };

    if ((savedKey && savedKey.trim()) || provider === 'custom') {
      const activeProviderName = providerDisplayNames[provider] || provider.toUpperCase();
      const activeModel = (savedModel && savedModel.trim()) ? savedModel.trim().toUpperCase() : (providerDefaults[provider]?.placeholder || 'DEFAULT').toUpperCase();

      if (keyStatusDot) keyStatusDot.className = 'key-status-dot active';
      if (keyStatusTitle) keyStatusTitle.textContent = `Provider Configured: ${activeProviderName}`;
      if (keyStatusDesc) keyStatusDesc.textContent = `Scans will route via ${activeProviderName} using model [${activeModel}].`;

      if (sidebarAgentText) {
        sidebarAgentText.textContent = `AI: ${activeProviderName} (${activeModel})`;
      }
      if (sidebarAgentDot) {
        sidebarAgentDot.style.backgroundColor = '#10b981';
        sidebarAgentDot.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.6)';
      }
    } else {
      if (keyStatusDot) keyStatusDot.className = 'key-status-dot warning';
      if (keyStatusTitle) keyStatusTitle.textContent = 'No Custom Key Configured';
      if (keyStatusDesc) keyStatusDesc.textContent = 'Operating with server default Gemini environment or simulation engine.';

      if (sidebarAgentText) {
        sidebarAgentText.textContent = 'AI ENGINE: SERVER DEFAULT';
      }
      if (sidebarAgentDot) {
        sidebarAgentDot.style.backgroundColor = '#f59e0b';
        sidebarAgentDot.style.boxShadow = '0 0 8px rgba(245, 158, 11, 0.6)';
      }
    }
  }

  if (llmProviderSelect) {
    llmProviderSelect.addEventListener('change', updateProviderUI);
  }

  if (toggleKeyVisibilityBtn) {
    toggleKeyVisibilityBtn.addEventListener('click', () => {
      if (userApiKeyInput.type === 'password') {
        userApiKeyInput.type = 'text';
        toggleKeyVisibilityBtn.textContent = 'Hide';
      } else {
        userApiKeyInput.type = 'password';
        toggleKeyVisibilityBtn.textContent = 'Show';
      }
    });
  }

  if (saveKeyBtn) {
    saveKeyBtn.addEventListener('click', () => {
      const provider = llmProviderSelect.value;
      const keyVal = userApiKeyInput.value.trim();
      const modelVal = llmModelInput.value.trim();
      const urlVal = customBaseUrlInput.value.trim();

      if (provider !== 'custom' && !keyVal) {
        alert(`Please enter a valid API key for ${provider.toUpperCase()} before saving.`);
        return;
      }

      localStorage.setItem('securityhelpdesk_llm_provider', provider);
      localStorage.setItem('securityhelpdesk_user_api_key', keyVal);
      localStorage.setItem('securityhelpdesk_llm_model', modelVal);
      localStorage.setItem('securityhelpdesk_base_url', urlVal);

      updateKeyStatusUI();
      alert(`LLM Configuration for ${provider.toUpperCase()} saved successfully.`);
    });
  }

  if (clearKeyBtn) {
    clearKeyBtn.addEventListener('click', () => {
      localStorage.removeItem('securityhelpdesk_llm_provider');
      localStorage.removeItem('securityhelpdesk_user_api_key');
      localStorage.removeItem('securityhelpdesk_llm_model');
      localStorage.removeItem('securityhelpdesk_base_url');

      updateKeyStatusUI();
      alert('LLM Configuration reset to defaults.');
    });
  }

  if (testKeyBtn) {
    testKeyBtn.addEventListener('click', async () => {
      const provider = llmProviderSelect.value;
      const keyVal = userApiKeyInput.value.trim();
      const modelVal = llmModelInput.value.trim();
      const urlVal = customBaseUrlInput.value.trim();

      if (provider !== 'custom' && !keyVal) {
        alert(`Please enter an API key for ${provider.toUpperCase()} to test.`);
        return;
      }

      if (keyStatusDot) keyStatusDot.className = 'key-status-dot warning';
      if (keyStatusTitle) keyStatusTitle.textContent = `Validating ${provider.toUpperCase()} Connection...`;
      if (keyStatusDesc) keyStatusDesc.textContent = `Sending test completion prompt to ${provider.toUpperCase()} endpoint...`;

      try {
        const response = await fetch('/api/test-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: provider,
            apiKey: keyVal,
            modelName: modelVal,
            baseUrl: urlVal
          })
        });
        const res = await response.json();
        if (res.valid) {
          if (keyStatusDot) keyStatusDot.className = 'key-status-dot active';
          if (keyStatusTitle) keyStatusTitle.textContent = 'Connection Verified';
          if (keyStatusDesc) keyStatusDesc.textContent = res.message;
        } else {
          if (keyStatusDot) keyStatusDot.className = 'key-status-dot error';
          if (keyStatusTitle) keyStatusTitle.textContent = 'Validation Failed';
          if (keyStatusDesc) keyStatusDesc.textContent = res.message;
        }
      } catch (err) {
        if (keyStatusDot) keyStatusDot.className = 'key-status-dot error';
        if (keyStatusTitle) keyStatusTitle.textContent = 'Test Network Error';
        if (keyStatusDesc) keyStatusDesc.textContent = err.message;
      }
    });
  }

  // ==========================================
  // UTILITY: FILE DOWNLOAD
  // ==========================================
  function triggerFileDownload(filename, textContent, mimeType = 'text/plain') {
    const blob = new Blob([textContent], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'security_export.txt';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  // ==========================================
  // 6. SBOM ANALYZER WORKFLOW
  // ==========================================
  const loadPythonSbomBtn = document.getElementById('load-python-sbom-btn');
  const loadNodeSbomBtn = document.getElementById('load-node-sbom-btn');
  const sbomForm = document.getElementById('sbom-audit-form');
  const sbomInput = document.getElementById('sbom-manifest-input');
  const sbomPlaceholder = document.getElementById('sbom-placeholder');
  const sbomResultsArea = document.getElementById('sbom-results-area');
  const sbomTotalCount = document.getElementById('sbom-total-count');
  const sbomVulnCount = document.getElementById('sbom-vuln-count');
  const sbomRiskStatus = document.getElementById('sbom-risk-status');
  const sbomVulnList = document.getElementById('sbom-vuln-list');
  const sbomCleanList = document.getElementById('sbom-clean-list');

  const samplePythonSbom = `# Production Microservices Manifest
fastapi>=0.110.0
uvicorn>=0.28.0
log4j==2.14.1
requests==2.25.1
urllib3==1.26.4
aiohttp==3.8.1
paramiko==2.7.2
pillow==9.5.0
beautifulsoup4>=4.12.0
python-dotenv>=1.0.1`;

  const sampleNodeSbom = `{
  "name": "enterprise-backend",
  "version": "2.4.0",
  "dependencies": {
    "express": "^4.17.1",
    "axios": "^1.4.0",
    "jsonwebtoken": "^8.5.1",
    "lodash": "^4.17.19",
    "moment": "^2.29.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}`;

  if (loadPythonSbomBtn && sbomInput) {
    loadPythonSbomBtn.addEventListener('click', () => {
      sbomInput.value = samplePythonSbom;
    });
  }

  if (loadNodeSbomBtn && sbomInput) {
    loadNodeSbomBtn.addEventListener('click', () => {
      sbomInput.value = sampleNodeSbom;
    });
  }

  if (sbomForm) {
    sbomForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const manifest = sbomInput.value.trim();
      if (!manifest) return;

      if (sbomPlaceholder) sbomPlaceholder.classList.add('hidden');
      if (sbomResultsArea) sbomResultsArea.classList.remove('hidden');

      if (sbomRiskStatus) {
        sbomRiskStatus.textContent = 'AUDITING...';
        sbomRiskStatus.className = 'metric-badge';
      }

      if (sbomVulnList) {
        sbomVulnList.innerHTML = `
          <div class="placeholder-loader">
            <div class="spinner"></div>
            <p>Correlating dependency graph with CISA KEV and CVE catalogs...</p>
          </div>
        `;
      }

      try {
        const response = await fetch('/api/sbom/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ manifest })
        });
        if (!response.ok) throw new Error('SBOM server audit failed');
        const data = await response.json();

        if (sbomTotalCount) sbomTotalCount.textContent = data.totalDependencies;
        if (sbomVulnCount) sbomVulnCount.textContent = data.vulnerableCount;

        if (sbomRiskStatus) {
          sbomRiskStatus.textContent = data.riskLevel;
          if (data.riskLevel === 'CRITICAL') sbomRiskStatus.className = 'metric-badge critical';
          else if (data.riskLevel === 'HIGH') sbomRiskStatus.className = 'metric-badge high';
          else sbomRiskStatus.className = 'metric-badge';
        }

        // Render Vulnerabilities
        if (sbomVulnList) {
          if (data.matchedVulnerabilities && data.matchedVulnerabilities.length > 0) {
            sbomVulnList.innerHTML = data.matchedVulnerabilities.map(v => `
              <div class="sbom-vuln-item">
                <div class="sbom-vuln-header">
                  <span class="sbom-pkg-name">${v.package} (installed: <code>${v.version}</code>)</span>
                  <span class="badge ${v.severity === 'CRITICAL' ? 'red' : 'orange'}">${v.severity}</span>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-white); font-weight: 600; margin-bottom: 4px;">
                  ${v.cveId}: ${v.title}
                </div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 6px;">
                  Constraint: ${v.affectedConstraint} &bull; CISA KEV: <strong>${v.cisaKev ? 'YES 🚨' : 'No'}</strong> &bull; Source: ${v.source}
                </div>
                <div style="font-size: 0.82rem; color: #38bdf8; background: rgba(56, 189, 248, 0.08); padding: 6px 10px; border-radius: 4px;">
                  <strong>Remediation:</strong> ${v.remediation}
                </div>
              </div>
            `).join('');
          } else {
            sbomVulnList.innerHTML = `
              <div style="padding: 20px; text-align: center; color: #6ee7b7; background: rgba(16, 185, 129, 0.08); border-radius: 8px;">
                ✓ All parsed dependencies are clean. No matched vulnerabilities or CISA KEV zero-days identified.
              </div>
            `;
          }
        }

        // Render Clean Packages
        if (sbomCleanList) {
          if (data.cleanDependencies && data.cleanDependencies.length > 0) {
            sbomCleanList.innerHTML = data.cleanDependencies.map(pkg => `
              <span class="clean-chip">✓ ${pkg}</span>
            `).join('');
          } else {
            sbomCleanList.innerHTML = `<span style="font-size: 0.8rem; color: var(--text-muted);">None</span>`;
          }
        }

      } catch (err) {
        if (sbomVulnList) {
          sbomVulnList.innerHTML = `<div style="color: #ef4444; padding: 20px;">Error running SBOM audit: ${err.message}</div>`;
        }
      }
    });
  }

  // ==========================================
  // 7. WEBHOOK DISPATCH WORKFLOW
  // ==========================================
  const webhookPlatformSelect = document.getElementById('webhook-platform-select');
  const webhookUrlInput = document.getElementById('webhook-url-input');
  const saveWebhookBtn = document.getElementById('save-webhook-btn');
  const testWebhookBtn = document.getElementById('test-webhook-btn');
  const webhookStatus = document.getElementById('webhook-status');

  if (webhookUrlInput) {
    webhookUrlInput.value = localStorage.getItem('securityhelpdesk_webhook_url') || '';
  }
  if (webhookPlatformSelect) {
    webhookPlatformSelect.value = localStorage.getItem('securityhelpdesk_webhook_platform') || 'slack';
  }

  if (saveWebhookBtn) {
    saveWebhookBtn.addEventListener('click', () => {
      const platform = webhookPlatformSelect.value;
      const url = webhookUrlInput.value.trim();
      localStorage.setItem('securityhelpdesk_webhook_platform', platform);
      localStorage.setItem('securityhelpdesk_webhook_url', url);
      if (webhookStatus) {
        webhookStatus.textContent = `Webhook configuration for ${platform.toUpperCase()} saved.`;
        webhookStatus.style.color = '#10b981';
      }
    });
  }

  if (testWebhookBtn) {
    testWebhookBtn.addEventListener('click', async () => {
      const platform = webhookPlatformSelect.value;
      const url = webhookUrlInput.value.trim();
      if (!url) {
        alert('Please specify a webhook URL first.');
        return;
      }

      if (webhookStatus) {
        webhookStatus.textContent = `Dispatching test security alert to ${platform.toUpperCase()}...`;
        webhookStatus.style.color = '#f59e0b';
      }

      try {
        const res = await fetch('/api/send-webhook', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            webhookUrl: url,
            platform: platform,
            alertData: {
              title: "Test Security Alert: Critical Vulnerability Simulation",
              cveId: "CVE-2024-TEST",
              severity: "CRITICAL",
              executiveSummary: "This is an automated verification alert from the SECURITYHELPDESK Autonomous Security Platform."
            }
          })
        });
        const resData = await res.json();
        if (webhookStatus) {
          webhookStatus.textContent = resData.message;
          webhookStatus.style.color = resData.success ? '#10b981' : '#f59e0b';
        }
      } catch (err) {
        if (webhookStatus) {
          webhookStatus.textContent = 'Network error sending webhook: ' + err.message;
          webhookStatus.style.color = '#ef4444';
        }
      }
    });
  }

  // Initialize Key Status on startup
  updateKeyStatusUI();

  // Load Ingestion Feed automatically on boot
  loadThreatFeeds();
});
