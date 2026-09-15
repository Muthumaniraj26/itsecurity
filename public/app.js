/**
 * Security Intelligence - Enterprise AI Threat Operations Platform
 * Vanilla JavaScript Controller (No frameworks, strictly standard Web APIs)
 * Zero Emojis - Semantic UI - Resilient Backend Integration
 */

document.addEventListener('DOMContentLoaded', () => {

  // ==========================================================================
  // GLOBAL APPLICATION STATE
  // ==========================================================================
  let currentUser = null;
  let authToken = localStorage.getItem('secintel_auth_token') || null;
  let activeView = 'home';
  let threatFeeds = [];
  let selectedFeedItem = null;
  let currentAnalysisReport = null;
  let historyRecords = [];
  let savedReports = [];
  let onboardingStepIndex = 0;

  // ==========================================================================
  // AUTH & HEADERS HELPERS
  // ==========================================================================
  function getHeaders(includeAuth = true, includeLLM = false) {
    const headers = { 'Content-Type': 'application/json' };
    if (includeAuth && authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }
    if (includeLLM) {
      const provider = localStorage.getItem('secintel_llm_provider') || 'google';
      const userKey = localStorage.getItem('secintel_user_api_key');
      const modelName = localStorage.getItem('secintel_llm_model');
      const baseUrl = localStorage.getItem('secintel_base_url');

      headers['x-llm-provider'] = provider;
      if (userKey && userKey.trim()) headers['x-api-key'] = userKey.trim();
      if (modelName && modelName.trim()) headers['x-llm-model'] = modelName.trim();
      if (baseUrl && baseUrl.trim()) headers['x-base-url'] = baseUrl.trim();
    }
    return headers;
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' +
             d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return dateStr;
    }
  }

  function getInitials(name) {
    if (!name) return 'U';
    const parts = name.trim().split(' ');
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }

  function getRiskBadge(riskLevel) {
    const level = (riskLevel || 'INFORMATIONAL').toUpperCase();
    if (level === 'CRITICAL') {
      return '<span class="badge badge-critical"><span class="badge-dot"></span>CRITICAL</span>';
    } else if (level === 'HIGH' || level === 'DANGEROUS') {
      return '<span class="badge badge-high"><span class="badge-dot"></span>HIGH</span>';
    } else if (level === 'MEDIUM' || level === 'SUSPICIOUS' || level === 'LOW TRUST') {
      return '<span class="badge badge-medium"><span class="badge-dot"></span>MEDIUM</span>';
    } else if (level === 'LOW' || level === 'SAFE' || level === 'TRUSTWORTHY') {
      return '<span class="badge badge-low"><span class="badge-dot"></span>LOW</span>';
    } else {
      return '<span class="badge badge-info"><span class="badge-dot"></span>INFO</span>';
    }
  }

  // ==========================================================================
  // TOAST NOTIFICATIONS & CLIPBOARD HELPERS
  // ==========================================================================
  function showToast(message, duration = 2800) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
      <span>${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 260);
    }, duration);
  }

  function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showToast(successMsg);
      }).catch(() => {
        fallbackCopyText(text, successMsg);
      });
    } else {
      fallbackCopyText(text, successMsg);
    }
  }

  function fallbackCopyText(text, successMsg) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showToast(successMsg);
    } catch (e) {
      showToast('Copy failed');
    }
    document.body.removeChild(textarea);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function parseInlineMarkdown(str) {
    if (!str) return '';
    return str
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/__(.+?)__/g, '<strong>$1</strong>')
      .replace(/(^|[^\*])\*([^\*\n]+)\*([^\*]|$)/g, '$1<em>$2</em>$3')
      .replace(/(^|[^_])_([^_\n]+)_([^_]|$)/g, '$1<em>$2</em>$3');
  }

  function formatMarkdownResponse(raw) {
    if (!raw) return '';

    // Normalize newlines
    let text = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    // 1. Break major section headers into their own lines
    text = text.replace(/([^\n])\s*(\*\*(?:Explanation|Threat Summary|Actionable Guidance|Next Steps|Key Takeaways|Remediation Steps|Exposure Analysis|Mitigation Plan|Impact Analysis|Target Infrastructure|Recommendations?|Perimeter Defense|Log Review|Network Traffic Analysis|Credential Revocation|Legal & Privacy Notification):\*\*)/gi, '$1\n\n$2\n');

    // 2. Clean double asterisks bullets
    text = text.replace(/\*\s+\*\s+/g, '* ');

    // 3. Break bullet items that are stuck to prior sentences or colons
    text = text.replace(/([.:?!])\s+\*\s+/g, '$1\n* ');
    text = text.replace(/([^\n])\s+(\*\s+\*\*)/g, '$1\n* **');

    // 4. Break numbered items stuck to prior sentences or colons
    text = text.replace(/([.:?!])\s+(\d+\.)\s+/g, '$1\n$2 ');
    text = text.replace(/([^\n])\s+(\d+\.\s+\*\*)/g, '$1\n$2');

    // 5. Clean redundant standalone bullet markers
    text = text.replace(/^\s*\*\s*$/gm, '');
    text = text.replace(/^\s*\d+\.\s*$/gm, '');

    // 4. Extract code blocks
    const codeBlocks = [];
    text = text.replace(/```([a-zA-Z0-9_\-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      const idx = codeBlocks.length;
      const safeCode = escapeHtml(code);
      codeBlocks.push(`<pre class="chat-code-block"><code class="language-${lang || 'text'}">${safeCode}</code></pre>`);
      return `__CODE_BLOCK_${idx}__`;
    });

    // 5. Inline code
    text = text.replace(/`([^`\n]+)`/g, (m, c) => {
      return `<code>${escapeHtml(c)}</code>`;
    });

    const lines = text.split('\n');
    let html = '';
    let inUl = false;
    let inOl = false;
    let inBlockquote = false;

    const closeLists = () => {
      if (inUl) { html += '</ul>'; inUl = false; }
      if (inOl) { html += '</ol>'; inOl = false; }
      if (inBlockquote) { html += '</blockquote>'; inBlockquote = false; }
    };

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line) {
        closeLists();
        continue;
      }

      // Check code block token
      if (line.startsWith('__CODE_BLOCK_') && line.endsWith('__')) {
        closeLists();
        const codeIdx = parseInt(line.replace('__CODE_BLOCK_', '').replace('__', ''), 10);
        html += codeBlocks[codeIdx] || '';
        continue;
      }

      // Markdown Headers: #, ##, ###, ####
      const headerMatch = line.match(/^(#{1,6})\s+(.*)$/);
      if (headerMatch) {
        closeLists();
        const level = Math.min(Math.max(headerMatch[1].length, 4), 5);
        html += `<h${level}>${parseInlineMarkdown(headerMatch[2])}</h${level}>`;
        continue;
      }

      // Section bold headers e.g. "**Explanation:**" or "**Actionable Guidance:**"
      const sectionMatch = line.match(/^(\*\*(?:Explanation|Threat Summary|Actionable Guidance|Next Steps|Key Takeaways|Remediation Steps|Exposure Analysis|Mitigation Plan|Impact Analysis|Target Infrastructure|Recommendations?):\*\*)\s*(.*)$/i);
      if (sectionMatch) {
        closeLists();
        const title = parseInlineMarkdown(sectionMatch[1]);
        const remainder = sectionMatch[2] ? parseInlineMarkdown(sectionMatch[2]) : '';
        html += `<h4>${title}</h4>`;
        if (remainder) {
          html += `<p>${remainder}</p>`;
        }
        continue;
      }

      // Blockquote: > quote
      if (line.startsWith('>')) {
        if (inUl || inOl) closeLists();
        if (!inBlockquote) { html += '<blockquote>'; inBlockquote = true; }
        html += `<p>${parseInlineMarkdown(line.substring(1).trim())}</p>`;
        continue;
      } else if (inBlockquote) {
        html += '</blockquote>';
        inBlockquote = false;
      }

      // Unordered list item: * or -
      const ulMatch = line.match(/^[\*\-]\s+(.*)$/);
      if (ulMatch) {
        if (inOl) { html += '</ol>'; inOl = false; }
        if (!inUl) { html += '<ul>'; inUl = true; }
        html += `<li>${parseInlineMarkdown(ulMatch[1])}</li>`;
        continue;
      }

      // Ordered list item: 1. or 2.
      const olMatch = line.match(/^(\d+)\.\s+(.*)$/);
      if (olMatch) {
        if (inUl) { html += '</ul>'; inUl = false; }
        if (!inOl) { html += '<ol>'; inOl = true; }
        html += `<li>${parseInlineMarkdown(olMatch[2])}</li>`;
        continue;
      }

      // Regular paragraph
      closeLists();
      html += `<p>${parseInlineMarkdown(line)}</p>`;
    }

    closeLists();
    return html;
  }

  // ==========================================================================
  // NAVIGATION & VIEW SWITCHER (NON-BLOCKING & RESILIENT)
  // ==========================================================================
  const allPageViews = document.querySelectorAll('.page-view');
  const allNavLinks = document.querySelectorAll('.nav-link');
  const publicNavContainer = document.getElementById('public-nav-links');
  const authNavContainer = document.getElementById('auth-nav-links');
  const publicActionsContainer = document.getElementById('public-actions');
  const authActionsContainer = document.getElementById('auth-actions');
  const mobileToggleBtn = document.getElementById('mobile-toggle-btn');
  const mainNav = document.getElementById('main-nav');

  function navigateTo(viewId) {
    activeView = viewId;

    // Toggle active view instantaneously
    allPageViews.forEach(view => {
      if (view.id === `view-${viewId}`) {
        view.classList.add('active');
      } else {
        view.classList.remove('active');
      }
    });

    // Update nav links active state
    allNavLinks.forEach(link => {
      if (link.getAttribute('data-view') === viewId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Close mobile nav drawer if open
    if (mainNav) mainNav.classList.remove('mobile-open');

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Handle view-specific non-blocking background initializations
    if (viewId === 'dashboard') {
      loadDashboardData();
    } else if (viewId === 'history') {
      loadHistoryRecords();
    } else if (viewId === 'reports') {
      loadSavedReports();
    } else if (viewId === 'settings') {
      populateSettingsProfile();
    } else if (viewId === 'tools') {
      // If no tool pane is currently visible, activate default threat pane
      const visiblePane = document.querySelector('#view-tools .tool-pane:not(.hidden)');
      if (!visiblePane) {
        activateToolPane('pane-threat');
      }
      if (threatFeeds.length === 0) {
        loadThreatFeeds(false);
      }
    }
  }

  // Universal helper for button actions (handles both views and tool shortcuts)
  function switchView(target) {
    if (target === 'threats' || target === 'threat_digest') {
      navigateTo('tools');
      activateToolPane('pane-threat');
    } else if (target === 'phishing' || target === 'url') {
      navigateTo('tools');
      activateToolPane('pane-url');
    } else if (target === 'scam' || target === 'scam_detector') {
      navigateTo('tools');
      activateToolPane('pane-scam');
    } else if (target === 'sbom' || target === 'dependencies') {
      navigateTo('tools');
      activateToolPane('pane-sbom');
    } else if (target === 'llm' || target === 'gateway') {
      navigateTo('tools');
      activateToolPane('pane-llm');
    } else {
      navigateTo(target);
    }
  }

  // Bind Navigation link buttons
  allNavLinks.forEach(link => {
    link.addEventListener('click', () => {
      const targetView = link.getAttribute('data-view');
      if (targetView) navigateTo(targetView);
    });
  });

  // Mobile menu toggle
  if (mobileToggleBtn && mainNav) {
    mobileToggleBtn.addEventListener('click', () => {
      mainNav.classList.toggle('mobile-open');
    });
  }

  // Brand button navigation
  const brandBtn = document.getElementById('nav-brand-btn');
  if (brandBtn) {
    brandBtn.addEventListener('click', () => {
      navigateTo(currentUser ? 'dashboard' : 'home');
    });
  }

  // Header login / register buttons
  const btnGotoLogin = document.getElementById('btn-goto-login');
  const btnGotoRegister = document.getElementById('btn-goto-register');
  const linkToRegister = document.getElementById('link-to-register');
  const linkToLogin = document.getElementById('link-to-login');
  const btnGotoSettings = document.getElementById('btn-goto-settings');
  const heroGetStartedBtn = document.getElementById('hero-get-started-btn');
  const heroExploreToolsBtn = document.getElementById('hero-explore-tools-btn');
  const btnDashboardNewAnalysis = document.getElementById('btn-dashboard-new-analysis');
  const btnViewAllHistory = document.getElementById('btn-view-all-history');

  if (btnGotoLogin) btnGotoLogin.addEventListener('click', () => navigateTo('login'));
  if (btnGotoRegister) btnGotoRegister.addEventListener('click', () => navigateTo('register'));
  if (linkToRegister) linkToRegister.addEventListener('click', (e) => { e.preventDefault(); navigateTo('register'); });
  if (linkToLogin) linkToLogin.addEventListener('click', (e) => { e.preventDefault(); navigateTo('login'); });
  if (btnGotoSettings) btnGotoSettings.addEventListener('click', () => navigateTo('settings'));
  if (heroGetStartedBtn) heroGetStartedBtn.addEventListener('click', () => navigateTo(currentUser ? 'dashboard' : 'register'));
  if (heroExploreToolsBtn) heroExploreToolsBtn.addEventListener('click', () => navigateTo('tools'));
  if (btnDashboardNewAnalysis) btnDashboardNewAnalysis.addEventListener('click', () => navigateTo('tools'));
  if (btnViewAllHistory) btnViewAllHistory.addEventListener('click', () => navigateTo('history'));

  // Footer Navigation links
  document.querySelectorAll('[data-footer-nav]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = link.getAttribute('data-footer-nav');
      if (target) navigateTo(target);
    });
  });

  // Capability cards navigation
  document.querySelectorAll('.capability-card').forEach(card => {
    card.addEventListener('click', () => {
      const toolPane = card.getAttribute('data-action-tool');
      const targetView = card.getAttribute('data-action-view');
      if (toolPane) {
        navigateTo('tools');
        activateToolPane(toolPane);
      } else if (targetView) {
        navigateTo(targetView);
      }
    });
  });

  // Switch tool buttons
  document.querySelectorAll('[data-switch-tool]').forEach(btn => {
    btn.addEventListener('click', () => {
      const tool = btn.getAttribute('data-switch-tool');
      navigateTo('tools');
      if (tool === 'phishing') activateToolPane('pane-url');
      else if (tool === 'scam') activateToolPane('pane-scam');
      else if (tool === 'threats') activateToolPane('pane-threat');
    });
  });

  function updateAuthStateUI() {
    if (currentUser) {
      if (publicNavContainer) publicNavContainer.classList.add('hidden');
      if (authNavContainer) authNavContainer.classList.remove('hidden');
      if (publicActionsContainer) publicActionsContainer.classList.add('hidden');
      if (authActionsContainer) authActionsContainer.classList.remove('hidden');

      const nameEl = document.getElementById('nav-user-name');
      const avatarEl = document.getElementById('nav-user-avatar');
      if (nameEl) nameEl.textContent = currentUser.name;
      if (avatarEl) avatarEl.textContent = getInitials(currentUser.name);
    } else {
      if (publicNavContainer) publicNavContainer.classList.remove('hidden');
      if (authNavContainer) authNavContainer.classList.add('hidden');
      if (publicActionsContainer) publicActionsContainer.classList.remove('hidden');
      if (authActionsContainer) authActionsContainer.classList.add('hidden');
    }
  }

  // ==========================================================================
  // AUTHENTICATION LOGIC (USER STORE API)
  // ==========================================================================
  async function checkSession() {
    if (!authToken) {
      updateAuthStateUI();
      if (['dashboard', 'history', 'reports', 'settings'].includes(activeView)) {
        navigateTo('home');
      }
      return;
    }

    try {
      const res = await fetch('/api/user/me', {
        headers: getHeaders(true, false)
      });
      if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        updateAuthStateUI();
        if (activeView === 'login' || activeView === 'register') {
          navigateTo('dashboard');
        }

        // Check if onboarding is needed
        if (currentUser && !currentUser.onboardingCompleted) {
          startOnboarding();
        }
      } else {
        // Token invalid or expired
        localStorage.removeItem('secintel_auth_token');
        authToken = null;
        currentUser = null;
        updateAuthStateUI();
        if (['dashboard', 'history', 'reports', 'settings'].includes(activeView)) {
          navigateTo('home');
        }
      }
    } catch (e) {
      updateAuthStateUI();
      if (['dashboard', 'history', 'reports', 'settings'].includes(activeView)) {
        navigateTo('home');
      }
    }
  }

  // Sign In Form Submission
  const formLogin = document.getElementById('form-login');
  const loginAlert = document.getElementById('login-alert');
  const loginAlertText = document.getElementById('login-alert-text');

  if (formLogin) {
    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;

      if (loginAlert) loginAlert.classList.add('hidden');

      try {
        const res = await fetch('/api/user/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Sign in failed. Please verify credentials.');
        }

        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('secintel_auth_token', authToken);

        formLogin.reset();
        updateAuthStateUI();
        navigateTo('dashboard');

        if (!currentUser.onboardingCompleted) {
          startOnboarding();
        }
      } catch (err) {
        if (loginAlert && loginAlertText) {
          loginAlertText.textContent = err.message;
          loginAlert.classList.remove('hidden');
        }
      }
    });
  }

  // Registration Form Submission
  const formRegister = document.getElementById('form-register');
  const registerAlert = document.getElementById('register-alert');
  const registerAlertText = document.getElementById('register-alert-text');

  if (formRegister) {
    formRegister.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;
      const passwordConfirm = document.getElementById('reg-password-confirm').value;

      if (registerAlert) registerAlert.classList.add('hidden');

      if (password !== passwordConfirm) {
        if (registerAlert && registerAlertText) {
          registerAlertText.textContent = 'Passwords do not match.';
          registerAlert.classList.remove('hidden');
        }
        return;
      }

      try {
        const res = await fetch('/api/user/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Registration could not be completed.');
        }

        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('secintel_auth_token', authToken);

        formRegister.reset();
        updateAuthStateUI();
        navigateTo('dashboard');
        startOnboarding();
      } catch (err) {
        if (registerAlert && registerAlertText) {
          registerAlertText.textContent = err.message;
          registerAlert.classList.remove('hidden');
        }
      }
    });
  }

  // Logout
  const btnLogout = document.getElementById('btn-logout');
  const btnSettingsSignout = document.getElementById('btn-settings-signout');

  async function handleLogout() {
    try {
      if (authToken) {
        await fetch('/api/user/logout', {
          method: 'POST',
          headers: getHeaders(true, false)
        });
      }
    } catch (e) {}

    localStorage.removeItem('secintel_auth_token');
    authToken = null;
    currentUser = null;
    updateAuthStateUI();
    navigateTo('home');
  }

  if (btnLogout) btnLogout.addEventListener('click', handleLogout);
  if (btnSettingsSignout) btnSettingsSignout.addEventListener('click', handleLogout);

  // Change Password Form
  const formChangePassword = document.getElementById('form-change-password');
  const passwordAlert = document.getElementById('password-alert');
  const passwordAlertText = document.getElementById('password-alert-text');

  if (formChangePassword) {
    formChangePassword.addEventListener('submit', async (e) => {
      e.preventDefault();
      const currentPassword = document.getElementById('input-current-password').value;
      const newPassword = document.getElementById('input-new-password').value;
      const confirmPassword = document.getElementById('input-confirm-password').value;

      if (passwordAlert) passwordAlert.classList.add('hidden');

      if (newPassword !== confirmPassword) {
        if (passwordAlert && passwordAlertText) {
          passwordAlertText.textContent = 'New passwords do not match.';
          passwordAlert.classList.remove('hidden');
        }
        return;
      }

      try {
        const res = await fetch('/api/user/change-password', {
          method: 'POST',
          headers: getHeaders(true, false),
          body: JSON.stringify({ currentPassword, newPassword })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to update password.');

        formChangePassword.reset();
        alert('Password updated successfully.');
      } catch (err) {
        if (passwordAlert && passwordAlertText) {
          passwordAlertText.textContent = err.message;
          passwordAlert.classList.remove('hidden');
        }
      }
    });
  }

  function populateSettingsProfile() {
    if (!currentUser) return;
    const nameInput = document.getElementById('settings-profile-name');
    const emailInput = document.getElementById('settings-profile-email');
    const createdInput = document.getElementById('settings-profile-created');
    if (nameInput) nameInput.value = currentUser.name || '';
    if (emailInput) emailInput.value = currentUser.email || '';
    if (createdInput) createdInput.value = formatDateTime(currentUser.createdAt);
  }

  // ==========================================================================
  // FIRST-TIME ONBOARDING EXPERIENCE
  // ==========================================================================
  const modalOnboarding = document.getElementById('modal-onboarding');
  const onboardingBody = document.getElementById('onboarding-body');
  const onboardingIndicator = document.getElementById('onboarding-indicator');
  const btnOnboardingPrev = document.getElementById('btn-onboarding-prev');
  const btnOnboardingNext = document.getElementById('btn-onboarding-next');
  const btnSkipOnboarding = document.getElementById('btn-skip-onboarding');

  const onboardingSteps = [
    {
      title: 'Welcome to Security Intelligence',
      content: `
        <p style="font-size: 0.95rem; line-height: 1.6; color: var(--text-secondary); margin-bottom: 12px;">
          Security Intelligence is an enterprise AI operations console for automated threat telemetry, zero-day correlation, and web safety inspection.
        </p>
        <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.5;">
          The platform operates strictly on empirical evidence, ensuring full explainability behind risk scores and vulnerability assessments.
        </p>
      `
    },
    {
      title: 'Available Security Tools',
      content: `
        <div style="display: flex; flex-direction: column; gap: 10px;">
          <div style="padding: 10px; border: 1px solid var(--border-default); border-radius: 6px;">
            <strong style="color: var(--primary-900);">URL Threat Analysis:</strong> Non-rendering phishing inspection and UCI benchmark feature extraction.
          </div>
          <div style="padding: 10px; border: 1px solid var(--border-default); border-radius: 6px;">
            <strong style="color: var(--primary-900);">Website Scam Detector:</strong> RDAP registrar age analysis, commercial claims audit, and trust score metrics.
          </div>
          <div style="padding: 10px; border: 1px solid var(--border-default); border-radius: 6px;">
            <strong style="color: var(--primary-900);">Threat Digest Hub:</strong> Real-time CISA and ZDI bulletin aggregation with CISA KEV zero-day matching.
          </div>
        </div>
      `
    },
    {
      title: 'How to Run an Analysis',
      content: `
        <p style="font-size: 0.92rem; color: var(--text-secondary); line-height: 1.6; margin-bottom: 12px;">
          Select any tool from the <strong>Tools</strong> workspace, input the target link, and click <strong>Run Analysis</strong>.
        </p>
        <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.5;">
          Execution progress transparently reports live pipeline stages: parameter collection, feature extraction, and multi-LLM synthesis.
        </p>
      `
    },
    {
      title: 'Observed Evidence vs. AI Assessment',
      content: `
        <p style="font-size: 0.92rem; color: var(--text-secondary); line-height: 1.6; margin-bottom: 12px;">
          All results are explicitly split into two dedicated sections:
        </p>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <div style="padding: 8px 12px; background-color: var(--bg-tertiary); border-radius: 4px; font-size: 0.86rem;">
            <strong>Observed Evidence:</strong> Concrete scraped parameters, SSL status, and official CVE records.
          </div>
          <div style="padding: 8px 12px; background-color: var(--primary-50); border: 1px solid var(--accent-blue-border); border-radius: 4px; font-size: 0.86rem;">
            <strong>AI Assessment:</strong> Contextual interpretation, exposure justification, and engineering action plans.
          </div>
        </div>
      `
    },
    {
      title: 'History & Saved Reports',
      content: `
        <p style="font-size: 0.92rem; color: var(--text-secondary); line-height: 1.6; margin-bottom: 12px;">
          Every completed analysis is automatically recorded to your environment database.
        </p>
        <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.5;">
          You can bookmark specific audits to your <strong>Saved Reports</strong> repository and export structured advisories in Markdown or JSON for incident documentation.
        </p>
      `
    }
  ];

  function renderOnboardingStep() {
    const step = onboardingSteps[onboardingStepIndex];
    const titleEl = document.getElementById('onboarding-title');
    if (titleEl) titleEl.textContent = step.title;
    if (onboardingBody) onboardingBody.innerHTML = step.content;

    // Update dots
    if (onboardingIndicator) {
      const dots = onboardingIndicator.querySelectorAll('.onboarding-dot');
      dots.forEach((dot, idx) => {
        if (idx === onboardingStepIndex) dot.classList.add('active');
        else dot.classList.remove('active');
      });
    }

    if (btnOnboardingPrev) {
      btnOnboardingPrev.style.visibility = onboardingStepIndex === 0 ? 'hidden' : 'visible';
    }
    if (btnOnboardingNext) {
      btnOnboardingNext.textContent = onboardingStepIndex === onboardingSteps.length - 1 ? 'Complete' : 'Next';
    }
  }

  function startOnboarding() {
    onboardingStepIndex = 0;
    if (modalOnboarding) modalOnboarding.classList.remove('hidden');
    renderOnboardingStep();
  }

  async function finishOnboarding() {
    if (modalOnboarding) modalOnboarding.classList.add('hidden');
    if (currentUser) {
      currentUser.onboardingCompleted = true;
      try {
        await fetch('/api/user/onboarding/complete', {
          method: 'POST',
          headers: getHeaders(true, false)
        });
      } catch (e) {}
    }
  }

  if (btnOnboardingNext) {
    btnOnboardingNext.addEventListener('click', () => {
      if (onboardingStepIndex < onboardingSteps.length - 1) {
        onboardingStepIndex++;
        renderOnboardingStep();
      } else {
        finishOnboarding();
      }
    });
  }

  if (btnOnboardingPrev) {
    btnOnboardingPrev.addEventListener('click', () => {
      if (onboardingStepIndex > 0) {
        onboardingStepIndex--;
        renderOnboardingStep();
      }
    });
  }

  if (btnSkipOnboarding) btnSkipOnboarding.addEventListener('click', finishOnboarding);

  // ==========================================================================
  // DASHBOARD TELEMETRY & METRICS
  // ==========================================================================
  async function loadDashboardData() {
    try {
      const res = await fetch('/api/user/history', {
        headers: getHeaders(true, false)
      });
      if (!res.ok) return;

      historyRecords = await res.json();
      const totalCount = historyRecords.length;

      let highCount = 0;
      let medCount = 0;
      let lowCount = 0;

      historyRecords.forEach(item => {
        const lvl = (item.riskLevel || '').toUpperCase();
        if (lvl === 'CRITICAL' || lvl === 'HIGH' || lvl === 'DANGEROUS') highCount++;
        else if (lvl === 'MEDIUM' || lvl === 'SUSPICIOUS' || lvl === 'LOW TRUST') medCount++;
        else lowCount++;
      });

      const totalEl = document.getElementById('metric-total-count');
      const highEl = document.getElementById('metric-high-count');
      const medEl = document.getElementById('metric-medium-count');
      const lowEl = document.getElementById('metric-low-count');

      if (totalEl) totalEl.textContent = totalCount;
      if (highEl) highEl.textContent = highCount;
      if (medEl) medEl.textContent = medCount;
      if (lowEl) lowEl.textContent = lowCount;

      renderDashboardRecent(historyRecords.slice(0, 5));
    } catch (e) {}
  }

  function renderDashboardRecent(recentItems) {
    const container = document.getElementById('dashboard-recent-container');
    if (!container) return;

    if (!recentItems || recentItems.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
          <h4 class="empty-state-title">No analyses yet</h4>
          <p class="empty-state-desc">Run your first security analysis using the tools above to populate activity telemetry.</p>
          <button type="button" class="btn btn-primary btn-sm" id="btn-empty-launch">Launch First Analysis</button>
        </div>
      `;
      const btn = document.getElementById('btn-empty-launch');
      if (btn) btn.addEventListener('click', () => { navigateTo('tools'); activateToolPane('pane-url'); });
      return;
    }

    container.innerHTML = `
      <div class="table-wrapper" style="box-shadow: none; border: none;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Target</th>
              <th>Risk Level</th>
              <th>Confidence</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            ${recentItems.map(r => `
              <tr>
                <td><strong>${r.tool}</strong></td>
                <td style="font-family: var(--font-mono); font-size: 0.82rem;">${r.target}</td>
                <td>${getRiskBadge(r.riskLevel)}</td>
                <td>${r.confidence}%</td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">${formatDateTime(r.createdAt)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // ==========================================================================
  // TOOL PANES SWITCHER
  // ==========================================================================
  const toolPaneButtons = [
    { btnId: 'tab-btn-threat', paneId: 'pane-threat' },
    { btnId: 'tab-btn-url', paneId: 'pane-url' },
    { btnId: 'tab-btn-scam', paneId: 'pane-scam' },
    { btnId: 'tab-btn-sbom', paneId: 'pane-sbom' },
    { btnId: 'tab-btn-llm', paneId: 'pane-llm' }
  ];

  function activateToolPane(targetPaneId) {
    toolPaneButtons.forEach(({ btnId, paneId }) => {
      const btn = document.getElementById(btnId);
      const pane = document.getElementById(paneId);
      if (paneId === targetPaneId) {
        if (btn) btn.classList.add('active');
        if (pane) pane.classList.remove('hidden');
      } else {
        if (btn) btn.classList.remove('active');
        if (pane) pane.classList.add('hidden');
      }
    });

    if (targetPaneId === 'pane-threat' && threatFeeds.length === 0) {
      loadThreatFeeds();
    }
  }

  toolPaneButtons.forEach(({ btnId, paneId }) => {
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.addEventListener('click', () => activateToolPane(paneId));
      btn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          activateToolPane(paneId);
        }
      });
    }
  });

  // ==========================================================================
  // TOOL 1: URL PHISHING & THREAT ANALYSIS
  // ==========================================================================
  const formScanUrl = document.getElementById('form-scan-url');
  const inputScanUrl = document.getElementById('input-scan-url');
  const urlScanStages = document.getElementById('url-scan-stages');
  const urlResultsContainer = document.getElementById('url-results-container');
  const btnClearUrl = document.getElementById('btn-clear-url');

  // Preset sample chips for URL Phishing
  document.querySelectorAll('[data-preset-url]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (inputScanUrl) {
        inputScanUrl.value = btn.getAttribute('data-preset-url');
        inputScanUrl.focus();
        showToast('Sample URL preloaded');
      }
    });
  });

  if (btnClearUrl && inputScanUrl) {
    btnClearUrl.addEventListener('click', () => {
      inputScanUrl.value = '';
      inputScanUrl.focus();
      if (urlResultsContainer) urlResultsContainer.classList.add('hidden');
    });
  }

  // Preset sample chips for Scam Detector
  document.querySelectorAll('[data-preset-scam]').forEach(btn => {
    btn.addEventListener('click', () => {
      const scamInput = document.getElementById('input-scan-scam');
      if (scamInput) {
        scamInput.value = btn.getAttribute('data-preset-scam');
        scamInput.focus();
        showToast('Sample domain preloaded');
      }
    });
  });

  function advanceUrlStages(stageNum) {
    for (let i = 1; i <= 5; i++) {
      const stageEl = document.getElementById(`url-stage-${i}`);
      if (!stageEl) continue;
      if (i < stageNum) {
        stageEl.className = 'stage-item completed';
      } else if (i === stageNum) {
        stageEl.className = 'stage-item in-progress';
      } else {
        stageEl.className = 'stage-item';
      }
    }
  }

  if (formScanUrl) {
    formScanUrl.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = inputScanUrl.value.trim();
      if (!url) return;

      if (urlScanStages) urlScanStages.classList.remove('hidden');
      if (urlResultsContainer) urlResultsContainer.classList.add('hidden');
      advanceUrlStages(1);

      try {
        advanceUrlStages(2);
        const stageTimer = setTimeout(() => advanceUrlStages(3), 600);

        const res = await fetch('/api/scan-url', {
          method: 'POST',
          headers: getHeaders(true, true),
          body: JSON.stringify({ url })
        });
        clearTimeout(stageTimer);

        advanceUrlStages(4);
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Service unavailable or analysis timed out.');
        }

        const data = await res.json();
        advanceUrlStages(5);

        // Map severity
        const prob = data.analysis.phishingProbability || 0;
        let riskLevel = 'Low';
        let uncertaintyLabel = 'No significant indicators detected';
        if (prob >= 70 || data.analysis.dangerLevel === 'Dangerous') {
          riskLevel = 'High';
          uncertaintyLabel = 'Potential Phishing (High probability)';
        } else if (prob >= 35 || data.analysis.dangerLevel === 'Suspicious') {
          riskLevel = 'Medium';
          uncertaintyLabel = 'Suspicious Link (Inconclusive indicators)';
        }

        // Auto-record analysis in user store history
        try {
          await fetch('/api/user/history', {
            method: 'POST',
            headers: getHeaders(true, false),
            body: JSON.stringify({
              tool: 'URL Phishing & Threat Analysis',
              target: url,
              riskLevel: riskLevel,
              confidence: Math.max(70, Math.min(99, prob + 15)),
              summary: data.analysis.verdictReasoning || 'URL phishing scan completed.',
              resultJson: data
            })
          });
        } catch (saveErr) {}

        // Render Results
        renderUrlResults(data, url, riskLevel, uncertaintyLabel);
        if (urlScanStages) urlScanStages.classList.add('hidden');
        if (urlResultsContainer) urlResultsContainer.classList.remove('hidden');

      } catch (err) {
        if (urlScanStages) urlScanStages.classList.add('hidden');
        if (urlResultsContainer) {
          urlResultsContainer.innerHTML = `
            <div class="error-state">
              <h4 class="error-state-title">Analysis could not be completed</h4>
              <p class="error-state-desc">${err.message}</p>
              <button type="button" class="btn btn-secondary btn-sm" style="margin-top: 12px;" onclick="document.getElementById('form-scan-url').dispatchEvent(new Event('submit'))">Retry Analysis</button>
            </div>
          `;
          urlResultsContainer.classList.remove('hidden');
        }
      }
    });
  }

  function renderUrlResults(data, targetUrl, riskLevel, uncertaintyLabel) {
    const scraped = data.scraped || {};
    const meta = scraped.pageMetadata || {};
    const domainInfo = scraped.domainInfo || {};
    const analysis = data.analysis || {};
    const mlVector = analysis.mlFeatureVector || {};

    const prob = analysis.phishingProbability || 0;
    const confidence = Math.max(70, Math.min(98, prob + 12));
    const dangerLevel = analysis.dangerLevel || (prob >= 70 ? 'Dangerous' : (prob >= 35 ? 'Suspicious' : 'Safe'));
    const meterClass = prob >= 60 ? 'critical' : (prob >= 25 ? 'medium' : 'low');

    urlResultsContainer.innerHTML = `
      <div class="results-card">
        <!-- Header Banner -->
        <div class="results-header-banner">
          <div class="target-info">
            <div class="report-badge-pill">URL Phishing &amp; Threat Analysis Report</div>
            <div class="target-url-box">
              <span class="target-url-text" id="url-target-display" title="${targetUrl}">${targetUrl}</span>
              <button type="button" class="btn-copy-target" data-copy-target="${targetUrl}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy URL
              </button>
            </div>
            <div class="results-meta-row">
              <span class="results-meta-item">Classification: <strong>${uncertaintyLabel}</strong></span>
              <span class="results-meta-item">Analyzed: <strong>${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</strong></span>
            </div>
          </div>
          <div>
            ${getRiskBadge(riskLevel)}
          </div>
        </div>

        <!-- Threat Score Meter Bar -->
        <div class="threat-meter-container">
          <div class="threat-meter-bar-wrap">
            <div class="threat-meter-labels">
              <span>PHISHING PROBABILITY GAUGE</span>
              <span><strong>${prob}%</strong> &bull; ${dangerLevel}</span>
            </div>
            <div class="threat-meter-track">
              <div class="threat-meter-fill ${meterClass}" style="width: ${Math.max(5, prob)}%;"></div>
            </div>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
            <span>EVIDENCE CONFIDENCE:</span>
            <strong style="color: var(--primary-900); font-size: 0.85rem;">${confidence}%</strong>
          </div>
        </div>

        <!-- Metric Cards -->
        <div class="results-summary-grid">
          <div class="summary-metric-box">
            <div class="label">Phishing Probability</div>
            <div class="value" style="color: ${prob >= 60 ? 'var(--severity-critical-text)' : (prob >= 25 ? 'var(--severity-high-text)' : 'var(--severity-low-text)')};">
              ${prob}%
            </div>
          </div>
          <div class="summary-metric-box">
            <div class="label">Danger Rating</div>
            <div class="value">${dangerLevel}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">Domain Age</div>
            <div class="value">${domainInfo.ageDays !== null ? `${domainInfo.ageDays} days` : 'Unknown'}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">SSL Certificate</div>
            <div class="value" style="font-size: 1.05rem;">${scraped.isHttps ? 'Valid HTTPS' : 'Insecure (HTTP)'}</div>
          </div>
        </div>

        <!-- Strict Separation: Observed Evidence vs AI Assessment -->
        <div class="analysis-dual-panel">
          
          <!-- LEFT: Observed Evidence -->
          <div class="panel-evidence">
            <div class="panel-heading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
              <span>Observed Evidence</span>
            </div>
            <table class="evidence-table">
              <tbody>
                <tr>
                  <td class="prop-name">Target Domain</td>
                  <td class="prop-val">${scraped.domain || 'N/A'}</td>
                </tr>
                <tr>
                  <td class="prop-name">Registrar</td>
                  <td class="prop-val">${domainInfo.registrar || 'Unknown'}</td>
                </tr>
                <tr>
                  <td class="prop-name">Password Input Detected</td>
                  <td class="prop-val">${meta.hasPasswordFields ? '<span style="color: var(--severity-critical-text); font-weight:600;">Yes (Credential Trap)</span>' : 'No'}</td>
                </tr>
                <tr>
                  <td class="prop-name">Outbound Links Ratio</td>
                  <td class="prop-val">${meta.externalLinks || 0} / ${meta.totalLinks || 0}</td>
                </tr>
                <tr>
                  <td class="prop-name">Short URL Service</td>
                  <td class="prop-val">${meta.isShortUrl ? '<span style="color: var(--severity-high-text);">Yes (Redirector)</span>' : 'Clean'}</td>
                </tr>
                <tr>
                  <td class="prop-name">Abnormal Form Action</td>
                  <td class="prop-val">${meta.emptyOrExternalForm ? '<span style="color: var(--severity-critical-text); font-weight:600;">Yes (External Target)</span>' : 'Clean'}</td>
                </tr>
                <tr>
                  <td class="prop-name">Hidden Iframe</td>
                  <td class="prop-val">${meta.hasIframe ? '<span style="color: var(--severity-high-text);">Yes (Overlay)</span>' : 'Clean'}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- RIGHT: AI Interpretation -->
          <div class="panel-ai">
            <div class="panel-heading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
              <span>AI Assessment &amp; Explanation</span>
            </div>
            <p class="ai-reasoning-text"><strong>Verdict Reasoning:</strong> ${analysis.verdictReasoning || 'Analysis evaluated site characteristics against phishing telemetry.'}</p>
            <p class="ai-reasoning-text"><strong>Layout &amp; DOM Check:</strong> ${analysis.visualLayoutCheck || 'No layout anomalies reported.'}</p>
            
            <div style="margin-top: 14px;">
              <strong style="font-size: 0.78rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Identified Risk Factors</strong>
              <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 8px;">
                ${analysis.riskFactors && analysis.riskFactors.length > 0
                  ? analysis.riskFactors.map(f => `<div style="font-size: 0.84rem; color: var(--severity-critical-text); background: var(--severity-critical-bg); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--severity-critical-border);">${f}</div>`).join('')
                  : `<div style="font-size: 0.84rem; color: var(--severity-low-text); background: var(--severity-low-bg); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--severity-low-border);">No critical threat indicators detected.</div>`
                }
              </div>
            </div>
          </div>

        </div>

        <!-- Recommended Actions -->
        <div style="margin-top: 24px;">
          <h4 style="font-family: var(--font-heading); font-size: 1rem; font-weight: 600; color: var(--primary-900);">Recommended Mitigation Actions</h4>
          <div class="action-plan-list">
            ${riskLevel === 'High' || prob >= 60
              ? `
                <div class="action-plan-item"><span class="action-plan-num">01</span><span>Block destination domain on corporate perimeter firewall and DNS resolvers.</span></div>
                <div class="action-plan-item"><span class="action-plan-num">02</span><span>Initiate password reset &amp; MFA session revocation for users who interacted with this destination.</span></div>
                <div class="action-plan-item"><span class="action-plan-num">03</span><span>Export structured advisory and attach to SIEM / Incident Response ticket.</span></div>
              `
              : `
                <div class="action-plan-item"><span class="action-plan-num">01</span><span>No perimeter block required. Standard telemetry logging and monitoring active.</span></div>
                <div class="action-plan-item"><span class="action-plan-num">02</span><span>Re-audit endpoint if domain WHOIS or DNS infrastructure changes.</span></div>
              `
            }
          </div>
        </div>

        <!-- Actions: Save Report & Export -->
        <div style="display: flex; gap: 12px; margin-top: 28px; padding-top: 20px; border-top: 1px solid var(--border-default); flex-wrap: wrap;">
          <button type="button" class="btn btn-primary btn-sm" id="btn-save-url-report">Save Report</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-url-md">Export Markdown</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-url-json">Export JSON</button>
        </div>
      </div>
    `;

    // Bind copy button
    urlResultsContainer.querySelectorAll('[data-copy-target]').forEach(btn => {
      btn.addEventListener('click', () => {
        const val = btn.getAttribute('data-copy-target');
        copyToClipboard(val, 'Target URL copied to clipboard!');
      });
    });

    // Bind save report button
    const btnSaveReport = document.getElementById('btn-save-url-report');
    if (btnSaveReport) {
      btnSaveReport.addEventListener('click', async () => {
        try {
          const saveRes = await fetch('/api/user/reports', {
            method: 'POST',
            headers: getHeaders(true, false),
            body: JSON.stringify({
              reportName: `URL Analysis: ${scraped.domain || targetUrl}`,
              target: targetUrl,
              riskLevel: riskLevel,
              contentJson: { scraped, analysis }
            })
          });
          if (saveRes.ok) {
            showToast('Report saved to your repository.');
            btnSaveReport.textContent = 'Report Saved';
            btnSaveReport.disabled = true;
          }
        } catch (e) {
          showToast('Could not save report: ' + e.message);
        }
      });
    }

    // Bind export buttons
    const btnExportMd = document.getElementById('btn-export-url-md');
    const btnExportJson = document.getElementById('btn-export-url-json');

    if (btnExportMd) {
      btnExportMd.addEventListener('click', async () => {
        try {
          const res = await fetch('/api/export-advisory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'phishing', format: 'markdown', scraped, analysis })
          });
          const exp = await res.json();
          downloadTextFile(exp.filename, exp.content, 'text/markdown');
          showToast('Markdown advisory downloaded.');
        } catch (e) {
          showToast('Export failed: ' + e.message);
        }
      });
    }

    if (btnExportJson) {
      btnExportJson.addEventListener('click', async () => {
        try {
          const res = await fetch('/api/export-advisory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'phishing', format: 'json', scraped, analysis })
          });
          const exp = await res.json();
          downloadTextFile(exp.filename, JSON.stringify(exp.content, null, 2), 'application/json');
          showToast('JSON telemetry downloaded.');
        } catch (e) {
          showToast('Export failed: ' + e.message);
        }
      });
    }
  }

  // ==========================================================================
  // TOOL 2: ENTERPRISE DOMAIN TARGET & WEBSITE SCAM INTELLIGENCE
  // ==========================================================================
  const formScanScam = document.getElementById('form-scan-scam');
  const inputScanScam = document.getElementById('input-scan-scam');
  const scamScanStages = document.getElementById('scam-scan-stages');
  const scamResultsContainer = document.getElementById('scam-results-container');

  // Bind Preset Buttons
  document.querySelectorAll('[data-preset-scam]').forEach(btn => {
    btn.addEventListener('click', () => {
      const presetDomain = btn.getAttribute('data-preset-scam');
      if (inputScanScam) {
        inputScanScam.value = presetDomain;
        if (formScanScam) formScanScam.dispatchEvent(new Event('submit'));
      }
    });
  });

  const btnClearScam = document.getElementById('btn-clear-scam');
  if (btnClearScam && inputScanScam) {
    btnClearScam.addEventListener('click', () => {
      inputScanScam.value = '';
      if (scamResultsContainer) scamResultsContainer.classList.add('hidden');
    });
  }

  function advanceScamStages(stageNum) {
    for (let i = 1; i <= 5; i++) {
      const stageEl = document.getElementById(`scam-stage-${i}`);
      if (!stageEl) continue;
      if (i < stageNum) {
        stageEl.className = 'sec-step-row completed';
      } else if (i === stageNum) {
        stageEl.className = 'sec-step-row in-progress';
      } else {
        stageEl.className = 'sec-step-row';
      }
    }
  }

  if (formScanScam) {
    formScanScam.addEventListener('submit', async (e) => {
      e.preventDefault();
      const domain = inputScanScam.value.trim();
      if (!domain) return;

      if (scamScanStages) scamScanStages.classList.remove('hidden');
      if (scamResultsContainer) scamResultsContainer.classList.add('hidden');
      advanceScamStages(1);

      try {
        advanceScamStages(2);
        const stageTimer3 = setTimeout(() => advanceScamStages(3), 500);
        const stageTimer4 = setTimeout(() => advanceScamStages(4), 1000);

        const res = await fetch('/api/detect-scam', {
          method: 'POST',
          headers: getHeaders(true, true),
          body: JSON.stringify({ url: domain })
        });

        clearTimeout(stageTimer3);
        clearTimeout(stageTimer4);
        advanceScamStages(5);

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Service unavailable or domain audit failed.');
        }

        const data = await res.json();

        // Auto-record analysis in user store history
        try {
          await fetch('/api/user/history', {
            method: 'POST',
            headers: getHeaders(true, false),
            body: JSON.stringify({
              tool: 'Domain Security & Scam Intelligence',
              target: data.domain || domain,
              riskLevel: data.riskLevel || 'LOW',
              confidence: data.aiReport?.confidenceScore || 90,
              summary: data.aiReport?.executiveSummary || data.threatClassification || 'Domain security audit completed.',
              resultJson: data
            })
          });
        } catch (saveErr) {}

        // Render Comprehensive Enterprise Results
        renderScamResults(data, domain);
        if (scamScanStages) scamScanStages.classList.add('hidden');
        if (scamResultsContainer) scamResultsContainer.classList.remove('hidden');

      } catch (err) {
        if (scamScanStages) scamScanStages.classList.add('hidden');
        if (scamResultsContainer) {
          scamResultsContainer.innerHTML = `
            <div class="error-state">
              <h4 class="error-state-title">Domain Security Audit Failed</h4>
              <p class="error-state-desc">${err.message}</p>
              <button type="button" class="btn btn-secondary btn-sm" style="margin-top: 12px;" onclick="document.getElementById('form-scan-scam').dispatchEvent(new Event('submit'))">Retry Audit</button>
            </div>
          `;
          scamResultsContainer.classList.remove('hidden');
        }
      }
    });
  }

  function renderScamResults(data, inputTarget) {
    const domain = data.domain || inputTarget;
    const riskScore = data.riskScore ?? 50;
    const trustScore = data.trustScore ?? (100 - riskScore);
    const riskLevel = (data.riskLevel || 'MEDIUM').toUpperCase();
    const threatClass = data.threatClassification || 'General Web Target';

    const domainInfo = data.domainIntelligence || {};
    const dnsInfo = data.dnsIntelligence || {};
    const sslInfo = data.sslIntelligence || {};
    const webSec = data.webSecurity || {};
    const emailSec = data.emailSecurity || {};
    const geoInfo = data.infrastructure || {};
    const phishingRadar = data.phishingRadar || {};
    const threatIntel = data.threatIntelligence || {};
    const contentInfo = data.contentAnalysis || {};
    const aiReport = data.aiReport || {};
    const breakdown = data.breakdown || [];
    const openPorts = data.openPorts || [];
    const subdomains = data.subdomains || [];

    // Meter class
    const meterClass = riskScore >= 70 ? 'critical' : (riskScore >= 40 ? 'warning' : 'good');

    scamResultsContainer.innerHTML = `
      <div class="results-card">
        <!-- Enterprise Header Banner -->
        <div class="domain-dossier-hero">
          <div class="domain-dossier-top">
            <div>
              <div style="font-size: 0.72rem; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 4px;">
                INTELLIGENCE TARGET DOSSIER
              </div>
              <div class="domain-target-header-title">${domain}</div>
              <div class="domain-dossier-badges">
                <span class="dossier-chip">
                  <span class="telemetry-dot-pulse" style="background: ${riskScore >= 70 ? '#ef4444' : (riskScore >= 40 ? '#f59e0b' : '#10b981')};"></span>
                  <strong>${threatClass}</strong>
                </span>
                <span class="dossier-chip">Audited: ${data.scannedAt || new Date().toLocaleTimeString()}</span>
                <span class="dossier-chip">IP: <strong>${geoInfo.ip || (dnsInfo.A && dnsInfo.A[0]) || 'Unknown'}</strong></span>
                <span class="dossier-chip">Location: <strong>${geoInfo.country || 'Global'} (${geoInfo.countryCode || 'UN'})</strong></span>
              </div>
            </div>
            <div>
              ${getRiskBadge(riskLevel)}
            </div>
          </div>

          <!-- Dual Gauge: Risk vs Trust -->
          <div class="threat-meter-container" style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: var(--radius-md); padding: 14px 18px;">
            <div class="threat-meter-bar-wrap">
              <div class="threat-meter-labels" style="color: #e2e8f0;">
                <span><strong>DOMAIN RISK ENGINE (WEIGHTED)</strong></span>
                <span><strong>Risk Score: ${riskScore}/100</strong> &bull; Trust Rating: ${trustScore}/100</span>
              </div>
              <div class="threat-meter-track" style="background: #334155; height: 9px;">
                <div class="threat-meter-fill ${meterClass}" style="width: ${Math.max(4, riskScore)}%;"></div>
              </div>
            </div>
            <div style="font-size: 0.78rem; color: #94a3b8; display: flex; align-items: center; justify-content: space-between; margin-top: 8px;">
              <span>Registrar: <strong style="color: #ffffff;">${domainInfo.registrar || 'Unknown'}</strong></span>
              <span>Domain Age: <strong style="color: #60a5fa;">${domainInfo.ageDays !== null ? `${domainInfo.ageDays} days` : 'Unverified'}</strong></span>
              <span>TLS Health: <strong style="color: ${sslInfo.health === 'HEALTHY' ? '#34d399' : '#fbbf24'};">${sslInfo.health || 'ACTIVE'}</strong></span>
            </div>
          </div>

          <!-- 6-Pillar Risk Engine Grid Breakdown -->
          <div class="pillar-breakdown-grid">
            ${breakdown.map(p => {
              const statusClass = (p.status || 'Good').toLowerCase();
              const fillClass = statusClass === 'critical' ? 'critical' : (statusClass === 'warning' ? 'warning' : 'good');
              const fillPct = (p.score / p.maxScore) * 100;
              return `
                <div class="pillar-card">
                  <div class="pillar-header">
                    <span class="pillar-title">${p.pillar}</span>
                    <span class="pillar-score ${fillClass}">${p.score}/${p.maxScore}</span>
                  </div>
                  <div class="pillar-bar-track">
                    <div class="pillar-bar-fill ${fillClass}" style="width: ${Math.max(6, fillPct)}%;"></div>
                  </div>
                  <div class="pillar-desc">${p.summary}</div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <!-- Tabbed Navigation Bar -->
        <div class="dossier-tab-nav" role="tablist">
          <button type="button" class="dossier-tab-btn active" data-dossier-tab="tab-ai-overview">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
            AI Assessment &amp; Overview
          </button>
          <button type="button" class="dossier-tab-btn" data-dossier-tab="tab-dns-email">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
            DNS &amp; Email Protections
          </button>
          <button type="button" class="dossier-tab-btn" data-dossier-tab="tab-ssl-tls">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            SSL/TLS Cryptography
          </button>
          <button type="button" class="dossier-tab-btn" data-dossier-tab="tab-headers-ports">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Headers &amp; Open Ports
          </button>
          <button type="button" class="dossier-tab-btn" data-dossier-tab="tab-phishing-typos">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Phishing &amp; Typosquat Radar
          </button>
          <button type="button" class="dossier-tab-btn" data-dossier-tab="tab-infra-geo">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            Infrastructure &amp; Geo
          </button>
        </div>

        <!-- TAB 1: AI ASSESSMENT & EXECUTIVE OVERVIEW -->
        <div id="tab-ai-overview" class="dossier-tab-pane">
          <div class="dossier-grid-2">
            <!-- AI Security Analyst Card -->
            <div class="dossier-box" style="background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-color: #bfdbfe;">
              <div class="dossier-box-title" style="color: #1e3a8a;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                AI Security Analyst Synthesis
              </div>
              <p style="font-size: 0.9rem; color: var(--text-primary); line-height: 1.6; margin-bottom: 12px;">
                ${aiReport.executiveSummary || 'Domain intelligence synthesis generated.'}
              </p>
              
              <div style="background: var(--bg-tertiary); border: 1px solid var(--border-default); border-radius: var(--radius-md); padding: 12px; margin-bottom: 12px;">
                <div style="font-size: 0.78rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Technical Verdict</div>
                <div style="font-size: 0.88rem; font-weight: 600; color: ${riskScore >= 70 ? 'var(--severity-critical-text)' : 'var(--primary-800)'};">
                  ${aiReport.technicalVerdict || threatClass}
                </div>
              </div>

              <div>
                <div style="font-size: 0.78rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Correlated Evidence Points</div>
                <ul style="padding-left: 18px; margin: 0; font-size: 0.84rem; color: var(--text-secondary); line-height: 1.55;">
                  ${(aiReport.keyCorrelatedFindings || data.redFlags || []).map(f => `<li>${f}</li>`).join('')}
                </ul>
              </div>
            </div>

            <!-- Domain Registration & Verification Card -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                Domain Ownership &amp; Longevity
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Target Domain</span>
                <span class="dossier-prop-value font-mono">${domain}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Registrar</span>
                <span class="dossier-prop-value">${domainInfo.registrar || 'Unknown'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Registration Date</span>
                <span class="dossier-prop-value">${domainInfo.createdDate || 'Unverified'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Domain Age</span>
                <span class="dossier-prop-value" style="color: ${domainInfo.ageDays < 30 ? 'var(--severity-critical-text)' : 'var(--severity-low-text)'};">
                  ${domainInfo.ageDays !== null ? `${domainInfo.ageDays} days` : 'Unknown'}
                </span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Expiry Date</span>
                <span class="dossier-prop-value">${domainInfo.expiresDate || 'N/A'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Privacy Protected</span>
                <span class="dossier-prop-value">${domainInfo.privacyProtected ? 'Yes (WhoisGuard / Masked)' : 'Direct Public Registration'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">DNSSEC Validation</span>
                <span class="dossier-prop-value">${dnsInfo.hasDnssec ? '<span class="badge badge-low">Signed</span>' : '<span class="badge badge-info">Unsigned</span>'}</span>
              </div>
            </div>
          </div>

          <!-- Prescriptive Defense Steps -->
          <div class="dossier-box">
            <div class="dossier-box-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Recommended Countermeasures &amp; Mitigation Guidance
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
              ${(aiReport.recommendedActions || [
                'Do not input sensitive credentials or credit card details.',
                'Enforce strict SPF, DKIM, and DMARC policies at the DNS boundary.',
                'Inspect TLS certificates for expiration and domain mismatch.'
              ]).map((act, idx) => `
                <div style="background: var(--bg-secondary); border: 1px solid var(--border-default); border-radius: var(--radius-md); padding: 12px 14px;">
                  <span style="font-weight: 700; font-size: 0.78rem; color: var(--primary-700); text-transform: uppercase;">Step ${idx + 1}</span>
                  <p style="font-size: 0.85rem; color: var(--text-primary); margin-top: 4px; line-height: 1.45;">${act}</p>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- TAB 2: DNS & EMAIL SECURITY -->
        <div id="tab-dns-email" class="dossier-tab-pane hidden">
          <div class="dossier-grid-2">
            <!-- Email Security Posture -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/></svg>
                Email Spoofing &amp; Anti-Phishing Defenses
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">SPF Record</span>
                <span class="dossier-prop-value">${emailSec.spf?.deployed ? `<span class="badge badge-low">${emailSec.spf.policy}</span>` : '<span class="badge badge-critical">Missing SPF</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">DMARC Enforcement</span>
                <span class="dossier-prop-value">${emailSec.dmarc?.deployed ? `<span class="badge badge-low">p=${emailSec.dmarc.policy}</span>` : '<span class="badge badge-critical">No DMARC</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">DKIM Selectors</span>
                <span class="dossier-prop-value">${emailSec.dkim?.deployed ? `<span class="badge badge-low">${emailSec.dkim.discoveredSelectors?.join(', ')}</span>` : '<span class="badge badge-info">Standard Selectors Unsigned</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">MX Mail Route</span>
                <span class="dossier-prop-value">${emailSec.mxVerification?.hasMx ? `${emailSec.mxVerification.mxCount} Mail Servers Active` : 'No Mail Servers'}</span>
              </div>
              ${emailSec.spf?.raw ? `
                <div style="margin-top: 10px; background: var(--bg-tertiary); padding: 8px 10px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.74rem; word-break: break-all;">
                  <strong>Raw SPF:</strong> ${emailSec.spf.raw}
                </div>
              ` : ''}
              ${emailSec.dmarc?.raw ? `
                <div style="margin-top: 6px; background: var(--bg-tertiary); padding: 8px 10px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.74rem; word-break: break-all;">
                  <strong>Raw DMARC:</strong> ${emailSec.dmarc.raw}
                </div>
              ` : ''}
            </div>

            <!-- DNS Records Dump -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>
                Core DNS Records (Zone Dump)
              </div>
              <div style="margin-bottom: 8px;">
                <strong style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">A Records (IPv4):</strong>
                <div>${(dnsInfo.A || []).map(ip => `<span class="dns-record-badge">${ip}</span>`).join('') || '<span style="font-size:0.8rem; color:var(--text-muted);">None</span>'}</div>
              </div>
              <div style="margin-bottom: 8px;">
                <strong style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">MX Records (Mail Exchangers):</strong>
                <div>${(dnsInfo.MX || []).map(m => `<span class="dns-record-badge">Pri ${m.priority}: ${m.host}</span>`).join('') || '<span style="font-size:0.8rem; color:var(--text-muted);">None</span>'}</div>
              </div>
              <div style="margin-bottom: 8px;">
                <strong style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">Nameservers (NS):</strong>
                <div>${(dnsInfo.NS || []).map(ns => `<span class="dns-record-badge">${ns}</span>`).join('') || '<span style="font-size:0.8rem; color:var(--text-muted);">None</span>'}</div>
              </div>
              <div>
                <strong style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">TXT Verification Records:</strong>
                <div style="max-height: 100px; overflow-y: auto;">
                  ${(dnsInfo.TXT || []).map(t => `<div class="dns-record-badge" style="display:block; margin: 2px 0;">${t}</div>`).join('') || '<span style="font-size:0.8rem; color:var(--text-muted);">None</span>'}
                </div>
              </div>
            </div>
          </div>

          <!-- Active Subdomains -->
          <div class="dossier-box">
            <div class="dossier-box-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
              Discovered Active Subdomains (${subdomains.length})
            </div>
            ${subdomains.length > 0 ? `
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                ${subdomains.map(s => `<span class="dns-record-badge" style="background: #ffffff; border-color: var(--primary-300); color: var(--primary-900);"><strong>${s.subdomain}</strong> &rarr; ${s.ip}</span>`).join('')}
              </div>
            ` : `<p style="font-size: 0.84rem; color: var(--text-muted);">No common active public subdomains discovered during passive query.</p>`}
          </div>
        </div>

        <!-- TAB 3: SSL/TLS CRYPTOGRAPHY -->
        <div id="tab-ssl-tls" class="dossier-tab-pane hidden">
          <div class="dossier-grid-2">
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                TLS Certificate Hierarchy &amp; Parameters
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Certificate Issuer</span>
                <span class="dossier-prop-value">${sslInfo.issuer?.organization || 'Unknown CA'} (${sslInfo.issuer?.commonName || 'N/A'})</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Subject Common Name</span>
                <span class="dossier-prop-value font-mono">${sslInfo.subject?.commonName || domain}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Valid From</span>
                <span class="dossier-prop-value">${sslInfo.validFrom || 'N/A'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Valid Until</span>
                <span class="dossier-prop-value">${sslInfo.validTo || 'N/A'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Days Remaining</span>
                <span class="dossier-prop-value" style="color: ${sslInfo.daysRemaining < 15 ? 'var(--severity-critical-text)' : 'var(--severity-low-text)'};">
                  ${sslInfo.daysRemaining !== null ? `${sslInfo.daysRemaining} days` : 'N/A'}
                </span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Key Architecture</span>
                <span class="dossier-prop-value">${sslInfo.keyType || 'RSA'} ${sslInfo.keySize || 2048}-bit</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Signature Algorithm</span>
                <span class="dossier-prop-value font-mono">${sslInfo.signatureAlgorithm || 'sha256WithRSAEncryption'}</span>
              </div>
            </div>

            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Subject Alternative Names (SANs) &amp; Trust Flags
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Self-Signed Check</span>
                <span class="dossier-prop-value">${sslInfo.isSelfSigned ? '<span class="badge badge-critical">SELF SIGNED</span>' : '<span class="badge badge-low">Public CA</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Domain Mismatch</span>
                <span class="dossier-prop-value">${sslInfo.domainMismatch ? '<span class="badge badge-critical">MISMATCH</span>' : '<span class="badge badge-low">Valid Match</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Fresh Issuance (<14d)</span>
                <span class="dossier-prop-value">${sslInfo.isFreshlyIssued ? '<span class="badge badge-high">Fresh Cert</span>' : 'Standard Baseline'}</span>
              </div>
              <div style="margin-top: 12px;">
                <strong style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">Authorized SANs List:</strong>
                <div style="max-height: 120px; overflow-y: auto; margin-top: 6px;">
                  ${(sslInfo.sans || []).map(s => `<span class="dns-record-badge">${s}</span>`).join('') || '<span style="font-size:0.8rem; color:var(--text-muted);">None</span>'}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 4: HEADERS & OPEN PORTS -->
        <div id="tab-headers-ports" class="dossier-tab-pane hidden">
          <div class="dossier-grid-2">
            <!-- Security Headers -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                HTTP Security Headers &bull; Grade ${webSec.securityHeaders?.grade || 'F'}
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Strict-Transport-Security (HSTS)</span>
                <span class="dossier-prop-value">${webSec.securityHeaders?.hsts?.present ? '<span class="badge badge-low">Enforced</span>' : '<span class="badge badge-critical">Missing</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Content-Security-Policy (CSP)</span>
                <span class="dossier-prop-value">${webSec.securityHeaders?.csp?.present ? '<span class="badge badge-low">Active</span>' : '<span class="badge badge-critical">Missing</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">X-Frame-Options (Clickjack)</span>
                <span class="dossier-prop-value">${webSec.securityHeaders?.xFrameOptions?.present ? '<span class="badge badge-low">Active</span>' : '<span class="badge badge-high">Missing</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">X-Content-Type-Options</span>
                <span class="dossier-prop-value">${webSec.securityHeaders?.xContentTypeOptions?.present ? '<span class="badge badge-low">nosniff</span>' : '<span class="badge badge-high">Missing</span>'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Server Fingerprint</span>
                <span class="dossier-prop-value">${webSec.serverHeader || 'Hidden / WAF'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">CMS / Web Stack</span>
                <span class="dossier-prop-value">${(webSec.techStack || []).join(', ') || 'Custom Application'}</span>
              </div>
            </div>

            <!-- Open Ports Table -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
                Perimeter Open Port Scan Results
              </div>
              ${openPorts.length > 0 ? `
                <table class="typosquat-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Service</th>
                      <th>Status</th>
                      <th>Risk Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${openPorts.map(p => `
                      <tr>
                        <td class="font-mono" style="font-weight:700;">${p.port}</td>
                        <td>${p.service}</td>
                        <td><span class="badge badge-low">OPEN</span></td>
                        <td><span class="badge badge-${p.risk === 'Critical' ? 'critical' : (p.risk === 'High' ? 'high' : 'info')}">${p.risk}</span></td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              ` : `<p style="font-size: 0.84rem; color: var(--text-muted);">All standard perimeter non-web ports are filtered or closed.</p>`}
            </div>
          </div>
        </div>

        <!-- TAB 5: PHISHING & TYPOSQUATTING RADAR -->
        <div id="tab-phishing-typos" class="dossier-tab-pane hidden">
          <div class="dossier-grid-2">
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                Brand Abuse &amp; Phishing Heuristics
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Brand Impersonation Target</span>
                <span class="dossier-prop-value" style="color: ${phishingRadar.isBrandImpersonation ? 'var(--severity-critical-text)' : 'inherit'};">
                  ${phishingRadar.impersonatedBrand || 'None (Authentic or Unclaimed)'}
                </span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Suspicious Phishing Tokens</span>
                <span class="dossier-prop-value">${phishingRadar.suspiciousTokensFound?.join(', ') || 'Zero Security Lures'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Homoglyphs / Punycode</span>
                <span class="dossier-prop-value">${phishingRadar.hasHomoglyphs ? '<span class="badge badge-critical">PUNYCODE ACTIVE</span>' : 'Standard ASCII'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">TLD Abuse Rate</span>
                <span class="dossier-prop-value">${threatIntel.tldRisk || 'Low'} (${threatIntel.tld || '.com'})</span>
              </div>
            </div>

            <!-- Typosquatting Generated Lookalikes -->
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
                Typosquatting &amp; Homoglyph Radar Variants
              </div>
              <div style="max-height: 200px; overflow-y: auto;">
                <table class="typosquat-table">
                  <thead>
                    <tr>
                      <th>Lookalike Domain</th>
                      <th>Technique</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${(phishingRadar.lookalikeVariants || []).map(v => `
                      <tr>
                        <td class="font-mono">${v.domain}</td>
                        <td style="color: var(--text-muted);">${v.technique}</td>
                      </tr>
                    `).join('') || `<tr><td colspan="2">No variants generated.</td></tr>`}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 6: INFRASTRUCTURE & GEO -->
        <div id="tab-infra-geo" class="dossier-tab-pane hidden">
          <div class="dossier-grid-2">
            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                Hosting &amp; ASN Coordinates
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Primary IP Address</span>
                <span class="dossier-prop-value font-mono">${geoInfo.ip || 'Unresolved'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Autonomous System (ASN)</span>
                <span class="dossier-prop-value font-mono">${geoInfo.asn || 'Unknown ASN'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Hosting Provider / Org</span>
                <span class="dossier-prop-value">${geoInfo.org || geoInfo.isp || 'Unknown'}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Hosting Datacenter Flag</span>
                <span class="dossier-prop-value">${geoInfo.isHosting ? '<span class="badge badge-info">Datacenter / Cloud</span>' : 'Standard ISP / Dedicated'}</span>
              </div>
            </div>

            <div class="dossier-box">
              <div class="dossier-box-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
                Physical Geolocation
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">Country</span>
                <span class="dossier-prop-value">${geoInfo.country || 'Global'} (${geoInfo.countryCode || 'N/A'})</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">City / Region</span>
                <span class="dossier-prop-value">${geoInfo.city || 'Unknown'}, ${geoInfo.region || ''}</span>
              </div>
              <div class="dossier-prop-row">
                <span class="dossier-prop-name">GPS Coordinates</span>
                <span class="dossier-prop-value font-mono">${geoInfo.latitude ? `${geoInfo.latitude}, ${geoInfo.longitude}` : 'N/A'}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; gap: 12px; margin-top: 24px; padding-top: 18px; border-top: 1px solid var(--border-default); flex-wrap: wrap;">
          <button type="button" class="btn btn-primary btn-sm" id="btn-save-scam-report">Save Dossier Report</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-scam-md">Export Markdown</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-scam-json">Export JSON</button>
        </div>
      </div>
    `;

    // Bind Dossier Tab Switching
    scamResultsContainer.querySelectorAll('[data-dossier-tab]').forEach(tabBtn => {
      tabBtn.addEventListener('click', () => {
        const targetTabId = tabBtn.getAttribute('data-dossier-tab');
        scamResultsContainer.querySelectorAll('.dossier-tab-btn').forEach(b => b.classList.remove('active'));
        scamResultsContainer.querySelectorAll('.dossier-tab-pane').forEach(p => p.classList.add('hidden'));

        tabBtn.classList.add('active');
        const targetPane = document.getElementById(targetTabId);
        if (targetPane) targetPane.classList.remove('hidden');
      });
    });

    // Bind save report button
    const btnSaveReport = document.getElementById('btn-save-scam-report');
    if (btnSaveReport) {
      btnSaveReport.addEventListener('click', async () => {
        try {
          const saveRes = await fetch('/api/user/reports', {
            method: 'POST',
            headers: getHeaders(true, false),
            body: JSON.stringify({
              reportName: `Domain Dossier: ${domain}`,
              target: domain,
              riskLevel: riskLevel,
              contentJson: data
            })
          });
          if (saveRes.ok) {
            showToast('Dossier saved to your repository.');
            btnSaveReport.textContent = 'Report Saved';
            btnSaveReport.disabled = true;
          }
        } catch (e) {
          showToast('Could not save report: ' + e.message);
        }
      });
    }

    // Bind export buttons
    const btnExportMd = document.getElementById('btn-export-scam-md');
    const btnExportJson = document.getElementById('btn-export-scam-json');

    if (btnExportMd) {
      btnExportMd.addEventListener('click', () => {
        const mdContent = `# DOMAIN SECURITY INTELLIGENCE DOSSIER
Target Domain: ${domain}
Risk Score: ${riskScore}/100 (${riskLevel})
Threat Classification: ${threatClass}

## Executive Summary
${aiReport.executiveSummary || 'Audit concluded.'}

## Technical Verdict
${aiReport.technicalVerdict || 'N/A'}

## Domain Intelligence
- Registrar: ${domainInfo.registrar || 'Unknown'}
- Domain Age: ${domainInfo.ageDays || 'Unknown'} days
- Created: ${domainInfo.createdDate || 'N/A'}
- Primary IP: ${geoInfo.ip || 'N/A'} (${geoInfo.country || 'Global'})

## SSL/TLS Certificate
- Issuer: ${sslInfo.issuer?.organization || 'N/A'}
- Valid: ${sslInfo.validFrom} to ${sslInfo.validTo}
- Status: ${sslInfo.health}

## DNS & Email Protections
- SPF Policy: ${emailSec.spf?.policy || 'Missing'}
- DMARC Policy: ${emailSec.dmarc?.policy || 'Missing'}
- Nameservers: ${(dnsInfo.NS || []).join(', ')}

## Recommendations
${(aiReport.recommendedActions || []).map(r => '- ' + r).join('\n')}
`;
        downloadTextFile(`domain_dossier_${domain}.md`, mdContent, 'text/markdown');
        showToast('Markdown dossier downloaded.');
      });
    }

    if (btnExportJson) {
      btnExportJson.addEventListener('click', () => {
        downloadTextFile(`domain_dossier_${domain}.json`, JSON.stringify(data, null, 2), 'application/json');
        showToast('JSON telemetry downloaded.');
      });
    }
  }

  // ==========================================================================
  // TOOL 3: THREAT DIGEST FEED HUB
  // ==========================================================================
  const feedItemsList = document.getElementById('feed-items-list');
  const feedItemsCount = document.getElementById('feed-items-count');
  const inputFeedSearch = document.getElementById('input-feed-search');
  const btnRefreshFeeds = document.getElementById('btn-refresh-feeds');
  const threatPanelContainer = document.getElementById('threat-panel-container');

  // Home Page Welcome Intel Hub Showcase elements
  const homeThreatGrid = document.getElementById('home-threat-grid');
  const homeFeedCounter = document.getElementById('home-live-feed-counter');
  const homeSearchInput = document.getElementById('home-feed-search-input');
  const btnHomeRefreshFeeds = document.getElementById('btn-home-refresh-feeds');
  const btnHomeOpenWorkbench = document.getElementById('btn-home-open-workbench');
  const homeFeedTabs = document.querySelectorAll('.home-feed-tab');
  const homeTrendChips = document.querySelectorAll('.trend-chip-item');
  let currentHomeFilter = 'all';

  function categorizeFeedItem(item) {
    const text = ((item.title || '') + ' ' + (item.description || '')).toLowerCase();
    if (text.includes('cisa') || text.includes('kev') || text.includes('exploited') || text.includes('actively')) {
      return { tag: 'CISA KEV EXPLOIT', badge: '<span class="badge badge-critical"><span class="badge-dot"></span>CRITICAL KEV</span>', category: 'cisa' };
    }
    if (text.includes('phish') || text.includes('passkey') || text.includes('credential') || text.includes('identity') || text.includes('token')) {
      return { tag: 'PHISHING & IDENTITY', badge: '<span class="badge badge-high"><span class="badge-dot"></span>HIGH RISK</span>', category: 'phishing' };
    }
    if (text.includes('cloud') || text.includes('microsoft') || text.includes('m365') || text.includes('azure') || text.includes('aws') || text.includes('google cloud')) {
      return { tag: 'CLOUD & M365 DEFENSE', badge: '<span class="badge badge-medium"><span class="badge-dot"></span>MEDIUM RISK</span>', category: 'cloud' };
    }
    if (text.includes('compliance') || text.includes('privacy') || text.includes('nis2') || text.includes('gdpr') || text.includes('regulatory') || text.includes('breach')) {
      return { tag: 'COMPLIANCE & PRIVACY', badge: '<span class="badge badge-info"><span class="badge-dot"></span>COMPLIANCE</span>', category: 'compliance' };
    }
    if (text.includes('zero-day') || text.includes('0-day') || text.includes('rce') || text.includes('cve-')) {
      return { tag: 'VULNERABILITY INTEL', badge: '<span class="badge badge-high"><span class="badge-dot"></span>HIGH RISK</span>', category: 'cisa' };
    }
    return { tag: 'THREAT ADVISORY', badge: '<span class="badge badge-info"><span class="badge-dot"></span>INFO</span>', category: 'all' };
  }

  function renderHomeThreatGrid(items) {
    if (!homeThreatGrid) return;
    if (!items || items.length === 0) {
      homeThreatGrid.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 36px 16px; text-align: center; color: var(--text-muted); font-size: 0.9rem;">
          No security advisories match the selected filter.
        </div>
      `;
      return;
    }

    // Display top 8 cards for rich homepage layout
    const displayItems = items.slice(0, 8);

    homeThreatGrid.innerHTML = displayItems.map((item, idx) => {
      const cat = categorizeFeedItem(item);
      const words = (item.description || '').split(' ').length;
      const readTime = Math.max(2, Math.ceil(words / 30)) + ' min read';
      const imgUrl = item.imageUrl || 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80';
      
      return `
        <div class="news-feed-card">
          <div class="news-feed-img-wrap">
            <img src="${escapeHtml(imgUrl)}" alt="${escapeHtml(item.title)}" loading="lazy" onerror="this.onerror=null; this.src='https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80'">
            <div class="news-feed-img-overlay"></div>
            <div class="news-feed-img-tag">${cat.tag}</div>
          </div>
          <div class="news-feed-content">
            <div class="news-feed-header">
              <span class="news-feed-source-chip">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                ${escapeHtml(item.source || 'Advisory Feed')}
              </span>
              ${cat.badge}
            </div>
            <h4 class="news-feed-title">${escapeHtml(item.title)}</h4>
            <p class="news-feed-desc">${escapeHtml(item.description || 'Live threat intelligence telemetry and CVE advisory ingestion.')}</p>
          </div>
          <div class="news-feed-footer-wrap">
            <div class="news-feed-meta">
              <span>${formatDateTime(item.pubDate)}</span>
              <span>&bull;</span>
              <span>${readTime}</span>
            </div>
            <div class="news-feed-actions">
              <button type="button" class="btn-analyze-feed-card" data-home-feed-idx="${idx}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                <span>Analyze with AI Analyst</span>
              </button>
              <a href="${item.link}" target="_blank" rel="noopener noreferrer" class="btn-official-feed-link" title="Open official bulletin">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
              </a>
            </div>
          </div>
        </div>
      `;
    }).join('');

    // Attach click listener on each card's AI Analyst button
    homeThreatGrid.querySelectorAll('.btn-analyze-feed-card').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-home-feed-idx'), 10);
        const item = displayItems[idx];
        if (item) {
          selectedFeedItem = item;
          switchView('threats');
          // Highlight in main workbench feed list
          if (feedItemsList) {
            feedItemsList.querySelectorAll('.feed-item-card').forEach((c, i) => {
              if (threatFeeds[i] && threatFeeds[i].link === item.link) {
                c.classList.add('selected');
                c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              } else {
                c.classList.remove('selected');
              }
            });
          }
          analyzeThreatItem(item);
          const wb = document.getElementById('threat-panel-container');
          if (wb) wb.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });
  }

  function applyHomeFeedFilter() {
    let filtered = [...threatFeeds];
    const query = (homeSearchInput ? homeSearchInput.value : '').toLowerCase().trim();

    if (currentHomeFilter !== 'all') {
      filtered = filtered.filter(item => {
        const cat = categorizeFeedItem(item);
        if (currentHomeFilter === 'cisa') return cat.category === 'cisa';
        if (currentHomeFilter === 'phishing') return cat.category === 'phishing';
        if (currentHomeFilter === 'cloud') return cat.category === 'cloud';
        if (currentHomeFilter === 'compliance') return cat.category === 'compliance';
        return true;
      });
    }

    if (query) {
      filtered = filtered.filter(i =>
        (i.title && i.title.toLowerCase().includes(query)) ||
        (i.source && i.source.toLowerCase().includes(query)) ||
        (i.description && i.description.toLowerCase().includes(query))
      );
    }

    renderHomeThreatGrid(filtered);
  }

  async function loadThreatFeeds(forceRefresh = false) {
    // 1. Instant Cache Hydration if previously loaded from live sources
    if (!forceRefresh && threatFeeds.length === 0) {
      try {
        const cached = localStorage.getItem('secintel_cached_threat_feeds');
        if (cached) {
          const parsed = JSON.parse(cached);
          if (Array.isArray(parsed) && parsed.length > 0) {
            threatFeeds = parsed;
            if (feedItemsCount) feedItemsCount.textContent = threatFeeds.length;
            if (homeFeedCounter) homeFeedCounter.textContent = `${threatFeeds.length} Feeds Monitored`;
            renderThreatItems(threatFeeds);
            renderHomeThreatGrid(threatFeeds);
          }
        }
      } catch (e) {}
    }

    // 2. Fetch fresh live feeds directly from real security sources
    try {
      const url = `/api/feeds${forceRefresh ? '?refresh=true' : ''}`;
      const res = await fetch(url);

      if (res.ok) {
        const freshFeeds = await res.json();
        if (Array.isArray(freshFeeds) && freshFeeds.length > 0) {
          threatFeeds = freshFeeds;
          try {
            localStorage.setItem('secintel_cached_threat_feeds', JSON.stringify(freshFeeds));
          } catch (e) {}

          if (feedItemsCount) feedItemsCount.textContent = threatFeeds.length;
          if (homeFeedCounter) homeFeedCounter.textContent = `${threatFeeds.length} Feeds Monitored`;
          
          renderThreatItems(threatFeeds);
          renderHomeThreatGrid(threatFeeds);
        }
      }
    } catch (err) {
      if (threatFeeds.length === 0) {
        if (feedItemsList) {
          feedItemsList.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">Connecting to live security sources...</div>`;
        }
      }
    }
  }

  function renderThreatItems(items) {
    if (!feedItemsList) return;
    if (!items || items.length === 0) {
      feedItemsList.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">No bulletins match query.</div>`;
      return;
    }

    feedItemsList.innerHTML = items.map((item, idx) => {
      const imgUrl = item.imageUrl || 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80';
      return `
        <div class="feed-item-card ${selectedFeedItem && selectedFeedItem.link === item.link ? 'selected' : ''}" data-feed-idx="${idx}">
          <div class="feed-item-flex">
            <img src="${escapeHtml(imgUrl)}" alt="" class="feed-item-thumb" onerror="this.onerror=null; this.src='https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80'">
            <div class="feed-item-info">
              <div class="feed-item-source-row">
                <span>${escapeHtml(item.source || 'Advisory')}</span>
                <span>${formatDateTime(item.pubDate)}</span>
              </div>
              <div class="feed-item-title">${escapeHtml(item.title)}</div>
            </div>
          </div>
          <div class="feed-item-desc">${escapeHtml(item.description || 'No summary text provided.')}</div>
        </div>
      `;
    }).join('');

    // Attach click listener
    feedItemsList.querySelectorAll('.feed-item-card').forEach(card => {
      card.addEventListener('click', () => {
        const idx = parseInt(card.getAttribute('data-feed-idx'), 10);
        selectedFeedItem = items[idx];
        feedItemsList.querySelectorAll('.feed-item-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        analyzeThreatItem(selectedFeedItem);
      });
    });
  }

  if (inputFeedSearch) {
    inputFeedSearch.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();
      if (!query) {
        renderThreatItems(threatFeeds);
        return;
      }
      const filtered = threatFeeds.filter(i =>
        (i.title && i.title.toLowerCase().includes(query)) ||
        (i.source && i.source.toLowerCase().includes(query)) ||
        (i.description && i.description.toLowerCase().includes(query))
      );
      renderThreatItems(filtered);
    });
  }

  if (btnRefreshFeeds) btnRefreshFeeds.addEventListener('click', () => loadThreatFeeds(true));

  // Home controls setup
  if (btnHomeRefreshFeeds) {
    btnHomeRefreshFeeds.addEventListener('click', () => {
      loadThreatFeeds(true);
      showToast('Live threat feeds synchronized!');
    });
  }

  if (btnHomeOpenWorkbench) {
    btnHomeOpenWorkbench.addEventListener('click', () => {
      switchView('threats');
    });
  }

  if (homeSearchInput) {
    homeSearchInput.addEventListener('input', applyHomeFeedFilter);
  }

  homeFeedTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      homeFeedTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentHomeFilter = tab.getAttribute('data-filter') || 'all';
      applyHomeFeedFilter();
    });
  });

  homeTrendChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const topic = chip.getAttribute('data-topic') || '';
      if (homeSearchInput) {
        homeSearchInput.value = topic;
        applyHomeFeedFilter();
        homeSearchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  });

  async function analyzeThreatItem(item) {
    if (!threatPanelContainer) return;
    threatPanelContainer.innerHTML = `
      <div class="loading-state">
        <div class="spinner"></div>
        <h4 style="font-size: 1rem; color: var(--primary-900); margin-bottom: 4px;">Synthesizing Security Advisory</h4>
        <p style="font-size: 0.85rem; color: var(--text-muted);">Extracting CVE, querying CISA KEV catalog, and mapping MITRE ATT&amp;CK TTPs...</p>
      </div>
    `;

    try {
      const res = await fetch('/api/analyze-feed', {
        method: 'POST',
        headers: getHeaders(true, true),
        body: JSON.stringify(item)
      });

      if (!res.ok) throw new Error('Failed to analyze advisory.');
      const data = await res.json();
      const analysis = data.analysis || data;

      // Automatically store in history if user is logged in
      try {
        await fetch('/api/user/analyses', {
          method: 'POST',
          headers: getHeaders(true, false),
          body: JSON.stringify({
            tool: 'Threat Digest',
            target: item.title,
            riskLevel: analysis.severity || 'Medium',
            confidence: 90,
            summary: analysis.executiveSummary || 'Threat feed analyzed.',
            resultJson: data
          })
        });
      } catch (e) {}

      renderThreatAnalysisDetail(item, analysis);
    } catch (err) {
      threatPanelContainer.innerHTML = `
        <div class="error-state">
          <h4 class="error-state-title">Analysis Failed</h4>
          <p class="error-state-desc">${err.message}</p>
        </div>
      `;
    }
  }

  function renderThreatAnalysisDetail(item, analysis) {
    const isCisaKev = analysis.cisaKevStatus === 'CONFIRMED_EXPLOITED';
    const mitre = analysis.mitreTtp || { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' };
    const hasCve = Boolean(analysis.cveId && analysis.cveId !== 'N/A' && analysis.cveId !== 'None' && analysis.cveId.toUpperCase().startsWith('CVE-'));
    
    const threatDisplayName = hasCve ? analysis.cveId : (item.title || 'Security Threat Advisory');
    const entityLabel = hasCve ? 'Identified CVE' : 'Advisory Category';
    const entityVal = hasCve 
      ? `<span class="badge badge-warning" style="font-family: var(--font-mono); font-size: 0.95rem; letter-spacing: 0.04em;">${analysis.cveId}</span>`
      : `<span class="badge badge-info" style="font-size: 0.85rem; font-weight: 600;">${analysis.incidentCategory || 'Data Breach & Credential Infiltration'}</span>`;

    const scoreLabel = hasCve ? 'NIST NVD CVSS v3.1' : 'Threat Impact Rating';
    const scoreVal = (analysis.cvssScore && analysis.cvssScore > 0)
      ? `<span style="font-weight: 700; color: ${analysis.severity === 'CRITICAL' ? 'var(--severity-critical-text)' : 'var(--severity-high-text)'};">${analysis.cvssScore} / 10.0</span> <span style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase;">(${analysis.cvssSeverity || analysis.severity || 'HIGH'})</span>`
      : `<span style="font-weight: 700; color: var(--severity-high-text);">7.8 / 10.0</span> <span style="font-size: 0.78rem; font-weight: 600;">(${analysis.severity || 'HIGH'})</span>`;

    const cweLabel = hasCve ? 'Weakness (CWE)' : 'Root Vector & Weakness';
    const cweVal = (analysis.cweId && analysis.cweId !== 'N/A')
      ? `<span style="font-weight: 600; font-family: var(--font-mono); font-size: 0.88rem;">${analysis.cweId}</span>: <span style="font-size: 0.82rem; color: var(--text-secondary);">${analysis.cweName || 'Security Flaw'}</span>`
      : `<span style="font-weight: 600; font-family: var(--font-mono); font-size: 0.88rem;">CWE-522</span>: <span style="font-size: 0.82rem; color: var(--text-secondary);">Compromised Account Credentials</span>`;

    const cisaStatusHtml = isCisaKev
      ? 'CONFIRMED ACTIVE EXPLOITATION IN THE WILD (Zero-Day)'
      : (hasCve ? 'No active exploitation recorded in CISA KEV catalog.' : 'Security incident evaluated against Threat & Breach taxonomy.');

    const imgUrl = item.imageUrl || 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80';

    threatPanelContainer.innerHTML = `
      <div>
        <!-- Featured Threat Banner -->
        <div class="threat-detail-hero">
          <img src="${escapeHtml(imgUrl)}" alt="${escapeHtml(item.title)}" onerror="this.onerror=null; this.src='https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80'">
          <div class="threat-detail-hero-gradient"></div>
          <div class="threat-detail-hero-badge">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>${escapeHtml(analysis.incidentCategory || (hasCve ? 'Vulnerability Intelligence' : 'Security Advisory'))}</span>
          </div>
        </div>

        <div style="display: flex; align-items: flex-start; justify-content: space-between; border-bottom: 1px solid var(--border-default); padding-bottom: 16px; margin-bottom: 20px; gap: 16px; flex-wrap: wrap;">
          <div>
            ${getRiskBadge(analysis.severity)}
            <h3 style="font-family: var(--font-heading); font-size: 1.35rem; font-weight: 700; color: var(--primary-900); margin-top: 8px;">${item.title}</h3>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
              Source: <strong>${item.source}</strong> &bull; Published: ${formatDateTime(item.pubDate)}
            </div>
          </div>
          <div>
            <a href="${item.link}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm">Original Bulletin &rarr;</a>
          </div>
        </div>

        <!-- CISA KEV Exploitation Status Notice -->
        <div style="margin-bottom: 20px; padding: 12px 16px; border-radius: var(--radius-md); ${isCisaKev ? 'background-color: var(--severity-critical-bg); border: 1px solid var(--severity-critical-border); color: var(--severity-critical-text);' : 'background-color: var(--severity-low-bg); border: 1px solid var(--severity-low-border); color: var(--severity-low-text);'}">
          <strong>CISA KEV Catalog Status:</strong> ${cisaStatusHtml}
        </div>

        <!-- Vulnerability Telemetry Grid -->
        <div class="results-summary-grid" style="margin-bottom: 20px;">
          <div class="summary-metric-box">
            <div class="label">${entityLabel}</div>
            <div class="value">${entityVal}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">${scoreLabel}</div>
            <div class="value">${scoreVal}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">${cweLabel}</div>
            <div class="value" style="line-height: 1.35;">${cweVal}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">MITRE ATT&amp;CK TTP</div>
            <div class="value" style="font-size: 0.95rem;"><strong>${mitre.id}</strong>: <span style="font-size: 0.82rem; color: var(--text-secondary);">${mitre.name}</span></div>
          </div>
        </div>

        <!-- Contextual Risk Reasoning -->
        <div class="card" style="margin-bottom: 20px; background-color: var(--bg-tertiary);">
          <strong style="font-size: 0.85rem; color: var(--primary-900);">Contextual Risk Reasoning:</strong>
          <p style="font-size: 0.9rem; color: var(--text-secondary); margin-top: 4px; line-height: 1.55;">
            ${analysis.severityReasoning || 'Risk evaluated based on vulnerability mechanics and exploitation likelihood.'}
          </p>
        </div>

        <!-- Executive Summary -->
        <div style="margin-bottom: 20px;">
          <h4 style="font-family: var(--font-heading); font-size: 1.05rem; font-weight: 600; color: var(--primary-900); margin-bottom: 6px;">Executive Intelligence Digest</h4>
          <p style="font-size: 0.92rem; color: var(--text-secondary); line-height: 1.6;">${analysis.executiveSummary || 'No summary available.'}</p>
        </div>

        <!-- Engineering Remediation Action Plan -->
        <div style="margin-bottom: 20px;">
          <h4 style="font-family: var(--font-heading); font-size: 1.05rem; font-weight: 600; color: var(--primary-900); margin-bottom: 8px;">Engineering Remediation Action Plan</h4>
          <div class="action-plan-list">
            ${analysis.actionPlan && analysis.actionPlan.length > 0
              ? analysis.actionPlan.map((step, idx) => `
                <div class="action-plan-item">
                  <span class="action-plan-num">0${idx + 1}</span>
                  <span>${step}</span>
                </div>
              `).join('')
              : '<div class="action-plan-item"><span>Apply latest vendor security patches immediately.</span></div>'
            }
          </div>
        </div>

        <!-- Export Buttons -->
        <div style="display: flex; gap: 12px; margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border-default);">
          <button type="button" class="btn btn-primary btn-sm" id="btn-save-threat-report">Save Report</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-threat-md">Export Markdown</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-export-threat-json">Export JSON</button>
        </div>

        <!-- Interactive AI Security Analyst Chat -->
        <div class="threat-chat-card">
          <div class="threat-chat-header">
            <div class="threat-chat-title-wrap">
              <div class="threat-chat-icon">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
              </div>
              <div>
                <div class="threat-chat-title">Ask AI Security Analyst</div>
                <div class="threat-chat-subtitle">Synthesizing advisory telemetry, CVE exposure, and actionable remediation</div>
              </div>
            </div>
            <div style="display: flex; gap: 8px;">
              <button type="button" class="btn btn-secondary btn-xs" id="btn-clear-threat-chat" title="Clear conversation log">Clear Chat</button>
            </div>
          </div>

          <div id="threat-chat-log" class="threat-chat-log">
            <div class="chat-msg analyst">
              <div class="chat-msg-header">
                <span class="chat-msg-author analyst">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  AI Security Analyst
                </span>
                <span class="chat-msg-time">Ready</span>
              </div>
              <div class="chat-msg-bubble">
                <p>I have synthesized this advisory (<strong>${escapeHtml(threatDisplayName)}</strong>). Ask me anything regarding threat vector exposure, log hunting queries, or immediate containment procedures.</p>
              </div>
            </div>
          </div>

          <!-- Prompt suggestion chips -->
          <div class="chat-chips-container">
            <span class="chat-chips-label">Quick Prompts:</span>
            <button type="button" class="chat-chip-btn" data-prompt="Explain this threat in detail and its key exposure risks.">Explain this threat</button>
            <button type="button" class="chat-chip-btn" data-prompt="What immediate actionable remediation steps should we take?">Actionable Guidance</button>
            <button type="button" class="chat-chip-btn" data-prompt="How do I hunt for IOCs in Microsoft 365, Azure AD, or Firewall logs?">Log Review &amp; IOC Hunting</button>
            <button type="button" class="chat-chip-btn" data-prompt="What perimeter firewall or IPS rules should be deployed?">Firewall &amp; IPS Rules</button>
            <button type="button" class="chat-chip-btn" data-prompt="Is our Linux / Cloud infrastructure vulnerable?">Infrastructure Exposure</button>
          </div>

          <!-- Chat Input Form -->
          <div class="chat-form-container">
            <form id="form-threat-chat" class="chat-input-row">
              <input type="text" id="input-threat-chat" class="chat-input-field" placeholder="Ask about exposure, log queries, mitigation, or remediation..." required autocomplete="off">
              <button type="submit" class="btn btn-primary btn-sm" id="btn-submit-threat-chat" style="display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; padding: 10px 18px;">
                <span>Ask</span>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
              </button>
            </form>
          </div>
        </div>
      </div>
    `;

    // Save report
    const btnSaveThreat = document.getElementById('btn-save-threat-report');
    if (btnSaveThreat) {
      btnSaveThreat.addEventListener('click', async () => {
        try {
          const saveRes = await fetch('/api/user/reports', {
            method: 'POST',
            headers: getHeaders(true, false),
            body: JSON.stringify({
              reportName: `Advisory: ${analysis.cveId || item.title}`,
              target: item.title,
              riskLevel: analysis.severity || 'Medium',
              contentJson: { item, analysis }
            })
          });
          if (saveRes.ok) {
            showToast('Report saved to your repository.');
            btnSaveThreat.textContent = 'Report Saved';
            btnSaveThreat.disabled = true;
          }
        } catch (e) {
          showToast('Could not save report: ' + e.message);
        }
      });
    }

    // Export buttons
    const btnExportMd = document.getElementById('btn-export-threat-md');
    const btnExportJson = document.getElementById('btn-export-threat-json');

    if (btnExportMd) {
      btnExportMd.addEventListener('click', async () => {
        try {
          const res = await fetch('/api/export-advisory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'threat', format: 'markdown', item, analysis })
          });
          const exp = await res.json();
          downloadTextFile(exp.filename, exp.content, 'text/markdown');
        } catch (e) {
          showToast('Export failed: ' + e.message);
        }
      });
    }

    if (btnExportJson) {
      btnExportJson.addEventListener('click', async () => {
        try {
          const res = await fetch('/api/export-advisory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'threat', format: 'json', item, analysis })
          });
          const exp = await res.json();
          downloadTextFile(exp.filename, JSON.stringify(exp.content, null, 2), 'application/json');
        } catch (e) {
          showToast('Export failed: ' + e.message);
        }
      });
    }

    // Interactive Chat handler
    const formChat = document.getElementById('form-threat-chat');
    const inputChat = document.getElementById('input-threat-chat');
    const chatLog = document.getElementById('threat-chat-log');
    const btnClearChat = document.getElementById('btn-clear-threat-chat');
    const chatHistory = [];

    const sendUserQuery = async (queryText) => {
      const userMsg = (queryText || '').trim();
      if (!userMsg) return;

      const nowTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      // Add user message bubble
      const userBubble = document.createElement('div');
      userBubble.className = 'chat-msg user';
      userBubble.innerHTML = `
        <div class="chat-msg-header">
          <span class="chat-msg-author user">You</span>
          <span class="chat-msg-time">${nowTime}</span>
        </div>
        <div class="chat-msg-bubble">
          <p>${escapeHtml(userMsg)}</p>
        </div>
      `;
      chatLog.appendChild(userBubble);
      if (inputChat) inputChat.value = '';
      chatLog.scrollTop = chatLog.scrollHeight;

      // Add loading state bubble
      const loadingId = 'chat-loading-' + Date.now();
      const loadingBubble = document.createElement('div');
      loadingBubble.id = loadingId;
      loadingBubble.className = 'chat-msg analyst';
      loadingBubble.innerHTML = `
        <div class="chat-msg-header">
          <span class="chat-msg-author analyst">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            AI Security Analyst
          </span>
          <span class="chat-msg-time">Analyzing...</span>
        </div>
        <div class="chat-msg-bubble" style="display: flex; align-items: center; gap: 10px; padding: 12px 18px;">
          <span style="font-size: 0.85rem; color: var(--text-secondary);">Synthesizing advisory guidance</span>
          <span class="chat-typing-dots">
            <span class="chat-typing-dot"></span>
            <span class="chat-typing-dot"></span>
            <span class="chat-typing-dot"></span>
          </span>
        </div>
      `;
      chatLog.appendChild(loadingBubble);
      chatLog.scrollTop = chatLog.scrollHeight;

      chatHistory.push({ role: 'user', content: userMsg });

      try {
        const chatRes = await fetch('/api/threat-chat', {
          method: 'POST',
          headers: getHeaders(true, true),
          body: JSON.stringify({
            message: userMsg,
            context: {
              title: item.title,
              cveId: threatDisplayName,
              cvssScore: analysis.cvssScore,
              cweId: analysis.cweId,
              cisaKevStatus: analysis.cisaKevStatus,
              severity: analysis.severity,
              affectedSystems: analysis.affectedSystems,
              severityReasoning: analysis.severityReasoning,
              actionPlan: analysis.actionPlan
            },
            history: chatHistory
          })
        });

        const chatData = await chatRes.json();
        const responseTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const rawAnswer = chatData.answer || 'Assessment complete. No further actions identified.';
        const formattedHtml = formatMarkdownResponse(rawAnswer);

        const loadEl = document.getElementById(loadingId);
        if (loadEl) {
          loadEl.innerHTML = `
            <div class="chat-msg-header">
              <span class="chat-msg-author analyst">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                AI Security Analyst
              </span>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span class="chat-msg-time">${responseTime}</span>
                <button type="button" class="chat-btn-copy-msg" data-copy-payload="${encodeURIComponent(rawAnswer)}" title="Copy response">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  Copy
                </button>
              </div>
            </div>
            <div class="chat-msg-bubble">
              ${formattedHtml}
            </div>
          `;

          // Setup copy button on this new message
          const copyBtn = loadEl.querySelector('.chat-btn-copy-msg');
          if (copyBtn) {
            copyBtn.addEventListener('click', () => {
              const payload = decodeURIComponent(copyBtn.getAttribute('data-copy-payload') || '');
              copyToClipboard(payload, 'Analyst response copied to clipboard!');
            });
          }
        }
        chatHistory.push({ role: 'assistant', content: rawAnswer });
        chatLog.scrollTop = chatLog.scrollHeight;
      } catch (err) {
        const loadEl = document.getElementById(loadingId);
        if (loadEl) {
          loadEl.innerHTML = `
            <div class="chat-msg-header">
              <span class="chat-msg-author analyst">AI Security Analyst</span>
              <span class="chat-msg-time">Error</span>
            </div>
            <div class="chat-msg-bubble" style="border-left-color: var(--danger-500); background-color: #fef2f2;">
              <p style="color: #991b1b; font-weight: 500;">Unable to connect to AI Security Analyst service: ${escapeHtml(err.message)}</p>
            </div>
          `;
        }
      }
    };

    if (formChat && inputChat) {
      formChat.addEventListener('submit', (e) => {
        e.preventDefault();
        sendUserQuery(inputChat.value);
      });
    }

    // Quick Prompt Chips
    const promptChips = document.querySelectorAll('.chat-chip-btn');
    promptChips.forEach(chip => {
      chip.addEventListener('click', () => {
        const prompt = chip.getAttribute('data-prompt');
        if (prompt) {
          sendUserQuery(prompt);
        }
      });
    });

    // Clear chat
    if (btnClearChat && chatLog) {
      btnClearChat.addEventListener('click', () => {
        chatHistory.length = 0;
        chatLog.innerHTML = `
          <div class="chat-msg analyst">
            <div class="chat-msg-header">
              <span class="chat-msg-author analyst">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                AI Security Analyst
              </span>
              <span class="chat-msg-time">Ready</span>
            </div>
            <div class="chat-msg-bubble">
              <p>Conversation cleared. Ask me anything regarding <strong>${escapeHtml(threatDisplayName)}</strong>.</p>
            </div>
          </div>
        `;
        showToast('Chat history cleared.');
      });
    }
  }

  // ==========================================================================
  // TOOL 4: SBOM DEPENDENCY ANALYZER
  // ==========================================================================
  const formScanSbom = document.getElementById('form-scan-sbom');
  const inputSbomManifest = document.getElementById('input-sbom-manifest');
  const sbomResultsContainer = document.getElementById('sbom-results-container');
  const btnSbomSamplePy = document.getElementById('btn-sbom-sample-py');
  const btnSbomSampleNode = document.getElementById('btn-sbom-sample-node');
  const btnSbomSampleCycloneDx = document.getElementById('btn-sbom-sample-cyclonedx');
  const btnSbomSampleSpring = document.getElementById('btn-sbom-sample-spring');

  const samplePy = `fastapi>=0.110.0\nuvicorn>=0.28.0\nlog4j==2.14.1\nrequests==2.25.1\nurllib3==1.26.4\naiohttp==3.8.1\nparamiko==2.7.2`;
  const sampleNode = `{\n  "dependencies": {\n    "express": "^4.17.1",\n    "axios": "^1.4.0",\n    "jsonwebtoken": "^8.5.1",\n    "lodash": "^4.17.19"\n  }\n}`;
  const sampleCycloneDx = `{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.4",\n  "components": [\n    { "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },\n    { "name": "lodash", "version": "4.17.19", "purl": "pkg:npm/lodash@4.17.19" },\n    { "name": "fastapi", "version": "0.110.0", "purl": "pkg:pypi/fastapi@0.110.0" }\n  ]\n}`;
  const sampleSpring = `spring-beans==5.3.17\nspring-webmvc==5.3.17\njackson-databind==2.12.0\nlog4j-core==2.14.1`;

  if (btnSbomSamplePy && inputSbomManifest) {
    btnSbomSamplePy.addEventListener('click', () => { inputSbomManifest.value = samplePy; showToast('Python requirements loaded'); });
  }
  if (btnSbomSampleNode && inputSbomManifest) {
    btnSbomSampleNode.addEventListener('click', () => { inputSbomManifest.value = sampleNode; showToast('Node.js package.json loaded'); });
  }
  if (btnSbomSampleCycloneDx && inputSbomManifest) {
    btnSbomSampleCycloneDx.addEventListener('click', () => { inputSbomManifest.value = sampleCycloneDx; showToast('CycloneDX SBOM loaded'); });
  }
  if (btnSbomSampleSpring && inputSbomManifest) {
    btnSbomSampleSpring.addEventListener('click', () => { inputSbomManifest.value = sampleSpring; showToast('Java Spring manifest loaded'); });
  }

  const btnCaseStudyLog4j = document.getElementById('btn-case-study-log4j');
  const btnCaseStudySpring = document.getElementById('btn-case-study-spring');

  if (btnCaseStudyLog4j && inputSbomManifest) {
    btnCaseStudyLog4j.addEventListener('click', () => {
      inputSbomManifest.value = `log4j-core==2.14.1\nspring-core==5.3.18\nfastapi>=0.110.0\nrequests==2.25.1`;
      showToast('Log4j CVE-2021-44228 manifest loaded');
      formScanSbom.dispatchEvent(new Event('submit'));
    });
  }

  if (btnCaseStudySpring && inputSbomManifest) {
    btnCaseStudySpring.addEventListener('click', () => {
      inputSbomManifest.value = `spring-beans==5.3.17\nspring-webmvc==5.3.17\njackson-databind==2.12.0`;
      showToast('Spring4Shell CVE-2022-22965 manifest loaded');
      formScanSbom.dispatchEvent(new Event('submit'));
    });
  }

  if (formScanSbom) {
    formScanSbom.addEventListener('submit', async (e) => {
      e.preventDefault();
      const manifest = inputSbomManifest.value.trim();
      if (!manifest) return;

      if (sbomResultsContainer) {
        sbomResultsContainer.innerHTML = `
          <div class="loading-state">
            <div class="spinner"></div>
            <p style="font-size: 0.85rem; color: var(--text-muted);">Auditing dependencies against live CVE and CISA catalogs...</p>
          </div>
        `;
        sbomResultsContainer.classList.remove('hidden');
      }

      try {
        const res = await fetch('/api/sbom/audit', {
          method: 'POST',
          headers: getHeaders(true, true),
          body: JSON.stringify({ manifest })
        });
        if (!res.ok) throw new Error('SBOM audit server error.');

        const data = await res.json();
        renderSbomResults(data);
      } catch (err) {
        if (sbomResultsContainer) {
          sbomResultsContainer.innerHTML = `
            <div class="error-state">
              <h4 class="error-state-title">Audit Failed</h4>
              <p class="error-state-desc">${err.message}</p>
            </div>
          `;
        }
      }
    });
  }

  function renderSbomResults(data) {
    if (!sbomResultsContainer) return;
    const ecoBadge = data.ecosystem ? `<span style="font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-default); color: var(--text-secondary); margin-left: 8px;">${data.ecosystem}</span>` : '';
    
    sbomResultsContainer.innerHTML = `
      <div class="results-card">
        <div class="results-header-banner">
          <div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">DEPENDENCY MANIFEST AUDIT</span>
              ${ecoBadge}
            </div>
            <h3>AI-Powered SBOM Security Evaluation</h3>
          </div>
          <div>${getRiskBadge(data.riskLevel)}</div>
        </div>

        ${data.summary ? `
          <div style="margin: 12px 0 16px; padding: 12px 14px; background: var(--bg-tertiary); border-left: 3px solid var(--primary-600); border-radius: 4px; font-size: 0.88rem; color: var(--text-primary); line-height: 1.5;">
            <strong>AI Security Intelligence:</strong> ${data.summary}
          </div>
        ` : ''}

        <div class="results-summary-grid">
          <div class="summary-metric-box">
            <div class="label">Total Packages Audited</div>
            <div class="value">${data.totalDependencies || 0}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">Vulnerable / Malicious</div>
            <div class="value" style="color: ${data.vulnerableCount > 0 ? 'var(--severity-critical-text)' : 'var(--severity-low-text)'};">${data.vulnerableCount || 0}</div>
          </div>
          <div class="summary-metric-box">
            <div class="label">Overall Status</div>
            <div class="value" style="font-size: 1.15rem;">${data.riskLevel || 'Safe'}</div>
          </div>
        </div>

        <h4 style="font-family: var(--font-heading); font-size: 1.05rem; font-weight: 600; color: var(--primary-900); margin: 20px 0 10px;">Matched Vulnerabilities & Supply Chain Threats</h4>
        ${data.matchedVulnerabilities && data.matchedVulnerabilities.length > 0
          ? `
            <div class="table-wrapper">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Installed</th>
                    <th>Severity</th>
                    <th>Threat / CVE</th>
                    <th>CISA KEV</th>
                    <th>Remediation Guidance</th>
                  </tr>
                </thead>
                <tbody>
                  ${data.matchedVulnerabilities.map(v => `
                    <tr>
                      <td>
                        <strong>${v.package}</strong>
                        ${v.threatCategory ? `<div style="font-size: 0.72rem; color: var(--severity-critical-text); font-weight: 600;">${v.threatCategory}</div>` : ''}
                      </td>
                      <td><code>${v.version}</code></td>
                      <td>${getRiskBadge(v.severity)}</td>
                      <td>
                        <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 600;">${v.cveId}</span>
                        ${v.title ? `<div style="font-size: 0.75rem; color: var(--text-secondary); max-width: 200px;">${v.title}</div>` : ''}
                      </td>
                      <td>${v.cisaKev ? '<strong style="color: var(--severity-critical-text);">YES</strong>' : 'No'}</td>
                      <td style="font-size: 0.82rem; color: var(--primary-700);">${v.remediation}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `
          : (data.riskLevel === 'SAFE' 
              ? `<div style="padding: 16px; background-color: var(--severity-low-bg); border: 1px solid var(--severity-low-border); border-radius: var(--radius-md); color: var(--severity-low-text); font-size: 0.88rem;">All parsed dependencies are verified clean by live AI threat intelligence.</div>`
              : `<div style="padding: 16px; background-color: var(--severity-critical-bg); border: 1px solid var(--severity-critical-border); border-radius: var(--radius-md); color: var(--severity-critical-text); font-size: 0.88rem;">${data.summary || 'AI Model could not complete analysis. Check connection and API key.'}</div>`
            )
        }

        <div style="margin-top: 20px;">
          <h5 style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px;">Clean Packages</h5>
          <div style="display: flex; flex-wrap: wrap; gap: 6px;">
            ${data.cleanDependencies && data.cleanDependencies.length > 0
              ? data.cleanDependencies.map(pkg => `<span style="font-size: 0.8rem; background-color: var(--bg-tertiary); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border-default);">${pkg}</span>`).join('')
              : '<span style="font-size: 0.8rem; color: var(--text-muted);">None</span>'
            }
          </div>
        </div>
      </div>
    `;
  }

  // ==========================================================================
  // TOOL 5: LLM GATEWAY & WEBHOOKS
  // ==========================================================================
  const selectLlmProvider = document.getElementById('select-llm-provider');
  const inputLlmKey = document.getElementById('input-llm-key');
  const inputLlmModel = document.getElementById('input-llm-model');
  const inputCustomBaseUrl = document.getElementById('input-custom-base-url');
  const groupCustomBaseUrl = document.getElementById('group-custom-base-url');
  const labelLlmKey = document.getElementById('label-llm-key');
  const btnToggleKeyView = document.getElementById('btn-toggle-key-view');
  const btnSaveLlmConfig = document.getElementById('btn-save-llm-config');
  const btnTestLlmKey = document.getElementById('btn-test-llm-key');
  const btnResetLlmConfig = document.getElementById('btn-reset-llm-config');
  const llmStatusText = document.getElementById('llm-status-text');

  const providerInfo = {
    google: { label: 'Google Gemini API Key', placeholder: 'gemini-2.5-flash' },
    openai: { label: 'OpenAI API Key', placeholder: 'gpt-4o-mini' },
    anthropic: { label: 'Anthropic Claude API Key', placeholder: 'claude-3-5-sonnet-20241022' },
    groq: { label: 'Groq Cloud API Key', placeholder: 'llama-3.3-70b-versatile' },
    custom: { label: 'Custom Endpoint API Key (Optional)', placeholder: 'model-name' }
  };

  function updateLlmUI() {
    const prov = selectLlmProvider ? selectLlmProvider.value : 'google';
    const info = providerInfo[prov] || providerInfo.google;

    if (labelLlmKey) labelLlmKey.textContent = info.label;
    if (inputLlmModel) inputLlmModel.placeholder = `e.g. ${info.placeholder}`;

    if (groupCustomBaseUrl) {
      if (prov === 'custom') groupCustomBaseUrl.classList.remove('hidden');
      else groupCustomBaseUrl.classList.add('hidden');
    }
  }

  function loadSavedLlmConfig() {
    const savedProv = localStorage.getItem('secintel_llm_provider') || 'google';
    const savedKey = localStorage.getItem('secintel_user_api_key') || '';
    const savedModel = localStorage.getItem('secintel_llm_model') || '';
    const savedUrl = localStorage.getItem('secintel_base_url') || '';

    if (selectLlmProvider) selectLlmProvider.value = savedProv;
    if (inputLlmKey) inputLlmKey.value = savedKey;
    if (inputLlmModel) inputLlmModel.value = savedModel;
    if (inputCustomBaseUrl) inputCustomBaseUrl.value = savedUrl;

    updateLlmUI();

    if (llmStatusText) {
      if (savedKey || savedProv === 'custom') {
        llmStatusText.textContent = `LLM Engine: Configured for ${savedProv.toUpperCase()} (${savedModel || 'Default'}).`;
        llmStatusText.style.color = 'var(--primary-700)';
      } else {
        llmStatusText.textContent = 'LLM Engine: Operating with server default environment or simulation fallback.';
        llmStatusText.style.color = 'var(--text-secondary)';
      }
    }
  }

  if (selectLlmProvider) selectLlmProvider.addEventListener('change', updateLlmUI);

  if (btnToggleKeyView && inputLlmKey) {
    btnToggleKeyView.addEventListener('click', () => {
      if (inputLlmKey.type === 'password') {
        inputLlmKey.type = 'text';
        btnToggleKeyView.textContent = 'Hide';
      } else {
        inputLlmKey.type = 'password';
        btnToggleKeyView.textContent = 'Show';
      }
    });
  }

  if (btnSaveLlmConfig) {
    btnSaveLlmConfig.addEventListener('click', () => {
      const prov = selectLlmProvider.value;
      const key = inputLlmKey.value.trim();
      const model = inputLlmModel.value.trim();
      const url = inputCustomBaseUrl.value.trim();

      localStorage.setItem('secintel_llm_provider', prov);
      localStorage.setItem('secintel_user_api_key', key);
      localStorage.setItem('secintel_llm_model', model);
      localStorage.setItem('secintel_base_url', url);

      loadSavedLlmConfig();
      alert(`LLM settings for ${prov.toUpperCase()} saved.`);
    });
  }

  if (btnResetLlmConfig) {
    btnResetLlmConfig.addEventListener('click', () => {
      localStorage.removeItem('secintel_llm_provider');
      localStorage.removeItem('secintel_user_api_key');
      localStorage.removeItem('secintel_llm_model');
      localStorage.removeItem('secintel_base_url');
      loadSavedLlmConfig();
      alert('LLM settings reset to defaults.');
    });
  }

  if (btnTestLlmKey) {
    btnTestLlmKey.addEventListener('click', async () => {
      const prov = selectLlmProvider.value;
      const key = inputLlmKey.value.trim();
      const model = inputLlmModel.value.trim();
      const url = inputCustomBaseUrl.value.trim();

      if (llmStatusText) {
        llmStatusText.textContent = `Validating ${prov.toUpperCase()} connection...`;
        llmStatusText.style.color = 'var(--text-muted)';
      }

      try {
        const res = await fetch('/api/test-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: prov, apiKey: key, modelName: model, baseUrl: url })
        });
        const resData = await res.json();
        if (llmStatusText) {
          llmStatusText.textContent = resData.valid ? `Verified: ${resData.message}` : `Failed: ${resData.message}`;
          llmStatusText.style.color = resData.valid ? 'var(--severity-low-text)' : 'var(--severity-critical-text)';
        }
      } catch (err) {
        if (llmStatusText) {
          llmStatusText.textContent = 'Connection test failed: ' + err.message;
          llmStatusText.style.color = 'var(--severity-critical-text)';
        }
      }
    });
  }

  // Webhooks
  const selectWebhookPlatform = document.getElementById('select-webhook-platform');
  const inputWebhookUrl = document.getElementById('input-webhook-url');
  const btnSaveWebhook = document.getElementById('btn-save-webhook');
  const btnTestWebhook = document.getElementById('btn-test-webhook');
  const webhookFeedback = document.getElementById('webhook-feedback');

  if (inputWebhookUrl) inputWebhookUrl.value = localStorage.getItem('secintel_webhook_url') || '';
  if (selectWebhookPlatform) selectWebhookPlatform.value = localStorage.getItem('secintel_webhook_platform') || 'slack';

  if (btnSaveWebhook) {
    btnSaveWebhook.addEventListener('click', () => {
      localStorage.setItem('secintel_webhook_url', inputWebhookUrl.value.trim());
      localStorage.setItem('secintel_webhook_platform', selectWebhookPlatform.value);
      if (webhookFeedback) {
        webhookFeedback.textContent = 'Webhook configuration saved.';
        webhookFeedback.style.color = 'var(--severity-low-text)';
      }
    });
  }

  if (btnTestWebhook) {
    btnTestWebhook.addEventListener('click', async () => {
      const url = inputWebhookUrl.value.trim();
      const platform = selectWebhookPlatform.value;
      if (!url) {
        alert('Please enter a webhook URL first.');
        return;
      }

      if (webhookFeedback) {
        webhookFeedback.textContent = 'Sending test alert dispatch...';
        webhookFeedback.style.color = 'var(--text-muted)';
      }

      try {
        const res = await fetch('/api/send-webhook', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            webhookUrl: url,
            platform: platform,
            alertData: {
              title: "Test Security Alert: Incident Verification",
              cveId: "CVE-2024-TEST",
              severity: "CRITICAL",
              executiveSummary: "Automated alert verification dispatch from Security Intelligence Operations."
            }
          })
        });
        const resData = await res.json();
        if (webhookFeedback) {
          webhookFeedback.textContent = resData.message;
          webhookFeedback.style.color = resData.success ? 'var(--severity-low-text)' : 'var(--severity-high-text)';
        }
      } catch (err) {
        if (webhookFeedback) {
          webhookFeedback.textContent = 'Network error: ' + err.message;
          webhookFeedback.style.color = 'var(--severity-critical-text)';
        }
      }
    });
  }

  // ==========================================================================
  // HISTORY VIEW LOGIC
  // ==========================================================================
  const historyTableBody = document.getElementById('history-table-body');
  const inputHistorySearch = document.getElementById('input-history-search');
  const selectHistoryToolFilter = document.getElementById('select-history-tool-filter');
  const selectHistoryRiskFilter = document.getElementById('select-history-risk-filter');
  const btnRefreshHistory = document.getElementById('btn-refresh-history');

  async function loadHistoryRecords() {
    if (!historyTableBody) return;
    historyTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px;">Loading records...</td></tr>`;

    try {
      const res = await fetch('/api/user/history', { headers: getHeaders(true, false) });
      if (!res.ok) throw new Error('Could not fetch history.');
      historyRecords = await res.json();
      applyHistoryFilters();
    } catch (e) {
      historyTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--severity-critical-text);">${e.message}</td></tr>`;
    }
  }

  function applyHistoryFilters() {
    if (!historyTableBody) return;
    const query = inputHistorySearch ? inputHistorySearch.value.toLowerCase().trim() : '';
    const toolFilter = selectHistoryToolFilter ? selectHistoryToolFilter.value : 'all';
    const riskFilter = selectHistoryRiskFilter ? selectHistoryRiskFilter.value : 'all';

    let filtered = historyRecords;

    if (query) {
      filtered = filtered.filter(item =>
        (item.target && item.target.toLowerCase().includes(query)) ||
        (item.tool && item.tool.toLowerCase().includes(query)) ||
        (item.summary && item.summary.toLowerCase().includes(query))
      );
    }

    if (toolFilter !== 'all') {
      filtered = filtered.filter(item => item.tool === toolFilter);
    }

    if (riskFilter !== 'all') {
      filtered = filtered.filter(item => item.riskLevel.toUpperCase() === riskFilter);
    }

    if (filtered.length === 0) {
      historyTableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding: 36px; color: var(--text-muted);">
            No analysis records found matching your filters.
          </td>
        </tr>
      `;
      return;
    }

    historyTableBody.innerHTML = filtered.map((rec, idx) => `
      <tr>
        <td><strong>${rec.tool}</strong></td>
        <td style="font-family: var(--font-mono); font-size: 0.82rem; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${rec.target}</td>
        <td>${getRiskBadge(rec.riskLevel)}</td>
        <td>${rec.confidence}%</td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${formatDateTime(rec.createdAt)}</td>
        <td>
          <button type="button" class="btn btn-secondary btn-sm btn-view-history-detail" data-idx="${idx}">Inspect</button>
        </td>
      </tr>
    `).join('');

    // Attach inspect listeners
    historyTableBody.querySelectorAll('.btn-view-history-detail').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        showReportDetailModal(filtered[idx].target, filtered[idx].resultJson, filtered[idx].riskLevel);
      });
    });
  }

  if (inputHistorySearch) inputHistorySearch.addEventListener('input', applyHistoryFilters);
  if (selectHistoryToolFilter) selectHistoryToolFilter.addEventListener('change', applyHistoryFilters);
  if (selectHistoryRiskFilter) selectHistoryRiskFilter.addEventListener('change', applyHistoryFilters);
  if (btnRefreshHistory) btnRefreshHistory.addEventListener('click', loadHistoryRecords);

  // ==========================================================================
  // SAVED REPORTS VIEW LOGIC
  // ==========================================================================
  const reportsTableBody = document.getElementById('reports-table-body');

  async function loadSavedReports() {
    if (!reportsTableBody) return;
    reportsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px;">Loading reports...</td></tr>`;

    try {
      const res = await fetch('/api/user/reports', { headers: getHeaders(true, false) });
      if (!res.ok) throw new Error('Could not fetch saved reports.');
      savedReports = await res.json();

      if (savedReports.length === 0) {
        reportsTableBody.innerHTML = `
          <tr>
            <td colspan="5" style="text-align: center; padding: 36px; color: var(--text-muted);">
              No saved reports in repository. Save an advisory from the Tools analysis page to view it here.
            </td>
          </tr>
        `;
        return;
      }

      reportsTableBody.innerHTML = savedReports.map((rep, idx) => `
        <tr>
          <td><strong>${rep.reportName}</strong></td>
          <td style="font-family: var(--font-mono); font-size: 0.82rem;">${rep.target}</td>
          <td>${getRiskBadge(rep.riskLevel)}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${formatDateTime(rep.createdAt)}</td>
          <td>
            <div style="display: flex; gap: 6px;">
              <button type="button" class="btn btn-secondary btn-sm btn-view-report" data-rep-idx="${idx}">View</button>
              <button type="button" class="btn btn-secondary btn-sm btn-export-rep-md" data-rep-idx="${idx}">Markdown</button>
              <button type="button" class="btn btn-danger btn-sm btn-delete-rep" data-rep-id="${rep.id}">Delete</button>
            </div>
          </td>
        </tr>
      `).join('');

      // Bind actions
      reportsTableBody.querySelectorAll('.btn-view-report').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.getAttribute('data-rep-idx'), 10);
          showReportDetailModal(savedReports[idx].reportName, savedReports[idx].content, savedReports[idx].riskLevel);
        });
      });

      reportsTableBody.querySelectorAll('.btn-export-rep-md').forEach(btn => {
        btn.addEventListener('click', async () => {
          const idx = parseInt(btn.getAttribute('data-rep-idx'), 10);
          const rep = savedReports[idx];
          downloadTextFile(`report_${rep.id}.json`, JSON.stringify(rep.content, null, 2), 'application/json');
        });
      });

      reportsTableBody.querySelectorAll('.btn-delete-rep').forEach(btn => {
        btn.addEventListener('click', async () => {
          const repId = btn.getAttribute('data-rep-id');
          if (!confirm('Are you sure you want to delete this saved report?')) return;
          try {
            await fetch(`/api/user/reports/${repId}`, {
              method: 'DELETE',
              headers: getHeaders(true, false)
            });
            loadSavedReports();
          } catch (e) {
            alert('Delete failed: ' + e.message);
          }
        });
      });

    } catch (err) {
      reportsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px; color: var(--severity-critical-text);">${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // REPORT DETAIL MODAL
  // ==========================================================================
  const modalReportDetail = document.getElementById('modal-report-detail');
  const modalReportTitle = document.getElementById('modal-report-title');
  const modalReportBody = document.getElementById('modal-report-body');
  const btnCloseReportModal = document.getElementById('btn-close-report-modal');
  const btnCloseReportModal2 = document.getElementById('btn-close-report-modal-2');

  function showReportDetailModal(title, contentObj, riskLevel) {
    if (!modalReportDetail || !modalReportBody) return;
    if (modalReportTitle) modalReportTitle.textContent = title || 'Report Details';

    modalReportBody.innerHTML = `
      <div style="margin-bottom: 16px;">
        <span style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted);">EVALUATED RISK:</span>
        ${getRiskBadge(riskLevel)}
      </div>
      <div style="background-color: var(--bg-tertiary); padding: 16px; border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; max-height: 50vh; overflow-y: auto;">
${JSON.stringify(contentObj, null, 2)}
      </div>
    `;

    modalReportDetail.classList.remove('hidden');
  }

  if (btnCloseReportModal) btnCloseReportModal.addEventListener('click', () => modalReportDetail.classList.add('hidden'));
  if (btnCloseReportModal2) btnCloseReportModal2.addEventListener('click', () => modalReportDetail.classList.add('hidden'));

  // ==========================================================================
  // FILE DOWNLOAD HELPER
  // ==========================================================================
  function downloadTextFile(filename, content, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'security_intelligence_export.txt';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  // ==========================================================================
  // PRICING PAGE CONTROLLER
  // ==========================================================================
  const billingMonthlyBtn = document.getElementById('billing-monthly-btn');
  const billingAnnualBtn = document.getElementById('billing-annual-btn');
  const priceValPro = document.getElementById('price-val-pro');
  const priceNotePro = document.getElementById('price-note-pro');
  const priceValEnt = document.getElementById('price-val-ent');
  const priceNoteEnt = document.getElementById('price-note-ent');

  let currentBillingCycle = 'monthly';

  function setBillingCycle(cycle) {
    currentBillingCycle = cycle;
    if (cycle === 'annual') {
      if (billingAnnualBtn) billingAnnualBtn.classList.add('active');
      if (billingMonthlyBtn) billingMonthlyBtn.classList.remove('active');
      if (priceValPro) priceValPro.textContent = '39';
      if (priceNotePro) priceNotePro.textContent = 'Billed annually ($468/yr - 20% savings)';
      if (priceValEnt) priceValEnt.textContent = '159';
      if (priceNoteEnt) priceNoteEnt.textContent = 'Billed annually ($1,908/yr - 20% savings)';
    } else {
      if (billingMonthlyBtn) billingMonthlyBtn.classList.add('active');
      if (billingAnnualBtn) billingAnnualBtn.classList.remove('active');
      if (priceValPro) priceValPro.textContent = '49';
      if (priceNotePro) priceNotePro.textContent = 'Billed monthly ($588/yr)';
      if (priceValEnt) priceValEnt.textContent = '199';
      if (priceNoteEnt) priceNoteEnt.textContent = 'Billed monthly ($2,388/yr)';
    }
  }

  if (billingMonthlyBtn) billingMonthlyBtn.addEventListener('click', () => setBillingCycle('monthly'));
  if (billingAnnualBtn) billingAnnualBtn.addEventListener('click', () => setBillingCycle('annual'));

  // Pricing Plan CTA buttons
  const btnTierCommunity = document.getElementById('btn-tier-community');
  const btnTierPro = document.getElementById('btn-tier-pro');
  const btnTierEnterprise = document.getElementById('btn-tier-enterprise');
  const btnTierCustom = document.getElementById('btn-tier-custom');

  if (btnTierCommunity) {
    btnTierCommunity.addEventListener('click', () => {
      navigateTo(currentUser ? 'tools' : 'register');
    });
  }

  if (btnTierPro) {
    btnTierPro.addEventListener('click', () => {
      if (currentUser) {
        navigateTo('settings');
      } else {
        navigateTo('register');
      }
    });
  }

  if (btnTierEnterprise) {
    btnTierEnterprise.addEventListener('click', () => {
      if (currentUser) {
        navigateTo('settings');
      } else {
        navigateTo('register');
      }
    });
  }

  if (btnTierCustom) {
    btnTierCustom.addEventListener('click', () => {
      navigateTo('docs');
      const offlineDoc = document.getElementById('doc-offline-deployment');
      if (offlineDoc) offlineDoc.scrollIntoView({ behavior: 'smooth' });
    });
  }

  // ==========================================================================
  // DOCUMENTATION PORTAL ENHANCEMENTS
  // ==========================================================================
  const docSearchInput = document.getElementById('doc-search-input');
  const docNavItems = document.querySelectorAll('.doc-nav-item');
  const docCategoryGroups = document.querySelectorAll('.doc-category-group');

  if (docSearchInput) {
    docSearchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();

      docCategoryGroups.forEach(group => {
        let groupHasMatch = false;
        const items = group.querySelectorAll('.doc-nav-item');

        items.forEach(item => {
          const text = item.textContent.toLowerCase();
          const targetId = item.querySelector('a')?.getAttribute('href')?.replace('#', '');
          const article = targetId ? document.getElementById(targetId) : null;
          const articleText = article ? article.textContent.toLowerCase() : '';

          if (!q || text.includes(q) || articleText.includes(q)) {
            item.style.display = 'block';
            groupHasMatch = true;
          } else {
            item.style.display = 'none';
          }
        });

        group.style.display = groupHasMatch ? 'block' : 'none';
      });
    });
  }

  // Doc Code Snippet Copy Buttons
  document.querySelectorAll('.doc-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const codeBlock = btn.closest('.doc-code-block');
      const codeElement = codeBlock ? codeBlock.querySelector('code') : null;
      if (codeElement) {
        const text = codeElement.innerText;
        navigator.clipboard.writeText(text).then(() => {
          const orig = btn.textContent;
          btn.textContent = 'Copied!';
          btn.style.borderColor = '#22c55e';
          btn.style.color = '#22c55e';
          setTimeout(() => {
            btn.textContent = orig;
            btn.style.borderColor = '';
            btn.style.color = '';
          }, 2000);
        }).catch(() => {
          btn.textContent = 'Failed';
        });
      }
    });
  });

  // Doc Navigation smooth active item highlight
  docNavItems.forEach(item => {
    const link = item.querySelector('a');
    if (link) {
      link.addEventListener('click', (e) => {
        docNavItems.forEach(i => i.classList.remove('active'));
        item.classList.add('active');
      });
    }
  });

  // ==========================================================================
  // ABOUT PAGE INTERACTIVE CONTROLLERS
  // ==========================================================================
  const pillarNavBtns = document.querySelectorAll('.pillar-nav-btn');
  const pillarCardDisplay = document.getElementById('pillar-card-display');

  const pillarData = {
    'explainable': {
      badge: 'GROUNDED IN EVIDENCE',
      heading: 'Zero-Hallucination Threat Grounding',
      text: 'Unlike generic chatbots that guess at vulnerability mechanics, Security Intelligence uses a strict <strong>deterministic sandbox pipeline</strong>. We crawl HTML DOMs, inspect form submission vectors, verify SSL certificate chains, and pull raw RDAP registration telemetry. The AI never invents facts; it translates verified telemetry into structured incident response guidance.',
      features: [
        { title: 'UCI Machine Learning Vectors:', desc: '12 calibrated phishing indicators (prefix/suffix tricks, @-symbols, suspicious subdomains).' },
        { title: 'Cryptographic Inspection:', desc: 'Validates TLS expiration, issuer reputation, and self-signed certificates.' },
        { title: 'Verifiable Reasoning:', desc: 'Separates observed empirical data from AI-generated analytical commentary.' }
      ]
    },
    'sovereign': {
      badge: 'AIR-GAPPED & ON-PREM',
      heading: '100% Sovereign & Local Model Execution',
      text: 'For sensitive defense, financial, and healthcare networks where data egress is forbidden, Security Intelligence operates completely offline. Connect directly to local self-hosted inference servers (Ollama, vLLM, LMStudio) using open-weights models like Llama 3 or Mistral without sending telemetry to external clouds.',
      features: [
        { title: 'Zero Data Leakage:', desc: 'Proprietary source code, URLs, and internal logs never leave your private VPC.' },
        { title: 'Local Caching Proxies:', desc: 'Offline mirrors for CISA KEV catalogs, NIST NVD, and RDAP registration stores.' },
        { title: 'Hardware Optimization:', desc: 'Runs efficiently on standard GPU workstations or quantized CPU inference.' }
      ]
    },
    'threat-intel': {
      badge: 'AUTHORITATIVE FEEDS',
      heading: 'Unified Threat Intelligence Convergence',
      text: 'Cyber incidents require cross-referencing multiple authoritative sources in seconds. Security Intelligence converges real-time security bulletins from CISA, BleepingComputer, and ZDI with official CVE records and the CISA Known Exploited Vulnerabilities (KEV) catalog.',
      features: [
        { title: 'CISA KEV Verification:', desc: 'Instant confirmation of active exploitation in the wild by nation-state actors.' },
        { title: 'MITRE ATT&CK Mapping:', desc: 'Correlates vulnerabilities to specific enterprise Tactics, Techniques, and Procedures.' },
        { title: 'NIST NVD CVSS v3.1:', desc: 'Pulls exact vector strings and base metrics for risk prioritization.' }
      ]
    },
    'compliance': {
      badge: 'REGULATORY COMPLIANCE',
      heading: 'Incident Response & Governance Readiness',
      text: 'Under directives like EU NIS2 and GDPR, organizations face stringent 24-to-72-hour incident disclosure mandates. Security Intelligence produces standardized Markdown and JSON reports detailing affected systems, root causes, and remediation evidence ready for audit review.',
      features: [
        { title: 'NIS2 & GDPR Ready:', desc: 'Structured timeline exports and breach assessment templates for DPO notifications.' },
        { title: 'SOC2 Type II Audit Trail:', desc: 'Persistent investigation history logs with cryptographic user attribution.' },
        { title: 'Executive & Engineering Formats:', desc: 'Dual-format exports tailored for C-suite briefings or DevOps Jira tickets.' }
      ]
    }
  };

  pillarNavBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      pillarNavBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const pillarKey = btn.getAttribute('data-pillar');
      const data = pillarData[pillarKey];
      if (data && pillarCardDisplay) {
        pillarCardDisplay.innerHTML = `
          <div class="pillar-panel active">
            <div class="pillar-badge">${data.badge}</div>
            <h3 class="pillar-heading">${data.heading}</h3>
            <p class="pillar-text">${data.text}</p>
            <div class="pillar-features-grid">
              ${data.features.map(f => `
                <div class="pillar-feature-item">
                  <strong>${f.title}</strong> ${f.desc}
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    });
  });

  // Interactive Architecture Inspector
  const archNodes = document.querySelectorAll('.arch-stage-node');
  const archDetailBadge = document.getElementById('arch-detail-badge');
  const archDetailTitle = document.getElementById('arch-detail-title');
  const archDetailDesc = document.getElementById('arch-detail-desc');
  const archDetailSpecs = document.getElementById('arch-detail-specs');

  const archStagesData = {
    'ingest': {
      badge: 'STAGE 1: TARGET INGESTION',
      title: 'Target Normalization & Safe Ingestion',
      desc: 'Accepts suspect URLs, domain names, security advisories, or software manifest files (SBOM). Inputs are sanitized, normalized against RFC 3986 standards, and passed to non-rendering sandboxes with strict timeout boundaries to prevent SSRF and local network traversal.',
      specs: [
        { label: 'Max Input Timeout:', value: '8.0 seconds' },
        { label: 'Network Isolation:', value: 'Private IP loopback blocking' },
        { label: 'Supported Formats:', value: 'URLs, Domains, RSS 2.0/Atom, pip/npm manifests' }
      ]
    },
    'sandbox': {
      badge: 'STAGE 2: ISOLATED SANDBOX',
      title: 'Headless Sandboxing & Heuristic Extraction',
      desc: 'Non-rendering asynchronous sandboxes safely inspect the target web asset. The crawler extracts raw HTML DOM trees, form action endpoints, SSL/TLS certificate chains, and performs RDAP registration queries to determine domain longevity.',
      specs: [
        { label: 'Inspection Depth:', value: 'Form handlers, redirect chains, certificate issuer' },
        { label: 'Execution Safety:', value: 'Zero client-side JS execution' },
        { label: 'Heuristic Models:', value: '30-vector UCI benchmark analyzer' }
      ]
    },
    'intel': {
      badge: 'STAGE 3: THREAT INTEL CORRELATION',
      title: 'Vulnerability & Exploitation Catalog Matching',
      desc: 'Observed artifacts and CVE entities are correlated against the live CISA Known Exploited Vulnerabilities (KEV) cache, NIST NVD CVSS v3.1 database, and MITRE ATT&CK enterprise enterprise matrix.',
      specs: [
        { label: 'KEV Correlation:', value: 'Active exploit verification in the wild' },
        { label: 'TTP Mapping:', value: 'Adversary tactic & technique assignment' },
        { label: 'Severity Calibration:', value: 'Context-aware risk scoring' }
      ]
    },
    'ai': {
      badge: 'STAGE 4: MULTI-LLM GATEWAY',
      title: 'Context-Grounded AI Synthesis Engine',
      desc: 'The platform packages verified empirical telemetry into a tamper-proof prompt template and routes it through our multi-LLM gateway (Google Gemini, OpenAI, Claude, Groq, or Local Ollama/vLLM) with strict grounding guardrails.',
      specs: [
        { label: 'Provider Agnostic:', value: 'Cloud or 100% on-premises offline models' },
        { label: 'Prompt Grounding:', value: 'Strict zero-hallucination constraint rules' },
        { label: 'Response Latency:', value: 'Sub-second streaming synthesis' }
      ]
    },
    'ops': {
      badge: 'STAGE 5: SECOPS ACTION PLAN',
      title: 'Actionable Incident Guidance & Report Export',
      desc: 'Outputs structured executive digests, technical exposure breakdowns, prioritized engineering checklists, custom SIEM/KQL hunting queries, and exportable Markdown/JSON advisories ready for incident response.',
      specs: [
        { label: 'Export Formats:', value: 'Markdown (.md), JSON, PDF-ready HTML' },
        { label: 'SIEM Integration:', value: 'Automated webhook dispatch to Slack/Teams/SIEM' },
        { label: 'Interactive Chat:', value: 'Real-time AI Security Analyst Q&A assistant' }
      ]
    }
  };

  archNodes.forEach(node => {
    node.addEventListener('click', () => {
      archNodes.forEach(n => n.classList.remove('active'));
      node.classList.add('active');
      const stageKey = node.getAttribute('data-stage');
      const stage = archStagesData[stageKey];
      if (stage && archDetailTitle && archDetailDesc) {
        if (archDetailBadge) archDetailBadge.textContent = stage.badge;
        archDetailTitle.textContent = stage.title;
        archDetailDesc.textContent = stage.desc;
        if (archDetailSpecs) {
          archDetailSpecs.innerHTML = stage.specs.map(s => `
            <div class="arch-spec-item"><strong>${s.label}</strong> ${s.value}</div>
          `).join('');
        }
      }
    });
  });

  // Interactive FAQ Accordion
  document.querySelectorAll('.about-faq-question').forEach(btn => {
    btn.addEventListener('click', () => {
      const answer = btn.nextElementSibling;
      const isExpanded = btn.classList.contains('active');
      
      // Close other open FAQs
      document.querySelectorAll('.about-faq-question').forEach(b => {
        b.classList.remove('active');
        if (b.nextElementSibling) b.nextElementSibling.classList.remove('show');
      });

      if (!isExpanded && answer) {
        btn.classList.add('active');
        answer.classList.add('show');
      }
    });
  });

  // About CTA Buttons
  const btnAboutGotoTools = document.getElementById('btn-about-goto-tools');
  const btnAboutGotoDocs = document.getElementById('btn-about-goto-docs');
  if (btnAboutGotoTools) {
    btnAboutGotoTools.addEventListener('click', () => switchView('tools'));
  }
  if (btnAboutGotoDocs) {
    btnAboutGotoDocs.addEventListener('click', () => switchView('docs'));
  }

  // ==========================================================================
  // INITIALIZATION ON BOOT
  // ==========================================================================
  loadSavedLlmConfig();
  checkSession();
  loadThreatFeeds();

});

