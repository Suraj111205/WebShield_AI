/**
 * WebShield AI - Dynamic Autonomous Security Advisor & Scanner
 * Starts clean and fresh on page load/reload as requested.
 */

let currentScanData = null;
let activeFilter = 'ALL';
let isScanning = false;
let simulationInterval = null;
let currentSelectedLevel = 'basic';

const SCAN_LEVEL_DATA = {
    basic: {
        name: "Basic Scan",
        sub: "A quick surface check - great for beginners.",
        depth: 0,
        checks: [
            "SSL/TLS certificate validity (Is your site using HTTPS?)",
            "Security headers missing (X-Frame-Options, CSP, etc.)",
            "Exposed admin pages (e.g. /admin, /login easily found)",
            "Directory listing enabled (visitors can browse your files)",
            "Outdated software versions detected",
            "Open ports that shouldn't be public"
        ]
    },
    medium: {
        name: "Medium Scan",
        sub: "Follows all direct links & checks forms - recommended for most sites.",
        depth: 1,
        checks: [
            "Everything in Basic Scan",
            "Level-1 Breadth-First Search link crawling (up to 10 pages)",
            "Unencrypted HTTP form submissions detection",
            "Missing Anti-CSRF protection tokens on HTML forms",
            "Sensitive internal routes and login endpoints",
            "Clickjacking vulnerability verification"
        ]
    },
    deep: {
        name: "Deep Scan",
        sub: "Thorough multi-page crawler & deep security audit - up to 25 pages.",
        depth: 2,
        checks: [
            "Everything in Basic & Medium scans",
            "Deep 2-level BFS queue traversal across site tree",
            "Cookie security flags check (HttpOnly, Secure, SameSite)",
            "Backup & hidden file exposure audit (.git, .env, .bak)",
            "Cross-Site Scripting (XSS) input surface mapping",
            "Full Executive PDF report generation with fix guidance"
        ]
    }
};

// ==========================================================================
// Fresh Startup & Clean Slate on Page Reload
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
    // 1. Clear any lingering previous scan data so reload always deletes old information
    cleanReloadState();

    // 2. Initialize input synchronizers
    initTargetSync();

    // 3. Reset to default Basic Scan level
    selectScannerLevel('basic');

    // 4. Always reset chat history to clean state on fresh page load/reload
    clearChatHistory();

    // 6. Initialize user authentication state and scan quota
    initAuthAndQuota();
});

function cleanReloadState() {
    // Clear stored previous scans, target URLs, and chat history so page is completely fresh
    localStorage.removeItem("webshield_last_scan");
    localStorage.removeItem("webshield_target_url");
    localStorage.removeItem("webshield_terminal_logs");
    localStorage.removeItem("webshield_chat_history");
    clearChatHistory();
    currentScanData = null;

    // Reset guest scan quota session on reload so each refresh resets free scans back to 2
    const freshGuestId = "guest_" + Date.now() + "_" + Math.random().toString(36).substring(2, 10);
    localStorage.setItem("webshield_guest_id", freshGuestId);
    sessionStorage.setItem("webshield_guest_id", freshGuestId);

    // Reset input fields to empty
    const cardUrl = document.getElementById("card-target-url");
    const targetInput = document.getElementById("target-url");
    if (cardUrl) cardUrl.value = "";
    if (targetInput) targetInput.value = "";

    // Hide results dashboard and telemetry card
    const dashboard = document.getElementById("results-dashboard");
    const telemetry = document.getElementById("telemetry-card");
    if (dashboard) dashboard.style.display = "none";
    if (telemetry) telemetry.style.display = "none";

    // Reset stepper and OWASP pills
    resetStepper();
    resetOwaspPills();

    // Reset terminal log to clean greeting
    const terminal = document.getElementById("terminal-body");
    if (terminal) {
        terminal.innerHTML = `
            <div class="log-entry">
                <span class="log-ts">[00:00.00]</span> 
                <span class="log-info">INFO:</span> WebShield AI Security Advisor ready. Choose a scan mode and enter your website URL above.
            </div>
        `;
    }
}

function initTargetSync() {
    const cardUrl = document.getElementById("card-target-url");
    const targetInput = document.getElementById("target-url");
    const protocolSelect = document.getElementById("protocol-select");

    if (cardUrl) {
        cardUrl.addEventListener("input", () => {
            const val = cardUrl.value.trim();
            if (targetInput) {
                targetInput.value = val.replace(/^(https?:\/\/)+/gi, '').trim();
            }
        });
    }

    if (targetInput) {
        targetInput.addEventListener("input", () => {
            let val = targetInput.value.trim();
            if (val.toLowerCase().startsWith("http://")) {
                if (protocolSelect) protocolSelect.value = "http://";
                targetInput.value = val.substring(7);
            } else if (val.toLowerCase().startsWith("https://")) {
                if (protocolSelect) protocolSelect.value = "https://";
                targetInput.value = val.substring(8);
            }
            const full = getFullTargetUrl();
            if (cardUrl) cardUrl.value = full;
        });
    }
}

function initHeroCounters() {
    // Honest static metrics - no fake counter animation
}

function restoreChatHistory() {
    clearChatHistory();
}

function clearChatHistory() {
    const stream = document.getElementById("drawer-chat-stream");
    if (stream) {
        stream.innerHTML = `
            <div class="chat-bubble bot">
                Hello! I am your <strong>WebShield AI Security Advisor</strong>. I am here to help you understand your website security in plain, easy English! Ask me any question about what we found on your website, OWASP Top 10 risks, or how to easily fix vulnerabilities.
            </div>
        `;
    }
    localStorage.removeItem("webshield_chat_history");
}

function resetScanResults() {
    cleanReloadState();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ==========================================================================
// Dynamic OWASP Matrix Integration
// ==========================================================================
function updateOwaspMatrixStatus(vulnerabilities) {
    const counts = {
        'A01': 0, 'A02': 0, 'A03': 0, 'A04': 0, 'A05': 0,
        'A06': 0, 'A07': 0, 'A08': 0, 'A09': 0, 'A10': 0
    };

    vulnerabilities.forEach(v => {
        const cat = (v.owasp_category || '').toUpperCase();
        for (let code in counts) {
            if (cat.includes(code)) {
                counts[code]++;
            }
        }
    });

    for (let code in counts) {
        const pill = document.getElementById(`owasp-status-${code}`);
        if (!pill) continue;
        const count = counts[code];
        if (count > 0) {
            pill.className = "owasp-status-pill flagged";
            pill.innerHTML = `${count} ${count === 1 ? 'Issue' : 'Issues'} Found`;
        } else {
            pill.className = "owasp-status-pill clean";
            pill.innerHTML = `Safe (Clean)`;
        }
    }
}

function resetOwaspPills() {
    for (let i = 1; i <= 10; i++) {
        const code = i < 10 ? `A0${i}` : `A${i}`;
        const pill = document.getElementById(`owasp-status-${code}`);
        if (pill) {
            pill.className = "owasp-status-pill pending";
            pill.innerHTML = `Ready to Audit`;
        }
    }
}

// ==========================================================================
// Scanner Level & Mode Selection
// ==========================================================================
function selectScannerLevel(level) {
    currentSelectedLevel = level;
    const data = SCAN_LEVEL_DATA[level];
    if (!data) return;

    // Update active tab buttons
    document.querySelectorAll(".scan-tab-btn").forEach(btn => btn.classList.remove("active"));
    const activeTab = document.getElementById(`tab-scan-${level}`);
    if (activeTab) activeTab.classList.add("active");

    // Update mode title & description
    const modeNameEl = document.getElementById("scan-mode-name");
    const modeDescEl = document.getElementById("scan-mode-desc");
    if (modeNameEl) modeNameEl.textContent = data.name;
    if (modeDescEl) modeDescEl.textContent = data.sub;

    // Update checklist
    const listEl = document.getElementById("what-we-check-list");
    if (listEl) {
        listEl.innerHTML = data.checks.map(item => `
            <div class="check-feature-item">
                <span class="icon" style="font-weight: 700;">+</span>
                <span>${escapeHtml(item)}</span>
            </div>
        `).join("");
    }

    // Sync crawl-depth dropdown
    const crawlDepthSelect = document.getElementById("crawl-depth");
    if (crawlDepthSelect) {
        crawlDepthSelect.value = String(data.depth);
    }
}

// ==========================================================================
// Target Helpers
// ==========================================================================
function getFullTargetUrl() {
    const cardInput = document.getElementById("card-target-url");
    if (cardInput && cardInput.value.trim()) {
        let v = cardInput.value.trim();
        if (!v.startsWith("http://") && !v.startsWith("https://")) {
            v = "https://" + v;
        }
        return v;
    }

    let url = document.getElementById("target-url").value.trim();
    url = url.replace(/^(https?:\/\/)+/gi, '').trim();
    const protocol = (document.getElementById("protocol-select") && document.getElementById("protocol-select").value) || "https://";
    return protocol + url;
}

function fillTarget(rawTarget) {
    const cardInput = document.getElementById("card-target-url");
    const targetInput = document.getElementById("target-url");
    const protocolSelect = document.getElementById("protocol-select");

    let clean = (rawTarget || '').trim();
    let protocol = "https://";

    if (clean.toLowerCase().startsWith("http://")) {
        protocol = "http://";
        clean = clean.substring(7);
    } else if (clean.toLowerCase().startsWith("https://")) {
        protocol = "https://";
        clean = clean.substring(8);
    }

    clean = clean.replace(/^(https?:\/\/)+/gi, '').replace(/\/+$/, '');

    if (targetInput) targetInput.value = clean;
    if (protocolSelect) protocolSelect.value = protocol;
    if (cardInput) cardInput.value = clean ? (protocol + clean) : "";
}

// ==========================================================================
// Scan Launchers
// ==========================================================================
function launchCardScan() {
    const cardInput = document.getElementById("card-target-url");
    let target = cardInput ? cardInput.value.trim() : "";
    if (!target) {
        alert("Please enter a website URL to scan (e.g. example.com)");
        if (cardInput) cardInput.focus();
        return;
    }
    fillTarget(target);

    const depthSelect = document.getElementById("crawl-depth");
    if (depthSelect) {
        depthSelect.value = String(SCAN_LEVEL_DATA[currentSelectedLevel].depth);
    }

    launchAutonomousScan();
}

async function launchAutonomousScan() {
    if (isScanning) return;

    // Check if guest has exhausted the 2-scan limit before launching
    if (!currentUser && currentQuota && currentQuota.remaining <= 0) {
        openLimitModal("Your free credits are over");
        addTerminalLog("ERROR", "Your free credits are over! Please sign in or register for unlimited scans.");
        return;
    }

    const target = getFullTargetUrl();
    const depth = parseInt(document.getElementById("crawl-depth").value, 10) || 0;
    const speed = document.getElementById("scan-speed") ? document.getElementById("scan-speed").value : "Balanced";

    if (!target || target === "https://" || target === "http://") {
        alert("Please enter a valid website address to scan.");
        return;
    }

    isScanning = true;
    const startBtn = document.getElementById("btn-card-start");
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.innerHTML = `<span>Scanning Website...</span>`;
    }

    showTelemetryCard();
    resetStepper();
    document.getElementById("telemetry-card").scrollIntoView({ behavior: 'smooth' });

    addTerminalLog("INFO", `Launching WebShield AI scan against: ${target}`);
    addTerminalLog("INFO", `Configuration: Level=${currentSelectedLevel.toUpperCase()} (Depth=${depth}), Engine=BFS Session Pool`);

    startProgressSimulation();

    try {
        const token = getAuthToken();
        const guestId = getGuestId();

        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": token ? `Bearer ${token}` : "",
                "x-auth-token": token,
                "x-guest-id": guestId
            },
            body: JSON.stringify({
                target_url: target,
                crawl_depth: depth,
                scan_speed: speed,
                report_format: "PDF",
                authorized: true
            })
        });

        const data = await response.json();

        // Check if guest scan limit reached
        if (data.limit_reached || data.error_code === "SCAN_LIMIT_REACHED") {
            if (simulationInterval) clearInterval(simulationInterval);
            isScanning = false;
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = `
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    <span>Start Free Scan</span>
                `;
            }
            if (data.quota) updateQuotaUI(data.quota);
            openLimitModal("Your free credits are over");
            addTerminalLog("ERROR", "Your free credits are over! Please sign in or register for unlimited scans.");
            return;
        }

        if (!response.ok || data.status === "error") {
            throw new Error(data.message || `Scan request failed with HTTP ${response.status}`);
        }

        // Update quota on successful scan
        if (data.quota) {
            updateQuotaUI(data.quota);
        }

        if (simulationInterval) clearInterval(simulationInterval);
        for (let i = 1; i <= 5; i++) {
            setStepStatus(i, 'completed');
        }
        updateProgress(100, "Website Scan Completed Successfully");

        addTerminalLog("SUCCESS", `Scan finished for ${data.target}!`);
        addTerminalLog("SUCCESS", `Found ${data.crawl.pages} pages, ${data.crawl.forms} forms, and ${data.crawl.endpoints} links.`);
        addTerminalLog("INFO", `Report generated: ${data.report}`);

        currentScanData = data;

        // Render results and update OWASP badges
        setTimeout(() => {
            renderScanResults(data);
            updateOwaspMatrixStatus(data.vulnerabilities || []);
            document.getElementById("results-dashboard").scrollIntoView({ behavior: 'smooth' });
        }, 500);

    } catch (err) {
        if (simulationInterval) clearInterval(simulationInterval);
        addTerminalLog("ERROR", `Scan Failed: ${err.message}`);
        alert(`Scan failed: ${err.message}`);
    } finally {
        isScanning = false;
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <span>Start Free Scan</span>
            `;
        }
    }
}

// ==========================================================================
// Telemetry & Progress
// ==========================================================================
function showTelemetryCard() {
    const card = document.getElementById("telemetry-card");
    if (card) card.style.display = "block";
}

function resetStepper() {
    for (let i = 1; i <= 5; i++) {
        const step = document.getElementById(`step-${i}`);
        if (step) step.className = "step-node";
    }
    setStepStatus(1, 'active');
    updateProgress(5, "Connecting to target website...");
}

function setStepStatus(stepNum, status) {
    const step = document.getElementById(`step-${stepNum}`);
    if (!step) return;
    step.className = `step-node ${status}`;
}

function updateProgress(pct, label) {
    const fill = document.getElementById("progress-bar-fill");
    const pctEl = document.getElementById("pipeline-pct");
    const labelEl = document.getElementById("pipeline-status-label");
    if (fill) fill.style.width = `${pct}%`;
    if (pctEl) pctEl.innerText = `${pct}%`;
    if (label && labelEl) labelEl.innerText = label;
}

function addTerminalLog(type, msg) {
    const terminal = document.getElementById("terminal-body");
    if (!terminal) return;

    const now = new Date();
    const timeStr = `${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(Math.floor(now.getMilliseconds() / 10)).padStart(2, '0')}`;

    let typeClass = "log-info";
    if (type === "SUCCESS") typeClass = "log-success";
    else if (type === "WARN") typeClass = "log-warn";
    else if (type === "ERROR") typeClass = "log-err";

    const entry = document.createElement("div");
    entry.className = "log-entry";
    entry.innerHTML = `<span class="log-ts">[${timeStr}]</span> <span class="${typeClass}">${type}:</span> ${escapeHtml(msg)}`;
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;
}

function startProgressSimulation() {
    let tick = 0;
    if (simulationInterval) clearInterval(simulationInterval);

    simulationInterval = setInterval(() => {
        tick++;
        if (tick === 2) {
            setStepStatus(1, 'completed');
            setStepStatus(2, 'active');
            updateProgress(25, "Crawling pages with BFS algorithm...");
            addTerminalLog("INFO", "Following internal links and mapping website structure...");
        } else if (tick === 6) {
            setStepStatus(2, 'completed');
            setStepStatus(3, 'active');
            updateProgress(55, "Running passive safety checks...");
            addTerminalLog("INFO", "Inspecting headers (CSP, HSTS, X-Frame-Options) and HTML forms...");
        } else if (tick === 11) {
            setStepStatus(3, 'completed');
            setStepStatus(4, 'active');
            updateProgress(78, "AI Advisor reviewing findings...");
            addTerminalLog("INFO", "Grouping issues by OWASP categories and severity...");
        } else if (tick === 15) {
            setStepStatus(4, 'completed');
            setStepStatus(5, 'active');
            updateProgress(92, "Creating PDF report...");
        }
    }, 450);
}

// ==========================================================================
// Dashboard & Findings Rendering
// ==========================================================================
function renderScanResults(data) {
    const dashboard = document.getElementById("results-dashboard");
    if (!dashboard) return;
    dashboard.style.display = "block";

    const verify = data.verification || {};
    const statusCodeEl = document.getElementById("metric-status-code");
    const domainEl = document.getElementById("metric-target-domain");
    if (statusCodeEl) statusCodeEl.innerText = verify.status_code || 200;
    if (domainEl) domainEl.innerText = data.target;

    const crawl = data.crawl || {};
    const crawledPagesEl = document.getElementById("metric-crawled-pages");
    const formsCountEl = document.getElementById("metric-forms-count");
    const endpointsCountEl = document.getElementById("metric-endpoints-count");
    if (crawledPagesEl) crawledPagesEl.innerText = crawl.pages || 0;
    if (formsCountEl) formsCountEl.innerText = crawl.forms || 0;
    if (endpointsCountEl) endpointsCountEl.innerText = crawl.endpoints || 0;

    const vulns = data.vulnerabilities || [];
    const findingsCountEl = document.getElementById("metric-findings-count");
    if (findingsCountEl) findingsCountEl.innerText = vulns.length;

    let high = 0, med = 0, low = 0;
    vulns.forEach(v => {
        if (v.severity === 'Critical' || v.severity === 'High') high++;
        else if (v.severity === 'Medium') med++;
        else low++;
    });
    const breakdownEl = document.getElementById("metric-findings-breakdown");
    if (breakdownEl) breakdownEl.innerText = `${high} High • ${med} Med • ${low} Low`;

    const pdfBtn = document.getElementById("btn-download-pdf");
    if (pdfBtn && data.report) {
        pdfBtn.href = data.report;
    }

    renderAttackSurface(data);
    renderFindings(vulns);
}

function renderAttackSurface(data) {
    const crawl = data.crawl || {};

    const pages = crawl.pages_data || [];
    const pagesCountEl = document.getElementById("tab-count-pages");
    if (pagesCountEl) pagesCountEl.innerText = pages.length;
    const pagesBody = document.getElementById("table-pages-body");

    if (pagesBody) {
        if (!pages.length) {
            pagesBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No pages mapped.</td></tr>`;
        } else {
            pagesBody.innerHTML = pages.map(p => {
                const code = p.status_code || 200;
                const badgeClass = code < 300 ? 'http-200' : (code < 400 ? 'http-300' : (code < 500 ? 'http-400' : 'http-500'));
                return `
                    <tr>
                        <td><span class="status-badge-http ${badgeClass}">HTTP ${code}</span></td>
                        <td style="font-family: var(--font-sans); font-weight: 500;">${escapeHtml(p.title || 'Untitled Document')}</td>
                        <td><a href="${escapeHtml(p.url)}" target="_blank" rel="noreferrer" style="color: var(--neon-cyan); text-decoration: none;">${escapeHtml(p.url)}</a></td>
                    </tr>
                `;
            }).join('');
        }
    }

    const forms = crawl.forms_data || [];
    const formsCountEl = document.getElementById("tab-count-forms");
    if (formsCountEl) formsCountEl.innerText = forms.length;
    const formsBody = document.getElementById("table-forms-body");

    if (formsBody) {
        if (!forms.length) {
            formsBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No forms discovered.</td></tr>`;
        } else {
            formsBody.innerHTML = forms.map(f => `
                <tr>
                    <td><span style="font-weight: 700; color: var(--neon-cyan);">${escapeHtml(f.method || 'GET')}</span></td>
                    <td>${escapeHtml(f.action || f.page)}</td>
                    <td style="color: var(--text-muted);">${(f.inputs && f.inputs.length) ? f.inputs.map(i => `<code style="background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:3px; margin-right:4px;">${escapeHtml(i)}</code>`).join(' ') : '<em>No input parameters</em>'}</td>
                </tr>
            `).join('');
        }
    }

    const endpoints = crawl.endpoints_data || [];
    const epCountEl = document.getElementById("tab-count-endpoints");
    if (epCountEl) epCountEl.innerText = endpoints.length;
    const endpointsBody = document.getElementById("table-endpoints-body");

    if (endpointsBody) {
        if (!endpoints.length) {
            endpointsBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No endpoints mapped.</td></tr>`;
        } else {
            endpointsBody.innerHTML = endpoints.map((ep, i) => `
                <tr>
                    <td style="color: var(--text-dim); width: 50px;">${i + 1}</td>
                    <td><span style="color: #fff;">${escapeHtml(ep)}</span></td>
                    <td style="width: 100px;">
                        <a href="${escapeHtml(ep)}" target="_blank" rel="noreferrer" style="color: var(--neon-cyan); text-decoration: none; font-size: 0.8rem;">Visit ↗</a>
                    </td>
                </tr>
            `).join('');
        }
    }
}

function switchSurfaceTab(tabName, btnElement) {
    document.querySelectorAll(".surface-tab").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".surface-tab-content").forEach(content => content.classList.remove("active"));

    if (btnElement) btnElement.classList.add("active");
    const targetContent = document.getElementById(`surface-tab-${tabName}`);
    if (targetContent) targetContent.classList.add("active");
}

function filterFindings(severity, btnElement) {
    activeFilter = severity;
    document.querySelectorAll(".filter-pill-btn").forEach(btn => btn.classList.remove("active"));
    if (btnElement) btnElement.classList.add("active");

    if (currentScanData && currentScanData.vulnerabilities) {
        let filtered = currentScanData.vulnerabilities;
        if (severity !== 'ALL') {
            filtered = filtered.filter(v => v.severity.toLowerCase() === severity.toLowerCase());
        }
        renderFindings(filtered);
    }
}

function renderFindings(vulns) {
    const container = document.getElementById("findings-list-container");
    if (!container) return;

    if (!vulns || !vulns.length) {
        container.innerHTML = `
            <div style="text-align: center; padding: 48px; background: rgba(0,230,118,0.05); border: 1px dashed var(--neon-emerald); border-radius: var(--radius-lg);">
                <div style="margin-bottom: 12px; color: var(--neon-emerald);">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="m9 12 2 2 4-4"/>
                    </svg>
                </div>
                <h3 style="color: var(--neon-emerald); font-weight: 700; margin-bottom: 6px;">No Security Issues Found</h3>
                <p style="color: var(--text-muted); font-size: 0.9rem;">Your website looks safe for the selected scan level.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = vulns.map((v, idx) => {
        let sevClass = "sev-low";
        let sevColor = "var(--neon-cyan)";
        if (v.severity === 'Critical' || v.severity === 'High') {
            sevClass = "sev-high";
            sevColor = "var(--neon-crimson)";
        } else if (v.severity === 'Medium') {
            sevClass = "sev-med";
            sevColor = "var(--neon-amber)";
        }

        const owaspBadge = v.owasp_category ? `<span class="badge-owasp">${escapeHtml(v.owasp_category)}</span>` : '';
        const cvssVal = (typeof v.cvss_score === 'number' && v.cvss_score > 0) ? v.cvss_score.toFixed(1) : (v.severity === 'High' ? '7.5' : (v.severity === 'Medium' ? '5.3' : '2.5'));

        return `
            <div class="finding-card ${sevClass}" id="finding-item-${idx}">
                <div class="finding-header">
                    <div class="finding-title-group">
                        <span class="finding-badge-sev ${sevClass}">${escapeHtml(v.severity)} Risk</span>
                        ${owaspBadge}
                        <h3 class="finding-title">${escapeHtml(v.type)}</h3>
                    </div>
                    <div class="cvss-score-pill" title="Security Risk Score">
                        <span style="font-size: 0.7rem; color: var(--text-dim);">RISK</span>
                        <strong style="color: ${sevColor}; font-size: 1.05rem;">${cvssVal}</strong>
                    </div>
                </div>

                <div class="finding-body">
                    <p class="finding-desc">${escapeHtml(v.description || 'Security check identified a weakness on this page.')}</p>

                    ${v.evidence ? `
                        <div class="finding-evidence-box">
                            <span class="evidence-label">Where We Found It:</span>
                            <div class="evidence-code">${escapeHtml(v.evidence)}</div>
                        </div>
                    ` : ''}

                    <div class="finding-fix-card">
                        <div class="fix-header">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 14 14"></polyline>
                            </svg>
                            <span>How to Fix This:</span>
                        </div>
                        <p class="fix-desc">${escapeHtml(v.recommendation || 'Add standard security headers in your web server settings.')}</p>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================================================
// Ask WebShield AI Slide Drawer
// ==========================================================================
function toggleAIDrawer(open) {
    const overlay = document.getElementById("ai-drawer-overlay");
    if (!overlay) return;
    if (open) {
        overlay.classList.add("open");
        const queryInput = document.getElementById("ai-user-query");
        if (queryInput) queryInput.focus();
    } else {
        overlay.classList.remove("open");
    }
}

function onOverlayClick(e) {
    if (e.target.id === "ai-drawer-overlay") {
        toggleAIDrawer(false);
    }
}

function askQuickPrompt(questionText) {
    const input = document.getElementById("ai-user-query");
    if (input) {
        input.value = questionText;
        document.getElementById("ai-chat-form").dispatchEvent(new Event("submit"));
    }
}

function formatAiMarkdown(text) {
    if (!text) return "";
    let formatted = escapeHtml(text);
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
    formatted = formatted.replace(/`([^`]+)`/g, '<code style="background:rgba(0,229,255,0.12); color:#00e5ff; padding:2px 5px; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem;">$1</code>');
    return formatted;
}

async function handleAIChatSubmit(e) {
    e.preventDefault();
    const input = document.getElementById("ai-user-query");
    const query = input.value.trim();
    if (!query) return;

    input.value = "";
    const stream = document.getElementById("drawer-chat-stream");

    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble user";
    userBubble.innerText = query;
    stream.appendChild(userBubble);
    stream.scrollTop = stream.scrollHeight;

    const botBubble = document.createElement("div");
    botBubble.className = "chat-bubble bot";
    botBubble.innerHTML = `<span style="color:var(--neon-cyan);">Thinking and generating personalized advice...</span>`;
    stream.appendChild(botBubble);
    stream.scrollTop = stream.scrollHeight;

    try {
        const res = await fetch("/api/ai/ask", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ question: query })
        });
        const data = await res.json();

        let replyHtml = `<strong>${escapeHtml(data.title || 'Security Advisor')}</strong><br><br>`;
        replyHtml += `<div style="white-space: pre-wrap; line-height: 1.55;">${formatAiMarkdown(data.content || '')}</div>`;

        botBubble.innerHTML = replyHtml;

    } catch (err) {
        botBubble.innerHTML = `<span style="color:var(--neon-crimson);">Failed to contact AI service: ${escapeHtml(err.message)}</span>`;
    }

    stream.scrollTop = stream.scrollHeight;
}

// OWASP Filter
function filterOwaspCards(level, btn) {
    document.querySelectorAll(".owasp-filter-pill").forEach(p => p.classList.remove("active"));
    if (btn) btn.classList.add("active");

    const cards = document.querySelectorAll(".owasp-card-item");
    cards.forEach(card => {
        if (level === "ALL") {
            card.style.display = "block";
        } else {
            const cardLevel = card.getAttribute("data-scan-level");
            if (cardLevel && cardLevel.includes(level)) {
                card.style.display = "block";
            } else {
                card.style.display = "none";
            }
        }
    });
}

function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) {
        el.scrollIntoView({ behavior: "smooth" });
    }
}

// ==========================================================================
// Authentication & Quota Management
// ==========================================================================

let currentUser = null;
let currentQuota = { used: 0, remaining: 2, limit: 2, is_unlimited: false };

function getGuestId() {
    let gid = sessionStorage.getItem("webshield_guest_id") || localStorage.getItem("webshield_guest_id");
    if (!gid) {
        gid = "guest_" + Date.now() + "_" + Math.random().toString(36).substring(2, 10);
        localStorage.setItem("webshield_guest_id", gid);
        sessionStorage.setItem("webshield_guest_id", gid);
    }
    return gid;
}

function getAuthToken() {
    return localStorage.getItem("webshield_auth_token") || getCookie("webshield_session") || "";
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return "";
}

async function initAuthAndQuota() {
    const token = getAuthToken();
    const guestId = getGuestId();

    try {
        const res = await fetch("/api/auth/status", {
            headers: {
                "Authorization": token ? `Bearer ${token}` : "",
                "x-auth-token": token,
                "x-guest-id": guestId
            }
        });
        if (res.ok) {
            const data = await res.json();
            if (data.authenticated && data.user) {
                currentUser = data.user;
                currentQuota = {
                    is_unlimited: true,
                    used: data.user.scan_count || 0,
                    remaining: "unlimited",
                    limit: "unlimited"
                };
            } else {
                currentUser = null;
                currentQuota = data.quota || { used: 0, remaining: 2, limit: 2, is_unlimited: false };
            }
        }
    } catch (e) {
        console.warn("Could not fetch auth status:", e);
    }

    renderNavAuth();
    updateQuotaUI();
}

function renderNavAuth() {
    const container = document.getElementById("nav-auth-container");
    if (!container) return;

    if (currentUser) {
        const initial = (currentUser.name || currentUser.email || "U").charAt(0).toUpperCase();
        const displayName = currentUser.name || currentUser.email.split("@")[0];
        container.innerHTML = `
            <div class="user-profile-badge" title="${escapeHtml(currentUser.email)}">
                <div class="user-avatar-circle">${escapeHtml(initial)}</div>
                <span style="font-weight: 600; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(displayName)}</span>
                <span class="unlimited-badge-pill">UNLIMITED</span>
                <button type="button" class="btn-nav-logout" onclick="confirmLogout()" title="Log Out">Log Out</button>
            </div>
        `;
    } else {
        container.innerHTML = `
            <a href="/login" class="auth-nav-btn btn-nav-login">Sign In</a>
            <a href="/register" class="auth-nav-btn btn-nav-register">Create Account</a>
        `;
    }
}

function updateQuotaUI(quotaData) {
    if (quotaData) currentQuota = quotaData;

    const textEl = document.getElementById("quota-status-text");
    const quotaLink = document.querySelector(".quota-link");

    if (currentUser || currentQuota.is_unlimited) {
        if (textEl) {
            textEl.innerHTML = `<strong style="color: var(--neon-emerald);">Unlimited Scans Active</strong> • Logged in as ${escapeHtml(currentUser ? currentUser.email : 'Member')}`;
        }
        if (quotaLink) {
            quotaLink.innerText = "Member Access";
            quotaLink.style.color = "var(--neon-emerald)";
            quotaLink.onclick = function() {
                alert("You have Unlimited Scans as a registered WebShield AI member.");
            };
        }
    } else {
        const remaining = typeof currentQuota.remaining === 'number' ? currentQuota.remaining : 2;
        if (textEl) {
            if (remaining > 1) {
                textEl.innerHTML = `<span style="color: var(--neon-cyan); font-weight: 700;">${remaining} free scans</span> available today`;
            } else if (remaining === 1) {
                textEl.innerHTML = `<span style="color: var(--neon-amber); font-weight: 700;">1 free scan</span> remaining`;
            } else {
                textEl.innerHTML = `<span style="color: var(--neon-crimson); font-weight: 700;">0 free scans remaining</span> (Limit reached)`;
            }
        }
        if (quotaLink) {
            quotaLink.innerText = "Get unlimited →";
            quotaLink.style.color = "";
            quotaLink.onclick = function() {
                openLimitModal();
            };
        }
    }
}

async function handleLogout() {
    try {
        const token = getAuthToken();
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: { "Authorization": token ? `Bearer ${token}` : "" }
        });
    } catch (e) {}

    localStorage.removeItem("webshield_auth_token");
    localStorage.removeItem("webshield_user");
    document.cookie = "webshield_session=; path=/; max-age=0";
    currentUser = null;
    initAuthAndQuota();
}

function openLimitModal(customTitle, customDesc) {
    const modal = document.getElementById("limit-modal");
    if (!modal) return;
    const titleEl = document.getElementById("limit-modal-title");
    const descEl = document.getElementById("limit-modal-desc");
    if (titleEl) {
        titleEl.innerText = customTitle || "Your free credits are over";
    }
    if (descEl && customDesc) {
        descEl.innerHTML = customDesc;
    }
    modal.classList.add("active");
}

function closeLimitModal() {
    const modal = document.getElementById("limit-modal");
    if (modal) modal.classList.remove("active");
}

function openUnlimitedNotice() {
    if (currentUser) {
        alert("You have Unlimited Scans as an active WebShield AI member.");
    } else {
        openLimitModal("Your free credits are over");
    }
}

function showThreatIntelModal() {
    toggleAIDrawer(true);
    askQuickPrompt("What are the most active web vulnerabilities today according to threat intelligence?");
}

// Utility: HTML Escaper
function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}



function confirmClearChat() {
    showConfirmModal({
        title: "Clear Advisor Conversation?",
        message: "All previous questions and security recommendations in this session will be cleared.",
        confirmText: "Clear Conversation",
        cancelText: "Keep Chat",
        onConfirm: () => {
            clearChatHistory();
            showToastNotification("Advisor conversation cleared.");
        }
    });
}

function confirmLogout() {
    showConfirmModal({
        title: "Sign Out of WebShield AI?",
        message: "Are you sure you want to end your active member session?",
        confirmText: "Sign Out",
        cancelText: "Stay Signed In",
        onConfirm: () => {
            handleLogout();
        }
    });
}


/**
 * WebShield AI - Comprehensive 20 Features Engine
 * Integrates seamlessly with existing scanner engine without breaking any existing functionality.
 */

// --------------------------------------------------------------------------
// 1. Theme Engine: Light/Dark Theme Switcher with LocalStorage
// --------------------------------------------------------------------------
function initTheme() {
    const savedTheme = localStorage.getItem('webshield_theme');
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    const theme = savedTheme ? savedTheme : (prefersLight ? 'light' : 'dark');
    applyTheme(theme);
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('webshield_theme', theme);
    updateThemeIcons(theme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(nextTheme);
}

function updateThemeIcons(theme) {
    const iconSVGs = {
        sun: `<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>`,
        moon: `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`
    };

    document.querySelectorAll('.theme-toggle-icon').forEach(iconEl => {
        // In light theme show moon to switch to dark; in dark theme show sun to switch to light
        iconEl.innerHTML = theme === 'light' ? iconSVGs.moon : iconSVGs.sun;
    });

    document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
        btn.setAttribute('aria-label', `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`);
        btn.setAttribute('title', `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`);
    });
}

// --------------------------------------------------------------------------
// 2. Scroll Progress Bar
// --------------------------------------------------------------------------
function initScrollProgress() {
    const progressBar = document.getElementById('scroll-progress-bar');
    if (!progressBar) return;

    window.addEventListener('scroll', () => {
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const progress = scrollHeight > 0 ? (scrollTop / scrollHeight) * 100 : 0;
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', Math.round(progress));
    }, { passive: true });
}

// --------------------------------------------------------------------------
// 3. Sticky Header Scroll Elevation
// --------------------------------------------------------------------------
function initStickyHeader() {
    const header = document.querySelector('.top-navbar');
    if (!header) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 20) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    }, { passive: true });
}

// --------------------------------------------------------------------------
// 4. Back to Top Button
// --------------------------------------------------------------------------
function initBackToTop() {
    const btn = document.getElementById('btn-back-to-top');
    if (!btn) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
            btn.classList.add('visible');
            btn.setAttribute('aria-hidden', 'false');
        } else {
            btn.classList.remove('visible');
            btn.setAttribute('aria-hidden', 'true');
        }
    }, { passive: true });
}

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// --------------------------------------------------------------------------
// 5. Mobile Navigation Menu
// --------------------------------------------------------------------------
function toggleMobileMenu(forceClose = false) {
    const overlay = document.getElementById('mobile-drawer-overlay');
    const toggleBtn = document.getElementById('btn-mobile-menu');
    if (!overlay || !toggleBtn) return;

    const isOpen = overlay.classList.contains('active');
    const willOpen = forceClose ? false : !isOpen;

    if (willOpen) {
        overlay.classList.add('active');
        toggleBtn.setAttribute('aria-expanded', 'true');
        document.body.style.overflow = 'hidden';
    } else {
        overlay.classList.remove('active');
        toggleBtn.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
    }
}

// --------------------------------------------------------------------------
// 6. Universal Copy to Clipboard
// --------------------------------------------------------------------------
async function copyToClipboard(text, btnElement) {
    if (!text) return;
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }

        if (btnElement) {
            const originalHTML = btnElement.innerHTML;
            btnElement.classList.add('copied');
            btnElement.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                <span>Copied!</span>
            `;
            setTimeout(() => {
                btnElement.classList.remove('copied');
                btnElement.innerHTML = originalHTML;
            }, 2000);
        }
        showToastNotification("Copied to clipboard!");
    } catch (err) {
        showToastNotification("Unable to copy to clipboard.");
    }
}

// Accessible Toast Notification
function showToastNotification(msg) {
    let toast = document.getElementById('webshield-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'webshield-toast';
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            left: 50%;
            transform: translateX(-50%) translateY(20px);
            background: var(--bg-surface-elevated, #131722);
            color: var(--text-main, #fff);
            border: 1px solid var(--neon-cyan, #00e5ff);
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
            z-index: 10010;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            opacity: 0;
            transition: all 0.25s ease;
            pointer-events: none;
        `;
        document.body.appendChild(toast);
    }
    toast.innerText = msg;
    toast.style.opacity = '1';
    toast.style.transform = 'translateX(-50%) translateY(0)';
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-50%) translateY(20px)';
    }, 2500);
}

// --------------------------------------------------------------------------
// 7. Site Search Engine
// --------------------------------------------------------------------------
const SITE_SEARCH_INDEX = [
    { title: "Basic Scan Profile", category: "SCANNER", desc: "Fast surface audit inspecting SSL/TLS, HSTS, CSP, and exposed headers.", target: "#scanner-card" },
    { title: "Medium Scan Profile", category: "SCANNER", desc: "Interactive level-1 BFS crawl evaluating HTML forms, POST CSRF tokens, and auth endpoints.", target: "#scanner-card" },
    { title: "Deep Scan Profile", category: "SCANNER", desc: "Exhaustive depth-2 BFS queue crawl checking cookie flags, hidden files, and full PDF export.", target: "#scanner-card" },
    { title: "A01: Broken Access Control", category: "OWASP", desc: "Detection of exposed /admin endpoints, sensitive directories, and unauthorized routes.", target: "#owasp-card-A01" },
    { title: "A02: Cryptographic Failures", category: "OWASP", desc: "SSL/TLS validation, Strict-Transport-Security (HSTS), and insecure HTTP transmissions.", target: "#owasp-card-A02" },
    { title: "A03: Injection (SQL & XSS)", category: "OWASP", desc: "Cross-Site Scripting (XSS) input surface mapping and unvalidated form submission checks.", target: "#owasp-card-A03" },
    { title: "A04: Insecure Design", category: "OWASP", desc: "Rate-limiting absence, bot credential-stuffing exposure, and missing security architecture.", target: "#owasp-card-A04" },
    { title: "A05: Security Misconfiguration", category: "OWASP", desc: "Missing CSP, X-Frame-Options, X-Content-Type-Options nosniff, and default file leaks.", target: "#owasp-card-A05" },
    { title: "A06: Vulnerable & Outdated Components", category: "OWASP", desc: "Exposed web server technology banners (Server, X-Powered-By) and known version vulnerabilities.", target: "#owasp-card-A06" },
    { title: "A07: Identification & Auth Failures", category: "OWASP", desc: "Unencrypted login form submissions, missing password protection, and session cookie flags.", target: "#owasp-card-A07" },
    { title: "A08: Software & Data Integrity Failures", category: "OWASP", desc: "Subresource Integrity (SRI) on external scripts and untrusted CDN imports.", target: "#owasp-card-A08" },
    { title: "A09: Security Logging & Monitoring", category: "OWASP", desc: "Suspicious HTTP status code audits and missing threat detection telemetry.", target: "#owasp-card-A09" },
    { title: "A10: Server-Side Request Forgery (SSRF)", category: "OWASP", desc: "Targeted outbound URL parameter checks and unauthorized internal network calls.", target: "#owasp-card-A10" },
    { title: "Discovered Pages & Attack Surface", category: "PAGES", desc: "View all crawled site routes, depth hierarchy, and HTTP response codes.", target: "#attack-surface-section" },
    { title: "Security Issues & Findings", category: "FINDINGS", desc: "Review severity-rated vulnerability cards, impacted endpoints, and remediation fixes.", target: "#findings-section" },
    { title: "Privacy Policy", category: "LEGAL", desc: "Data protection standards, temporary scan cache retention, and user privacy rights.", target: "/privacy" },
    { title: "Terms and Conditions", category: "LEGAL", desc: "Authorized scanning requirements, liability limitations, and permitted use.", target: "/terms" },
    { title: "Frequently Asked Questions", category: "FAQ", desc: "Learn how the BFS engine works, scan permissions, and safety guarantees.", target: "#faq-section" }
];

let activeSearchFilter = "ALL";

function openSiteSearch() {
    const modal = document.getElementById('site-search-modal');
    const input = document.getElementById('site-search-input');
    if (!modal) return;
    modal.classList.add('active');
    if (input) {
        input.value = "";
        setTimeout(() => input.focus(), 50);
        renderSearchResults("");
    }
}

function closeSiteSearch() {
    const modal = document.getElementById('site-search-modal');
    if (modal) modal.classList.remove('active');
}

function filterSearchCategory(category, btnElement) {
    activeSearchFilter = category;
    document.querySelectorAll('.search-filter-pill').forEach(btn => btn.classList.remove('active'));
    if (btnElement) btnElement.classList.add('active');
    const input = document.getElementById('site-search-input');
    renderSearchResults(input ? input.value : "");
}

function handleSiteSearchInput(e) {
    renderSearchResults(e.target.value);
}

function renderSearchResults(query) {
    const container = document.getElementById('search-results-container');
    if (!container) return;

    const trimmed = query.trim().toLowerCase();
    const filtered = SITE_SEARCH_INDEX.filter(item => {
        const matchesCategory = activeSearchFilter === "ALL" || item.category === activeSearchFilter;
        if (!matchesCategory) return false;
        if (!trimmed) return true;
        return item.title.toLowerCase().includes(trimmed) || 
               item.desc.toLowerCase().includes(trimmed) ||
               item.category.toLowerCase().includes(trimmed);
    });

    if (!filtered.length) {
        container.innerHTML = `
            <div style="text-align: center; padding: 32px 16px; color: var(--text-dim);">
                <div style="font-size: 1rem; margin-bottom: 4px;">No matches found for "${escapeHtml(query)}"</div>
                <div style="font-size: 0.8rem;">Try searching for "OWASP", "CSP", "HSTS", or "Login"</div>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(item => `
        <a href="${item.target}" class="search-result-item" onclick="onSearchResultClick('${item.target}', event)">
            <div class="search-result-top">
                <span class="search-result-title">${escapeHtml(item.title)}</span>
                <span class="search-result-category">${escapeHtml(item.category)}</span>
            </div>
            <div class="search-result-desc">${escapeHtml(item.desc)}</div>
        </a>
    `).join('');
}

function onSearchResultClick(target, event) {
    closeSiteSearch();
    if (target.startsWith('#')) {
        event.preventDefault();
        const el = document.querySelector(target);
        if (el) {
            el.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

// --------------------------------------------------------------------------
// 8. Cookie Consent & Preferences Management
// --------------------------------------------------------------------------
function initCookieConsent() {
    const consent = localStorage.getItem('webshield_cookie_consent');
    if (!consent) {
        setTimeout(() => {
            const banner = document.getElementById('cookie-banner');
            if (banner) banner.classList.add('active');
        }, 800);
    } else {
        try {
            const parsed = JSON.parse(consent);
            applyCookiePreferences(parsed);
        } catch (e) {}
    }
}

function acceptAllCookies() {
    const preferences = { necessary: true, analytics: true, telemetry: true, timestamp: new Date().toISOString() };
    saveConsent(preferences);
}

function rejectOptionalCookies() {
    const preferences = { necessary: true, analytics: false, telemetry: false, timestamp: new Date().toISOString() };
    saveConsent(preferences);
}

function saveConsent(preferences) {
    localStorage.setItem('webshield_cookie_consent', JSON.stringify(preferences));
    const banner = document.getElementById('cookie-banner');
    if (banner) banner.classList.remove('active');
    closeCookiePreferences();
    applyCookiePreferences(preferences);
    showToastNotification("Cookie preferences saved.");
}

function applyCookiePreferences(prefs) {
    if (prefs.analytics) {
        initUtmTracking(true);
    }
}

function openCookiePreferences() {
    const modal = document.getElementById('cookie-prefs-modal');
    if (!modal) return;
    const consent = localStorage.getItem('webshield_cookie_consent');
    if (consent) {
        try {
            const parsed = JSON.parse(consent);
            const analyticsInput = document.getElementById('cookie-pref-analytics');
            const telemetryInput = document.getElementById('cookie-pref-telemetry');
            if (analyticsInput) analyticsInput.checked = !!parsed.analytics;
            if (telemetryInput) telemetryInput.checked = !!parsed.telemetry;
        } catch (e) {}
    }
    modal.classList.add('active');
}

function closeCookiePreferences() {
    const modal = document.getElementById('cookie-prefs-modal');
    if (modal) modal.classList.remove('active');
}

function saveCustomPreferences() {
    const analytics = document.getElementById('cookie-pref-analytics')?.checked ?? false;
    const telemetry = document.getElementById('cookie-pref-telemetry')?.checked ?? false;
    saveConsent({ necessary: true, analytics, telemetry, timestamp: new Date().toISOString() });
}

// --------------------------------------------------------------------------
// 9. UTM Parameter Attribution Tracking
// --------------------------------------------------------------------------
function initUtmTracking(consentGranted = false) {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const utmKeys = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];
        const utmFound = {};
        let hasUtm = false;

        utmKeys.forEach(key => {
            const val = urlParams.get(key);
            if (val) {
                utmFound[key] = val.trim();
                hasUtm = true;
            }
        });

        if (hasUtm) {
            sessionStorage.setItem('webshield_utm', JSON.stringify(utmFound));
        }
    } catch (e) {}
}

function getStoredUtm() {
    try {
        const stored = sessionStorage.getItem('webshield_utm');
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        return {};
    }
}

// --------------------------------------------------------------------------
// 10. Floating Contact Button & Security Disclosure Modal
// --------------------------------------------------------------------------
function openContactModal() {
    const modal = document.getElementById('contact-modal');
    if (modal) modal.classList.add('active');
}

function closeContactModal() {
    const modal = document.getElementById('contact-modal');
    if (modal) modal.classList.remove('active');
}

async function handleContactSubmit(e) {
    e.preventDefault();
    const nameInput = document.getElementById('contact-name');
    const emailInput = document.getElementById('contact-email');
    const subjectInput = document.getElementById('contact-subject');
    const messageInput = document.getElementById('contact-message');
    const urlInput = document.getElementById('contact-target-url');
    const submitBtn = document.getElementById('contact-btn-submit');
    const alertBox = document.getElementById('contact-alert-box');

    const email = emailInput?.value.trim() || "";
    const message = messageInput?.value.trim() || "";

    // Clear previous errors
    emailInput?.classList.remove('is-invalid');
    messageInput?.classList.remove('is-invalid');
    if (alertBox) alertBox.style.display = 'none';

    if (!email || !email.includes('@')) {
        emailInput?.classList.add('is-invalid');
        emailInput?.focus();
        showContactAlert('error', 'Please enter a valid email address.');
        return;
    }

    if (!message || message.length < 5) {
        messageInput?.classList.add('is-invalid');
        messageInput?.focus();
        showContactAlert('error', 'Please write a message of at least 5 characters.');
        return;
    }

    const utm = getStoredUtm();
    const payload = {
        name: nameInput?.value.trim() || "",
        email: email,
        subject: subjectInput?.value || "General Inquiry",
        message: message,
        target_url: urlInput?.value.trim() || "",
        utm_source: utm.utm_source || "",
        utm_medium: utm.utm_medium || ""
    };

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="spinner-inline" style="margin-right: 6px;"></span> Sending...`;
    }

    try {
        const res = await fetch('/api/contact', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (res.ok && data.success) {
            showContactAlert('success', data.message || `Message received. Reference ID: ${data.reference_id}`);
            // Reset fields
            if (messageInput) messageInput.value = "";
            if (urlInput) urlInput.value = "";
            setTimeout(() => {
                closeContactModal();
                if (alertBox) alertBox.style.display = 'none';
            }, 3000);
        } else {
            showContactAlert('error', data.message || 'Error sending message. Please try again.');
        }
    } catch (err) {
        showContactAlert('error', 'Network error. Could not contact the server.');
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerText = 'Send Message';
        }
    }
}

function showContactAlert(type, msg) {
    const box = document.getElementById('contact-alert-box');
    if (!box) return;
    box.className = type === 'success' ? 'form-success-banner' : 'form-error-text';
    box.innerText = msg;
    box.style.display = 'block';
}

// --------------------------------------------------------------------------
// 11. Confirmation Modal for Destructive Actions
// --------------------------------------------------------------------------
let confirmCallback = null;

function showConfirmModal({ title, message, confirmText = "Confirm", cancelText = "Cancel", onConfirm }) {
    const modal = document.getElementById('confirm-modal');
    const titleEl = document.getElementById('confirm-modal-title');
    const descEl = document.getElementById('confirm-modal-desc');
    const confirmBtn = document.getElementById('confirm-modal-btn');
    const cancelBtn = document.getElementById('confirm-modal-cancel');

    if (!modal) return;
    if (titleEl) titleEl.innerText = title;
    if (descEl) descEl.innerText = message;
    if (confirmBtn) confirmBtn.innerText = confirmText;
    if (cancelBtn) cancelBtn.innerText = cancelText;

    confirmCallback = onConfirm;
    modal.classList.add('active');
    setTimeout(() => confirmBtn?.focus(), 50);
}

function closeConfirmModal() {
    const modal = document.getElementById('confirm-modal');
    if (modal) modal.classList.remove('active');
    confirmCallback = null;
}

function executeConfirmAction() {
    if (typeof confirmCallback === 'function') {
        confirmCallback();
    }
    closeConfirmModal();
}

// --------------------------------------------------------------------------
// Global Keyboard Shortcut Listeners
// --------------------------------------------------------------------------
document.addEventListener('keydown', (e) => {
    // Ctrl+K or / opens site search
    if ((e.ctrlKey && e.key === 'k') || (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName))) {
        e.preventDefault();
        openSiteSearch();
    }
    // Escape closes modals
    if (e.key === 'Escape') {
        closeSiteSearch();
        closeContactModal();
        closeConfirmModal();
        closeCookiePreferences();
        toggleMobileMenu(true);
    }
});

// Run initializers
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initScrollProgress();
    initStickyHeader();
    initBackToTop();
    initCookieConsent();
    initUtmTracking();
});
