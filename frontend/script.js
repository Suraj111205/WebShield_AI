/**
 * WebShield AI — Dynamic Autonomous Security Advisor & Scanner
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
        sub: "A quick surface check — great for beginners.",
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
        sub: "Follows all direct links & checks forms — recommended for most sites.",
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
        sub: "Thorough multi-page crawler & deep security audit — up to 25 pages.",
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

    // 4. Initialize dynamic counter animations
    initHeroCounters();

    // 5. Restore chat history if user was interacting with advisor
    restoreChatHistory();
});

function cleanReloadState() {
    // Clear stored previous scans and target URLs so page is completely fresh
    localStorage.removeItem("webshield_last_scan");
    localStorage.removeItem("webshield_target_url");
    localStorage.removeItem("webshield_terminal_logs");
    currentScanData = null;

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
    const heroScansEl = document.getElementById("hero-stat-scans");
    if (heroScansEl) {
        animateValue(heroScansEl, 0, 1250, 700, "+");
    }
    const heroVulnsEl = document.getElementById("hero-stat-vulns");
    if (heroVulnsEl) {
        animateValue(heroVulnsEl, 0, 15, 500, "+");
    }
}

function animateValue(obj, start, end, duration, suffix = "") {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start) + suffix;
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

function restoreChatHistory() {
    const savedChat = localStorage.getItem("webshield_chat_history");
    const stream = document.getElementById("drawer-chat-stream");
    if (savedChat && stream) {
        stream.innerHTML = savedChat;
        stream.scrollTop = stream.scrollHeight;
    }
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
            pill.innerHTML = `⚠️ ${count} ${count === 1 ? 'Issue' : 'Issues'} Found`;
        } else {
            pill.className = "owasp-status-pill clean";
            pill.innerHTML = `✓ Safe (Clean)`;
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
                <span class="icon">✓</span>
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
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target_url: target,
                crawl_depth: depth,
                scan_speed: speed,
                report_format: "PDF",
                authorized: true
            })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Scan request failed with HTTP ${response.status}`);
        }

        const data = await response.json();

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
                    <td><span style="font-weight: 700; color: var(--neon-purple);">${escapeHtml(f.method || 'GET')}</span></td>
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
                <div style="font-size: 2.5rem; margin-bottom: 12px;">🛡️</div>
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
    botBubble.innerHTML = `<span style="color:var(--neon-cyan);">Thinking and preparing simple advice...</span>`;
    stream.appendChild(botBubble);
    stream.scrollTop = stream.scrollHeight;

    try {
        const res = await fetch("/api/ai/ask", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ question: query })
        });
        const data = await res.json();

        let replyHtml = `<strong>${escapeHtml(data.title || 'Security Analysis')}</strong><br><br>`;
        replyHtml += `<div style="white-space: pre-wrap;">${escapeHtml(data.content || '')}</div>`;

        if (data.remediation) {
            replyHtml += `<br><div style="margin-top:8px; padding:10px; background:#05070d; border-radius:6px; border:1px solid rgba(0,229,255,0.2);">`;
            replyHtml += `<div style="color:var(--neon-cyan); font-weight:700; font-size:0.75rem; margin-bottom:6px;">PROPOSED REMEDIATION:</div>`;
            for (const [key, code] of Object.entries(data.remediation)) {
                replyHtml += `<div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; margin-top:4px;">${escapeHtml(key)}:</div>`;
                replyHtml += `<code style="display:block; background:#000; padding:6px; border-radius:4px; font-family:var(--font-mono); font-size:0.75rem; color:#a5d6a7; overflow-x:auto;">${escapeHtml(code)}</code>`;
            }
            replyHtml += `</div>`;
        }

        botBubble.innerHTML = replyHtml;
        localStorage.setItem("webshield_chat_history", stream.innerHTML);

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

function openUnlimitedNotice() {
    alert("🎉 WebShield AI Community Edition: You have Unlimited Free Scans for educational and authorized defensive testing!");
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
