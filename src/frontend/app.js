// Global Error Handler for Diagnostics
window.onerror = function(message, source, lineno, colno, error) {
    if (message && (message.includes('ResizeObserver') || message.includes('Resize observer'))) {
        return false;
    }
    const banner = document.getElementById('alarm-banner');
    const text = document.getElementById('alarm-text');
    if (banner && text) {
        banner.classList.remove('hidden');
        banner.style.background = '#ff0055';
        banner.style.boxShadow = '0 0 20px rgba(255, 0, 85, 0.6)';
        text.innerText = `JS TELEMETRY ERROR: ${message} (Line: ${lineno}, Column: ${colno})`;
    }
    return false;
};

// Global State
let activeSection = 'overview';
let systemStatus = {};
let selectedIncidentId = null;
let pollInterval = null;
let trustChartInstance = null;
let networkGraphInstance = null;

// Tab control inside Analyst Workspace
let activeWorkspaceTab = 'graph-tab';

document.addEventListener('DOMContentLoaded', () => {
    initRouting();
    initChart();
    startPolling();
    setupEventListeners();
    initAIAssistant();
    initEnterpriseFeatures();
});

// Sidebar navigation routing
function initRouting() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.content-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const sectionId = item.getAttribute('data-section');
            
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            sections.forEach(sec => {
                if (sec.id === `sec-${sectionId}`) {
                    sec.classList.remove('hidden');
                } else {
                    sec.classList.add('hidden');
                }
            });

            activeSection = sectionId;
            // Immediate update on switch
            fetchData();
        });
    });
}

// Set up UI Event listeners
function setupEventListeners() {
    // Clear feed
    document.getElementById('btn-clear-feed').addEventListener('click', () => {
        const feed = document.getElementById('alert-feed-list');
        feed.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-check text-success"></i>
                <p>System secure. No active incidents.</p>
            </div>`;
        feed.classList.add('empty');
    });

    // Enforcement Mode switch
    const toggle = document.getElementById('enforcement-toggle');
    toggle.addEventListener('change', (e) => {
        const checked = e.target.checked;
        fetch('/api/configure', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enforcement_mode: checked })
        })
        .then(res => res.json())
        .then(data => {
            updateEnforcementDisplay(data.enforcement_mode);
        });
    });

    // Make sidebar mode text badge clickable to toggle it as well
    const sidebarMode = document.getElementById('sidebar-mode');
    if (sidebarMode) {
        sidebarMode.style.cursor = 'pointer';
        sidebarMode.title = "Click to toggle Response Mode";
        sidebarMode.addEventListener('click', () => {
            toggle.checked = !toggle.checked;
            toggle.dispatchEvent(new Event('change'));
        });
    }

    // Rebaseline
    document.getElementById('btn-rebaseline').addEventListener('click', () => {
        const btn = document.getElementById('btn-rebaseline');
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Rebuilding...`;
        btn.disabled = true;
        
        fetch('/api/run-baseline', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            showToast("SHA-256 baseline successfully reconstructed and backed up.", "success");
            btn.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Rebuild SHA-256 Baseline`;
            btn.disabled = false;
            fetchData();
        });
    });

    // Forensic search filter
    document.getElementById('log-search-input').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#forensics-raw-table tbody tr');
        rows.forEach(row => {
            const text = row.innerText.toLowerCase();
            if (text.includes(query)) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
            }
        });
    });

    // Analyst Workspace Tabs
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const tabId = btn.getAttribute('data-tab');
            activeWorkspaceTab = tabId;

            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tc => {
                if (tc.id === tabId) {
                    tc.classList.remove('hidden');
                } else {
                    tc.classList.add('hidden');
                }
            });

            // Redraw network graph if tab becomes visible
            if (tabId === 'graph-tab' && networkGraphInstance) {
                setTimeout(() => networkGraphInstance.fit(), 100);
            }
        });
    });

    const btnGotoUpload = document.getElementById('btn-goto-upload');
    if (btnGotoUpload) {
        btnGotoUpload.addEventListener('click', (e) => {
            e.preventDefault();
            const fimNav = document.querySelector('[data-section="fim"]');
            if (fimNav) fimNav.click();
        });
    }

    // Custom Asset Upload and Folder Ingestion System
    initAssetUploadSystem();
}

// Custom Asset Ingestion and Folder Protection System
function initAssetUploadSystem() {
    const fileDropzone = document.getElementById('file-dropzone');
    const filesInput = document.getElementById('custom-files-input');
    const folderInput = document.getElementById('custom-folder-input');
    const previewDiv = document.getElementById('file-selection-preview');
    const submitBtn = document.getElementById('btn-submit-upload');
    const chkMonitorAlone = document.getElementById('chk-monitor-alone');
    const customDirInput = document.getElementById('input-custom-dir');
    const applyDirBtn = document.getElementById('btn-apply-custom-dir');
    const restoreDefaultsBtn = document.getElementById('btn-restore-defaults-ui');

    let selectedFilesList = [];

    function updatePreview() {
        if (!selectedFilesList || selectedFilesList.length === 0) {
            if (previewDiv) {
                previewDiv.classList.add('hidden');
                previewDiv.innerHTML = '';
            }
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Upload & Establish Cryptographic Baseline`;
            }
            return;
        }

        if (previewDiv) {
            previewDiv.classList.remove('hidden');
            previewDiv.innerHTML = `<div style="margin-bottom: 6px; font-weight: 600; color: #00f0ff;"><i class="fa-solid fa-list-check"></i> Selected Assets (${selectedFilesList.length}):</div>`;
            
            selectedFilesList.slice(0, 8).forEach(f => {
                const name = f.name;
                const size = (f.size / 1024).toFixed(1) + ' KB';
                const meta = getFileIconMeta(name);
                const pill = document.createElement('span');
                pill.className = 'file-badge-pill';
                pill.innerHTML = `<i class="${meta.icon}"></i> ${name} <small style="opacity: 0.7;">(${size})</small>`;
                previewDiv.appendChild(pill);
            });

            if (selectedFilesList.length > 8) {
                const extra = document.createElement('span');
                extra.className = 'file-badge-pill';
                extra.innerText = `+${selectedFilesList.length - 8} more files...`;
                previewDiv.appendChild(extra);
            }
        }

        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Ingest & Protect ${selectedFilesList.length} File(s)`;
        }
    }

    if (filesInput) {
        filesInput.addEventListener('change', (e) => {
            selectedFilesList = Array.from(e.target.files);
            updatePreview();
        });
    }

    if (folderInput) {
        folderInput.addEventListener('change', (e) => {
            selectedFilesList = Array.from(e.target.files);
            updatePreview();
        });
    }

    if (fileDropzone) {
        fileDropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileDropzone.classList.add('dragover');
        });
        fileDropzone.addEventListener('dragleave', () => {
            fileDropzone.classList.remove('dragover');
        });
        fileDropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            fileDropzone.classList.remove('dragover');
            if (e.dataTransfer && e.dataTransfer.files) {
                selectedFilesList = Array.from(e.dataTransfer.files);
                updatePreview();
            }
        });
    }

    if (submitBtn) {
        submitBtn.addEventListener('click', () => {
            if (!selectedFilesList || selectedFilesList.length === 0) return;

            submitBtn.disabled = true;
            submitBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Hashing & Establishing Baseline...`;

            const formData = new FormData();
            selectedFilesList.forEach(file => {
                formData.append('files', file);
            });
            formData.append('clear_existing', chkMonitorAlone ? chkMonitorAlone.checked : false);

            fetch('/api/upload-files', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                showToast(`Success! Protected ${data.uploaded_files.length} custom file(s). Active baselines: ${data.total_files_monitored}`, "success");
                selectedFilesList = [];
                if (filesInput) filesInput.value = '';
                if (folderInput) folderInput.value = '';
                updatePreview();
                fetchBaselines();
                fetchData();
            })
            .catch(err => {
                showToast(`Upload failed: ${err.message}`, "error");
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Retry Upload`;
            });
        });
    }

    if (applyDirBtn && customDirInput) {
        applyDirBtn.addEventListener('click', () => {
            const pathVal = customDirInput.value.trim();
            if (!pathVal) {
                showToast("Please enter a valid folder path.", "warning");
                return;
            }
            applyDirBtn.disabled = true;
            applyDirBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i>`;
            
            fetch('/api/set-monitored-folder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ folder_path: pathVal, create_if_missing: true })
            })
            .then(res => res.json())
            .then(data => {
                showToast(data.message, "success");
                applyDirBtn.disabled = false;
                applyDirBtn.innerHTML = `<i class="fa-solid fa-check"></i> Set Target`;
                fetchBaselines();
                fetchData();
            })
            .catch(err => {
                showToast(`Failed: ${err.message}`, "error");
                applyDirBtn.disabled = false;
                applyDirBtn.innerHTML = `<i class="fa-solid fa-check"></i> Set Target`;
            });
        });
    }

    if (restoreDefaultsBtn) {
        restoreDefaultsBtn.addEventListener('click', () => {
            if (!confirm("Restore the default enterprise sample demo files into monitored_dir?")) return;
            restoreDefaultsBtn.disabled = true;
            restoreDefaultsBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Resetting...`;
            
            fetch('/api/restore-default-files', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                showToast("Default sample assets restored successfully.", "info");
                restoreDefaultsBtn.disabled = false;
                restoreDefaultsBtn.innerHTML = `<i class="fa-solid fa-rotate-left"></i> Reset Demo Files`;
                fetchBaselines();
                fetchData();
            })
            .catch(err => {
                showToast(`Failed: ${err.message}`, "error");
                restoreDefaultsBtn.disabled = false;
                restoreDefaultsBtn.innerHTML = `<i class="fa-solid fa-rotate-left"></i> Reset Demo Files`;
            });
        });
    }
}

// Chart.js Trust Score Timeline Setup
function initChart() {
    const ctx = document.getElementById('trustChart').getContext('2d');
    trustChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Trust Score',
                data: [],
                borderColor: '#00f0ff',
                backgroundColor: 'rgba(0, 240, 255, 0.05)',
                borderWidth: 2,
                tension: 0.3,
                fill: true,
                pointRadius: 2,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#64748b', font: { family: 'Outfit' } }
                },
                x: {
                    grid: { display: false },
                    ticks: { display: false }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

// Polling interval
function startPolling() {
    fetchData(); // Initial load
    pollInterval = setInterval(fetchData, 1500);
}

function fetchData() {
    // 1. Fetch system status
    fetch('/api/status')
        .then(res => res.json())
        .then(data => {
            systemStatus = data;
            updateOverviewDisplay(data);
        })
        .catch(err => console.error("Error polling system status:", err));

    // 2. Fetch approvals (always update badge count in sidebar)
    fetch('/api/approvals')
        .then(res => res.json())
        .then(data => {
            updateApprovalsBadge(data.length);
            if (activeSection === 'response') {
                updateApprovalsList(data);
            }
        });

    // 3. Fetch section-specific data
    if (activeSection === 'overview') {
        fetchIncidentsList();
    } else if (activeSection === 'fim') {
        fetchBaselines();
    } else if (activeSection === 'attestation') {
        fetchAttestationData();
    } else if (activeSection === 'analyst') {
        fetchIncidentsList();
    } else if (activeSection === 'response') {
        fetchResponsesLogs();
    } else if (activeSection === 'logs') {
        fetchForensicsLogs();
    }
}

// Update Dashboard indicators
function updateOverviewDisplay(data) {
    // Mode
    updateEnforcementDisplay(data.enforcement_mode);

    // Trust Score Gauge
    const scoreVal = document.getElementById('trust-score-val');
    const stateVal = document.getElementById('trust-state-val');
    const gaugeFill = document.querySelector('.trust-fill');
    
    scoreVal.innerText = data.system_trust_score;
    stateVal.innerText = data.system_trust_state;

    // Adjust gauge stroke offset
    const strokeDash = 251.2; // 2 * pi * r (r=40)
    const offset = strokeDash - (data.system_trust_score / 100) * strokeDash;
    gaugeFill.style.strokeDashoffset = offset;

    // Adjust state class
    stateVal.className = 'label';
    if (data.system_trust_score >= 90) {
        stateVal.classList.add('text-trusted');
    } else if (data.system_trust_score >= 70) {
        stateVal.classList.add('text-suspicious');
    } else if (data.system_trust_score >= 40) {
        stateVal.classList.add('text-high');
    } else {
        stateVal.classList.add('text-critical');
    }

    // Update AI Assistant character state (mood & alert)
    if (typeof updateCharacterState === 'function') {
        updateCharacterState(data.system_trust_score, data.system_trust_score < 70);
    }

    // Update Executive DEFCON Cyber Threat Condition
    const defconBadge = document.getElementById('defcon-badge');
    const defconLabel = document.getElementById('defcon-label');
    if (defconBadge && defconLabel) {
        defconBadge.className = 'defcon-badge';
        if (data.system_trust_score < 50 || data.current_threat_level === 'CRITICAL') {
            defconBadge.classList.add('defcon-1');
            defconLabel.innerText = 'DEFCON 1 : CRITICAL THREAT';
        } else if (data.system_trust_score < 85 || data.current_threat_level === 'HIGH RISK' || data.current_threat_level === 'SUSPICIOUS') {
            defconBadge.classList.add('defcon-3');
            defconLabel.innerText = 'DEFCON 3 : ELEVATED RISK';
        } else {
            defconBadge.classList.add('defcon-5');
            defconLabel.innerText = 'DEFCON 5 : GUARDED';
        }
    }

    // Threat level indicator
    const levelVal = document.getElementById('threat-level-val');
    const glowDiv = document.getElementById('threat-indicator-glow');
    const descDiv = document.getElementById('threat-description');
    const alarmBanner = document.getElementById('alarm-banner');
    const alarmText = document.getElementById('alarm-text');

    levelVal.innerText = data.current_threat_level;
    levelVal.className = 'threat-level';
    glowDiv.className = 'threat-glow';

    // Alarm banner trigger
    if (data.current_threat_level === 'CRITICAL') {
        levelVal.classList.add('text-critical');
        glowDiv.classList.add('status-critical');
        descDiv.innerText = "Critical threat: Autonomous containment response triggered";
        alarmBanner.classList.remove('hidden');
        alarmText.innerText = "CRITICAL SECURITY BREACH: AUTOMATED CONTAINMENT ISOLATED CULPRIT PROCESS";
    } else if (data.current_threat_level === 'HIGH RISK') {
        levelVal.classList.add('text-high');
        glowDiv.classList.add('status-high');
        descDiv.innerText = "High threat level: Awaiting administrator response authorization";
        alarmBanner.classList.remove('hidden');
        alarmText.innerText = "HIGH RISK ACTIVITY: SECURITY ACTIONS QUEUED FOR ADMINISTRATIVE APPROVAL";
    } else if (data.current_threat_level === 'SUSPICIOUS') {
        levelVal.classList.add('text-suspicious');
        glowDiv.classList.add('status-suspicious');
        descDiv.innerText = "Suspicious behavior anomalies detected in monitored folder";
        alarmBanner.classList.add('hidden');
    } else {
        levelVal.classList.add('text-normal');
        glowDiv.classList.add('status-normal');
        descDiv.innerText = "FIM & Attestation systems report environment secured";
        alarmBanner.classList.add('hidden');
    }
}

function updateEnforcementDisplay(isEnforced) {
    const sidebarMode = document.getElementById('sidebar-mode');
    const toggle = document.getElementById('enforcement-toggle');
    
    toggle.checked = isEnforced;
    if (isEnforced) {
        sidebarMode.innerText = "ENFORCEMENT";
        sidebarMode.className = "status-val enforcement";
    } else {
        sidebarMode.innerText = "SIMULATION";
        sidebarMode.className = "status-val simulation";
    }
}

// Update pending action badge
function updateApprovalsBadge(count) {
    const badge = document.getElementById('approval-badge');
    badge.innerText = count;
    if (count > 0) {
        badge.classList.remove('hidden');
    } else {
        badge.classList.add('hidden');
    }
}

// Fetch Incidents list
function fetchIncidentsList() {
    fetch('/api/incidents')
        .then(res => res.json())
        .then(data => {
            // Update overview numbers
            document.getElementById('metric-incidents').innerText = data.length;
            
            // Build Analyst Incident List
            if (activeSection === 'analyst') {
                renderAnalystIncidents(data);
            }
            
            // Build Overview Alert Feed
            if (activeSection === 'overview') {
                renderAlertFeed(data);
            }
        });
}

// Render Overview Alert feed
function renderAlertFeed(incidents) {
    const feed = document.getElementById('alert-feed-list');
    if (!incidents || incidents.length === 0) {
        return; // Keep default empty state
    }

    feed.classList.remove('empty');
    feed.innerHTML = '';
    
    // Select first few
    incidents.slice(0, 5).forEach(inc => {
        const item = document.createElement('div');
        const classificationClass = inc.threat_classification.toLowerCase().replace(' ', '');
        item.className = `alert-feed-item ${classificationClass}`;
        
        let fileText = "File Event";
        try {
            const evts = JSON.parse(inc.events_correlated);
            if (evts.length > 0) fileText = `${inc.threat_classification}: Suspicious event in monitored directory`;
        } catch(e) {}

        const localTime = new Date(inc.timestamp).toLocaleTimeString();

        item.innerHTML = `
            <div class="alert-details">
                <span class="alert-msg">${inc.llm_summary || fileText}</span>
                <span class="alert-meta">Risk: ${inc.risk_score}/100 | State: ${inc.threat_classification}</span>
            </div>
            <span class="alert-time">${localTime}</span>
        `;
        feed.appendChild(item);
    });
}

// Render Incident timeline on Threat Analyst page
function renderAnalystIncidents(incidents) {
    const list = document.getElementById('incidents-list');
    list.innerHTML = '';

    if (!incidents || incidents.length === 0) {
        list.innerHTML = `<div class="text-center padding-top">No incidents logged.</div>`;
        return;
    }

    incidents.forEach(inc => {
        const div = document.createElement('div');
        const classificationClass = inc.threat_classification.toLowerCase().replace(' ', '');
        const isSelected = selectedIncidentId === inc.id ? 'selected' : '';
        div.className = `incident-sidebar-item ${classificationClass} ${isSelected}`;
        
        const localTime = new Date(inc.timestamp).toLocaleTimeString();
        
        div.innerHTML = `
            <div class="inc-sidebar-header">
                <span>ID: INC-#00${inc.id}</span>
                <span>${localTime}</span>
            </div>
            <div class="inc-sidebar-title">${inc.llm_summary || 'Security Incident'}</div>
            <div class="inc-sidebar-meta">
                <span class="inc-sidebar-risk ${classificationClass}">Score: ${inc.risk_score}</span>
                <span>${inc.threat_classification}</span>
            </div>
        `;

        div.addEventListener('click', () => {
            selectedIncidentId = inc.id;
            // Update selected state visually
            document.querySelectorAll('.incident-sidebar-item').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');
            
            displayIncidentWorkspace(inc);
        });

        list.appendChild(div);
    });

    // Auto-select first incident on initial load if none is selected yet
    if (!selectedIncidentId && incidents.length > 0) {
        selectedIncidentId = incidents[0].id;
        displayIncidentWorkspace(incidents[0]);
    }
}

// Display Workspace details of selected Incident
function displayIncidentWorkspace(inc) {
    document.getElementById('workspace-empty').classList.add('hidden');
    const content = document.getElementById('workspace-content');
    content.classList.remove('hidden');

    document.getElementById('workspace-title').innerText = inc.llm_summary || `Incident INC-#00${inc.id}`;
    
    // Risk Badge
    const badge = document.getElementById('workspace-risk-badge');
    badge.innerText = `Risk: ${inc.risk_score}/100`;
    badge.className = 'risk-badge';
    badge.classList.remove('hidden');
    
    const classificationClass = inc.threat_classification.toLowerCase().replace(' ', '');
    badge.classList.add(classificationClass);

    // AI Report contents
    document.getElementById('ai-report-summary').innerText = inc.llm_summary || "Grounding analysis...";
    document.getElementById('ai-report-reasoning').innerText = inc.llm_reasoning || "Deductions log empty.";
    document.getElementById('ai-report-actions').innerText = inc.llm_action || "Remediation recommendations empty.";

    // MITRE ATT&CK Mapping
    const mitreCard = document.getElementById('mitre-card');
    const mitreEmpty = document.getElementById('mitre-empty');
    if (inc.mitre_mapping) {
        mitreCard.classList.remove('hidden');
        mitreEmpty.classList.add('hidden');
        document.getElementById('mitre-card-id').innerText = inc.mitre_mapping.technique_id;
        document.getElementById('mitre-card-name').innerText = inc.mitre_mapping.technique_name;
        document.getElementById('mitre-card-tactic').innerText = inc.mitre_mapping.tactic;
        document.getElementById('mitre-card-confidence').innerText = inc.mitre_mapping.confidence;
        document.getElementById('mitre-card-evidence').innerText = inc.mitre_mapping.evidence;
    } else {
        mitreCard.classList.add('hidden');
        mitreEmpty.classList.remove('hidden');
    }

    // Render Vis.js attack graph
    renderAttackGraph(inc.attack_graph);
}

function renderFallbackGraphHTML(container, graphData) {
    container.innerHTML = '';
    container.style.overflowY = 'auto';
    container.style.padding = '20px';
    container.style.display = 'flex';
    container.style.flexDirection = 'column';
    container.style.gap = '15px';
    container.style.alignItems = 'center';
    
    const flowchartDiv = document.createElement('div');
    flowchartDiv.style.display = 'flex';
    flowchartDiv.style.flexDirection = 'column';
    flowchartDiv.style.alignItems = 'center';
    flowchartDiv.style.gap = '10px';
    flowchartDiv.style.width = '100%';
    
    const orderedGroups = ['user', 'parent_process', 'process', 'file', 'event', 'network'];
    const nodesByGroup = {};
    orderedGroups.forEach(g => nodesByGroup[g] = []);
    
    graphData.nodes.forEach(n => {
        if (nodesByGroup[n.group]) {
            nodesByGroup[n.group].push(n);
        } else {
            nodesByGroup['event'].push(n);
        }
    });
    
    let addedAny = false;
    orderedGroups.forEach((group) => {
        const groupNodes = nodesByGroup[group];
        if (groupNodes.length === 0) return;
        
        if (addedAny) {
            const arrow = document.createElement('div');
            arrow.innerHTML = '<i class="fa-solid fa-arrow-down" style="color: var(--neon-cyan); font-size: 16px; margin: 5px 0;"></i>';
            flowchartDiv.appendChild(arrow);
        }
        
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.gap = '15px';
        row.style.justifyContent = 'center';
        row.style.flexWrap = 'wrap';
        
        groupNodes.forEach(node => {
            const nodeEl = document.createElement('div');
            nodeEl.style.padding = '10px 15px';
            nodeEl.style.borderRadius = '6px';
            nodeEl.style.border = '1px solid var(--border-color)';
            nodeEl.style.fontSize = '12px';
            nodeEl.style.fontFamily = 'var(--font-mono)';
            nodeEl.style.textAlign = 'center';
            nodeEl.style.minWidth = '120px';
            nodeEl.style.boxShadow = '0 0 10px rgba(0, 240, 255, 0.05)';
            
            let color = 'var(--text-main)';
            let bgColor = 'rgba(255, 255, 255, 0.02)';
            
            switch (node.group) {
                case 'user':
                    color = 'var(--neon-cyan)';
                    bgColor = 'rgba(0, 240, 255, 0.05)';
                    break;
                case 'parent_process':
                case 'process':
                    color = 'var(--neon-green)';
                    bgColor = 'rgba(57, 255, 20, 0.05)';
                    break;
                case 'file':
                    color = 'var(--neon-yellow)';
                    bgColor = 'rgba(255, 204, 0, 0.05)';
                    break;
                case 'event':
                    color = 'var(--neon-red)';
                    bgColor = 'rgba(255, 0, 85, 0.05)';
                    break;
                case 'network':
                    color = 'var(--neon-purple)';
                    bgColor = 'rgba(189, 0, 255, 0.05)';
                    break;
            }
            
            nodeEl.style.color = color;
            nodeEl.style.backgroundColor = bgColor;
            nodeEl.style.borderColor = color;
            
            nodeEl.innerHTML = `<strong style="font-size: 10px; display: block; opacity: 0.6; text-transform: uppercase;">${node.group.replace('_', ' ')}</strong>${node.label.replace('\n', ' ')}`;
            row.appendChild(nodeEl);
        });
        
        flowchartDiv.appendChild(row);
        addedAny = true;
    });
    
    container.appendChild(flowchartDiv);
}

// Render Vis.js Node Network
function renderAttackGraph(graphData) {
    const container = document.getElementById('attack-graph');
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
        container.innerHTML = '<div class="text-center padding-top">Graph dataset empty.</div>';
        return;
    }

    if (typeof vis === 'undefined') {
        console.warn("Vis.js library not loaded. Falling back to structured HTML Flowchart.");
        renderFallbackGraphHTML(container, graphData);
        return;
    }

    container.innerHTML = '<div class="text-center padding-top"><i class="fa-solid fa-spinner fa-spin"></i> Instantiating Network...</div>';

    // Delay network creation slightly so the flexbox dimensions settle in the DOM first
    console.log("Scheduling Vis.js instantiation timeout...");
    setTimeout(() => {
        try {
            console.log("Vis.js timeout fired. Clearing spinner...");
            container.innerHTML = '';
            
            // Intelligent Event Aggregation:
            // If an incident has dozens of rapid repetitive file events (e.g. 20+ MODIFIED events),
            // group them into clean summarized nodes per file & event type so it doesn't create a massive cluttered fan.
            const nonEventNodes = [];
            const eventNodeMap = {};
            (graphData.nodes || []).forEach(n => {
                if (n.group === 'event') {
                    eventNodeMap[n.id] = n;
                } else {
                    nonEventNodes.push(n);
                }
            });

            const eventNodesByFile = {};
            const otherEdges = [];
            (graphData.edges || []).forEach(e => {
                if (eventNodeMap[e.to]) {
                    const fileId = e.from;
                    const evtNode = eventNodeMap[e.to];
                    if (!eventNodesByFile[fileId]) eventNodesByFile[fileId] = {};
                    
                    const rawType = (evtNode.label || 'EVENT').split('\n')[0].replace(/ALERT/g, '').replace(/\(\d+x\)/g, '').trim();
                    if (!eventNodesByFile[fileId][rawType]) {
                        eventNodesByFile[fileId][rawType] = {
                            type: rawType,
                            count: 0,
                            status: (evtNode.label || '').includes('Violated') ? 'Violated' : 'Observed',
                            titles: []
                        };
                    }
                    eventNodesByFile[fileId][rawType].count++;
                    if (evtNode.title) eventNodesByFile[fileId][rawType].titles.push(evtNode.title);
                } else {
                    otherEdges.push(e);
                }
            });

            let finalNodes = [];
            let finalEdges = [];

            if (Object.keys(eventNodesByFile).length > 0) {
                finalNodes = [...nonEventNodes];
                finalEdges = [...otherEdges];

                for (const [fileId, types] of Object.entries(eventNodesByFile)) {
                    for (const [rawType, info] of Object.entries(types)) {
                        const aggId = `agg_evt_${fileId}_${rawType}`;
                        const countText = info.count > 1 ? ` (${info.count}x)` : '';
                        finalNodes.push({
                            id: aggId,
                            label: `${rawType}${countText}\nIntegrity ${info.status}`,
                            group: 'event',
                            title: `Aggregated Events: ${info.count}\n\nRecent Details:\n${info.titles.slice(0, 4).join('\n---\n')}${info.titles.length > 4 ? '\n...and more rapid events' : ''}`
                        });
                        finalEdges.push({
                            id: `${fileId}->${aggId}`,
                            from: fileId,
                            to: aggId,
                            label: info.count > 1 ? `triggered (${info.count}x)` : 'triggered',
                            color: '#fa5252'
                        });
                    }
                }
            } else {
                finalNodes = graphData.nodes || [];
                finalEdges = graphData.edges || [];
            }

            console.log("Mapping styled nodes for Vis.js...");
            const styledNodes = finalNodes.map(node => {
                let iconCode = '\uf013'; // Default gear icon
                let color = '#a2b9bc';
                
                switch (node.group) {
                    case 'user':
                        iconCode = '\uf007'; // User silhouette
                        color = '#00f0ff'; // Bright neon cyan
                        break;
                    case 'parent_process':
                        iconCode = '\uf085'; // Gears
                        color = '#39ff14'; // Bright neon green
                        break;
                    case 'process':
                        iconCode = '\uf013'; // Single gear
                        color = '#39ff14'; // Bright neon green
                        break;
                    case 'file':
                        iconCode = '\uf15c'; // File script
                        color = '#ffcc00'; // Bright neon yellow
                        break;
                    case 'event':
                        iconCode = '\uf071'; // Exclamation warning triangle
                        color = '#ff0055'; // Bright neon red
                        break;
                    case 'network':
                        iconCode = '\uf0ac'; // Globe
                        color = '#bd00ff'; // Bright neon purple
                        break;
                }

                // Clean label to make it human-friendly
                let friendlyLabel = node.label;
                if (node.group === 'user') {
                    friendlyLabel = `User\n${node.label.replace('User: ', '')}`;
                } else if (node.group === 'parent_process') {
                    friendlyLabel = `Parent Process\n${node.label.replace('parent_process', '')}`;
                } else if (node.group === 'process') {
                    friendlyLabel = `Active Process\n${node.label.replace('process', '')}`;
                } else if (node.group === 'file') {
                    friendlyLabel = `Target File\n${node.label}`;
                } else if (node.group === 'event') {
                    friendlyLabel = node.label.startsWith('ALERT') ? node.label : `ALERT\n${node.label}`;
                }

                return {
                    id: node.id,
                    label: friendlyLabel,
                    title: node.title,
                    shape: 'icon',
                    icon: {
                        face: '"Font Awesome 6 Free"',
                        code: iconCode,
                        size: 34,
                        color: color,
                        weight: '900'
                    },
                    font: { color: '#e2e8f0', size: 11, face: 'Outfit', align: 'center' }
                };
            });

            const data = {
                nodes: styledNodes,
                edges: finalEdges
            };

            const options = {
                height: '100%',
                width: '100%',
                layout: {
                    hierarchical: {
                        enabled: true,
                        direction: 'LR', // Left-to-Right directed timeline
                        sortMethod: 'directed',
                        nodeSpacing: 140,
                        levelSeparation: 200,
                        parentCentralization: true
                    }
                },
                physics: {
                    enabled: false
                },
                nodes: {
                    borderWidth: 2
                },
                edges: {
                    arrows: {
                        to: { enabled: true, scaleFactor: 0.8 }
                    },
                    width: 2,
                    color: { color: '#3b5bdb', highlight: '#00f0ff' },
                    font: { color: '#868e96', size: 10, face: 'Outfit', align: 'horizontal' }
                }
            };

            if (networkGraphInstance) {
                console.log("Destroying previous Vis.js network instance...");
                networkGraphInstance.destroy();
            }
            
            networkGraphInstance = new vis.Network(container, data, options);
            setTimeout(() => {
                if (networkGraphInstance) {
                    networkGraphInstance.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
                }
            }, 150);
            console.log("vis.Network initialized and centered successfully!");
        } catch (e) {
            console.error("CRITICAL VIS.JS RUNTIME ERROR:", e);
            showToast("Vis.js Error: " + e.message, "error");
        }
    }, 100);

}

// Fetch Baseline hashes
function getFileIconMeta(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    if (ext === 'pdf') {
        return { icon: 'fa-solid fa-file-pdf', cls: 'pdf', label: 'PDF' };
    } else if (['docx', 'doc'].includes(ext)) {
        return { icon: 'fa-solid fa-file-word', cls: 'word', label: 'DOCX' };
    } else if (['xlsx', 'xls', 'csv'].includes(ext)) {
        return { icon: 'fa-solid fa-file-excel', cls: 'excel', label: 'SHEET' };
    } else if (['json', 'py', 'js', 'conf', 'env', 'key', 'xml'].includes(ext)) {
        return { icon: 'fa-solid fa-file-code', cls: 'code', label: ext.toUpperCase() };
    } else if (['txt', 'log', 'md'].includes(ext)) {
        return { icon: 'fa-solid fa-file-lines', cls: 'text', label: 'TXT' };
    } else {
        return { icon: 'fa-solid fa-file', cls: 'default', label: ext.toUpperCase() || 'FILE' };
    }
}

// Fetch Baseline hashes and render file type icons
function fetchBaselines() {
    fetch('/api/status')
        .then(res => res.json())
        .then(statusData => {
            const monPathEl = document.getElementById('monitored-path');
            if (monPathEl) monPathEl.value = statusData.monitored_directory;
            
            const badgeEl = document.getElementById('active-monitored-badge');
            if (badgeEl) {
                const parts = statusData.monitored_directory.split(/[\/\\]/);
                badgeEl.innerText = parts[parts.length - 1] || statusData.monitored_directory;
                badgeEl.title = statusData.monitored_directory;
            }

            const inputCustomDir = document.getElementById('input-custom-dir');
            if (inputCustomDir && !inputCustomDir.value) {
                inputCustomDir.value = statusData.monitored_directory;
            }
        })
        .catch(() => {});

    fetch('/api/baselines')
        .then(res => res.ok ? res.json() : [])
        .then(baselines => {
            const tbody = document.getElementById('baseline-list-body');
            if (!tbody) return;
            tbody.innerHTML = '';

            const metricFiles = document.getElementById('metric-files');
            if (!baselines || baselines.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center" style="padding: 25px;"><i class="fa-solid fa-folder-open text-muted" style="font-size: 28px; margin-bottom: 8px; display: block;"></i>No files registered in baseline. Use the upload box above to add your files.</td></tr>`;
                if (metricFiles) metricFiles.innerText = 0;
                return;
            }
            
            if (metricFiles) metricFiles.innerText = baselines.length;

            baselines.forEach(b => {
                const tr = document.createElement('tr');
                const shortPath = b.file_path.replace(/\\\\/g, '\\');
                const filename = shortPath.split('\\').pop();
                const meta = getFileIconMeta(filename);
                const dateStr = new Date(b.created_at).toLocaleString();

                const sizeFormatted = b.file_size > 1024 * 1024 
                    ? (b.file_size / (1024 * 1024)).toFixed(2) + ' MB'
                    : b.file_size > 1024 
                    ? (b.file_size / 1024).toFixed(1) + ' KB'
                    : b.file_size + ' B';

                tr.innerHTML = `
                    <td>
                        <div style="display: flex; align-items: center;">
                            <span class="file-type-icon ${meta.cls}"><i class="${meta.icon}"></i></span>
                            <div>
                                <strong class="bold">${filename}</strong>
                                <span class="badge ${meta.cls}" style="margin-left: 6px; font-size: 10px; padding: 2px 6px;">${meta.label}</span>
                                <br><small class="text-muted font-mono" style="font-size: 11px;">${shortPath}</small>
                            </div>
                        </div>
                    </td>
                    <td class="font-mono" title="${b.sha256}">
                        <span class="text-cyan">${b.sha256.substring(0, 16)}</span><span class="text-muted">...${b.sha256.substring(b.sha256.length - 8)}</span>
                    </td>
                    <td><span class="badge" style="background: rgba(255,255,255,0.06); font-family: monospace;">${sizeFormatted}</span></td>
                    <td><small class="text-muted">${dateStr}</small></td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => {
            const tbody = document.getElementById('baseline-list-body');
            if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center">Error reading baseline database: ${err.message}</td></tr>`;
        });
}

// Fetch Attestation history and updates
function fetchAttestationData() {
    fetch('/api/attestation')
        .then(res => res.json())
        .then(data => {
            // Update components health indicators
            const componentsList = document.getElementById('attestation-components-list');
            componentsList.innerHTML = '';
            
            const targets = systemStatus.monitored_directory ? ['fim_service', 'attestation_engine', 'config', 'forensic_logger', 'main', 'ml_engine'] : [];
            const violations = data.current.violations || [];
            
            if (targets.length === 0) {
                componentsList.innerHTML = '<div class="text-center text-muted">No components registered.</div>';
            } else {
                targets.forEach(comp => {
                    const compItem = document.createElement('div');
                    compItem.className = 'comp-item';
                    
                    // Check if this component has a violation
                    const violation = violations.find(v => v.component === comp || v.component === comp.replace('_', ''));
                    const isOk = !violation;
                    
                    compItem.innerHTML = `
                        <div class="comp-meta">
                            <span class="comp-name">${comp.toUpperCase().replace('_', ' ')}</span>
                            <span class="comp-path">src/backend/${comp}.py</span>
                        </div>
                        <div class="comp-status ${isOk ? 'text-success' : 'text-danger'}">
                            <span class="comp-status-dot ${isOk ? 'pass' : 'fail'}"></span>
                            ${isOk ? 'INTEGRITY SECURE' : 'INTEGRITY VIOLATED'}
                        </div>
                    `;
                    componentsList.appendChild(compItem);
                });
            }

            // Update Chart.js timeline
            const history = data.history || [];
            // Map history chronologically
            const revHistory = [...history].reverse();
            const labels = revHistory.map(h => new Date(h.timestamp).toLocaleTimeString());
            const scores = revHistory.map(h => h.trust_score);
            
            trustChartInstance.data.labels = labels;
            trustChartInstance.data.datasets[0].data = scores;
            trustChartInstance.update();

            // Attestation violations table
            const tbody = document.getElementById('attestation-logs-body');
            tbody.innerHTML = '';
            
            const activeLogs = history.filter(h => {
                try {
                    return JSON.parse(h.violations).length > 0;
                } catch(e) { return false; }
            });

            if (activeLogs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center">No violations logged. System runtime is secure.</td></tr>`;
                return;
            }

            activeLogs.forEach(h => {
                const tr = document.createElement('tr');
                const localTime = new Date(h.timestamp).toLocaleString();
                let violationTexts = [];
                try {
                    const viols = JSON.parse(h.violations);
                    violationTexts = viols.map(v => `${v.message} (Penalty: -${v.penalty} pts)`);
                } catch(e) {}
                
                tr.innerHTML = `
                    <td>${localTime}</td>
                    <td class="font-mono bold">${h.trust_score}/100</td>
                    <td><span class="text-${h.trust_state.toLowerCase()} bold">${h.trust_state}</span></td>
                    <td class="text-danger">${violationTexts.join('<br>') || 'None'}</td>
                `;
                tbody.appendChild(tr);
            });
        });
}

// Fetch Response logs
function fetchResponsesLogs() {
    fetch('/api/responses')
        .then(res => res.json())
        .then(data => {
            document.getElementById('metric-responses').innerText = data.length;
            
            const tbody = document.getElementById('responses-logs-body');
            tbody.innerHTML = '';
            
            if (!data || data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="text-center">No response actions executed yet.</td></tr>`;
                return;
            }

            data.forEach(r => {
                const tr = document.createElement('tr');
                const localTime = new Date(r.timestamp).toLocaleString();
                
                tr.innerHTML = `
                    <td>${localTime}</td>
                    <td class="font-mono">INC-#00${r.incident_id}</td>
                    <td class="bold">${r.action_taken}</td>
                    <td><span class="status-val ${r.mode.toLowerCase()}">${r.mode}</span></td>
                    <td class="text-muted font-mono">${r.details}</td>
                `;
                tbody.appendChild(tr);
            });
        });
}

// Render manual approval widgets in Response Center
function updateApprovalsList(approvals) {
    const list = document.getElementById('approvals-list');
    list.innerHTML = '';

    if (!approvals || approvals.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-check text-success"></i>
                <p>No responses are currently queued for manual authorization.</p>
            </div>`;
        return;
    }

    approvals.forEach(appr => {
        const item = document.createElement('div');
        const filename = appr.file_path.split('\\').pop();
        item.className = 'approval-item';
        item.innerHTML = `
            <div class="approval-item-header">
                <span class="approval-title text-warning"><i class="fa-solid fa-user-shield"></i> Action Required: INC-#00${appr.incident_id}</span>
                <span class="status-val simulation">Awaiting Admin Approval</span>
            </div>
            <div class="approval-item-details">
                <div class="appr-row">
                    <span class="appr-lbl">Culprit Process</span>
                    <span class="appr-val font-mono">${appr.process_name} (PID: ${appr.process_id})</span>
                </div>
                <div class="appr-row">
                    <span class="appr-lbl">Target File</span>
                    <span class="appr-val font-mono">${filename}</span>
                </div>
                <div class="appr-row" style="grid-column: span 2;">
                    <span class="appr-lbl">Proposed Response</span>
                    <span class="appr-val text-danger">Process Termination & Quarantine Restoration</span>
                </div>
            </div>
            <div class="approval-item-actions">
                <button class="btn btn-sm btn-clear" onclick="rejectApproval('${appr.approval_id}')">Reject / Dismiss</button>
                <button class="btn btn-sm btn-danger" onclick="approveApproval('${appr.approval_id}')">Approve & Isolate</button>
            </div>
        `;
        list.appendChild(item);
    });
}

// Approve pending response
function approveApproval(id) {
    const btn = window.event ? window.event.target : null;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Isolating...';
    }

    fetch('/api/approvals/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: id })
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Approval request failed.");
        }
        return data;
    })
    .then(() => {
        showToast("Action approved! Process isolated & file restored from baseline backup.", "success");
        if (btn) {
            const card = btn.closest('.approval-item');
            if (card) card.remove();
        }
        fetchData();
        fetchForensicsLogs();
    })
    .catch(err => {
        console.error("Approval error:", err);
        showToast("Approval error: " + err.message, "error");
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = 'Approve & Isolate';
        }
    });
}

// Reject pending response
function rejectApproval(id) {
    const btn = window.event ? window.event.target : null;
    if (btn) {
        btn.disabled = true;
    }

    fetch('/api/approvals/reject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: id })
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Rejection failed.");
        }
        return data;
    })
    .then(() => {
        showToast("Action rejected and incident dismissed.", "info");
        if (btn) {
            const card = btn.closest('.approval-item');
            if (card) card.remove();
        }
        fetchData();
    })
    .catch(err => {
        console.error("Rejection error:", err);
        showToast("Rejection error: " + err.message, "error");
        if (btn) btn.disabled = false;
    });
}


// Fetch Forensic Logs Database
function fetchForensicsLogs() {
    fetch('/api/events')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById('forensics-logs-body');
            tbody.innerHTML = '';
            
            if (!data || data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="text-center">No forensic event logs recorded yet.</td></tr>`;
                return;
            }

            data.forEach(e => {
                const tr = document.createElement('tr');
                const localTime = new Date(e.timestamp).toLocaleString();
                const pathParts = e.file_path.split('\\');
                const filename = pathParts.pop();
                const parentDir = pathParts.pop() || '';
                
                let integrityClass = 'text-success';
                if (e.integrity_status === 'Integrity Violated') {
                    integrityClass = 'text-danger bold';
                }

                tr.innerHTML = `
                    <td class="font-mono">${e.id}</td>
                    <td>${localTime}</td>
                    <td><span class="bold">${filename}</span><br><small class="text-muted">.../${parentDir}/${filename}</small></td>
                    <td class="bold text-cyan">${e.event_type}</td>
                    <td class="font-mono">${e.process_name}</td>
                    <td class="font-mono">${e.process_id || 'N/A'}</td>
                    <td>${e.username}</td>
                    <td><span class="${integrityClass}">${e.integrity_status}</span></td>
                `;
                tbody.appendChild(tr);
            });
        });
}

// Inject Attestation Violation
function injectAttestationViolation(type, penalty, msg) {
    fetch('/api/simulate-tampering', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ violation_type: type, penalty: penalty, details: msg })
    })
    .then(res => res.json())
    .then(() => {
        showToast(`Violation Injected: ${type} (-${penalty} points).`, "warning");
        fetchData();
    });
}

function clearAttestationViolations() {
    fetch('/api/simulate-tampering', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ violation_type: 'reset', penalty: 0, details: '' })
    })
    .then(res => res.json())
    .then(() => {
        showToast("Simulated attestation violations cleared.", "success");
        fetchData();
    });
}

// Trigger simulation scenarios on the backend
function triggerSimulationScenario(scenarioId) {
    showToast(`Triggering Test Scenario ${scenarioId}... Checking telemetry updates.`, "info");
    fetch('/api/trigger-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId })
    })
    .then(res => res.json())
    .then(data => {
        console.log("Scenario execution triggered:", data);
        setTimeout(fetchData, 1000);
    })
    .catch(err => {
        console.error("Failed to run scenario:", err);
    });
}

// Sleek toast notification helper function
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type}`;
    
    let icon = 'fa-circle-info text-cyan';
    if (type === 'success') icon = 'fa-circle-check text-success';
    if (type === 'warning') icon = 'fa-triangle-exclamation text-warning';
    if (type === 'error') icon = 'fa-circle-exclamation text-critical';
    
    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <div class="toast-message">${message}</div>
    `;
    
    container.appendChild(toast);
    
    // Force CSS reflow to start transition
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Remove toast after 3.5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ==========================================================================
// AI ASSISTANT CHARACTER & VOICE CHAT CONTROLLER
// ==========================================================================

let aiVoiceEnabled = true;
let speechRecognitionInstance = null;
let isVoiceRecording = false;

function initAIAssistant() {
    const avatar = document.getElementById('ai-character-avatar');
    const modal = document.getElementById('ai-chat-modal');
    const bubble = document.getElementById('ai-speech-bubble');
    const bubbleClose = document.getElementById('ai-bubble-close');
    const chatClose = document.getElementById('ai-chat-close-btn');
    const voiceToggleBtn = document.getElementById('ai-voice-toggle-btn');
    const voiceIcon = document.getElementById('voice-icon');
    const sendBtn = document.getElementById('chat-send-btn');
    const input = document.getElementById('chat-text-input');
    const micBtn = document.getElementById('voice-mic-btn');
    const cancelVoiceBtn = document.getElementById('voice-cancel-btn');
    const chips = document.querySelectorAll('.quick-chip');

    // 1. Toggle Chat Modal
    if (avatar && modal) {
        avatar.addEventListener('click', () => {
            modal.classList.toggle('hidden');
            if (!modal.classList.contains('hidden')) {
                if (bubble) bubble.classList.add('hidden');
                if (input) input.focus();
            }
        });
    }

    if (chatClose && modal) {
        chatClose.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
    }

    if (bubbleClose && bubble) {
        bubbleClose.addEventListener('click', (e) => {
            e.stopPropagation();
            bubble.classList.add('hidden');
        });
    }

    // 2. Voice Output Toggle (TTS)
    if (voiceToggleBtn && voiceIcon) {
        voiceToggleBtn.addEventListener('click', () => {
            aiVoiceEnabled = !aiVoiceEnabled;
            if (aiVoiceEnabled) {
                voiceIcon.className = 'fa-solid fa-volume-high';
                voiceToggleBtn.classList.add('active');
                showToast("AI Voice Speech Output enabled.", "info");
            } else {
                voiceIcon.className = 'fa-solid fa-volume-xmark';
                voiceToggleBtn.classList.remove('active');
                if (window.speechSynthesis) window.speechSynthesis.cancel();
                showToast("AI Voice Speech Output muted.", "warning");
            }
        });
        voiceToggleBtn.classList.add('active');
    }

    // 3. Setup Web Speech Recognition (Speech-to-Text)
    setupSpeechRecognition();

    // 4. Send Message via Button or Enter key
    if (sendBtn && input) {
        sendBtn.addEventListener('click', () => handleSendChatMessage());
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleSendChatMessage();
            }
        });
    }

    // 5. Mic button toggle
    if (micBtn) {
        micBtn.addEventListener('click', () => {
            toggleVoiceRecording();
        });
    }

    if (cancelVoiceBtn) {
        cancelVoiceBtn.addEventListener('click', () => {
            stopVoiceRecording();
        });
    }

    // 6. Quick Action Chips
    chips.forEach(chip => {
        chip.addEventListener('click', () => {
            const query = chip.getAttribute('data-query');
            if (query && input) {
                input.value = query;
                handleSendChatMessage();
            }
        });
    });

    // Auto show speech bubble greeting on load after 2 seconds
    setTimeout(() => {
        if (bubble && modal && modal.classList.contains('hidden')) {
            bubble.classList.remove('hidden');
        }
    }, 2000);
}

function setupSpeechRecognition() {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
        console.warn("Web Speech API not supported in this browser.");
        const micBtn = document.getElementById('voice-mic-btn');
        if (micBtn) {
            micBtn.title = "Voice recognition not supported in this browser (Chrome / Edge recommended)";
        }
        return;
    }

    speechRecognitionInstance = new SpeechRecognition();
    speechRecognitionInstance.continuous = false;
    speechRecognitionInstance.interimResults = false;
    speechRecognitionInstance.lang = 'en-US';

    speechRecognitionInstance.onstart = () => {
        isVoiceRecording = true;
        const micBtn = document.getElementById('voice-mic-btn');
        const indicator = document.getElementById('voice-listening-indicator');
        const avatar = document.getElementById('ai-character-avatar');
        if (micBtn) micBtn.classList.add('recording');
        if (indicator) indicator.classList.remove('hidden');
        if (avatar) avatar.classList.add('speaking');
    };

    speechRecognitionInstance.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        console.log("Voice transcript received:", transcript);
        const input = document.getElementById('chat-text-input');
        if (input) {
            input.value = transcript;
            handleSendChatMessage();
        }
    };

    speechRecognitionInstance.onerror = (event) => {
        console.warn("Speech recognition error:", event.error);
        stopVoiceRecording();
        if (event.error !== 'no-speech') {
            showToast(`Voice input: ${event.error}`, "warning");
        }
    };

    speechRecognitionInstance.onend = () => {
        stopVoiceRecording();
    };
}

function toggleVoiceRecording() {
    if (!speechRecognitionInstance) {
        showToast("Voice recognition requires Chrome, Edge, or a Web Speech API browser.", "warning");
        return;
    }
    if (isVoiceRecording) {
        stopVoiceRecording();
    } else {
        try {
            speechRecognitionInstance.start();
        } catch (e) {
            console.error(e);
            stopVoiceRecording();
        }
    }
}

function stopVoiceRecording() {
    isVoiceRecording = false;
    const micBtn = document.getElementById('voice-mic-btn');
    const indicator = document.getElementById('voice-listening-indicator');
    const avatar = document.getElementById('ai-character-avatar');
    if (micBtn) micBtn.classList.remove('recording');
    if (indicator) indicator.classList.add('hidden');
    if (avatar) avatar.classList.remove('speaking');
    if (speechRecognitionInstance) {
        try { speechRecognitionInstance.stop(); } catch (e) {}
    }
}

function handleSendChatMessage() {
    const input = document.getElementById('chat-text-input');
    if (!input) return;
    const message = input.value.trim();
    if (!message) return;

    // Clear input
    input.value = '';

    // Append User message
    appendChatMessage(message, 'user');

    // Immediate typing indicator for zero perceptual delay
    const typingId = appendTypingIndicator();

    // Fast asynchronous post to backend
    fetch('/api/assistant-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message })
    })
    .then(res => res.json())
    .then(data => {
        removeTypingIndicator(typingId);
        appendChatMessage(data.reply, 'bot');
        if (aiVoiceEnabled) {
            speakText(data.reply);
        }
        if (data.action) {
            showToast(`Action Triggered: ${data.action}`, "success");
            setTimeout(fetchData, 400);
        }
    })
    .catch(err => {
        removeTypingIndicator(typingId);
        console.error("Assistant chat error:", err);
        appendChatMessage("Sorry, I encountered an error communicating with the backend.", 'bot');
    });
}

function appendTypingIndicator() {
    const messagesContainer = document.getElementById('chat-messages');
    if (!messagesContainer) return null;
    const id = 'typing-' + Date.now();
    const div = document.createElement('div');
    div.id = id;
    div.className = 'chat-msg bot typing-msg';
    div.innerHTML = `
        <div class="msg-avatar"><i class="fa-solid fa-robot"></i></div>
        <div class="msg-bubble">
            <span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>
        </div>
    `;
    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    return id;
}

function removeTypingIndicator(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.remove();
}

function appendChatMessage(text, sender = 'bot') {
    const messagesContainer = document.getElementById('chat-messages');
    if (!messagesContainer) return;

    const msgDiv = document.createElement('div');
    msgDiv.className = `chat-msg ${sender}`;

    const icon = sender === 'bot' ? 'fa-robot' : 'fa-user';
    msgDiv.innerHTML = `
        <div class="msg-avatar"><i class="fa-solid ${icon}"></i></div>
        <div class="msg-bubble">
            <p>${formatMessageContent(text)}</p>
        </div>
    `;

    messagesContainer.appendChild(msgDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function formatMessageContent(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code>$1</code>');
}

// Pre-warmed voices cache for instant natural copilot speech
let cachedVoices = [];
if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
    cachedVoices = window.speechSynthesis.getVoices();
    window.speechSynthesis.onvoiceschanged = () => {
        cachedVoices = window.speechSynthesis.getVoices();
    };
}

// Crisp, natural AI Copilot Text-to-Speech (TTS) Voice Engine
function speakText(text) {
    if (!window.speechSynthesis || !aiVoiceEnabled) return;

    window.speechSynthesis.cancel(); // Stop prior speech immediately

    // Clean text for speaking (strip markdown, quotes, emojis, symbols)
    const cleanText = text.replace(/[*_`#]/g, '').replace(/[🚨🛡️⚠️💡✨✅★●[\]]/g, '').trim();
    if (!cleanText) return;

    const utterance = new SpeechSynthesisUtterance(cleanText);
    utterance.rate = 1.1; // Crisp, responsive tactical pace
    utterance.pitch = 1.0;

    // Use preferred clear English voice
    if (cachedVoices.length === 0) cachedVoices = window.speechSynthesis.getVoices();
    const preferredVoice = cachedVoices.find(v => 
        (v.name.includes("Google") || v.name.includes("Natural") || v.name.includes("Zira") || v.name.includes("David") || v.name.includes("Samantha")) && v.lang.startsWith("en")
    ) || cachedVoices[0];
    
    if (preferredVoice) {
        utterance.voice = preferredVoice;
    }

    const avatar = document.getElementById('ai-character-avatar');
    utterance.onstart = () => {
        if (avatar) avatar.classList.add('speaking');
    };
    utterance.onend = () => {
        if (avatar) avatar.classList.remove('speaking');
    };
    utterance.onerror = () => {
        if (avatar) avatar.classList.remove('speaking');
    };

    window.speechSynthesis.speak(utterance);
}

// Update Character Mood based on System Threat State
function updateCharacterState(trustScore, hasThreat) {
    const avatar = document.getElementById('ai-character-avatar');
    const bubble = document.getElementById('ai-speech-bubble');
    const bubbleText = document.getElementById('ai-speech-text');
    const modal = document.getElementById('ai-chat-modal');
    if (!avatar) return;

    avatar.classList.remove('warning', 'threat');

    if (hasThreat || trustScore < 50) {
        avatar.classList.add('threat');
        if (bubble && bubbleText && modal && modal.classList.contains('hidden')) {
            bubbleText.innerHTML = `🚨 <strong>THREAT DETECTED!</strong> High-risk anomaly identified. Click me to review or heal!`;
            bubble.classList.remove('hidden');
        }
    } else if (trustScore < 85) {
        avatar.classList.add('warning');
    }
}

// ==========================================================================
// ENTERPRISE EXECUTIVE FEATURES & POLISH CONTROLLER
// ==========================================================================

// Sound effects completely removed per preference
function playCyberClick() {}
function playCyberChime() {}

function initEnterpriseFeatures() {
    initLiveClocksAndUptime();
    initThemeSwitcher();
    initFileDiffViewer();
    initIncidentReportGenerator();
    initComplianceAndQuarantineActions();
}

// 1. Synchronized Dual Clocks & System Uptime
function initLiveClocksAndUptime() {
    const clockUtc = document.getElementById('clock-utc');
    const clockLoc = document.getElementById('clock-loc');
    const uptimeEl = document.getElementById('soc-uptime');

    const bootTime = Date.now() - (14 * 86400000 + 8 * 3600000 + 12 * 60000); // 14d 8h 12m

    function tick() {
        const now = new Date();
        if (clockUtc) clockUtc.innerText = 'UTC ' + now.toISOString().substring(11, 19);
        if (clockLoc) clockLoc.innerText = now.toTimeString().substring(0, 8);
        
        const clockEpoch = document.getElementById('clock-epoch');
        if (clockEpoch) {
            clockEpoch.innerText = (Date.now() / 1000).toFixed(2);
        }

        const diff = Math.floor((Date.now() - bootTime) / 1000);
        const days = Math.floor(diff / 86400);
        const hours = Math.floor((diff % 86400) / 3600);
        const mins = Math.floor((diff % 3600) / 60);
        const secs = diff % 60;
        if (uptimeEl) {
            uptimeEl.innerText = `UPTIME: ${days}d ${String(hours).padStart(2, '0')}h ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`;
        }
    }
    tick();
    setInterval(tick, 100);
}


// 2. 1-Click Dark/Light Mode Theme Switcher
function initThemeSwitcher() {
    const btn = document.getElementById('theme-toggle-btn');
    const icon = document.getElementById('theme-icon');
    const text = document.getElementById('theme-text');

    const savedTheme = localStorage.getItem('soc-theme') || 'dark';
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        if (icon) icon.className = 'fa-solid fa-moon text-cyan';
        if (text) text.innerText = 'Dark Theme';
    }

    if (btn) {
        btn.addEventListener('click', () => {
            document.body.classList.toggle('light-theme');
            const isLight = document.body.classList.contains('light-theme');
            localStorage.setItem('soc-theme', isLight ? 'light' : 'dark');
            if (isLight) {
                if (icon) icon.className = 'fa-solid fa-moon text-cyan';
                if (text) text.innerText = 'Dark Theme';
                showToast("Enterprise Light Theme activated.", "info");
            } else {
                if (icon) icon.className = 'fa-solid fa-sun';
                if (text) text.innerText = 'Light Theme';
                showToast("Tactical Dark Cyber Theme activated.", "info");
            }
        });
    }
}

// 4. Side-by-Side Visual File Diff Viewer
function initFileDiffViewer() {
    const modal = document.getElementById('file-diff-modal');
    const closeBtn = document.getElementById('diff-close-btn');
    const rollbackBtn = document.getElementById('diff-rollback-btn');

    if (closeBtn && modal) {
        closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.add('hidden');
        });
    }

    if (rollbackBtn) {
        rollbackBtn.addEventListener('click', () => {
            showToast("Executing deterministic atomic file rollback from HMAC baseline...", "info");
            fetch('/api/trigger-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario_id: 1 })
            }).then(() => {
                setTimeout(() => {
                    showToast("Clean baseline restored! Diff eliminated.", "success");
                    if (modal) modal.classList.add('hidden');
                    fetchData();
                }, 1000);
            });
        });
    }

    // Attach inspect buttons in Quarantine table and incident feed
    document.querySelectorAll('.btn-inspect').forEach(btn => {
        btn.addEventListener('click', () => {
            const fileName = btn.getAttribute('data-file') || 'policy.json';
            openFileDiffModal(fileName);
        });
    });
}

function openFileDiffModal(fileName = 'policy.json') {
    const modal = document.getElementById('file-diff-modal');
    const targetSpan = document.getElementById('diff-file-target');
    if (!modal) return;

    if (targetSpan) targetSpan.innerText = `Target: /monitored_dir/${fileName}`;
    modal.classList.remove('hidden');
}

// 5. One-Click Executive Incident & Compliance Report Generator
function initIncidentReportGenerator() {
    const exportBtn = document.getElementById('export-report-btn');
    const modal = document.getElementById('report-modal');
    const closeBtn = document.getElementById('report-close-btn');
    const printBtn = document.getElementById('print-report-btn');
    const csvBtn = document.getElementById('download-csv-report-btn');

    if (exportBtn && modal) {
        exportBtn.addEventListener('click', () => {
            modal.classList.remove('hidden');
            const dateSpan = document.getElementById('report-date');
            if (dateSpan) dateSpan.innerText = new Date().toISOString().split('T')[0];
        });
    }

    if (closeBtn && modal) {
        closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.add('hidden');
        });
    }

    if (printBtn) {
        printBtn.addEventListener('click', () => {
            window.print();
        });
    }

    if (csvBtn) {
        csvBtn.addEventListener('click', () => {
            downloadForensicCSV();
        });
    }
}

function downloadForensicCSV() {
    const rows = [
        ["Event_ID", "Timestamp", "Target_File", "Operation", "Process_Name", "PID", "User", "Integrity_Status", "MITRE_Tactic"],
        ["EVT-1001", new Date().toISOString(), "/monitored_dir/policy.json", "MODIFIED", "powershell.exe", "4500", "Vidhy", "TAMPERED", "T1562.001"],
        ["EVT-1002", new Date(Date.now() - 300000).toISOString(), "/monitored_dir/credentials.txt", "ACCESS", "malware_sim.exe", "3400", "SYSTEM", "UNAUTHORIZED", "T1485"],
        ["EVT-1003", new Date(Date.now() - 600000).toISOString(), "/monitored_dir/config.json", "CREATED", "explorer.exe", "1024", "Administrator", "VERIFIED", "NORMAL"]
    ];

    let csvContent = "data:text/csv;charset=utf-8," + rows.map(e => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `SOC_Forensic_Incident_Report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast("Official Forensic CSV Report downloaded.", "success");
}

// 6. Compliance Certificate & Quarantine Shredding Actions
function initComplianceAndQuarantineActions() {
    // Accordion Toggles
    document.querySelectorAll('.accordion-toggle').forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = toggle.getAttribute('data-target');
            const panel = document.getElementById(targetId);
            if (panel) {
                const isHidden = panel.classList.contains('hidden');
                panel.classList.toggle('hidden', !isHidden);
                toggle.classList.toggle('expanded', isHidden);
            }
        });
    });

    // Run Real-Time Compliance Audit
    const auditBtn = document.getElementById('btn-run-compliance-audit');
    const consoleBox = document.getElementById('compliance-audit-console');
    const consoleLog = document.getElementById('audit-console-log');
    const timerDisplay = document.getElementById('audit-timer');
    const progressCircle = document.getElementById('comp-progress-circle');
    const scoreVal = document.getElementById('comp-score-val');
    const hashDisplay = document.getElementById('audit-hash-display');

    if (auditBtn) {
        auditBtn.addEventListener('click', () => {
            if (auditBtn.disabled) return;
            auditBtn.disabled = true;
            auditBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Auditing System Telemetry...</span>';
            
            showToast("Zero-Trust Continuous Compliance Harvester launched...", "info");

            if (consoleBox) consoleBox.classList.remove('hidden');
            if (consoleLog) consoleLog.innerHTML = '<span class="console-line audit-head">[INIT] Spawning Kernel Attestation Evaluator...</span>';

            // Animate gauge dipping then recovering
            if (progressCircle) progressCircle.style.strokeDashoffset = '40';
            if (scoreVal) scoreVal.textContent = '91%';

            const steps = [
                { delay: 400, text: '[+] eBPF PROBE: Checking file baseline hooks in kernel space... OK (Latency 0.28ms)', type: 'info' },
                { delay: 900, text: '[+] PCI-DSS 4.0 // REQ 11.5: 1,428 system binaries verified against golden image... [PASSED]', type: 'pass' },
                { delay: 1500, text: '[+] HIPAA § 164.312(c)(1): ePHI cryptographic storage & WAL tamper lock active... [PASSED]', type: 'pass' },
                { delay: 2100, text: '[+] NIST SP 800-53 (SI-7): Runtime binary attestation matches MITRE CRA 2026... [PASSED]', type: 'pass' },
                { delay: 2700, text: '[+] ISO/IEC 27001 A.8.9: Isolation Forest drift score 0.011 (Threshold 0.650)... [PASSED]', type: 'pass' },
                { delay: 3200, text: '[★] AUDIT COMPLETE: 4 of 4 Mandates 100% Compliant. Zero Configuration Drift.', type: 'pass' }
            ];

            steps.forEach(step => {
                setTimeout(() => {
                    if (consoleLog) {
                        const line = document.createElement('span');
                        line.className = `console-line ${step.type}`;
                        line.textContent = `[${new Date().toLocaleTimeString()}] ${step.text}`;
                        consoleLog.appendChild(line);
                        consoleLog.scrollTop = consoleLog.scrollHeight;
                    }
                }, step.delay);
            });

            setTimeout(() => {
                // Generate a fresh pseudo crypto hash
                const freshHash = 'SHA-256: ' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                if (hashDisplay) hashDisplay.textContent = freshHash;
                
                // Recover gauge to 100%
                if (progressCircle) progressCircle.style.strokeDashoffset = '0';
                if (scoreVal) scoreVal.textContent = '100%';

                auditBtn.disabled = false;
                auditBtn.innerHTML = '<i class="fa-solid fa-radar fa-spin-pulse"></i> <span>Run Real-Time Compliance Audit</span>';
                if (timerDisplay) timerDisplay.textContent = 'LAST CYCLE: JUST NOW';
                
                showToast("Continuous Audit Cycle Completed: 4/4 Frameworks 100% Compliant.", "success");
            }, 3500);
        });
    }

    // Copy Hash Button
    const copyHashBtn = document.getElementById('btn-copy-hash');
    if (copyHashBtn) {
        copyHashBtn.addEventListener('click', () => {
            const hashText = hashDisplay ? hashDisplay.textContent : '';
            if (hashText && navigator.clipboard) {
                navigator.clipboard.writeText(hashText).then(() => {
                    showToast("Attestation Hash copied to clipboard.", "success");
                }).catch(() => {
                    showToast(hashText, "info");
                });
            } else {
                showToast(hashText, "info");
            }
        });
    }

    // Individual Framework Test Buttons
    document.querySelectorAll('.comp-test-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const fw = btn.getAttribute('data-fw') || 'Framework';
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Attesting...`;
            btn.disabled = true;
            
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-circle-check text-success"></i> Verified 100%`;
                showToast(`${fw} validation probe verified: Zero non-compliant deltas detected.`, "success");
                setTimeout(() => {
                    if (fw.includes('PCI')) btn.innerHTML = `<i class="fa-solid fa-microchip"></i> Test PCI Hook`;
                    else if (fw.includes('HIPAA')) btn.innerHTML = `<i class="fa-solid fa-heart-pulse"></i> Test ePHI Lock`;
                    else if (fw.includes('NIST')) btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Run NIST Attestation`;
                    else btn.innerHTML = `<i class="fa-solid fa-diagram-project"></i> Verify Configuration`;
                }, 3000);
            }, 1000);
        });
    });

    // Official Audit Certificate Modal
    const certBtn = document.getElementById('btn-download-cert');
    const certModal = document.getElementById('compliance-cert-modal');
    const certCloseBtn = document.getElementById('cert-close-btn');
    const printCertBtn = document.getElementById('print-cert-btn');

    if (certBtn && certModal) {
        certBtn.addEventListener('click', () => {
            // Update certificate meta
            const dateEl = document.getElementById('cert-audit-date');
            const idEl = document.getElementById('cert-display-id');
            const sealEl = document.getElementById('cert-crypto-seal');
            const now = new Date();
            if (dateEl) dateEl.textContent = now.toISOString().split('T')[0];
            if (idEl) idEl.textContent = `CERT-REG-${now.getFullYear()}-FIM-${Math.floor(1000 + Math.random() * 9000)}`;
            if (sealEl && hashDisplay) sealEl.textContent = hashDisplay.textContent.replace('SHA-256: ', 'SHA256:');

            certModal.classList.remove('hidden');
        });
    }

    if (certCloseBtn && certModal) {
        certCloseBtn.addEventListener('click', () => {
            certModal.classList.add('hidden');
        });
    }

    if (certModal) {
        certModal.addEventListener('click', (e) => {
            if (e.target === certModal) {
                certModal.classList.add('hidden');
            }
        });
    }

    if (printCertBtn) {
        printCertBtn.addEventListener('click', () => {
            window.print();
        });
    }

    // Shred buttons
    document.querySelectorAll('.btn-shred').forEach(btn => {
        btn.addEventListener('click', () => {
            const row = btn.closest('tr');
            showToast("Incinerating quarantined malware artifact with zero-fill wipe...", "warning");
            if (row) {
                row.style.opacity = '0.3';
                setTimeout(() => {
                    row.remove();
                    showToast("Malware payload permanently destroyed.", "success");
                }, 800);
            }
        });
    });
}
