document.addEventListener('DOMContentLoaded', () => {
    const elements = {
        tableBody: document.querySelector('#dns-table tbody'),
        tableWrap: document.querySelector('.table-wrap'),
        searchInput: document.getElementById('search-input'),
        searchFieldSelect: document.getElementById('search-field-select'),
        densitySelect: document.getElementById('density-select'),
        searchButton: document.getElementById('search-button'),
        searchExcludeBtn: document.getElementById('search-exclude-btn'),
        clearSearchButton: document.getElementById('clear-search-button'),
        clearDisplayButton: document.getElementById('clear-display-button'),
        exportCsvButton: document.getElementById('export-csv-button'),
        exportJsonButton: document.getElementById('export-json-button'),
        masterCb: document.getElementById('master-cb'),
        startButton: document.getElementById('start-button'),
        stopButton: document.getElementById('stop-button'),
        modeSelect: document.getElementById('mode-select'),
        toolSelect: document.getElementById('tool-select'),
        interfaceInput: document.getElementById('interface-input'),
        pcapInput: document.getElementById('pcap-input'),
        mongoUriInput: document.getElementById('mongo-uri-input'),
        mongoDbInput: document.getElementById('mongo-db-input'),
        mongoCollectionInput: document.getElementById('mongo-collection-input'),
        limitInput: document.getElementById('limit-input'),
        statusBadge: document.getElementById('status-badge'),
        streamPill: document.getElementById('stream-pill'),
        streamText: document.getElementById('stream-text'),
        heroNote: document.getElementById('hero-note'),
        monitorSummary: document.getElementById('monitor-summary'),
        activityFeed: document.getElementById('activity-feed'),
        lastUpdatePill: document.getElementById('last-update-pill'),
        focusBanner: document.getElementById('focus-banner'),
        focusIpDisplay: document.getElementById('focus-ip-display'),
        targetIpInput: document.getElementById('target-ip-input'),
        interfaceSelect: document.getElementById('interface-select'),
        sinkholeIpInput: document.getElementById('sinkhole-ip-input'),
        scanTargetContainer: document.getElementById('scan-target-container'),
        scanTargetInput: document.getElementById('scan-target-input'),
        resultCount: document.getElementById('result-count'),
        resetBtn: document.getElementById('reset-button'),
        refreshHistoryBtn: document.getElementById('refresh-history-btn'),
        historyList: document.getElementById('history-list'),
        totalEvents: document.getElementById('total-events'),
        uniqueDomains: document.getElementById('unique-domains'),
        eventsPerMinute: document.getElementById('events-per-minute'),
        topDomain: document.getElementById('top-domain'),
        topClient: document.getElementById('top-client'),
        topRecordType: document.getElementById('top-record-type'),
        uploadZone: document.getElementById('upload-zone'),
        pcapUploadInput: document.getElementById('pcap-upload'),
        uploadStatus: document.getElementById('upload-status'),
        statusFilename: document.querySelector('.status-filename'),
        uploadProgress: document.getElementById('upload-progress'),
        clearUploadBtn: document.getElementById('clear-upload-btn'),
        avgQps: document.getElementById('avg-qps'),
        trafficChartCanvas: document.getElementById('traffic-chart'),
        quickFilters: document.getElementById('quick-filters'),
    };

    const state = {
        dnsData: [],
        captureSession: null,
        summary: {},
        searchTerm: '',
        searchField: 'all',
        searchExclude: false,
        eventSource: null,
        pollTimer: null,
        reconnectTimer: null,
        streamConnected: false,
        trafficChart: null,
        chartData: Array(60).fill(0),
        targetIp: '',
        history: [],
        durationTimer: null,
        reconnectBackoff: 2000,
        quickFilterType: 'all',
        displayLimit: 100,
        scrollObserver: null,
        lastFilterSignature: '',
        clearTimestamp: 0,
    };

    const MAX_EVENTS = 500;

    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function highlightText(value, term) {
        const strValue = String(value ?? '');
        if (!term || state.searchExclude) return escapeHtml(strValue);

        let regex;
        let isRegex = false;
        const regexMatch = term.match(/^\/(.+)\/([gimsuy]*)$/);

        if (regexMatch) {
            try {
                let flags = regexMatch[2];
                if (!flags.includes('g')) flags += 'g'; // g flag required to find all highlights
                if (!flags.includes('i')) flags += 'i';
                regex = new RegExp(regexMatch[1], flags);
                isRegex = true;
            } catch (e) {
                // Ignore invalid regex, fallback to string search
            }
        }

        if (!isRegex) {
            const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            regex = new RegExp(`(${escapedTerm})`, 'gi');
            return strValue.split(regex).map((part, i) => {
                return (i % 2 === 1) 
                    ? `<mark class="highlight-match">${escapeHtml(part)}</mark>` 
                    : escapeHtml(part);
            }).join('');
        }

        let lastIndex = 0;
        let result = '';
        let match;

        regex.lastIndex = 0;
        while ((match = regex.exec(strValue)) !== null) {
            if (match[0].length === 0) { regex.lastIndex++; continue; }
            result += escapeHtml(strValue.substring(lastIndex, match.index));
            result += `<mark class="highlight-match">${escapeHtml(match[0])}</mark>`;
            lastIndex = regex.lastIndex;
        }
        
        result += escapeHtml(strValue.substring(lastIndex));
        return result;
    }

    function toDisplay(value, fallback = 'No data') {
        if (value === null || value === undefined || value === '') {
            return fallback;
        }
        return value;
    }

    function formatDateTime(value) {
        if (!value) {
            return 'Unknown';
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return value;
        }

        return date.toLocaleString();
    }

    function formatRelativeTime(value) {
        if (!value) {
            return 'No updates yet';
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return value;
        }

        const diffSeconds = Math.round((Date.now() - date.getTime()) / 1000);
        if (diffSeconds < 5) {
            return 'Just now';
        }
        if (diffSeconds < 60) {
            return `${diffSeconds}s ago`;
        }
        if (diffSeconds < 3600) {
            return `${Math.floor(diffSeconds / 60)}m ago`;
        }
        return `${Math.floor(diffSeconds / 3600)}h ago`;
    }

    function filteredData() {
        let data = state.dnsData;

        if (state.clearTimestamp) {
            data = data.filter(e => {
                const ts = new Date(e.timestamp).getTime();
                return isNaN(ts) ? true : ts > state.clearTimestamp;
            });
        }

        if (state.quickFilterType !== 'all') {
            data = data.filter(event => {
                const type = String(event.recordType || '').toUpperCase();
                if (state.quickFilterType === 'browser') {
                    return ['A', 'AAAA', 'HTTPS', 'CNAME'].includes(type);
                } else if (state.quickFilterType === 'mail') {
                    return ['MX', 'TXT'].includes(type);
                } else if (state.quickFilterType === 'infrastructure') {
                    return ['NS', 'SOA'].includes(type);
                }
                return true;
            });
        }

        if (state.targetIp) {
            const target = state.targetIp.toLowerCase();
            data = data.filter((event) => 
                String(event.sourceIp || '').toLowerCase().includes(target) || 
                String(event.destinationIp || '').toLowerCase().includes(target)
            );
        }

        if (state.searchTerm) {
            const term = state.searchTerm;
            let isRegex = false;
            let searchRegex;

            const regexMatch = term.match(/^\/(.+)\/([gimsuy]*)$/);
            if (regexMatch) {
                try {
                    let flags = regexMatch[2];
                    if (!flags.includes('i')) flags += 'i';
                    searchRegex = new RegExp(regexMatch[1], flags);
                    isRegex = true;
                } catch (e) {}
            }

            const lowerTerm = term.toLowerCase();

            data = data.filter((event) => {
                let match = false;
                const testMatch = (val) => {
                    const strVal = String(val || '');
                    if (isRegex) {
                        searchRegex.lastIndex = 0;
                        return searchRegex.test(strVal);
                    }
                    return strVal.toLowerCase().includes(lowerTerm);
                };

                if (state.searchField === 'domain') {
                    match = testMatch(event.domain);
                } else if (state.searchField === 'client') {
                    match = testMatch(event.sourceIp);
                } else if (state.searchField === 'resolver') {
                    match = testMatch(event.destinationIp);
                } else if (state.searchField === 'type') {
                    match = testMatch(event.recordType);
                } else {
                    const values = [
                        event.domain, event.recordType, event.sourceIp,
                        event.destinationIp, event.transport, event.tool,
                        event.mode, event.protocol, event.threatLevel,
                    ];
                    match = values.some(testMatch);
                }
                return state.searchExclude ? !match : match;
            });
        }

        return data;
    }

    function updateSearchUI() {
        const wrapper = elements.searchInput.parentElement;
        if (wrapper && wrapper.classList.contains('search-wrapper')) {
            wrapper.classList.toggle('has-value', elements.searchInput.value.trim().length > 0);
        }
    }

    function updateStatusBadge(status) {
        const normalized = status || 'idle';
        elements.statusBadge.textContent = normalized.charAt(0).toUpperCase() + normalized.slice(1);
        elements.statusBadge.className = `status-badge ${normalized}`;
    }

    function updateStreamState(connected, message) {
        state.streamConnected = connected;
        elements.streamPill.className = `stream-pill ${connected ? 'online' : 'offline'}`;
        elements.streamText.textContent = message || (connected ? 'Realtime stream connected' : 'Realtime stream offline');
    }

    function renderMetrics() {
        const summary = state.summary || {};
        elements.totalEvents.textContent = summary.totalEvents ?? state.dnsData.length;
        elements.uniqueDomains.textContent = summary.uniqueDomains ?? 0;
        elements.eventsPerMinute.textContent = Number(summary.eventsPerMinute || 0).toFixed(1);
        elements.topDomain.textContent = toDisplay(summary.topDomain);
        elements.topClient.textContent = toDisplay(summary.topSourceIp);
        elements.topRecordType.textContent = toDisplay(summary.topRecordType);
        elements.lastUpdatePill.textContent = formatRelativeTime(summary.lastEventAt);

        const qps = summary.eventsPerMinute ? (summary.eventsPerMinute / 60).toFixed(2) : '0.00';
        if (elements.avgQps) elements.avgQps.textContent = `${qps} QPS Avg`;
    }

    function renderActivityFeed() {
        const activity = (state.summary?.recentActivity || []).slice(0, 6);
        if (!activity.length) {
            const emptyHtml = `
                <div class="activity-item">
                    <div>
                        <p class="activity-message">No activity yet.</p>
                        <p class="activity-time">Start a live capture or load a PCAP to populate the feed.</p>
                    </div>
                </div>
            `;
            if (elements.activityFeed.innerHTML !== emptyHtml) elements.activityFeed.innerHTML = emptyHtml;
            return;
        }

        const feedHtml = activity
            .map((entry) => `
                <div class="activity-item ${escapeHtml(entry.level || 'info')}">
                    <div class="activity-content">
                            <p class="activity-message">${highlightText(entry.message || 'Update received', state.searchTerm)}</p>
                        <p class="activity-time">${escapeHtml(formatDateTime(entry.timestamp))}</p>
                </div>
                ${entry.level === 'high' ? `<span class="activity-level warning">Phish/Threat</span>` : `<span class="activity-level">${escapeHtml(entry.level || 'info')}</span>`}
            </div>
            `)
            .join('');

        if (elements.activityFeed.innerHTML !== feedHtml) elements.activityFeed.innerHTML = feedHtml;
    }

    function renderMonitorSummary() {
        const session = state.captureSession;
        if (!session) {
            if (!elements.monitorSummary.querySelector('.idle-state')) {
                elements.monitorSummary.innerHTML = `
                    <div class="summary-card idle-state">
                        <div class="summary-head">
                            <h3>Session Overview</h3>
                            <span class="mini-pill">Idle</span>
                        </div>
                        <p class="summary-note">No capture session has been started yet.</p>
                    </div>
                `;
            }
            updateStatusBadge('idle');
            elements.heroNote.textContent = 'Waiting for the backend to publish capture data.';
            return;
        }

        const config = session.config || {};
        updateStatusBadge(session.status || 'idle');
        elements.heroNote.textContent = session.note || 'Monitoring backend status.';

        if (!elements.monitorSummary.querySelector('.active-session-card')) {
            elements.monitorSummary.innerHTML = `
                <div class="summary-card active-session-card">
                    <div class="summary-head">
                        <h3>Session Overview</h3>
                        <span class="mini-pill" id="sum-tool"></span>
                    </div>
                    <div class="summary-grid">
                        <div class="summary-row">
                            <span>Status</span>
                            <strong id="sum-status" style="text-transform: capitalize;"></strong>
                        </div>
                        <div class="summary-row">
                            <span>Events Seen</span>
                            <strong id="sum-events"></strong>
                        </div>
                        <div class="summary-row">
                            <span>Mode</span>
                            <strong id="sum-mode" style="text-transform: capitalize;"></strong>
                        </div>
                        <div class="summary-row">
                            <span>Interface</span>
                            <strong id="sum-interface"></strong>
                        </div>
                        <div class="summary-row">
                            <span>Last Event</span>
                            <strong id="sum-last"></strong>
                        </div>
                    </div>
                    <p class="summary-note" id="sum-note"></p>
                    <div id="sum-errors"></div>
                </div>
            `;
        }

        document.getElementById('sum-tool').textContent = session.tool || config.preferredTool || 'auto';
        document.getElementById('sum-status').textContent = toDisplay(session.status, 'idle');
        document.getElementById('sum-events').textContent = session.eventsSeen ?? 0;
        document.getElementById('sum-mode').textContent = toDisplay(config.mode, 'live');
        document.getElementById('sum-interface').textContent = toDisplay(config.interface, 'auto');
        document.getElementById('sum-last').textContent = formatRelativeTime(session.lastEventAt);
        document.getElementById('sum-note').textContent = session.note || 'No session notes yet.';

        const errorsContainer = document.getElementById('sum-errors');
        const errors = (session.errors || []).slice(-3);
        if (errors.length) {
            const errHtml = `<div class="error-box">${errors.map(e => `<p>${escapeHtml(e)}</p>`).join('')}</div>`;
            if (errorsContainer.innerHTML !== errHtml) {
                errorsContainer.innerHTML = errHtml;
            }
        } else if (errorsContainer.innerHTML !== '') {
            errorsContainer.innerHTML = '';
        }
    }

    function getDnsMethodClass(protocol, transport) {
        const proto = String(protocol || 'DNS').toUpperCase();
        const trans = String(transport || 'udp').toLowerCase();
        if (proto === 'DOH' || trans === 'https') return 'doh';
        if (proto === 'DOT' || trans === 'tls') return 'dot';
        return 'dns';
    }

    function buildRow(event, index) {
        const row = document.createElement('tr');
        row.style.animationDelay = `${Math.min(index * 30, 300)}ms`;

        const protocol = event.protocol || 'DNS';
        const transport = event.transport || 'udp';
        const methodClass = getDnsMethodClass(protocol, transport);

        const threatLevel = event.threatLevel || 'low';

        const cells = [
            { isCheckbox: true, value: '' },
            { value: formatDateTime(event.timestamp), cls: '' },
            { value: event.domain || 'unknown', cls: 'domain-cell' },
            { value: event.recordType || event.type || 'A', cls: 'mono-cell' },
            { value: protocol.toUpperCase(), cls: `method-cell ${methodClass}`, isBadge: true },
            { value: threatLevel.toUpperCase(), cls: `threat-badge threat-${threatLevel}`, isBadge: true },
            { value: event.sourceIp || 'unknown', cls: 'mono-cell' },
            { value: event.destinationIp || 'unknown', cls: 'mono-cell' },
            { value: `${transport} / ${protocol}`, cls: 'mono-cell' },
            { value: event.tool || 'auto', cls: '' },
            { value: event.mode || 'live', cls: '' },
        ];

        cells.forEach((cellDef) => {
            const cell = document.createElement('td');
            if (state.targetIp && (event.sourceIp === state.targetIp || event.destinationIp === state.targetIp)) {
                row.classList.add('focus-highlight');
            }

            if (cellDef.isCheckbox) {
                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.className = 'row-cb';
                cb.checked = !!event._selected;
                cb.addEventListener('change', (e) => {
                    event._selected = e.target.checked;
                    updateMasterCbState();
                });
                cell.appendChild(cb);
                cell.className = 'cb-cell';
            } else if (cellDef.isBadge) {
                const badge = document.createElement('span');
                badge.className = cellDef.cls;
            badge.innerHTML = highlightText(cellDef.value, state.searchTerm);
                cell.appendChild(badge);
            } else {
            cell.innerHTML = highlightText(cellDef.value, state.searchTerm);
                if (cellDef.cls) cell.className = cellDef.cls;
            }
            row.appendChild(cell);

            if (event.action === 'sinkholed' && cellDef.value === threatLevel.toUpperCase()) {
            cell.innerHTML = highlightText('SPOOFED', state.searchTerm);
                cell.className = 'threat-badge threat-high';
                row.classList.add('focus-highlight');
                row.title = `Intercepted and spoofed via Scapy to point to Sinkhole IP`;
            }

            if (!cellDef.isCheckbox) {
                cell.classList.add('clickable-cell');
                cell.addEventListener('click', () => {
                    const term = String(cellDef.value).trim();
                    if (term) {
                        elements.searchInput.value = term;
                        state.searchTerm = term;
                        updateSearchUI();
                        renderTable();
                        renderActivityFeed();
                    }
                });
            }
        });

        return row;
    }

    function renderTable() {
        // Auto-reset the display limit if the user changes any filters
        const filterSig = `${state.searchTerm}|${state.searchField}|${state.searchExclude}|${state.quickFilterType}|${state.targetIp}`;
        if (state.lastFilterSignature !== filterSig) {
            state.displayLimit = 100;
            state.lastFilterSignature = filterSig;
        }

        const rows = filteredData();
        elements.tableBody.innerHTML = '';

        if (state.scrollObserver) {
            state.scrollObserver.disconnect();
        }

        if (!rows.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 11;
            cell.className = 'empty-state';
            cell.textContent = state.searchTerm
                ? 'No DNS events match the current filter.'
                : (state.clearTimestamp ? 'No new events since display was cleared.' : 'No DNS events captured yet.');
            row.appendChild(cell);
            elements.tableBody.appendChild(row);
            elements.resultCount.textContent = '0 events';
            return;
        }

        const limit = Math.min(rows.length, state.displayLimit);
        const fragment = document.createDocumentFragment();
        for (let i = 0; i < limit; i++) {
            fragment.appendChild(buildRow(rows[i], i));
        }

        if (rows.length > state.displayLimit) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 11;
            td.className = 'empty-state';
            td.style.padding = '24px';
            td.innerHTML = `<span class="mini-pill" style="cursor: pointer;">Scroll or click to load more (${rows.length - limit} remaining)</span>`;
            
            // Fallback in case observer fails
            tr.addEventListener('click', () => {
                state.displayLimit += 100;
                renderTable();
            });
            
            tr.appendChild(td);
            fragment.appendChild(tr);

            if (!state.scrollObserver) {
                state.scrollObserver = new IntersectionObserver((entries) => {
                    if (entries[0].isIntersecting) {
                        state.displayLimit += 100;
                        renderTable();
                    }
                }, { rootMargin: '400px' });
            }
            
            elements.tableBody.appendChild(fragment);
            state.scrollObserver.observe(tr);
        } else {
            elements.tableBody.appendChild(fragment);
        }

        elements.resultCount.textContent = `${rows.length} event${rows.length === 1 ? '' : 's'}`;
    }

    function renderCaptureStatus() {
        const session = state.captureSession;
        const statusEl = elements.statusFilename;
        const banner = document.getElementById('hero-note');

        if (session && session.status !== 'idle') {
            elements.uploadStatus.className = `upload-status active ${session.status}`;
            if (banner) {
                const start = session.startedAt ? new Date(session.startedAt) : new Date();
                if (!state.durationTimer) {
                    state.durationTimer = setInterval(() => {
                        const now = new Date();
                        const diff = Math.floor((now - start) / 1000);
                        const mins = Math.floor(diff / 60);
                        const secs = diff % 60;
                        banner.textContent = `Live Session Active • Duration: ${mins}m ${secs}s • Mode: ${session.mode}`;
                    }, 1000);
                }
            }
        } else {
            elements.uploadStatus.className = 'upload-status idle';
            if (state.durationTimer) {
                clearInterval(state.durationTimer);
                state.durationTimer = null;
            }
            if (banner) banner.textContent = 'Waiting for the backend to publish capture data.';
        }
    }

    function renderAll() {
        renderMetrics();
        renderMonitorSummary();
        renderActivityFeed();
        renderTable();
        renderCaptureStatus();
    }

    function mergeSnapshot(payload) {
        if (Array.isArray(payload?.data)) {
            state.dnsData = payload.data.slice(0, MAX_EVENTS);
        }
        if (payload?.captureSession) {
            state.captureSession = payload.captureSession;
        }
        if (payload?.summary) {
            state.summary = payload.summary;
        }
        renderAll();
        updateChartSnapshot();
    }

    function applyEvent(payload) {
        if (payload?.event) {
            const existingIdx = state.dnsData.findIndex((item) => item.id === payload.event.id);
            if (existingIdx !== -1) state.dnsData.splice(existingIdx, 1);
            state.dnsData.unshift(payload.event);
            if (state.dnsData.length > MAX_EVENTS) state.dnsData.pop();

            bumpChart();

            // Focus Mode: Highlight or add activity
            if (state.targetIp && (payload.event.sourceIp === state.targetIp || payload.event.destinationIp === state.targetIp)) {
                const deviceNote = `Observed targeted activity from ${state.targetIp} for ${payload.event.domain}`;
                const level = payload.event.threatLevel === 'high' ? 'error' : 'warning';
                state.summary.recentActivity = [{ timestamp: new Date().toISOString(), level, message: deviceNote }, ...(state.summary.recentActivity || [])].slice(0, 40);
            }
        }
        if (payload?.captureSession) {
            state.captureSession = payload.captureSession;
        }
        if (payload?.summary) {
            state.summary = payload.summary;
        }
        renderAll();
    }

    function buildCapturePayload() {
        return {
            mode: elements.modeSelect.value,
            preferredTool: elements.toolSelect.value,
            interface: elements.interfaceSelect.value,
            pcapPath: elements.pcapInput.value.trim(),
            mongoUri: elements.mongoUriInput.value.trim(),
            mongoDb: elements.mongoDbInput.value.trim(),
            mongoCollection: elements.mongoCollectionInput.value.trim(),
            limit: Number(elements.limitInput.value) || 0,
            sinkholeIp: elements.sinkholeIpInput?.value.trim(),
            scanTarget: elements.scanTargetInput?.value.trim(),
        };
    }

    function updateModeInputs() {
        const scanMode = elements.modeSelect.value === 'scan';
        const manualMode = elements.modeSelect.value === 'manual';
        elements.interfaceSelect.disabled = manualMode || scanMode;
        elements.pcapInput.required = manualMode;

        if (elements.scanTargetContainer) {
            elements.scanTargetContainer.style.display = scanMode ? 'flex' : 'none';
        }

        if (elements.uploadZone && elements.uploadZone.parentElement) {
            elements.uploadZone.parentElement.style.display = scanMode ? 'none' : 'flex';
        }
    }

    async function fetchSnapshot() {
        try {
            const response = await fetch('/api/dns-data');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            mergeSnapshot(payload);
        } catch (error) {
            console.error('Snapshot request failed:', error);
            updateStreamState(false, 'Realtime stream offline');
            elements.heroNote.textContent = 'Unable to reach the Flask backend. Start the server and try again.';
        }
    }

    async function fetchCaptureStatus() {
        try {
            const response = await fetch('/api/capture-status');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            mergeSnapshot(payload);
        } catch (error) {
            console.error('Capture status request failed:', error);
        }
    }

    async function fetchInterfaces() {
        try {
            const res = await fetch('/api/interfaces');
            const list = await res.json();
            elements.interfaceSelect.innerHTML = list.map(iface =>
                `<option value="${iface}">${iface}</option>`
            ).join('');
        } catch (e) {
            console.error("Failed to load interfaces", e);
        }
    }

    async function resetDashboard() {
        if (!confirm("Are you sure you want to clear all current metrics and event logs?")) return;
        try {
            const res = await fetch('/api/reset', { method: 'POST' });
            const snapshot = await res.json();
            state.dnsData = [];
            state.chartData.fill(0);
            state.clearTimestamp = 0;
            if (state.trafficChart) state.trafficChart.update();
            mergeSnapshot(snapshot);
            renderAll();
        } catch (e) {
            console.error("Reset failed", e);
        }
    }

    async function fetchHistory() {
        try {
            const res = await fetch('/api/history');
            state.history = await res.json();
            renderHistory();
        } catch (e) {
            console.error("Failed to fetch history", e);
        }
    }

    function renderHistory() {
        if (!state.history.length) {
            elements.historyList.innerHTML = '<p class="empty-note">No past sessions recorded yet.</p>';
            return;
        }

        elements.historyList.innerHTML = state.history.map(session => `
            <div class="history-item">
                <div class="history-item-info">
                    <p class="history-id">Session ${(session.id || 'unknown').replace('session-', '').substring(0, 8)}</p>
                    <p class="history-meta">${(session.config?.mode || 'live').toUpperCase()} • ${formatDateTime(session.startedAt)}</p>
                </div>
                <div class="history-stat">
                    <div class="mini-metric">
                        <strong>${session.eventsSeen || 0}</strong>
                        <span>Events</span>
                    </div>
                    <span class="history-badge ${session.status}">${session.status}</span>
                </div>
            </div>
        `).join('');
    }

    async function startCapture() {
        const payload = buildCapturePayload();
        if (payload.mode === 'manual' && !payload.pcapPath) {
            window.alert('Manual mode requires a PCAP file path.');
            return;
        }
        if (payload.mode === 'scan' && !payload.scanTarget) {
            window.alert('Scan mode requires a target IP or CIDR.');
            return;
        }

        elements.startButton.disabled = true;
        elements.startButton.textContent = 'Starting...';
        state.clearTimestamp = 0;

        try {
            const response = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Unable to start capture.');
            }
            mergeSnapshot(data);
        } catch (error) {
            console.error('Start capture failed:', error);
            elements.heroNote.textContent = error.message;
            updateStatusBadge('error');
        } finally {
            elements.startButton.disabled = false;
            elements.startButton.textContent = 'Start Capture';
        }
    }

    async function stopCapture() {
        elements.stopButton.disabled = true;
        elements.stopButton.textContent = 'Stopping...';

        try {
            const response = await fetch('/api/capture/stop', {
                method: 'POST',
            });
            const data = await response.json();
            mergeSnapshot(data);
        } catch (error) {
            console.error('Stop capture failed:', error);
            elements.heroNote.textContent = 'Unable to stop the active capture session.';
        } finally {
            elements.stopButton.disabled = false;
            elements.stopButton.textContent = 'Stop Capture';
        }
    }

    async function handleFileUpload(file) {
        if (!file) return;

        const fileName = file.name;
        if (!fileName.toLowerCase().endsWith('.pcap') && !fileName.toLowerCase().endsWith('.pcapng')) {
            window.alert('Please select a .pcap or .pcapng file.');
            return;
        }

        const MAX_SIZE = 50 * 1024 * 1024; // 50MB
        if (file.size > MAX_SIZE) {
            window.alert('File is too large. Maximum size is 50MB.');
            return;
        }

        elements.uploadStatus.hidden = false;
        elements.statusFilename.textContent = `Uploading ${fileName}...`;
        elements.uploadProgress.style.width = '0%';
        elements.uploadZone.classList.add('uploading');
        elements.clearUploadBtn.disabled = true;

        const formData = new FormData();
        formData.append('pcap', file);

        try {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload-pcap', true);

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total) * 100;
                    elements.uploadProgress.style.width = `${percent}%`;
                }
            };

            const cleanup = () => {
                elements.uploadZone.classList.remove('uploading');
                elements.clearUploadBtn.disabled = false;
            };

            xhr.onload = () => {
                cleanup();
                try {
                    if (xhr.status === 201) {
                        const result = JSON.parse(xhr.responseText);
                        elements.statusFilename.textContent = `Ready: ${fileName}`;
                        elements.pcapInput.value = result.pcapPath;
                        elements.modeSelect.value = 'manual';
                        updateModeInputs();
                        elements.heroNote.textContent = `Uploaded ${fileName} successfully. Ready to analyze.`;
                        state.clearTimestamp = 0;
                    } else {
                        const error = JSON.parse(xhr.responseText);
                        throw new Error(error.error || 'Upload failed');
                    }
                } catch (error) {
                    elements.statusFilename.textContent = `Upload failed: ${error.message}`;
                    elements.uploadProgress.style.width = '0%';
                }
            };

            xhr.onerror = () => {
                cleanup();
                elements.statusFilename.textContent = 'Upload failed: Network error during upload';
                elements.uploadProgress.style.width = '0%';
            };

            xhr.send(formData);
        } catch (error) {
            console.error('Upload failed:', error);
            elements.statusFilename.textContent = `Upload failed: ${error.message}`;
            elements.uploadProgress.style.width = '0%';
            elements.uploadZone.classList.remove('uploading');
            elements.clearUploadBtn.disabled = false;
        }
    }

    function clearUpload() {
        elements.pcapUploadInput.value = '';
        elements.uploadStatus.hidden = true;
        elements.statusFilename.textContent = 'No file selected';
        elements.uploadProgress.style.width = '0%';
        elements.pcapInput.value = '';
        elements.heroNote.textContent = 'Upload cleared. Ready for a new capture session.';
    }

    function initUploadZone() {
        const zone = elements.uploadZone;
        const input = elements.pcapUploadInput;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(name => {
            zone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        ['dragenter', 'dragover'].forEach(name => {
            zone.addEventListener(name, () => zone.classList.add('dragging'), false);
        });

        ['dragleave', 'drop'].forEach(name => {
            zone.addEventListener(name, () => zone.classList.remove('dragging'), false);
        });

        zone.addEventListener('drop', (e) => {
            const file = e.dataTransfer.files[0];
            handleFileUpload(file);
        }, false);

        input.addEventListener('change', (e) => {
            const file = e.target.files[0];
            handleFileUpload(file);
        });
    }


    function connectStream() {
        if (!window.EventSource) {
            return;
        }

        if (state.eventSource) {
            state.eventSource.close();
        }

        const eventSource = new EventSource('/api/stream');
        state.eventSource = eventSource;

        eventSource.addEventListener('open', () => {
            updateStreamState(true, 'Realtime stream connected');
            state.reconnectBackoff = 2000; // Reset backoff on successful connection
        });

        eventSource.addEventListener('snapshot', (event) => {
            mergeSnapshot(JSON.parse(event.data));
        });

        eventSource.addEventListener('dns-event', (event) => {
            applyEvent(JSON.parse(event.data));
        });

        eventSource.addEventListener('session', (event) => {
            mergeSnapshot(JSON.parse(event.data));
        });

        eventSource.addEventListener('error', () => {
            updateStreamState(false, 'Realtime stream reconnecting');
            eventSource.close();
            state.eventSource = null;
            if (state.reconnectTimer) {
                clearTimeout(state.reconnectTimer);
            }
            state.reconnectTimer = window.setTimeout(connectStream, state.reconnectBackoff);
            state.reconnectBackoff = Math.min(state.reconnectBackoff * 1.5, 30000); // Scale to 30s max
        });
    }

    function startPollingFallback() {
        if (state.pollTimer) {
            clearInterval(state.pollTimer);
        }
        state.pollTimer = window.setInterval(() => {
            fetchSnapshot();
            fetchCaptureStatus();
        }, 15000);
    }

    // ── Traffic Chart Integration ──────────────────────────────────────
    function initTrafficChart() {
        if (!elements.trafficChartCanvas || !window.Chart) return;

        const ctx = elements.trafficChartCanvas.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(56, 189, 248, 0.4)');
        gradient.addColorStop(1, 'rgba(56, 189, 248, 0.0)');

        state.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(60).fill(''),
                datasets: [{
                    label: 'Queries',
                    data: state.chartData,
                    borderColor: '#38bdf8',
                    borderWidth: 2,
                    fill: true,
                    backgroundColor: gradient,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { enabled: true } },
                scales: {
                    x: { display: false },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(100, 180, 255, 0.05)' },
                        ticks: { color: '#607a94', stepSize: 1 }
                    }
                },
                animation: { duration: 400 }
            }
        });
    }

    function bumpChart() {
        if (!state.trafficChart) return;
        const now = Math.floor(Date.now() / 1000);
        const second = now % 60;
        state.chartData[second] = (state.chartData[second] || 0) + 1;
        state.trafficChart.update('none');
    }

    function updateChartSnapshot() {
        if (!state.trafficChart) return;
        // Periodic reset of current bin happens naturally as time flows
        // But for a true "last 60s" sliding window, we'd need a more complex structure
        // This is a simplified rolling bucket visual.
    }

    // Tick the chart to rotate it or clear old bins
    window.setInterval(() => {
        if (!state.trafficChart) return;
        const now = Math.floor(Date.now() / 1000);
        const nextSecond = (now + 1) % 60;
        state.chartData[nextSecond] = 0; // Clear the upcoming bin
        state.trafficChart.update('none');
    }, 1000);

    elements.searchButton.addEventListener('click', () => {
        state.searchTerm = elements.searchInput.value.trim();
        updateSearchUI();
        renderTable();
    });

    elements.clearSearchButton.addEventListener('click', () => {
        elements.searchInput.value = '';
        state.searchTerm = '';
        updateSearchUI();
        renderTable();
        renderActivityFeed();
    });

    function updateMasterCbState() {
        if (!elements.masterCb) return;
        const displayed = filteredData();
        if (displayed.length === 0) {
            elements.masterCb.checked = false;
            elements.masterCb.indeterminate = false;
            return;
        }
        const selectedCount = displayed.filter(e => e._selected).length;
        if (selectedCount === 0) {
            elements.masterCb.checked = false;
            elements.masterCb.indeterminate = false;
        } else if (selectedCount === displayed.length) {
            elements.masterCb.checked = true;
            elements.masterCb.indeterminate = false;
        } else {
            elements.masterCb.checked = false;
            elements.masterCb.indeterminate = true;
        }
    }

    if (elements.masterCb) {
        elements.masterCb.addEventListener('change', (e) => {
            const isChecked = e.target.checked;
            const displayed = filteredData();
            displayed.forEach(event => {
                event._selected = isChecked;
            });
            const checkboxes = elements.tableBody.querySelectorAll('.row-cb');
            checkboxes.forEach(cb => cb.checked = isChecked);
        });
    }

    function triggerDownload(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    if (elements.exportCsvButton) {
        elements.exportCsvButton.addEventListener('click', () => {
            let data = filteredData();
            const selectedData = data.filter(e => e._selected);
            if (selectedData.length > 0) {
                data = selectedData;
            }
            if (!data.length) return;

            const headers = ["Time", "Domain", "Type", "Method", "Threat", "Threat Reasons", "Client", "Resolver", "Transport", "Answers", "TTL", "Tool", "Mode"];
            const rows = [headers.join(",")];

            data.forEach(event => {
                // Determine best timestamp source
                const ts = event.timestamp;
                const timeStr = (typeof ts === 'number')
                    ? new Date(ts * 1000).toISOString()
                    : new Date(ts).toISOString();

                const method = event.protocol || 'DNS/UDP';
                const threat = event.threatLevel || 'low';
                const reasonsStr = Array.isArray(event.threatReasons) ? event.threatReasons.join("; ") : (event.threatReasons || '');
                const answersStr = Array.isArray(event.answers) ? event.answers.join("; ") : (event.answers || '');
                
                const row = [
                    timeStr,
                    event.domain || '',
                    event.recordType || '',
                    method,
                    threat,
                    reasonsStr,
                    event.sourceIp || '',
                    event.destinationIp || '',
                    event.transport || '',
                    answersStr,
                    event.ttl || '',
                    event.tool || '',
                    event.mode || ''
                ].map(v => `"${String(v).replace(/"/g, '""')}"`);
                rows.push(row.join(","));
            });

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            triggerDownload(new Blob([rows.join("\n")], { type: 'text/csv' }), `dns-sinkhole-report-${timestamp}.csv`);
        });
    }

    if (elements.exportJsonButton) {
        elements.exportJsonButton.addEventListener('click', () => {
            let data = filteredData();
            const selectedData = data.filter(e => e._selected);
            if (selectedData.length > 0) {
                data = selectedData;
            }
            if (!data.length) return;

            const exportData = data.map(event => {
                const ts = event.timestamp;
                const timeStr = (typeof ts === 'number')
                    ? new Date(ts * 1000).toISOString()
                    : new Date(ts).toISOString();

                return {
                    time: timeStr,
                    domain: event.domain || '',
                    type: event.recordType || '',
                    method: event.protocol || 'DNS/UDP',
                    threat: event.threatLevel || 'low',
                    threatScore: event.threatScore || 0,
                    threatReasons: event.threatReasons || [],
                    client: event.sourceIp || '',
                    resolver: event.destinationIp || '',
                    transport: event.transport || '',
                    answers: event.answers || [],
                    ttl: event.ttl || null,
                    tool: event.tool || '',
                    mode: event.mode || ''
                };
            });

            const reportPayload = {
                metadata: {
                    exportedAt: new Date().toISOString(),
                    eventCount: exportData.length,
                    filters: { search: state.searchTerm, field: state.searchField, target: state.targetIp },
                    sessionSummary: state.summary || {}
                },
                events: exportData
            };

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            triggerDownload(new Blob([JSON.stringify(reportPayload, null, 2)], { type: 'application/json' }), `dns-sinkhole-report-${timestamp}.json`);
        });
    }


    elements.searchInput.addEventListener('input', () => {
        state.searchTerm = elements.searchInput.value.trim();
        updateSearchUI();
        renderTable();
        renderActivityFeed();
    });

    elements.searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            state.searchTerm = elements.searchInput.value.trim();
            updateSearchUI();
            renderTable();
            renderActivityFeed();
        }
    });

    if (elements.quickFilters) {
        elements.quickFilters.addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-btn')) {
                elements.quickFilters.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                e.target.classList.add('active');
                state.quickFilterType = e.target.dataset.filter;
                renderTable();
            }
        });
    }

    if (elements.clearDisplayButton) {
        elements.clearDisplayButton.addEventListener('click', () => {
            if (state.dnsData.length > 0) {
                const validTimestamps = state.dnsData.map(e => new Date(e.timestamp).getTime()).filter(ts => !isNaN(ts));
                if (validTimestamps.length > 0) {
                    state.clearTimestamp = Math.max(...validTimestamps);
                    renderTable();
                }
            }
        });
    }

    if (elements.searchFieldSelect) {
        elements.searchFieldSelect.addEventListener('change', (e) => {
            state.searchField = e.target.value;
            
            switch (state.searchField) {
                case 'domain':
                    elements.searchInput.placeholder = 'Filter by domain (e.g., google.com or /regex/)…';
                    break;
                case 'client':
                    elements.searchInput.placeholder = 'Filter by client IP (e.g., 192.168.1.5 or /^10\\./)…';
                    break;
                case 'resolver':
                    elements.searchInput.placeholder = 'Filter by resolver IP (e.g., 1.1.1.1)…';
                    break;
                case 'type':
                    elements.searchInput.placeholder = 'Filter by record type (e.g., A, MX or /A|MX|TXT/)…';
                    break;
                default:
                    elements.searchInput.placeholder = 'Filter by domain, type, client... Supports /regex/!';
            }

            renderTable();
            renderActivityFeed();
        });
    }

    if (elements.searchExcludeBtn) {
        elements.searchExcludeBtn.addEventListener('click', () => {
            state.searchExclude = !state.searchExclude;
            elements.searchExcludeBtn.classList.toggle('active', state.searchExclude);
            renderTable();
            renderActivityFeed();
        });
    }

    if (elements.activityFeed) {
        elements.activityFeed.addEventListener('click', (e) => {
            const mark = e.target.closest('mark.highlight-match');
            if (mark) {
                const term = mark.textContent.trim();
                elements.searchInput.value = term;
                state.searchTerm = term;
                updateSearchUI();
                renderTable();
            }
        });
    }

    if (elements.densitySelect && elements.tableWrap) {
        const savedDensity = localStorage.getItem('tableDensity') || 'comfortable';
        elements.densitySelect.value = savedDensity;
        elements.tableWrap.classList.add(`density-${savedDensity}`);

        elements.densitySelect.addEventListener('change', (e) => {
            const density = e.target.value;
            elements.tableWrap.classList.remove('density-comfortable', 'density-compact', 'density-dense');
            elements.tableWrap.classList.add(`density-${density}`);
            localStorage.setItem('tableDensity', density);
        });
    }

    elements.startButton.addEventListener('click', startCapture);
    elements.stopButton.addEventListener('click', stopCapture);
    elements.modeSelect.addEventListener('change', updateModeInputs);

    elements.clearUploadBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        clearUpload();
    });

    initUploadZone();
    initTrafficChart();
    fetchInterfaces();
    fetchHistory();
    updateModeInputs();

    elements.resetBtn.addEventListener('click', resetDashboard);
    elements.refreshHistoryBtn.addEventListener('click', fetchHistory);

    elements.targetIpInput.addEventListener('input', (e) => {
        state.targetIp = e.target.value.trim();
        if (state.targetIp) {
            elements.focusBanner.hidden = false;
            elements.focusIpDisplay.textContent = state.targetIp;
        } else {
            elements.focusBanner.hidden = true;
        }
        renderTable();
    });

    renderAll();
    fetchSnapshot();
    fetchCaptureStatus();
    connectStream();
    startPollingFallback();
    updateSearchUI();
});
