document.addEventListener('DOMContentLoaded', () => {
    const elements = {
        tableBody: document.querySelector('#dns-table tbody'),
        searchInput: document.getElementById('search-input'),
        searchButton: document.getElementById('search-button'),
        clearSearchButton: document.getElementById('clear-search-button'),
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
        resultCount: document.getElementById('result-count'),
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
        toggleManualPath: null,
        pcapPathContainer: null,
    };

    const state = {
        dnsData: [],
        captureSession: null,
        summary: {},
        searchTerm: '',
        eventSource: null,
        pollTimer: null,
        reconnectTimer: null,
        streamConnected: false,
    };

    const MAX_EVENTS = 500;

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
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
        if (!state.searchTerm) {
            return state.dnsData;
        }

        const term = state.searchTerm.toLowerCase();
        return state.dnsData.filter((event) => {
            const values = [
                event.domain,
                event.recordType,
                event.sourceIp,
                event.destinationIp,
                event.transport,
                event.tool,
                event.mode,
                event.protocol,
                event.threatLevel,
            ];
            return values.some((value) => String(value || '').toLowerCase().includes(term));
        });
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
    }

    function renderActivityFeed() {
        const activity = (state.summary?.recentActivity || []).slice(0, 6);
        if (!activity.length) {
            elements.activityFeed.innerHTML = `
                <div class="activity-item">
                    <div>
                        <p class="activity-message">No activity yet.</p>
                        <p class="activity-time">Start a live capture or load a PCAP to populate the feed.</p>
                    </div>
                </div>
            `;
            return;
        }

        elements.activityFeed.innerHTML = activity
            .map((entry) => `
                <div class="activity-item ${escapeHtml(entry.level || 'info')}">
                    <div class="activity-content">
                        <p class="activity-message">${escapeHtml(entry.message || 'Update received')}</p>
                        <p class="activity-time">${escapeHtml(formatDateTime(entry.timestamp))}</p>
                    </div>
                    <span class="activity-level">${escapeHtml(entry.level || 'info')}</span>
                </div>
            `)
            .join('');
    }

    function renderMonitorSummary() {
        const session = state.captureSession;
        if (!session) {
            elements.monitorSummary.innerHTML = `
                <div class="summary-card">
                    <div class="summary-head">
                        <h3>Session Overview</h3>
                        <span class="mini-pill">Idle</span>
                    </div>
                    <p class="summary-note">No capture session has been started yet.</p>
                </div>
            `;
            updateStatusBadge('idle');
            elements.heroNote.textContent = 'Waiting for the backend to publish capture data.';
            return;
        }

        const config = session.config || {};
        const errors = (session.errors || []).slice(-3);
        updateStatusBadge(session.status || 'idle');
        elements.heroNote.textContent = session.note || 'Monitoring backend status.';

        elements.monitorSummary.innerHTML = `
            <div class="summary-card">
                <div class="summary-head">
                    <h3>Session Overview</h3>
                    <span class="mini-pill">${escapeHtml(session.tool || config.preferredTool || 'auto')}</span>
                </div>
                <div class="summary-grid">
                    <div class="summary-row">
                        <span>Status</span>
                        <strong>${escapeHtml(toDisplay(session.status, 'idle'))}</strong>
                    </div>
                    <div class="summary-row">
                        <span>Events Seen</span>
                        <strong>${escapeHtml(session.eventsSeen ?? 0)}</strong>
                    </div>
                    <div class="summary-row">
                        <span>Mode</span>
                        <strong>${escapeHtml(toDisplay(config.mode, 'live'))}</strong>
                    </div>
                    <div class="summary-row">
                        <span>Interface</span>
                        <strong>${escapeHtml(toDisplay(config.interface, 'auto'))}</strong>
                    </div>
                    <div class="summary-row">
                        <span>Last Event</span>
                        <strong>${escapeHtml(formatRelativeTime(session.lastEventAt))}</strong>
                    </div>
                </div>
                <p class="summary-note">${escapeHtml(session.note || 'No session notes yet.')}</p>
                ${errors.length ? `
                    <div class="error-box">
                        ${errors.map((error) => `<p>${escapeHtml(error)}</p>`).join('')}
                    </div>
                ` : ''}
            </div>
        `;
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
            if (cellDef.isCheckbox) {
                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.className = 'row-export-cb';
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
                badge.textContent = cellDef.value;
                cell.appendChild(badge);
            } else {
                cell.textContent = cellDef.value;
                if (cellDef.cls) cell.className = cellDef.cls;
            }
            row.appendChild(cell);
        });

        return row;
    }

    function renderTable() {
        const rows = filteredData();
        elements.tableBody.innerHTML = '';

        if (!rows.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 11;
            cell.className = 'empty-state';
            cell.textContent = state.searchTerm
                ? 'No DNS events match the current filter.'
                : 'No DNS events captured yet.';
            row.appendChild(cell);
            elements.tableBody.appendChild(row);
        } else {
            rows.forEach((event, index) => elements.tableBody.appendChild(buildRow(event, index)));
        }

        elements.resultCount.textContent = `${rows.length} event${rows.length === 1 ? '' : 's'}`;
    }

    function renderAll() {
        renderMetrics();
        renderMonitorSummary();
        renderActivityFeed();
        renderTable();
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
    }

    function applyEvent(payload) {
        if (payload?.event) {
            const current = state.dnsData.filter((item) => item.id !== payload.event.id);
            state.dnsData = [payload.event, ...current].slice(0, MAX_EVENTS);
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
            interface: elements.interfaceInput.value.trim(),
            pcapPath: elements.pcapInput.value.trim(),
            mongoUri: elements.mongoUriInput.value.trim(),
            mongoDb: elements.mongoDbInput.value.trim(),
            mongoCollection: elements.mongoCollectionInput.value.trim(),
            limit: Number(elements.limitInput.value) || 0,
        };
    }

    function updateModeInputs() {
        const manualMode = elements.modeSelect.value === 'manual';
        elements.interfaceInput.disabled = manualMode;
        elements.pcapInput.required = manualMode;
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

    async function startCapture() {
        const payload = buildCapturePayload();
        if (payload.mode === 'manual' && !payload.pcapPath) {
            window.alert('Manual mode requires a PCAP file path.');
            return;
        }

        elements.startButton.disabled = true;
        elements.startButton.textContent = 'Starting...';

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

            xhr.onload = () => {
                if (xhr.status === 201) {
                    const result = JSON.parse(xhr.responseText);
                    elements.statusFilename.textContent = `Ready: ${fileName}`;
                    elements.pcapInput.value = result.pcapPath;
                    elements.modeSelect.value = 'manual';
                    updateModeInputs();
                    elements.heroNote.textContent = `Uploaded ${fileName} successfully. Ready to analyze.`;
                } else {
                    const error = JSON.parse(xhr.responseText);
                    throw new Error(error.error || 'Upload failed');
                }
            };

            xhr.onerror = () => {
                throw new Error('Network error during upload');
            };

            xhr.send(formData);
        } catch (error) {
            console.error('Upload failed:', error);
            elements.statusFilename.textContent = `Upload failed: ${error.message}`;
            elements.uploadProgress.style.width = '0%';
        } finally {
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
            state.reconnectTimer = window.setTimeout(connectStream, 4000);
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

    elements.searchButton.addEventListener('click', () => {
        state.searchTerm = elements.searchInput.value.trim();
        renderTable();
    });

    elements.clearSearchButton.addEventListener('click', () => {
        elements.searchInput.value = '';
        state.searchTerm = '';
        renderTable();
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
            const checkboxes = elements.tableBody.querySelectorAll('.row-export-cb');
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
            
            const headers = ["Time", "Domain", "Type", "Method", "Threat", "Client", "Resolver", "Transport", "Tool", "Mode"];
            const rows = [headers.join(",")];
            
            data.forEach(event => {
                const time = new Date(event.timestamp * 1000).toISOString();
                const method = event.protocol || 'DNS/UDP';
                const threat = event.threatLevel || 'low';
                const row = [
                    time,
                    event.domain || '',
                    event.recordType || '',
                    method,
                    threat,
                    event.sourceIp || '',
                    event.destinationIp || '',
                    event.transport || '',
                    event.tool || '',
                    event.mode || ''
                ].map(v => `"${String(v).replace(/"/g, '""')}"`);
                rows.push(row.join(","));
            });
            
            triggerDownload(new Blob([rows.join("\\n")], { type: 'text/csv' }), 'dns-sinkhole-export.csv');
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
            
            const exportData = data.map(event => ({
                time: new Date(event.timestamp * 1000).toISOString(),
                domain: event.domain || '',
                type: event.recordType || '',
                method: event.protocol || 'DNS/UDP',
                threat: event.threatLevel || 'low',
                client: event.sourceIp || '',
                resolver: event.destinationIp || '',
                transport: event.transport || '',
                tool: event.tool || '',
                mode: event.mode || '',
                answers: event.answers || []
            }));
            
            triggerDownload(new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' }), 'dns-sinkhole-export.json');
        });
    }


    elements.searchInput.addEventListener('input', () => {
        state.searchTerm = elements.searchInput.value.trim();
        renderTable();
    });

    elements.searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            state.searchTerm = elements.searchInput.value.trim();
            renderTable();
        }
    });

    elements.startButton.addEventListener('click', startCapture);
    elements.stopButton.addEventListener('click', stopCapture);
    elements.modeSelect.addEventListener('change', updateModeInputs);

    elements.clearUploadBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        clearUpload();
    });

    initUploadZone();
    updateModeInputs();
    renderAll();
    fetchSnapshot();
    fetchCaptureStatus();
    connectStream();
    startPollingFallback();
});
