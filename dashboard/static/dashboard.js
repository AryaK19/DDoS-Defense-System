/* ═══════════════════════════════════════════════════════════
   Dashboard JavaScript — WebSocket + Charts + Topology
   ═══════════════════════════════════════════════════════════ */

// ─── State ───────────────────────────────────────────────
let defenseEnabled = true;
let attackActive = false;
let logCount = 0;
const MAX_LOG_ENTRIES = 200;
const MAX_CHART_POINTS = 60;

// ─── WebSocket Connection ────────────────────────────────
const socket = io();

socket.on('connect', () => {
    addLog('system', 'Connected to simulation server');
});

socket.on('disconnect', () => {
    addLog('system', 'Disconnected from server');
    document.getElementById('status-text').textContent = 'Disconnected';
    document.getElementById('system-status').className = 'status-badge danger';
});

socket.on('system', (data) => {
    const msg = typeof data === 'string' ? data : (data.message || JSON.stringify(data));
    addLog('system', msg);
});

// Only use WebSocket for alerts and mitigations — NOT for metrics
// (metrics come from the single HTTP poll to avoid triple-update flicker)
socket.on('alert', (data) => {
    addLog('alert', `🚨 ${data.type.toUpperCase()} detected! Confidence: ${(data.confidence * 100).toFixed(1)}% | Sources: ${(data.sources || []).join(', ')}`);
    document.getElementById('system-status').className = 'status-badge danger';
    document.getElementById('status-text').textContent = 'ATTACK DETECTED';
});

socket.on('mitigation', (data) => {
    addLog('mitigation', `${data.action}: ${data.description}`);
});

// ─── Single Source of Truth: HTTP Polling ─────────────────
// Status poll (KPIs + metrics) — every 1s
setInterval(() => {
    fetch('/api/status')
        .then(r => r.json())
        .then(data => {
            if (data.metrics) updateMetrics(data.metrics);
        })
        .catch(() => { });
}, 1000);

// Topology poll (network map + node cards) — every 3s (slower = no flicker)
setInterval(() => {
    fetch('/api/topology')
        .then(r => r.json())
        .then(data => updateTopology(data))
        .catch(() => { });
}, 3000);

// ─── Traffic Chart (Chart.js) ────────────────────────────
const chartCtx = document.getElementById('traffic-chart').getContext('2d');
const trafficChart = new Chart(chartCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Throughput (Mbps)',
                data: [],
                borderColor: '#64ffda',
                backgroundColor: 'rgba(100, 255, 218, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
            },
            {
                label: 'Packet Loss (%)',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y1',
            },
            {
                label: 'Latency (ms)',
                data: [],
                borderColor: '#fbbf24',
                backgroundColor: 'rgba(251, 191, 36, 0.03)',
                borderWidth: 1.5,
                fill: false,
                tension: 0.4,
                pointRadius: 0,
                yAxisID: 'y1',
                hidden: true,
            },
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        interaction: { intersect: false, mode: 'index' },
        plugins: {
            legend: {
                labels: {
                    color: '#94a3b8',
                    font: { family: 'Inter', size: 11 }
                }
            }
        },
        scales: {
            x: {
                display: true,
                ticks: { color: '#64748b', font: { size: 10 }, maxTicksLimit: 10 },
                grid: { color: 'rgba(255,255,255,0.03)' }
            },
            y: {
                display: true,
                position: 'left',
                title: { display: true, text: 'Mbps', color: '#64ffda', font: { size: 11 } },
                ticks: { color: '#64748b', font: { size: 10 } },
                grid: { color: 'rgba(255,255,255,0.03)' },
                min: 0,
            },
            y1: {
                display: true,
                position: 'right',
                title: { display: true, text: '% / ms', color: '#ef4444', font: { size: 11 } },
                ticks: { color: '#64748b', font: { size: 10 } },
                grid: { drawOnChartArea: false },
                min: 0,
            }
        }
    }
});

// ─── vis.js Network Topology ─────────────────────────────
let visNetwork = null;
let visNodes = null;
let visEdges = null;
let topoData = null;

const NODE_STYLE = {
    server: { shape: 'icon', icon: { face: 'sans-serif', code: '\u{1F5A5}', size: 50, color: '#60a5fa' }, color: { background: '#1e3a5f', border: '#60a5fa', highlight: { background: '#2d5a8f', border: '#93bbfc' } }, font: { color: '#e2e8f0', size: 13 } },
    client: { shape: 'icon', icon: { face: 'sans-serif', code: '\u{1F4BB}', size: 45, color: '#34d399' }, color: { background: '#1a3d2e', border: '#34d399', highlight: { background: '#2a5d4e', border: '#6ee7b7' } }, font: { color: '#e2e8f0', size: 13 } },
    attacker: { shape: 'icon', icon: { face: 'sans-serif', code: '\u{1F47E}', size: 45, color: '#ef4444' }, color: { background: '#4c1d1d', border: '#ef4444', highlight: { background: '#7c2d2d', border: '#fca5a5' } }, font: { color: '#e2e8f0', size: 13 } },
    switch: { shape: 'icon', icon: { face: 'sans-serif', code: '\u{1F500}', size: 45, color: '#a78bfa' }, color: { background: '#2e1e5e', border: '#a78bfa', highlight: { background: '#4e2e8e', border: '#c4b5fd' } }, font: { color: '#e2e8f0', size: 13 } },
};

function initTopologyNetwork() {
    const container = document.getElementById('topology-network');
    visNodes = new vis.DataSet();
    visEdges = new vis.DataSet();

    const options = {
        nodes: {
            borderWidth: 2,
            borderWidthSelected: 3,
            shadow: { enabled: true, color: 'rgba(0,0,0,0.4)', size: 12, x: 0, y: 4 },
            font: { face: 'Inter, sans-serif', color: '#e2e8f0', size: 13, strokeWidth: 3, strokeColor: 'rgba(10,15,28,0.9)' },
            scaling: { min: 30, max: 50 },
        },
        edges: {
            width: 2,
            color: { color: 'rgba(100,255,218,0.25)', highlight: '#64ffda', hover: '#64ffda', opacity: 0.9 },
            smooth: { enabled: true, type: 'curvedCW', roundness: 0.15 },
            shadow: { enabled: true, color: 'rgba(0,0,0,0.3)', size: 6 },
            font: { face: 'JetBrains Mono, monospace', color: '#64748b', size: 11, strokeWidth: 2, strokeColor: 'rgba(10,15,28,0.8)', align: 'top' },
            arrows: { to: { enabled: false } },
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -120,
                centralGravity: 0.008,
                springLength: 200,
                springConstant: 0.04,
                damping: 0.5,
                avoidOverlap: 0.8,
            },
            stabilization: { iterations: 150, fit: true },
            maxVelocity: 30,
            minVelocity: 0.5,
        },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            zoomView: true,
            dragNodes: true,
            dragView: true,
        },
        layout: {
            improvedLayout: true,
        },
    };

    visNetwork = new vis.Network(container, { nodes: visNodes, edges: visEdges }, options);

    // Disable physics after initial stabilization so nodes stay put
    visNetwork.on('stabilized', () => {
        visNetwork.setOptions({ physics: { enabled: false } });
    });
}

// Initialize on load
initTopologyNetwork();

function updateVisTopology(data) {
    if (!data || !visNodes || !visEdges) return;
    topoData = data;

    const nodes = data.nodes || [];
    const links = data.links || [];

    // ---- Update nodes ----
    const existingNodeIds = new Set(visNodes.getIds());
    const currentNodeIds = new Set();

    nodes.forEach(node => {
        currentNodeIds.add(node.id);
        const style = NODE_STYLE[node.type] || NODE_STYLE.switch;
        const health = node.health || 0;
        const isIsolated = node.isolated || false;
        const isThrottled = node.rate_limited || false;

        let label = `${node.id}\n${node.ip}`;
        if (isIsolated) label += '\n⛔ ISOLATED';
        if (isThrottled) label += '\n🔽 THROTTLED';

        // Build tooltip (plain text — vis.js doesn't render HTML in title)
        const healthPct = (health * 100).toFixed(0);
        let title = `${node.id} (${node.type})\nIP: ${node.ip}\nHealth: ${healthPct}%`;
        if (isIsolated) title += '\n⛔ Isolated';
        if (isThrottled) title += '\n🔽 Rate Limited';

        let nodeColor, iconColor, borderDashes;
        if (isIsolated) {
            nodeColor = { background: '#1f2937', border: '#4b5563', highlight: { background: '#374151', border: '#6b7280' } };
            iconColor = '#6b7280';
            borderDashes = [6, 4];
        } else {
            nodeColor = style.color;
            iconColor = style.icon.color;
            borderDashes = false;
        }

        const nodeData = {
            id: node.id,
            label: label,
            title: title,
            color: nodeColor,
            icon: { ...style.icon, color: iconColor },
            shape: style.shape,
            font: { ...style.font, color: isIsolated ? '#6b7280' : '#e2e8f0' },
            shapeProperties: { borderDashes: borderDashes },
            borderWidth: isIsolated ? 1 : 2,
        };

        if (existingNodeIds.has(node.id)) {
            visNodes.update(nodeData);
        } else {
            visNodes.add(nodeData);
        }
    });

    // Remove stale nodes
    existingNodeIds.forEach(id => {
        if (!currentNodeIds.has(id)) visNodes.remove(id);
    });

    // ---- Update edges ----
    const existingEdgeIds = new Set(visEdges.getIds());
    const currentEdgeIds = new Set();

    links.forEach(link => {
        const edgeId = `${link.from}-${link.to}`;
        currentEdgeIds.add(edgeId);

        const util = link.utilization || 0;
        let edgeColor, edgeWidth;
        if (util > 0.8) {
            edgeColor = { color: 'rgba(239,68,68,0.8)', highlight: '#ef4444', hover: '#ef4444' };
            edgeWidth = 4;
        } else if (util > 0.5) {
            edgeColor = { color: 'rgba(251,191,36,0.6)', highlight: '#fbbf24', hover: '#fbbf24' };
            edgeWidth = 3;
        } else if (util > 0.1) {
            edgeColor = { color: 'rgba(100,255,218,0.35)', highlight: '#64ffda', hover: '#64ffda' };
            edgeWidth = 2;
        } else {
            edgeColor = { color: 'rgba(100,255,218,0.15)', highlight: '#64ffda', hover: '#64ffda' };
            edgeWidth = 1.5;
        }

        const utilLabel = util > 0.01 ? `${(util * 100).toFixed(0)}%` : '';

        const edgeData = {
            id: edgeId,
            from: link.from,
            to: link.to,
            width: edgeWidth,
            color: edgeColor,
            label: utilLabel,
        };

        if (existingEdgeIds.has(edgeId)) {
            visEdges.update(edgeData);
        } else {
            visEdges.add(edgeData);
        }
    });

    // Remove stale edges
    existingEdgeIds.forEach(id => {
        if (!currentEdgeIds.has(id)) visEdges.remove(id);
    });
}


// ─── Update Functions ────────────────────────────────────

function updateMetrics(data) {

    // KPI cards — use textContent for smooth updates (no innerHTML flicker)
    const tp = (data.throughput_bps || 0) / 1_000_000;
    const lat = data.latency_ms || 0;
    const loss = (data.packet_loss || 0) * 100;

    _setKPI('val-throughput', `${tp.toFixed(2)}`, 'Mbps');
    _setKPI('val-latency', `${lat.toFixed(1)}`, 'ms');
    _setKPI('val-loss', `${loss.toFixed(1)}`, '%');

    // Color coding
    const lossCard = document.getElementById('kpi-loss');
    const lossVal = document.getElementById('val-loss');
    if (loss > 10) {
        lossCard.classList.add('danger');
        lossVal.classList.add('danger');
    } else {
        lossCard.classList.remove('danger');
        lossVal.classList.remove('danger');
    }

    // Threat info
    if (data.threat) {
        const t = data.threat;
        if (t.threat_detected) {
            document.getElementById('val-detection').textContent =
                `${(t.confidence * 100).toFixed(0)}%`;
            document.getElementById('val-detection').classList.add('danger');
            document.getElementById('kpi-detection').classList.add('danger');
        } else {
            document.getElementById('val-detection').textContent = 'None';
            document.getElementById('val-detection').classList.remove('danger');
            document.getElementById('kpi-detection').classList.remove('danger');
        }
    }

    // Action
    if (data.action) {
        document.getElementById('val-action').textContent =
            data.action.replace(/_/g, ' ');
    }

    // Sim time
    if (data.sim_time !== undefined) {
        document.getElementById('sim-time').textContent =
            `T+${data.sim_time.toFixed(1)}s`;
    }

    // Phase indicator
    updatePhase(data.phase || 'monitor');

    // Update chart
    const timeLabel = data.sim_time ? data.sim_time.toFixed(0) + 's' : '';
    addChartPoint(timeLabel, tp, loss, lat);

    // System status
    if (data.threat && data.threat.threat_detected) {
        document.getElementById('system-status').className = 'status-badge danger';
        document.getElementById('status-text').textContent = 'UNDER ATTACK';
    } else if (data.defense_enabled) {
        document.getElementById('system-status').className = 'status-badge';
        document.getElementById('status-text').textContent = 'Protected';
    } else {
        document.getElementById('system-status').className = 'status-badge';
        document.getElementById('status-text').textContent = 'Monitoring';
    }
}

/** Set a KPI value + unit without innerHTML (prevents flicker) */
function _setKPI(id, value, unit) {
    const el = document.getElementById(id);
    if (!el) return;
    // Only update if value actually changed
    const newText = `${value}${unit}`;
    if (el.dataset.last === newText) return;
    el.dataset.last = newText;
    // Use two child spans to avoid innerHTML rebuild
    el.textContent = '';
    const valSpan = document.createTextNode(value);
    const unitSpan = document.createElement('span');
    unitSpan.className = 'kpi-unit';
    unitSpan.textContent = unit;
    el.appendChild(valSpan);
    el.appendChild(unitSpan);
}

function updatePhase(phase) {
    const phaseMap = {
        'monitor': 1, 'sense': 1,
        'analyze': 2, 'hypothesize': 2,
        'plan': 3, 'act': 3,
        'execute': 3,
        'verify': 4,
    };
    const activeIdx = phaseMap[phase] || 0;
    const labels = ['ph-sense', 'ph-hypothesize', 'ph-act', 'ph-verify'];
    const steps = ['phase-1', 'phase-2', 'phase-3', 'phase-4'];

    labels.forEach((id, i) => {
        const el = document.getElementById(id);
        el.classList.toggle('active', i + 1 === activeIdx);
    });
    steps.forEach((id, i) => {
        const el = document.getElementById(id);
        el.classList.toggle('active', i + 1 === activeIdx);
        el.classList.toggle('done', i + 1 < activeIdx);
    });
}

function addChartPoint(label, throughput, loss, latency) {
    const chart = trafficChart;
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(throughput);
    chart.data.datasets[1].data.push(loss);
    chart.data.datasets[2].data.push(latency);

    if (chart.data.labels.length > MAX_CHART_POINTS) {
        chart.data.labels.shift();
        chart.data.datasets.forEach(ds => ds.data.shift());
    }
    chart.update('none');
}

function updateTopology(data) {
    topoData = data;
    updateVisTopology(data);
    updateNodeCards(data.nodes || []);
}

/** Update node cards IN-PLACE instead of destroying/rebuilding DOM */
function updateNodeCards(nodes) {
    const container = document.getElementById('node-cards');

    nodes.forEach(node => {
        const cardId = `node-card-${node.id}`;
        let card = document.getElementById(cardId);

        const health = node.health || 0;
        let statusClass = 'healthy';
        if (node.isolated) statusClass = 'isolated';
        else if (health < 0.3) statusClass = 'critical';
        else if (health < 0.7) statusClass = 'degraded';

        const hColor = health > 0.7 ? '#34d399' : health > 0.3 ? '#fbbf24' : '#ef4444';
        const icons = { server: '🖥️', client: '💻', attacker: '👾', switch: '🔀' };

        if (!card) {
            // First time: create the card
            card = document.createElement('div');
            card.id = cardId;
            card.className = `node-card ${statusClass}`;
            card.innerHTML = `
                <div class="node-name">
                    ${icons[node.type] || '●'} ${node.id}
                    <span class="node-type">${node.type}</span>
                </div>
                <div class="node-info" style="font-size:11px; color:var(--text-muted); margin-top:4px">
                    ${node.ip}
                </div>
                <div class="node-health-bar">
                    <div class="node-health-fill" style="width:${health * 100}%; background:${hColor}"></div>
                </div>
            `;
            container.appendChild(card);
        } else {
            // Update existing card in-place (NO flicker)
            card.className = `node-card ${statusClass}`;

            const info = card.querySelector('.node-info');
            if (info) {
                const suffix = (node.isolated ? ' (ISOLATED)' : '') + (node.rate_limited ? ' (THROTTLED)' : '');
                info.textContent = node.ip + suffix;
            }

            const fill = card.querySelector('.node-health-fill');
            if (fill) {
                fill.style.width = `${health * 100}%`;
                fill.style.background = hColor;
            }
        }
    });
}

// ─── Controls ────────────────────────────────────────────

function startAttack() {
    const burstRate = parseFloat(document.getElementById('param-burst-rate').value) * 1_000_000;
    const burstLen = parseFloat(document.getElementById('param-burst-len').value);
    const period = parseFloat(document.getElementById('param-period').value);

    fetch('/api/attack/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            burst_rate_bps: burstRate,
            burst_length_ms: burstLen,
            period_ms: period
        })
    }).then(r => r.json()).then(() => {
        attackActive = true;
        document.getElementById('btn-start-attack').classList.add('active');
        document.getElementById('btn-start-attack').textContent = '🔴 Attack Active';
        document.getElementById('btn-stop-attack').style.display = 'flex';
        addLog('alert', `LDoS attack launched: ${burstRate / 1e6} Mbps burst, ${burstLen}ms length, ${period}ms period`);
    });
}

function stopAttack() {
    fetch('/api/attack/stop', { method: 'POST' })
        .then(r => r.json())
        .then(() => {
            attackActive = false;
            document.getElementById('btn-start-attack').classList.remove('active');
            document.getElementById('btn-start-attack').textContent = '🔴 Launch LDoS Attack';
            document.getElementById('btn-stop-attack').style.display = 'none';
            addLog('system', 'Attack stopped');
        });
}

function toggleDefense() {
    defenseEnabled = !defenseEnabled;
    const btn = document.getElementById('btn-toggle-defense');

    fetch('/api/defense/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: defenseEnabled })
    }).then(r => r.json()).then(() => {
        if (defenseEnabled) {
            btn.textContent = '✅ Defense Enabled';
            btn.classList.remove('disabled');
            addLog('mitigation', 'AI Defense ENABLED');
        } else {
            btn.textContent = '❌ Defense Disabled';
            btn.classList.add('disabled');
            addLog('system', 'AI Defense DISABLED');
        }
    });
}

function manualAction(action) {
    fetch('/api/defense/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            action: action,
            target_ip: '10.0.0.100'  // attacker IP
        })
    }).then(r => r.json()).then(data => {
        addLog('mitigation', `Manual: ${data.description || action}`);
    });
}

function resetSimulation() {
    fetch('/api/reset', { method: 'POST' })
        .then(r => r.json())
        .then(() => {
            attackActive = false;
            document.getElementById('btn-start-attack').classList.remove('active');
            document.getElementById('btn-start-attack').textContent = '🔴 Launch LDoS Attack';
            document.getElementById('btn-stop-attack').style.display = 'none';

            // Clear chart
            trafficChart.data.labels = [];
            trafficChart.data.datasets.forEach(ds => ds.data = []);
            trafficChart.update();

            // Clear vis.js topology and node cards
            if (visNodes) visNodes.clear();
            if (visEdges) visEdges.clear();
            document.getElementById('node-cards').innerHTML = '';

            addLog('system', 'Simulation reset');
        });
}


// ─── Event Log ───────────────────────────────────────────

function addLog(type, message) {
    const container = document.getElementById('log-entries');
    const time = document.getElementById('sim-time').textContent.replace('T+', '');

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-type ${type}">${type}</span>
        <span class="log-msg">${message}</span>
    `;

    container.insertBefore(entry, container.firstChild);
    logCount++;
    document.getElementById('log-count').textContent = `${logCount} events`;

    // Limit entries
    while (container.children.length > MAX_LOG_ENTRIES) {
        container.removeChild(container.lastChild);
    }
}
