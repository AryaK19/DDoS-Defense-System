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

// ─── Topology Canvas ─────────────────────────────────────
const topoCanvas = document.getElementById('topology-canvas');
const topoCtx = topoCanvas.getContext('2d');
let topoData = null;

function resizeTopoCanvas() {
    const wrapper = topoCanvas.parentElement;
    topoCanvas.width = wrapper.clientWidth;
    topoCanvas.height = wrapper.clientHeight;
    if (topoData) drawTopology();
}
window.addEventListener('resize', resizeTopoCanvas);
resizeTopoCanvas();

function drawTopology() {
    if (!topoData) return;
    const ctx = topoCtx;
    const w = topoCanvas.width;
    const h = topoCanvas.height;

    ctx.clearRect(0, 0, w, h);

    // Node positions (fixed layout)
    const positions = {};
    const nodes = topoData.nodes || [];
    const centerX = w / 2;
    const centerY = h / 2;

    nodes.forEach((node, i) => {
        switch (node.type) {
            case 'server':
                positions[node.id] = { x: centerX + 150, y: centerY };
                break;
            case 'switch':
                positions[node.id] = { x: centerX - 30, y: centerY };
                break;
            case 'client':
                positions[node.id] = { x: centerX - 200, y: centerY - 60 + i * 50 };
                break;
            case 'attacker':
                positions[node.id] = { x: centerX - 200, y: centerY + 70 };
                break;
            default:
                positions[node.id] = { x: 100 + i * 100, y: centerY };
        }
    });

    // Draw links
    const links = topoData.links || [];
    links.forEach(link => {
        const from = positions[link.from];
        const to = positions[link.to];
        if (!from || !to) return;

        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);

        // Color by utilization
        const util = link.utilization || 0;
        if (util > 0.8) {
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.7)';
            ctx.lineWidth = 3;
        } else if (util > 0.5) {
            ctx.strokeStyle = 'rgba(251, 191, 36, 0.5)';
            ctx.lineWidth = 2;
        } else {
            ctx.strokeStyle = 'rgba(100, 255, 218, 0.2)';
            ctx.lineWidth = 1.5;
        }
        ctx.stroke();

        // Utilization label
        if (util > 0.01) {
            const mx = (from.x + to.x) / 2;
            const my = (from.y + to.y) / 2 - 8;
            ctx.fillStyle = '#64748b';
            ctx.font = '10px JetBrains Mono';
            ctx.textAlign = 'center';
            ctx.fillText(`${(util * 100).toFixed(0)}%`, mx, my);
        }
    });

    // Draw nodes
    nodes.forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;

        const r = 22;

        // Glow for active nodes
        if (node.health < 0.5 && node.type !== 'attacker') {
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, r + 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
            ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);

        let color;
        switch (node.type) {
            case 'server': color = '#60a5fa'; break;
            case 'client': color = '#34d399'; break;
            case 'attacker': color = node.isolated ? '#4b5563' : '#ef4444'; break;
            case 'switch': color = '#a78bfa'; break;
            default: color = '#64748b';
        }

        if (node.isolated) {
            color = '#4b5563';
            ctx.setLineDash([4, 4]);
        }

        ctx.fillStyle = color + '20';
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.setLineDash([]);

        // Icon
        ctx.fillStyle = color;
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const icons = { server: '🖥', client: '💻', attacker: '👾', switch: '🔀' };
        ctx.fillText(icons[node.type] || '●', pos.x, pos.y);

        // Label
        ctx.fillStyle = '#e2e8f0';
        ctx.font = '11px Inter';
        ctx.fillText(node.id, pos.x, pos.y + r + 14);

        // Health bar under node
        const barW = 40;
        const barH = 3;
        const barX = pos.x - barW / 2;
        const barY = pos.y + r + 22;
        ctx.fillStyle = 'rgba(255,255,255,0.05)';
        ctx.fillRect(barX, barY, barW, barH);

        const health = node.health || 0;
        const hColor = health > 0.7 ? '#34d399' : health > 0.3 ? '#fbbf24' : '#ef4444';
        ctx.fillStyle = hColor;
        ctx.fillRect(barX, barY, barW * health, barH);
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
    drawTopology();
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

            // Clear node cards so they rebuild fresh
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
