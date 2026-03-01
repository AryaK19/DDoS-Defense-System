/* ═══════════════════════════════════════════════════════
   CloudServe Pro — Client-Side JavaScript
   Polls /api/health every 2s and updates status indicators
   ═══════════════════════════════════════════════════════ */

const POLL_INTERVAL = 2000;

// ─── Health Polling ─────────────────────────────────────

function pollHealth() {
    const start = performance.now();

    fetch('/api/health', { signal: AbortSignal.timeout(8000) })
        .then(r => r.json())
        .then(data => {
            const elapsed = performance.now() - start;
            updateStatusUI(data, elapsed);
        })
        .catch(err => {
            updateStatusUI({ status: 'critical', latency_ms: 9999, packet_loss: 1, throughput_bps: 0 }, 0);
        });
}

function updateStatusUI(data, realLatency) {
    const banner = document.getElementById('status-banner');
    const bannerMsg = document.getElementById('status-msg');
    const bannerIcon = document.getElementById('status-icon');
    const healthDot = document.getElementById('health-dot');
    const healthText = document.getElementById('health-text');

    // Update nav health indicator
    if (healthDot) {
        healthDot.className = `health-dot ${data.status}`;
    }
    if (healthText) {
        const labels = {
            healthy: 'All Systems Normal',
            degraded: 'Degraded Performance',
            critical: 'Service Disruption'
        };
        healthText.textContent = labels[data.status] || data.status;
    }

    // Status banner
    if (data.status === 'healthy') {
        banner.classList.add('hidden');
        banner.classList.remove('degraded', 'critical');
    } else if (data.status === 'degraded') {
        banner.classList.remove('hidden', 'critical');
        banner.classList.add('degraded');
        bannerIcon.textContent = '⚠️';
        bannerMsg.textContent = 'Service is experiencing higher than normal latency';
    } else {
        banner.classList.remove('hidden', 'degraded');
        banner.classList.add('critical');
        bannerIcon.textContent = '🚨';
        bannerMsg.textContent = 'Service disruption — AI defense system is responding';
    }

    // Update live status cards (if on home page)
    const liveLatency = document.getElementById('live-latency');
    const liveSuccess = document.getElementById('live-success');
    const liveThroughput = document.getElementById('live-throughput');
    const liveStatus = document.getElementById('live-status');

    if (liveLatency) {
        const lat = Math.round(data.latency_ms || 0);
        liveLatency.textContent = lat < 1000 ? `${lat}ms` : `${(lat / 1000).toFixed(1)}s`;
        liveLatency.style.color = lat < 50 ? 'var(--emerald)' : lat < 200 ? 'var(--amber)' : 'var(--red)';
    }
    if (liveSuccess) {
        const rate = ((1 - (data.packet_loss || 0)) * 100).toFixed(1);
        liveSuccess.textContent = `${rate}%`;
        liveSuccess.style.color = rate > 99 ? 'var(--emerald)' : rate > 90 ? 'var(--amber)' : 'var(--red)';
    }
    if (liveThroughput) {
        const mbps = ((data.throughput_bps || 0) / 1_000_000).toFixed(1);
        liveThroughput.textContent = `${mbps} Mbps`;
    }
    if (liveStatus) {
        const colors = { healthy: 'var(--emerald)', degraded: 'var(--amber)', critical: 'var(--red)' };
        const labels = { healthy: 'Operational', degraded: 'Degraded', critical: 'Disrupted' };
        liveStatus.innerHTML = `<span class="health-dot ${data.status}"></span> ${labels[data.status]}`;
    }

    // Update hero stats (if on home page)
    const statUptime = document.getElementById('stat-uptime');
    const statLatency = document.getElementById('stat-latency');
    if (statUptime) {
        statUptime.textContent = data.status === 'healthy' ? '99.97%' : data.status === 'degraded' ? '95.2%' : '87.3%';
    }
    if (statLatency) {
        const lat = Math.round(data.latency_ms || 20);
        statLatency.textContent = lat < 100 ? `~${lat}ms` : `${lat}ms`;
    }
}

// ─── Contact Form ───────────────────────────────────────

function submitForm(event) {
    event.preventDefault();
    const btn = document.getElementById('submit-btn');
    const status = document.getElementById('form-status');

    btn.disabled = true;
    btn.textContent = 'Sending...';

    // Simulate API call through the simulated network
    fetch('/api/data')
        .then(r => {
            if (!r.ok) throw new Error('Service unavailable');
            return r.json();
        })
        .then(() => {
            status.className = 'form-status success';
            status.textContent = '✅ Message sent successfully! We\'ll be in touch soon.';
            btn.textContent = 'Sent!';
            document.getElementById('contact-form').reset();
            setTimeout(() => {
                btn.disabled = false;
                btn.textContent = 'Send Message';
            }, 3000);
        })
        .catch(() => {
            status.className = 'form-status error';
            status.textContent = '❌ Failed to send — network congestion detected. Please retry.';
            btn.disabled = false;
            btn.textContent = 'Send Message';
        });

    return false;
}

// ─── Start Polling ──────────────────────────────────────

pollHealth();
setInterval(pollHealth, POLL_INTERVAL);
