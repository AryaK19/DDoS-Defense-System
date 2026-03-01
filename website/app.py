"""
User-Facing Dummy Website — Simulated web application.

This Flask app serves a realistic-looking website whose response latency
and error rate are tied to the simulation engine's current network health.
When a LDoS attack is active, users experience real degradation:
  - Pages load slowly (artificial delay based on latency_ms)
  - Some requests fail with 503 errors (based on packet_loss)
  - A "degraded service" banner appears

Runs on a separate port (default 8080) alongside the admin dashboard.
"""

import os
import sys
import time
import random
import threading
from flask import Flask, render_template, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

app = Flask(__name__)
app.config["SECRET_KEY"] = "cloudserve-demo-2026"

# Reference to the simulation engine (set by main.py)
simulation_engine = None


def init_website(engine):
    """Initialize the website with a reference to the simulation engine."""
    global simulation_engine
    simulation_engine = engine


def _get_network_health():
    """Get current network health metrics from the simulation."""
    if not simulation_engine:
        return {"latency_ms": 0, "packet_loss": 0, "throughput_bps": 2_000_000, "status": "healthy"}

    # Read from thread-safe snapshots (not live tick-counters)
    latency = simulation_engine._snapshot_latency
    loss = simulation_engine._snapshot_loss
    throughput = simulation_engine._snapshot_throughput

    if loss > 0.3:
        status = "critical"
    elif loss > 0.05:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "latency_ms": latency,
        "packet_loss": loss,
        "throughput_bps": throughput,
        "status": status,
    }


def _inject_latency():
    """
    Sleep to simulate network latency.
    In normal mode: barely noticeable (~20ms).
    During attack: pages take 1-5 seconds to load.
    """
    health = _get_network_health()
    loss = health["packet_loss"]

    # Simulate request failure based on packet loss
    if random.random() < loss * 0.8:  # 80% of packet-loss translates to failed requests
        return False  # Request "failed"

    # Inject latency as a fraction of actual simulated latency
    # Scale: 20ms base → barely noticeable, 500ms+ → noticeable slowdown
    delay_sec = min(5.0, health["latency_ms"] / 1000 * 3)  # 3x amplification
    if delay_sec > 0.01:
        time.sleep(delay_sec)

    return True  # Request succeeded


# ─── Page Routes ──────────────────────────────────────────────

@app.route("/")
def home():
    if not _inject_latency():
        return render_template("error.html", code=503, message="Service temporarily unavailable"), 503
    health = _get_network_health()
    return render_template("home.html", health=health)


@app.route("/products")
def products():
    if not _inject_latency():
        return render_template("error.html", code=503, message="Service temporarily unavailable"), 503
    health = _get_network_health()
    products_list = [
        {"name": "Cloud Compute", "desc": "Scalable virtual machines", "price": "$0.05/hr", "icon": "☁️"},
        {"name": "Object Storage", "desc": "S3-compatible blob storage", "price": "$0.02/GB", "icon": "📦"},
        {"name": "Managed Database", "desc": "PostgreSQL & Redis clusters", "price": "$15/mo", "icon": "🗄️"},
        {"name": "CDN Edge", "desc": "Global content delivery", "price": "$0.01/GB", "icon": "🌍"},
        {"name": "Load Balancer", "desc": "Auto-scaling traffic manager", "price": "$10/mo", "icon": "⚖️"},
        {"name": "DDoS Shield", "desc": "AI-powered attack mitigation", "price": "$25/mo", "icon": "🛡️"},
    ]
    return render_template("products.html", products=products_list, health=health)


@app.route("/contact")
def contact():
    if not _inject_latency():
        return render_template("error.html", code=503, message="Service temporarily unavailable"), 503
    health = _get_network_health()
    return render_template("contact.html", health=health)


@app.route("/api/health")
def api_health():
    """API endpoint to check service health — used by the JS on client side."""
    health = _get_network_health()
    return jsonify(health)


@app.route("/api/data")
def api_data():
    """Simulated API endpoint that returns mock data."""
    if not _inject_latency():
        return jsonify({"error": "Service unavailable"}), 503

    return jsonify({
        "timestamp": time.time(),
        "data": {
            "users_online": random.randint(1200, 3400),
            "requests_per_sec": random.randint(800, 2500),
            "uptime_pct": 99.97 if _get_network_health()["status"] == "healthy" else 87.3,
        }
    })


def run_website(host=None, port=None):
    """Start the website server."""
    host = host or config.WEBSITE["host"]
    port = port or config.WEBSITE["port"]
    print(f"\n{'='*60}")
    print(f"  🌐 {config.WEBSITE['name']} running at http://localhost:{port}")
    print(f"  Share via VS Code port-forward for user access")
    print(f"{'='*60}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
