"""
Flask Dashboard — Admin panel with WebSocket for real-time monitoring.
Provides REST API endpoints and live event streaming.
"""

import os
import sys
import json
import time
import threading
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = "ldos-defense-sim-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# These will be set by main.py
simulation_engine = None


def init_dashboard(engine):
    """Initialize the dashboard with a reference to the simulation engine."""
    global simulation_engine
    simulation_engine = engine

    # Register event callback for WebSocket streaming
    if engine and engine.orchestrator:
        engine.orchestrator.register_event_callback(_broadcast_event)


def _broadcast_event(event_type: str, data):
    """Broadcast simulation events to all connected WebSocket clients."""
    try:
        socketio.emit(event_type, data)
    except Exception:
        pass


# ─── Page Routes ──────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── REST API ─────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """Full system status."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503
    return jsonify(simulation_engine.get_status())


@app.route("/api/topology")
def api_topology():
    """Network topology snapshot."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503
    return jsonify(simulation_engine.get_topology())


@app.route("/api/metrics")
def api_metrics():
    """Time-series metrics."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503
    return jsonify(simulation_engine.get_metrics_history())


@app.route("/api/attack/start", methods=["POST"])
def api_attack_start():
    """Start an LDoS attack with optional custom parameters."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503

    params = request.json or {}
    simulation_engine.start_attack(
        burst_rate=params.get("burst_rate_bps"),
        burst_length=params.get("burst_length_ms"),
        period=params.get("period_ms"),
    )
    return jsonify({"status": "attack_started"})


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    """Stop the current attack."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503
    simulation_engine.stop_attack()
    return jsonify({"status": "attack_stopped"})


@app.route("/api/defense/toggle", methods=["POST"])
def api_defense_toggle():
    """Toggle AI defense on/off."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503

    data = request.json or {}
    enabled = data.get("enabled", True)
    simulation_engine.set_defense(enabled)
    return jsonify({"status": f"defense_{'enabled' if enabled else 'disabled'}"})


@app.route("/api/defense/manual", methods=["POST"])
def api_defense_manual():
    """Execute a manual defense action."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503

    data = request.json or {}
    action = data.get("action", "no_action")
    target = data.get("target_ip", "")
    result = simulation_engine.manual_action(action, target)
    return jsonify(result)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset the simulation."""
    if not simulation_engine:
        return jsonify({"error": "Simulation not initialized"}), 503
    simulation_engine.reset()
    return jsonify({"status": "reset_complete"})


# ─── WebSocket Events ────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    print("[Dashboard] Client connected")
    if simulation_engine:
        emit("system", {"message": "Connected to Self-Healing Defense Dashboard"})
        emit("topology", simulation_engine.get_topology())


@socketio.on("disconnect")
def handle_disconnect():
    print("[Dashboard] Client disconnected")


@socketio.on("request_status")
def handle_status_request():
    if simulation_engine:
        emit("status", simulation_engine.get_status())


def run_dashboard(host=None, port=None):
    """Start the dashboard server."""
    host = host or config.DASHBOARD["host"]
    port = port or config.DASHBOARD["port"]
    print(f"\n{'='*60}")
    print(f"  Dashboard running at http://localhost:{port}")
    print(f"  Share via VS Code port-forward for multi-user access")
    print(f"{'='*60}\n")
    socketio.run(app, host=host, port=port,
                 debug=False, allow_unsafe_werkzeug=True)
