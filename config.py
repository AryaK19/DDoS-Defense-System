"""
Centralized configuration for the AI-Based Self-Healing LDoS Defense Simulation.
All tunable parameters in one place for easy modification.
"""

# ─── Network Topology ────────────────────────────────────────────
NETWORK = {
    "server": {
        "ip": "10.0.0.1",
        "mac": "00:00:00:00:00:01",
        "type": "server",
    },
    "client1": {
        "ip": "10.0.0.2",
        "mac": "00:00:00:00:00:02",
        "type": "client",
    },
    "client2": {
        "ip": "10.0.0.3",
        "mac": "00:00:00:00:00:03",
        "type": "client",
    },
    "attacker": {
        "ip": "10.0.0.100",
        "mac": "00:00:00:00:00:FF",
        "type": "attacker",
    },
}

# Link parameters
LINK_BANDWIDTH_BPS = 10_000_000       # 10 Mbit/s bottleneck
LINK_LATENCY_MS = 20                  # 20ms one-way delay (40ms RTT)
LINK_BUFFER_SIZE = 200                # Max packets in queue (fits 1 tick of normal traffic; overflows during attack bursts)
LINK_BASE_LOSS_RATE = 0.001           # 0.1% base packet loss

# ─── TCP Flow Simulation ─────────────────────────────────────────
TCP = {
    "mss": 1460,                      # Maximum Segment Size (bytes)
    "initial_cwnd": 1,                # Initial congestion window (segments)
    "initial_ssthresh": 64,           # Initial slow-start threshold
    "min_rto_ms": 1000,               # Minimum RTO = 1 second (RFC 6298)
    "max_rto_ms": 60000,              # Maximum RTO = 60 seconds
    "rto_alpha": 0.125,               # SRTT smoothing factor
    "rto_beta": 0.25,                 # RTTVAR smoothing factor
}

# ─── LDoS Attack Parameters ──────────────────────────────────────
LDOS_ATTACK = {
    "burst_rate_bps": 50_000_000,      # 50 Mbit/s (5x bottleneck)
    "burst_length_ms": 30,             # 30ms burst duration
    "period_ms": 800,                  # 800ms period
    "packet_size": 1400,              # Attack packet size (bytes)
    "target_ip": "10.0.0.1",          # Target server
}

# ─── Normal Traffic Parameters ────────────────────────────────────
NORMAL_TRAFFIC = {
    "rate_bps": 2_000_000,            # 2 Mbit/s baseline
    "packet_size_range": (64, 1460),  # Variable packet sizes
    "jitter_ms": 5,                   # Timing jitter
}

# ─── Feature Extraction ──────────────────────────────────────────
FEATURES = {
    "window_size_ms": 1000,           # 1-second analysis windows
    "overlap_ms": 500,                # 50% overlap between windows
    "fft_threshold": 0.3,             # Periodicity detection threshold
}

# ─── Detection (Random Forest) ───────────────────────────────────
DETECTOR = {
    "model_path": "models/detector_rf.pkl",
    "n_estimators": 100,
    "max_depth": 15,
    "confidence_threshold": 0.55,      # Min confidence to flag as attack
    "training_samples": 5000,         # Samples per class for training
}

# ─── Reinforcement Learning (Q-Learning) ─────────────────────────
RL_AGENT = {
    "learning_rate": 0.1,
    "discount_factor": 0.95,
    "epsilon_start": 1.0,             # Initial exploration rate
    "epsilon_end": 0.05,              # Minimum exploration rate
    "epsilon_decay": 0.995,           # Decay per episode
    "reward_weights": {
        "throughput": 1.0,
        "latency": -0.5,
        "packet_loss": -2.0,
        "false_positive": -3.0,
    },
    "actions": [
        "no_action",
        "rate_limit",
        "drop_source",
        "reroute_traffic",
        "isolate_node",
        "scale_bandwidth",
    ],
}

# ─── Simulation ──────────────────────────────────────────────────
SIMULATION = {
    "tick_interval_ms": 100,          # Simulation tick = 100ms
    "real_time_factor": 1.0,          # 1.0 = real-time, 2.0 = 2x speed
    "duration_seconds": 120,          # Default scenario length
    "attack_start_sec": 15,           # When attack begins
    "defense_start_sec": 5,           # Delay before AI can respond
}

# ─── Dashboard ───────────────────────────────────────────────────
DASHBOARD = {
    "host": "0.0.0.0",
    "port": 5000,
    "update_interval_ms": 500,        # Push metrics every 500ms
    "max_log_entries": 1000,          # Max events in the log
}

# ─── User-Facing Website ─────────────────────────────────────────
WEBSITE = {
    "host": "0.0.0.0",
    "port": 8888,
    "name": "CloudServe Pro",         # Simulated company name
}
