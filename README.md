# 🛡️ AI-Based Self-Healing Low-Rate DDoS Defense System

> An interactive simulation demonstrating AI-powered detection and autonomous mitigation of Low-Rate DDoS (LDoS) attacks, with a real-time admin dashboard and a user-facing website that shows attack impact.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Flow](#system-flow)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [How to Use](#how-to-use)
- [What Happens When...](#what-happens-when)
- [Technologies Used](#technologies-used)
- [Multi-User Demo (Port Forwarding)](#multi-user-demo-port-forwarding)

---

## Overview

This project simulates a complete **AI-Based Self-Healing Network Defense System** that:

1. **Simulates a network** — Virtual topology with clients, a switch (bottleneck), a server, and an attacker
2. **Generates realistic traffic** — Normal TCP-like flows from 2 clients + LDoS attack pulses
3. **Detects attacks using AI** — Random Forest classifier analyzes traffic features in real-time
4. **Autonomously mitigates threats** — Q-Learning agent selects defense actions (rate-limit, isolate, reroute)
5. **Provides a live admin dashboard** — Real-time KPIs, charts, topology map, and manual controls
6. **Includes a user-facing website** — "CloudServe Pro" site whose performance degrades during attacks

### What is an LDoS Attack?

A **Low-Rate DDoS (LDoS)** attack sends periodic high-bandwidth bursts timed to coincide with TCP's retransmission timeout (RTO). Unlike volumetric DDoS, LDoS uses very little bandwidth overall but causes massive packet loss by exploiting network buffer dynamics.

```
Normal Traffic:  ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁    (steady ~2 Mbps)
LDoS Attack:     ████░░░░░░████░░░░░░████░░    (11 Mbps bursts, 10ms on, 990ms off)
Bottleneck:      ─────────── 10 Mbps ──────
                 ↑ bursts overflow the buffer → packets dropped
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SIMULATION ENGINE                 │
│                      (main.py)                       │
│                                                      │
│  ┌──────────┐   ┌────────┐   ┌──────────────────┐   │
│  │ Client 1 │──→│        │   │   MAPE-K Loop     │   │
│  │ 10.0.0.2 │   │ Switch │──→│  (self_healing.py) │  │
│  ├──────────┤   │  (BN)  │   │                    │  │
│  │ Client 2 │──→│        │──→│ M: Monitor packets │  │
│  │ 10.0.0.3 │   │        │   │ A: Analyze (RF)    │  │
│  ├──────────┤   │        │   │ P: Plan (Q-Learn)  │  │
│  │ Attacker │──→│        │   │ E: Execute action  │  │
│  │10.0.0.100│   └────────┘   │ K: Update knowledge│  │
│  └──────────┘        │       └──────────────────────┘ │
│                      ↓                                │
│               ┌────────────┐                          │
│               │   Server   │                          │
│               │  10.0.0.1  │                          │
│               └────────────┘                          │
└─────────────────────┬──────────────────┬──────────────┘
                      │                  │
          ┌───────────▼───────┐  ┌───────▼──────────┐
          │  Admin Dashboard  │  │  CloudServe Pro   │
          │   Port 5000       │  │   Port 8888       │
          │  (Real-time KPIs, │  │  (User-facing     │
          │   attack controls,│  │   website with    │
          │   topology view)  │  │   simulated lag)  │
          └───────────────────┘  └──────────────────┘
```

### MAPE-K Self-Healing Loop

The core defense operates as a **MAPE-K** (Monitor → Analyze → Plan → Execute → Knowledge) control loop:

```
          ┌─────────┐
          │ MONITOR │ ← Collect packets from the network each tick
          └────┬────┘
               ↓
          ┌─────────┐
          │ ANALYZE │ ← Random Forest extracts 12 features, classifies traffic
          └────┬────┘
               ↓
          ┌─────────┐
          │  PLAN   │ ← Q-Learning agent picks best defense action
          └────┬────┘
               ↓
          ┌─────────┐
          │ EXECUTE │ ← Mitigation engine applies action (rate-limit, isolate, etc.)
          └────┬────┘
               ↓
          ┌─────────────┐
          │  KNOWLEDGE  │ ← Agent receives reward, updates Q-table
          └─────────────┘
```

---

## System Flow

### What happens when you run `python main.py`:

```
1. INITIALIZATION
   ├── Create virtual network topology (2 clients + switch + server + attacker)
   ├── Create TCP flows for each client
   ├── Train Random Forest detector on synthetic data (normal vs LDoS)
   ├── Initialize Q-Learning defense agent
   └── Start MAPE-K orchestrator

2. SIMULATION STARTS (ticks every 100ms)
   ├── Each tick:
   │   ├── Reset link bandwidth counters
   │   ├── Generate normal traffic packets (2 clients × ~2 Mbps)
   │   ├── Generate attack traffic (if attack is active)
   │   ├── Route packets through network links
   │   ├── Drain link buffers (deliver queued packets)
   │   ├── Update node health + throughput metrics
   │   └── Feed packets to MAPE-K orchestrator
   │
   └── MAPE-K runs in parallel:
       ├── MONITOR: Collect packet window
       ├── ANALYZE: Extract features → RF classification
       ├── PLAN: If threat detected → Q-Learning picks action
       └── EXECUTE: Apply mitigation (rate-limit, isolate, etc.)

3. SERVERS START
   ├── Admin Dashboard on port 5000 (Flask + SocketIO)
   └── CloudServe Pro website on port 8888 (Flask)
```

---

## Project Structure

```
Simulation/
├── main.py                  # Master entry point — simulation loop + servers
├── config.py                # All tunable parameters in one place
├── network.py               # Virtual network: nodes, links, buffers, routing
├── tcp_flow.py              # TCP congestion control simulator (cwnd, srtt, RTO)
├── traffic_generator.py     # Normal traffic + LDoS attack pulse generator
├── feature_extractor.py     # Extracts 12 statistical features from traffic
├── detector.py              # Random Forest anomaly detector
├── rl_agent.py              # Tabular Q-Learning defense agent
├── mitigation.py            # Defense action execution engine
├── self_healing.py          # MAPE-K loop orchestrator
├── train_detector.py        # Standalone detector training script
├── requirements.txt         # Python dependencies
│
├── dashboard/               # Admin Dashboard (port 5000)
│   ├── app.py               # Flask + SocketIO backend
│   ├── templates/
│   │   └── index.html       # Dashboard HTML
│   └── static/
│       ├── style.css         # Dark theme styling
│       └── dashboard.js      # Real-time charts + topology canvas
│
└── website/                 # CloudServe Pro — User Website (port 8888)
    ├── app.py               # Flask app with latency injection
    ├── templates/
    │   ├── base.html         # Base layout with nav + footer
    │   ├── home.html         # Hero section + feature cards
    │   ├── products.html     # Product grid
    │   ├── contact.html      # Contact form
    │   └── error.html        # 503 error page (shown during attacks)
    └── static/
        ├── style.css         # Premium dark theme
        └── site.js           # Health polling + status updates
```

---

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# 1. Navigate to the Simulation folder
cd Simulation

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Running

```bash
# Start the full simulation
python main.py

# Options:
python main.py --port 5000           # Custom dashboard port
python main.py --website-port 8888   # Custom website port
python main.py --no-ai               # Disable AI defense (manual only)
python main.py --fast                 # Run at 2x speed
python main.py --speed 3.0           # Run at 3x speed
```

### What appears in the console:

```
============================================================
  AI-Based Self-Healing LDoS Defense System
  Initializing MAPE-K Loop...
============================================================

[INIT] Training anomaly detector...
[SIM] Simulation started at 1.0x speed
============================================================
  🌐 CloudServe Pro running at http://localhost:8888
============================================================

[DASHBOARD] Starting on port 5000...
[DASHBOARD] Open http://localhost:5000 in your browser
[WEBSITE]   Open http://localhost:8888 for the user view
```

### Open in browser:

| URL | Purpose |
|-----|---------|
| `http://localhost:5000` | **Admin Dashboard** — Monitor, attack controls, AI defense |
| `http://localhost:8888` | **CloudServe Pro** — User-facing website (shows attack impact) |

---

## How to Use

### Admin Dashboard (Port 5000)

The dashboard has several sections:

#### Top KPI Bar
| Metric | Normal Value | Under Attack |
|--------|-------------|-------------|
| **Throughput** | ~1.2–1.6 Mbps | Drops to 0.5–1.0 Mbps |
| **Latency** | ~13 ms | Spikes to 30–50+ ms |
| **Packet Loss** | < 1% | 30–70%+ |
| **Threat Level** | None | Shows % confidence |
| **AI Action** | no action | rate_limit / isolate / etc. |

#### MAPE-K Phase Indicator
Shows which phase the AI defense is currently in:
- **SENSE** → Collecting network data
- **HYPOTHESIZE** → Analyzing for threats
- **ACT** → Executing defense action
- **VERIFY** → Checking if action was effective

#### Live Traffic Chart
Real-time graph showing:
- 🟩 **Green line** = Throughput (Mbps)
- 🟥 **Red line** = Packet Loss (%)
- 🟡 **Yellow line** = Latency (hidden by default, click legend to show)

#### Network Topology Map
Visual representation of the network:
- 💻 Green circles = Clients (healthy)
- 🔀 Purple circle = Switch (bottleneck)
- 🖥️ Blue circle = Server
- 👾 Red circle = Attacker
- Dashed circles = Isolated nodes
- Link colors: green (low util) → yellow → red (saturated)

#### Attack Controls (Right Panel)

| Button | What It Does |
|--------|-------------|
| **🔴 Launch LDoS Attack** | Starts the attacker sending periodic bursts |
| **⬛ Stop Attack** | Stops the attack (appears after launch) |
| **Burst Rate** | Attack intensity in Mbps (default: 11 Mbps) |
| **Burst Length** | Duration of each burst in ms (default: 10 ms) |
| **Period** | Time between bursts in ms (default: 1000 ms) |

#### AI Defense Controls

| Button | What It Does |
|--------|-------------|
| **✅ Defense Enabled** | Toggle AI defense on/off |
| **Rate Limit Attacker** | Manually throttle the attacker's bandwidth |
| **Block Attacker** | Manually drop all attacker packets |
| **Isolate Attacker** | Manually disconnect attacker from network |
| **Reset** | Reset the entire simulation to initial state |

### CloudServe Pro Website (Port 8888)

This is what a **normal user** would see. Open it in another browser tab.

- **Normal mode**: Pages load instantly, green "✅ All Systems Normal" badge
- **During attack**: Pages load slowly (1–5 seconds), some fail with 503 errors
- **Status banner**: Appears at the top: ⚠️ yellow (degraded) or 🚨 red (disrupted)
- **Live stats**: Uptime, latency, success rate update every 2 seconds

---

## What Happens When...

### 🔴 You Click "Launch LDoS Attack"

```
1. Attack generator activates (10ms bursts at 11 Mbps, every 1 second)
2. Attack packets flood the switch → server bottleneck link
3. Link buffer (100 slots) overflows during bursts → normal packets dropped
4. Dashboard shows:
   ├── Packet loss spikes to 30-70%
   ├── Throughput dips during burst periods
   ├── Chart shows periodic red spikes matching attack period
   └── Topology map: attacker node glows, links turn red
5. CloudServe Pro website:
   ├── Pages take 1-5 seconds to load
   ├── Some requests fail → 503 "Service Unavailable" page
   └── Banner: 🚨 "Service disruption — AI defense system is responding"
```

### 🤖 The AI Defense Kicks In

```
1. MONITOR: Collects last 1 second of packets
2. ANALYZE: Feature extractor computes 12 features:
   ├── Packet rate, byte rate, avg packet size
   ├── Flow entropy, protocol distribution
   ├── Burst detection, periodicity (FFT)
   └── Inter-arrival time statistics
3. Random Forest classifies: "LDoS detected, 87% confidence"
4. PLAN: Q-Learning agent evaluates state:
   ├── State = (throughput_level, latency_level, loss_level, threat_level)
   ├── Picks action with highest Q-value (or explores randomly)
   └── Example: selects "rate_limit" for attacker IP
5. EXECUTE: Mitigation engine applies action:
   ├── rate_limit → Throttles attacker's bandwidth to 100 Kbps
   ├── isolate_node → Disconnects attacker from network entirely
   ├── drop_source → Silently drops all packets from attacker IP
   └── scale_bandwidth → Increases bottleneck link capacity
6. VERIFY: Checks if metrics improved → rewards/penalizes agent
```

### ⬛ You Click "Stop Attack"

```
1. Attack generator deactivates
2. No more burst packets on the network
3. Buffer congestion clears within 1-2 ticks
4. Metrics recover:
   ├── Packet loss drops back to ~0.1%
   ├── Throughput returns to ~1.2 Mbps
   └── Latency normalizes to ~13 ms
5. CloudServe Pro website loads fast again
6. AI agent switches to "no_action" (no threat detected)
```

### 🔄 You Click "Reset"

```
1. Stops any active attack
2. Clears all node metrics (packets sent/received/dropped)
3. Resets link queues and bandwidth counters
4. Clears MAPE-K packet window and threat state
5. Charts clear — starts fresh
6. Simulation continues with clean state
```

### ❌ You Disable AI Defense

```
1. MAPE-K loop still runs (monitors and analyzes)
2. But it DOES NOT execute any defense actions
3. Useful for demonstrating what happens without protection:
   ├── Attack causes sustained high packet loss
   ├── No automatic rate-limiting or isolation
   └── Only manual actions from the dashboard work
```

---

## Technologies Used

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.8+ | Core simulation |
| Detection | scikit-learn (Random Forest) | Anomaly classification |
| Defense | Tabular Q-Learning | Autonomous action selection |
| Dashboard | Flask + Flask-SocketIO | Real-time admin panel |
| Charts | Chart.js | Live throughput/loss graphs |
| Website | Flask + Jinja2 | User-facing demo site |
| Network | Custom discrete event sim | Packet-level simulation |

### Key Parameters (config.py)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `LINK_BANDWIDTH_BPS` | 10 Mbps | Bottleneck link capacity |
| `LINK_BUFFER_SIZE` | 100 | Max packets in queue |
| `LINK_LATENCY_MS` | 20 ms | One-way link delay |
| `NORMAL_TRAFFIC.rate_bps` | 2 Mbps | Per-client traffic rate |
| `LDOS_ATTACK.burst_rate_bps` | 11 Mbps | Attack burst intensity |
| `LDOS_ATTACK.burst_length_ms` | 10 ms | Burst duration |
| `LDOS_ATTACK.period_ms` | 1000 ms | Time between bursts |
| `DETECTOR.confidence_threshold` | 0.7 | Min confidence to flag attack |
| `SIMULATION.tick_interval_ms` | 100 ms | Simulation tick resolution |

---

## Multi-User Demo (Port Forwarding)

To let others interact with the simulation over your network:

### Using VS Code Port Forwarding

1. Open VS Code with the Simulation project
2. Run the simulation: `python main.py`
3. Open the **Ports** panel (bottom bar or `Ctrl+Shift+P` → "Forward a Port")
4. Forward port **5000** (Admin Dashboard)
5. Forward port **8888** (CloudServe Pro Website)
6. Share the forwarded URLs with your team

### Demo Scenario

1. **Person A** opens the CloudServe Pro website (port 8888) — browses normally
2. **Person B** opens the Admin Dashboard (port 5000) — monitors network
3. **Person B** launches an LDoS attack from the dashboard
4. **Person A** sees the website slow down, pages fail with 503 errors
5. **Person B** watches real-time metrics degrade on the dashboard
6. **Person B** enables AI defense → system auto-mitigates
7. **Person A** sees the website recover to normal speed
8. Everyone sees the self-healing system in action! 🎉

---


