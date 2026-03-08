# AI-Based Self-Healing Low-Rate DDoS Defense System

## Complete Theory, Architecture & Implementation Guide

> **Purpose:** This document explains every layer of the project — from the theoretical foundations of LDoS attacks, through the AI/ML models used for detection and mitigation, to the exact flow of data through the system. Use this to prepare for any questions during your presentation.

---

## Table of Contents

1. [What is a DDoS Attack?](#1-what-is-a-ddos-attack)
2. [Low-Rate DDoS (LDoS) — The Shrew Attack](#2-low-rate-ddos-ldos--the-shrew-attack)
3. [Why LDoS Is Hard to Detect](#3-why-ldos-is-hard-to-detect)
4. [Self-Healing Systems & the MAPE-K Loop](#4-self-healing-systems--the-mape-k-loop)
5. [System Architecture Overview](#5-system-architecture-overview)
6. [The Virtual Network Layer](#6-the-virtual-network-layer)
7. [Traffic Generation — Normal, Attack & Flash Crowd](#7-traffic-generation--normal-attack--flash-crowd)
8. [Feature Extraction — Turning Packets Into Numbers](#8-feature-extraction--turning-packets-into-numbers)
9. [Detection Engine — Random Forest Classifier](#9-detection-engine--random-forest-classifier)
10. [Reinforcement Learning Agent — Q-Learning](#10-reinforcement-learning-agent--q-learning)
11. [Mitigation Engine — Defense Actions](#11-mitigation-engine--defense-actions)
12. [Self-Healing Orchestrator — Putting It All Together](#12-self-healing-orchestrator--putting-it-all-together)
13. [The Dashboard & Website](#13-the-dashboard--website)
14. [Complete Data Flow — Step by Step](#14-complete-data-flow--step-by-step)
15. [Key Configuration Parameters](#15-key-configuration-parameters)
16. [Frequently Asked Questions](#16-frequently-asked-questions)

---

## 1. What is a DDoS Attack?

A **Distributed Denial of Service (DDoS)** attack aims to make a network service unavailable to its legitimate users. Traditional volumetric DDoS attacks flood the target with massive amounts of traffic (measured in Gbps) to saturate its bandwidth.

| Type | Measurement | Strategy | Average Rate |
|------|------------|----------|-------------|
| **Volumetric DDoS** | Bits per second (Bps) | Brute-force bandwidth saturation | Very high (100+ Gbps) |
| **Protocol DDoS** | Packets per second (PPS) | Exploit protocol weaknesses (SYN flood) | Medium-High |
| **Application Layer** | Requests per second (RPS) | HTTP floods, Slowloris | Medium |
| **Low-Rate DDoS (LDoS)** | Strategically timed pulses | Exploit TCP's congestion control | **Very low (10-20% of link)** |

The critical difference: **traditional DDoS is like a flood**, **LDoS is like a surgical strike**.

---

## 2. Low-Rate DDoS (LDoS) — The Shrew Attack

### 2.1 The Key Insight — Exploiting TCP's Trust

TCP assumes that packet loss means network congestion. When a TCP sender detects lost packets, it triggers the **Retransmission Timeout (RTO)** mechanism:

1. Sender transmits data → packets are lost
2. Sender waits for the RTO timer (minimum **1 second**, per RFC 6298)
3. Sender retransmits with a reduced congestion window
4. If retransmission fails again, RTO doubles (exponential backoff)

**The LDoS attacker weaponizes this trust.** By sending short, precise bursts timed to coincide with the RTO, the attacker keeps the victim's TCP flows in a perpetual timeout state.

### 2.2 The Three Attack Parameters

```
Timeline:  _____|████|___________________________|████|___________
                ^    ^                             ^    ^
              burst  quiet period (T ≈ RTO)        burst
```

| Parameter | Symbol | What It Does | Our Default Value |
|-----------|--------|-------------|-------------------|
| **Burst Rate** | R | Speed of attack packets during the pulse; must exceed the bottleneck bandwidth to cause buffer overflow | 50 Mbps (5× the 10 Mbps bottleneck) |
| **Burst Length** | L | Duration of each pulse; long enough to fill the buffer, short enough to keep average rate low | 30 ms |
| **Attack Period** | T | Time between pulses; set ≈ TCP minimum RTO so each burst hits right when TCP tries to retransmit | 800 ms |

### 2.3 Why It Works — The Math

- **Duty cycle** = L / T = 30ms / 800ms = **3.75%**
- **Average attack rate** = R × duty_cycle = 50 Mbps × 0.0375 = **1.875 Mbps**
- The bottleneck link is **10 Mbps**, so the attack uses only **~19% of the link capacity** on average
- But during each burst, the 50 Mbps burst **5× overflows** the 10 Mbps bottleneck
- This overflow drops legitimate packets sitting in the buffer
- TCP sees the loss → starts RTO countdown → just as it retransmits, another burst arrives

**Result:** Legitimate throughput drops to near zero, even though the average attack traffic looks "normal" to volume-based detectors.

### 2.4 TCP Congestion State During Attack

```
Normal:     cwnd grows (slow start → congestion avoidance) → full throughput
                ↓
During LDoS: cwnd = 1 → loss → RTO wait → retransmit → loss again → RTO doubles
                ↓
Result:     ssthresh = 1, cwnd = 1, RTO spirals to max (60s), throughput ≈ 0
```

In our simulation, this is visible in the flow data:
- `cwnd: 1` (congestion window stuck at minimum)
- `ssthresh: 2` (slow-start threshold collapsed)
- `rto_ms: 11305` (RTO has doubled multiple times from the 1000ms minimum)

---

## 3. Why LDoS Is Hard to Detect

Traditional DDoS detection uses threshold-based rules (e.g., "alert if traffic > 1 Gbps"). LDoS evades these because:

| Challenge | Explanation |
|-----------|------------|
| **Low average rate** | At 1.875 Mbps average, the attack looks like normal traffic to volume monitors |
| **Periodic but intermittent** | Bursts last only 30ms out of every 800ms — 96% of the time, there's NO attack traffic |
| **Mimics congestion** | The resulting packet loss looks identical to normal network congestion |
| **Mixed with normal traffic** | Attack packets share the same buffer as legitimate packets |

**This is why we need Machine Learning** — to detect the subtle statistical patterns (periodicity, burstiness, entropy shifts) that rule-based systems miss.

---

## 4. Self-Healing Systems & the MAPE-K Loop

### 4.1 What Is Self-Healing?

A self-healing system can:
1. **Recognize** when something is wrong
2. **Identify** the root cause
3. **Fix the problem** automatically
4. **Verify** the fix worked

This is inspired by biological immune systems — the body detects pathogens, generates antibodies, neutralizes threats, and remembers them for next time.

### 4.2 The MAPE-K Framework

MAPE-K (Monitor, Analyze, Plan, Execute, Knowledge) is the standard architecture for autonomous computing systems. Our system maps to it as:

```
┌─────────────────────────────────────────────────────────────┐
│                        KNOWLEDGE BASE                        │
│     (incidents, actions, metrics history, learned models)     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐│
│  │ MONITOR  │───▶│ ANALYZE  │───▶│   PLAN   │───▶│ EXECUTE  ││
│  │ (Sense)  │    │(Hypothe- │    │  (RL     │    │(Mitigate)││
│  │          │    │  size)   │    │  Agent)  │    │          ││
│  │ Collect  │    │ Feature  │    │ Select   │    │ Rate-    ││
│  │ packets, │    │ extract, │    │ optimal  │    │ limit,   ││
│  │ telemetry│    │ Random   │    │ defense  │    │ block,   ││
│  │          │    │ Forest   │    │ action   │    │ isolate  ││
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘│
│       ▲                                              │       │
│       └───────── VERIFY (check if attack stopped) ◀──┘       │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 Dashboard Phase Mapping

The dashboard shows these phases as:
| Dashboard Label | MAPE-K Phase | What Happens |
|----------------|--------------|-------------|
| **Sense** | Monitor | Packet collection from the network |
| **Hypothesize** | Analyze | ML model classifies traffic |
| **Act** | Plan + Execute | RL agent picks action, mitigation engine applies it |
| **Verify** | Verify + Knowledge | Check metrics improved, log to knowledge base |

---

## 5. System Architecture Overview

```
┌────────────────── Simulation Engine (main.py) ──────────────────┐
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────┐    │
│  │   Normal     │  │   LDoS      │  │    Flash Crowd        │    │
│  │   Traffic    │  │   Attack    │  │    Generator          │    │
│  │  Generator   │  │  Generator  │  │  (false-positive      │    │
│  │  (TCP,       │  │  (UDP       │  │   testing)            │    │
│  │   2 Mbps)    │  │  bursts)    │  │                       │    │
│  └──────┬───────┘  └──────┬──────┘  └──────────┬────────────┘    │
│         │                 │                     │                  │
│         ▼                 ▼                     ▼                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │           Virtual Network (network.py)                   │     │
│  │  client1 ──┐                                             │     │
│  │  client2 ──┼── switch ──[BOTTLENECK 10Mbps]── server     │     │
│  │  attacker ─┘     ▲                                       │     │
│  │                  │ packets enter FIFO buffer              │     │
│  │                  │ buffer full → DROP (this is the kill)  │     │
│  └──────────────────┼───────────────────────────────────────┘     │
│                     │                                              │
│         ┌───────────┴──────────────┐                              │
│         │  Self-Healing Orchestrator│                              │
│         │    (self_healing.py)      │                              │
│         │                          │                              │
│         │  1. Feature Extractor    │── 12 statistical features    │
│         │  2. Random Forest        │── classify: normal/ldos/fc   │
│         │  3. Q-Learning Agent     │── pick defense action        │
│         │  4. Mitigation Engine    │── execute on topology        │
│         │  5. Knowledge Base       │── remember everything        │
│         └──────────────────────────┘                              │
│                                                                   │
├───────────────────────────────────────────────────────────────────┤
│  Dashboard (Flask + Socket.IO + Chart.js + vis.js) → port 5000   │
│  Website  (Flask, "CloudServe Pro")                 → port 8888   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 6. The Virtual Network Layer

**File:** `network.py`

### 6.1 Why a Virtual Network?

Instead of requiring Mininet (Linux-only), we simulate an SDN-like network in pure Python. This makes the project portable and runnable on Windows.

### 6.2 Topology — Star Network with Bottleneck

```
client1 (10.0.0.2) ──┐
                       ├──── switch (10.0.0.254) ──[10 Mbps]── server (10.0.0.1)
client2 (10.0.0.3) ──┤                                ▲
                       │                          BOTTLENECK
attacker (10.0.0.100)─┘                     (this link is the target)
```

- **Client → Switch links:** 100 Mbps (fast, not the bottleneck)
- **Switch → Server link:** 10 Mbps (this is the bottleneck that LDoS attacks target)
- **Buffer size:** 200 packets (when this overflows, packets are dropped)

### 6.3 The Link Buffer — Where LDoS Kills

The `Link` class has a FIFO queue (`deque`) with a maximum capacity of 200 packets:

```python
def enqueue(self, packet) -> bool:
    # Buffer overflow — this is the LDoS kill mechanism
    if len(self.queue) >= self.buffer_size:
        self.packets_dropped += 1
        return False    # ← DROPPED! Legitimate packet lost
    
    self.queue.append(packet)
    return True         # ← Delivered successfully
```

During an LDoS burst:
1. Attacker sends 50 Mbps of UDP packets for 30ms
2. This fills the 200-packet buffer instantly
3. Legitimate TCP packets arriving during this burst are **dropped**
4. TCP sender sees the loss and enters RTO backoff

### 6.4 Rate Limiting and Isolation

When the AI defense activates:
- **Rate-limited nodes** have a per-tick byte budget. Excess packets are dropped:
  ```python
  if src_node.is_rate_limited and src_node.rate_limit_bps > 0:
      tick_budget = (src_node.rate_limit_bps / 8) * 0.1  # 100ms tick
      if src_node._bytes_this_tick + packet.size > tick_budget:
          return False  # Throttled
  ```
- **Isolated nodes** have all traffic dropped at the network layer — no packets in or out.

---

## 7. Traffic Generation — Normal, Attack & Flash Crowd

**File:** `traffic_generator.py`

### 7.1 Normal Traffic (`NormalTrafficGenerator`)

Simulates legitimate TCP traffic from clients to the server:
- **Rate:** 2 Mbps per client (configurable)
- **Packet sizes:** 64–1460 bytes (variable, like real HTTP traffic)
- **Natural jitter:** ±20% random variation (mimics real network behavior)
- **Protocol:** TCP

### 7.2 LDoS Attack (`LDoSAttackGenerator`)

Implements the Shrew attack with three configurable parameters:

```python
def generate_tick(self, current_time, tick_ms=100):
    # Where are we in the attack period?
    position_in_period = elapsed_ms % self.period_ms
    
    if position_in_period < self.burst_length_ms:
        # === BURST PHASE === send at burst_rate_bps
        # This OVERWHELMS the bottleneck buffer
    # else: QUIET PHASE — no packets (stealth)
```

Key design decisions:
- **Protocol:** UDP (attackers use UDP because it's connectionless — no handshake needed)
- **Fixed packet size:** 1400 bytes (uniform — this is detectable via entropy analysis)
- **Duty cycle calculation:** burst_length / period = the percentage of time actively attacking

### 7.3 Flash Crowd (`FlashCrowdGenerator`)

Simulates a sudden spike of **legitimate** users (e.g., a viral post sending thousands of visitors):
- Uses a **Gaussian bell curve** traffic pattern (gradual ramp up → peak → ramp down)
- Multiple source IPs (looks distributed)
- Used to test **false positive rates** — the detector must NOT classify this as an attack

---

## 8. Feature Extraction — Turning Packets Into Numbers

**File:** `feature_extractor.py`

ML models can't read raw packets. The Feature Extractor processes a sliding window of packets (1 second of traffic, ~5000 packets) and computes **12 statistical features**:

| # | Feature | What It Measures | Why It Matters for LDoS Detection |
|---|---------|-----------------|----------------------------------|
| 1 | **Packet Count** | Total packets in window | LDoS has fewer packets than volumetric DDoS |
| 2 | **Byte Count** | Total bytes in window | Low average indicates stealthy attack |
| 3 | **Packets/sec** | Packet arrival rate | Bursty (high variance) during LDoS |
| 4 | **Bytes/sec** | Throughput rate | Drops during attack bursts |
| 5 | **Packet Length Entropy** | Shannon entropy of packet sizes | LDoS uses uniform 1400B packets → **low entropy**; normal traffic has diverse sizes → **high entropy** |
| 6 | **Mean IAT** | Average inter-arrival time | LDoS creates bimodal IAT (very short during burst, very long during quiet) |
| 7 | **Std IAT** | Variability in inter-arrival time | **High std** = traffic comes in bursts, not steady |
| 8 | **Periodicity Score** | FFT-based periodic pattern detection | **THE key feature** — LDoS has strong periodic signal at frequency 1/T; normal traffic is random |
| 9 | **Flow Symmetry** | Ratio of unique sources to destinations | LDoS from one source → low symmetry |
| 10 | **Unique Sources** | Number of distinct source IPs | LDoS = 1 source IP; flash crowd = many IPs |
| 11 | **Peak-to-Average Ratio** | Burstiness metric | LDoS has **extreme** burstiness; normal traffic is steady |
| 12 | **Max Burst Size** | Largest traffic spike (bytes in 50ms bin) | Directly measures the attack pulse magnitude |

### 8.1 Shannon Entropy — Detecting Uniform Attack Packets

Shannon entropy measures the "randomness" of packet sizes:

```
H(X) = -Σ p(x) × log₂(p(x))
```

- **Normal traffic:** Packets range from 64B to 1460B → high entropy (~4-6 bits)
- **LDoS attack:** All packets are exactly 1400B → entropy ≈ 0 (perfectly uniform)
- **Flash crowd:** Variable sizes like normal traffic → high entropy

### 8.2 FFT Periodicity — The Smoking Gun

The **Fast Fourier Transform (FFT)** detects periodic patterns in the packet arrival times:

1. Divide the time window into 10ms bins
2. Count packets per bin → creates a time-series signal
3. Apply FFT to decompose into frequency components
4. **LDoS creates a dominant frequency at 1/T** (e.g., 1.25 Hz for T=800ms period)
5. Normal traffic has no dominant frequency (random)

```python
fft_vals = np.abs(np.fft.rfft(bins))   # Frequency decomposition
peak_energy = np.max(fft_vals)           # Dominant frequency strength
score = peak_energy / total_energy       # Periodicity score [0, 1]
```

A periodicity score > 0.3 strongly indicates an LDoS attack.

### 8.3 Burstiness — Peak-to-Average Ratio

Traffic is binned into 50ms windows. The peak bin's traffic is divided by the average:
- **Normal traffic:** Ratio ≈ 1-3 (roughly uniform with jitter)
- **LDoS at burst:** Ratio ≈ 20-100+ (one bin has a massive spike, others are near zero)

---

## 9. Detection Engine — Random Forest Classifier

**File:** `detector.py`

### 9.1 Why Random Forest?

| Model | Accuracy | Pros | Cons |
|-------|----------|------|------|
| **Random Forest** ✅ | **99.9%** | Resistant to overfitting, handles noise, fast inference, feature importance ranking | Less interpretable than linear models |
| SVM | 97-99% | Good for binary classification | Slower training, harder to tune |
| KNN | 99.8% | Simple, effective for local anomalies | Slow inference on large datasets |
| LSTM | High | Captures temporal dependencies | Requires GPU, complex to train |
| Logistic Regression | 85-95% | Interpretable, fast | Can't capture non-linear patterns |

We chose **Random Forest** because:
1. **99.9% accuracy** on our 3-class problem
2. **Fast inference** — decisions happen every 2 seconds in the MAPE-K loop
3. **No GPU required** — runs on any machine
4. **Handles the 12-feature input** without preprocessing
5. **Resistant to overfitting** — critical since we train on synthetic data

### 9.2 How Random Forest Works

A Random Forest is an **ensemble** of decision trees:

```
                    Random Forest (100 trees)
                   /        |        \
              Tree 1     Tree 2    ... Tree 100
              /    \     /    \        /    \
           split  split split split  split  split
            ...    ...   ...   ...    ...    ...
           
           vote:  vote:  vote:       vote:
          "ldos" "normal" "ldos"     "ldos"
          
          Final prediction: MAJORITY VOTE → "ldos" (87 out of 100 trees)
          Confidence: 87/100 = 0.87 (87%)
```

Each tree:
1. Trains on a random **subset** of the training data (bagging)
2. At each split, considers a random **subset** of features
3. This randomness makes the forest robust — no single tree's mistake dominates

**Configuration:** 100 trees, max depth 15, confidence threshold 55%

### 9.3 Three-Class Classification

The detector classifies traffic into:

| Class | Label | Characteristics |
|-------|-------|----------------|
| **Normal** | 0 | Steady rate, high entropy, no periodicity, moderate burstiness |
| **LDoS Attack** | 1 | Periodic bursts, low entropy, extreme burstiness, few source IPs |
| **Flash Crowd** | 2 | Sudden spike, high entropy, many source IPs, non-periodic |

The model outputs **probability for each class**:
```python
probabilities = model.predict_proba(features)
# Example: [0.05, 0.87, 0.08] → 5% normal, 87% LDoS, 8% flash crowd
```

### 9.4 Training Data — Synthetic Generation

Since we can't collect real LDoS attack data easily, we use **synthetic data generation**:

```python
class SyntheticDataGenerator:
    def generate_normal_sample(self):
        # Steady packets, variable sizes, random timing
        
    def generate_ldos_sample(self):
        # Periodic bursts with uniform packet sizes
        # Randomized attack parameters for generalization
        
    def generate_flash_crowd_sample(self):
        # Bell-curve traffic from many source IPs
```

**5000 samples per class** → 15,000 total training samples, 80/20 train-test split.

### 9.5 Exponential Decay for Threat Persistence

LDoS attacks are intermittent — 96% of the time there's no attack traffic. Without decay, the detector would flash "0% threat → 87% threat → 0% threat" every second, making the dashboard flicker.

**Solution:** Threat confidence decays exponentially between bursts:

```python
# If no attack packets in this window, decay instead of resetting
self.current_confidence *= 0.85   # Decay factor
# Confidence: 87% → 74% → 63% → 53% → 45% (over 5 cycles)
# It takes ~8 cycles (~16 seconds) to decay below the 55% threshold
```

This keeps the "ATTACK DETECTED" status visible between pulses.

---

## 10. Reinforcement Learning Agent — Q-Learning

**File:** `rl_agent.py`

### 10.1 Why Reinforcement Learning?

The detection engine tells us **what** is happening (attack detected). The RL agent decides **what to do about it**.

Why not just hard-code rules?
- Different attack parameters require different responses
- The optimal action depends on the current network state
- The agent should learn which actions actually help (measured by throughput recovery)

### 10.2 How Q-Learning Works

Q-Learning is a **model-free** RL algorithm that learns the value of each action in each state through trial and error:

```
Q(state, action) = Q(state, action) + α × [reward + γ × max Q(next_state, all_actions) - Q(state, action)]
                                        ↑                ↑
                                   learning rate    discount factor
```

The Q-table maps every (state, action) pair to a value. Higher value = better action in that state.

### 10.3 State Space — 5 Dimensions (Discretized)

The continuous network metrics are discretized into buckets for the Q-table:

| Dimension | Buckets | Meaning |
|-----------|---------|---------|
| **Throughput Ratio** | 0=low (<30%) 1=medium (30-70%) 2=high (>70%) | How much of baseline throughput we're getting |
| **Latency** | 0=low (<50ms) 1=medium (50-200ms) 2=high (>200ms) | Current network delay |
| **Packet Loss** | 0=none (<1%) 1=low (1-10%) 2=high (>10%) | How many packets being dropped |
| **Attack Confidence** | 0=none (<30%) 1=low (30-70%) 2=high (>70%) | ML detector's confidence |
| **Defense Active** | 0=no 1=yes | Are there active mitigation rules? |

**Total state space:** 3 × 3 × 3 × 3 × 2 = **162 possible states**

### 10.4 Action Space — 6 Defense Actions

| Action Index | Name | What It Does |
|-------------|------|-------------|
| 0 | `no_action` | Continue monitoring (appropriate when no threat or threat resolved) |
| 1 | `rate_limit` | Throttle the suspected attacker to 500 Kbps |
| 2 | `drop_source` | Block ALL traffic from the attacker IP |
| 3 | `reroute_traffic` | Add +5 Mbps bandwidth to the bottleneck (simulate alternate path) |
| 4 | `isolate_node` | Completely quarantine the attacker node from the network |
| 5 | `scale_bandwidth` | Double the bottleneck link capacity (capped at 100 Mbps) |

### 10.5 Reward Function — What Makes a Good Action

```python
Reward = w₁ × throughput_ratio - w₂ × (latency/1000) - w₃ × packet_loss - w₄ × false_positive
```

| Weight | Value | Meaning |
|--------|-------|---------|
| w₁ (throughput) | **+1.0** | Reward maintaining high throughput |
| w₂ (latency) | **-0.5** | Penalize high latency |
| w₃ (packet loss) | **-2.0** | Strongly penalize packet loss |
| w₄ (false positive) | **-3.0** | Heavily penalize blocking legitimate traffic |

**Key insight:** False positives are penalized **3× more** than packet loss, ensuring the agent is conservative — it would rather tolerate some attack traffic than accidentally block a legitimate user.

### 10.6 Epsilon-Greedy Exploration

The agent balances **exploration** (trying random actions to discover better strategies) with **exploitation** (using the best known action):

```
ε starts at 1.0 (100% random) → decays by 0.995 per episode → minimum 0.05 (5% random)
```

After pre-training (500 episodes), ε ≈ 0.08 — the agent mostly exploits its learned policy but still occasionally explores.

### 10.7 Pre-Training — Learning Before Deployment

Before live deployment, the agent trains on **simulated scenarios**:

1. **Phase 1 (10 steps):** Normal traffic — learns that `no_action` gives high reward
2. **Phase 2 (20 steps):** Attack ramps up — learns that `drop_source` and `rate_limit` give rewards when confidence is high
3. Agent learns: "When throughput is low AND attack confidence is high → block the source"

---

## 11. Mitigation Engine — Defense Actions

**File:** `mitigation.py`

### 11.1 Action Implementations

| Action | Network Effect | When It's Best |
|--------|---------------|---------------|
| **rate_limit** | Set node's byte budget to 500 Kbps/tick | Suspected attack, not yet confirmed |
| **drop_source** | Set `is_isolated = True` on the attacker node | Confirmed attack, high confidence |
| **reroute_traffic** | Add +5 Mbps to the bottleneck link | Attack overwhelming the bottleneck |
| **isolate_node** | Quarantine node completely (same as drop_source) | Compromised node must be contained |
| **scale_bandwidth** | Double bottleneck capacity (max 100 Mbps) | Need more headroom to absorb bursts |
| **restore_node** | Remove all restrictions, set health to 100% | After attack stops, re-integrate node |

### 11.2 Safety Guard — Protecting Legitimate Nodes

The mitigation engine has a **critical safety check** — it NEVER applies destructive actions to legitimate clients or the server:

```python
# SAFETY GUARD — never isolate, rate-limit, or block legitimate nodes
protected_ips = {server_ip, client1_ip, client2_ip}
if target_ip in protected_ips:
    return "BLOCKED: target is a protected node"
```

This prevents the worst-case scenario: the AI accidentally blocking legitimate users (which would be worse than the attack itself).

### 11.3 Bandwidth Scaling Cap

Without a cap, repeated `scale_bandwidth` actions would double 10 Mbps → 20 → 40 → 80 → 160 → ... into unrealistic values. We cap at **100 Mbps**:

```python
MAX_BANDWIDTH_BPS = 100_000_000  # 100 Mbps cap
new_bw = min(int(old_bw * scale_factor), MAX_BANDWIDTH_BPS)
```

---

## 12. Self-Healing Orchestrator — Putting It All Together

**File:** `self_healing.py`

The `SelfHealingOrchestrator` is the brain that runs the MAPE-K loop continuously:

```python
while running:
    # 1. MONITOR — Collect recent packets
    packets = collect_telemetry()      # ~5000 packets from sliding window
    metrics = compute_network_metrics() # throughput, latency, loss, utilization
    
    # 2. ANALYZE — Run ML detector
    threat = detector.analyze(packets)  # Returns: detected?, confidence, type, sources
    
    # 3. PLAN — Ask RL agent what to do
    if defense_enabled and threat.detected:
        action = agent.step(throughput, latency, loss, confidence)
    
    # 4. EXECUTE — Apply the action
    if action != "no_action":
        mitigation_engine.execute(action, target_ip=threat.source_ips[0])
    
    # 5. VERIFY + KNOWLEDGE — Log everything
    knowledge_base.record_metrics(metrics)
    knowledge_base.record_incident(threat)
    emit_event_to_dashboard(metrics)
    
    sleep(100ms)  # Next tick
```

### 12.1 The Knowledge Base

Stores:
- **Incidents:** Every detected threat (type, confidence, source IPs, timestamp)
- **Actions taken:** Every mitigation action (type, target, success, description)
- **Metric snapshots:** Rolling window of 1000 network state snapshots

This provides historical context for learning and post-incident review.

---

## 13. The Dashboard & Website

### 13.1 Admin Dashboard (Port 5000)

**Files:** `dashboard/app.py`, `dashboard/static/dashboard.js`, `dashboard/templates/index.html`

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **KPI Cards** | Vanilla JS | Real-time throughput, latency, packet loss, threat level, AI action |
| **Traffic Chart** | Chart.js | Live time-series of throughput, loss, and latency |
| **Phase Indicator** | CSS | Shows current MAPE-K phase (Sense/Hypothesize/Act/Verify) |
| **Network Topology** | vis.js Network | Interactive graph — drag nodes, hover for details, edges colored by utilization |
| **Node Health** | Vanilla JS | Per-node cards with health bars, status badges |
| **Event Log** | Vanilla JS | Chronological log of all system events |
| **Attack Controls** | Vanilla JS + API | Launch/stop attacks, configure burst parameters |
| **Defense Controls** | Vanilla JS + API | Enable/disable AI defense, manual actions |

Data flow: Dashboard polls `GET /api/status` every 1 second, `GET /api/topology` every 3 seconds.

### 13.2 User-Facing Website — CloudServe Pro (Port 8888)

**Files:** `website/app.py`, `website/templates/index.html`

Simulates a real website that end-users would access. Its behavior reflects the network's health:
- **Normal:** Fast loading, green indicators
- **Under attack (no AI):** 503 errors, degraded status, slow loading
- **Under attack (with AI):** Recovers as AI mitigates the attack

---

## 14. Complete Data Flow — Step by Step

### Scenario: Attack Launched, AI Detects and Mitigates

```
Time 0s:  System starts. Normal traffic flowing.
          Throughput: ~4 Mbps | Loss: 0% | Threat: None

Time 15s: User clicks "Launch LDoS Attack" (burst=50Mbps, length=30ms, period=800ms)
          │
          ├─ LDoSAttackGenerator starts sending UDP burst packets
          ├─ Every 800ms: 30ms burst of 50 Mbps traffic hits the bottleneck
          ├─ Buffer (200 packets) overflows during bursts
          ├─ Legitimate TCP packets are DROPPED
          ├─ TCP flows enter RTO backoff (cwnd → 1)
          │
          ▼
Time 17s: Feature Extractor detects:
          - Periodicity score ↑↑ (FFT finds 1.25 Hz peak)
          - Packet entropy ↓↓ (uniform 1400B attack packets)
          - Burstiness ratio ↑↑ (peak/avg > 20)
          - Unique sources = 1 (single attacker IP)
          │
          ├─ Random Forest classifies: [0.03, 0.91, 0.06]
          │  → 91% LDoS, 3% normal, 6% flash crowd
          ├─ Confidence 91% > 55% threshold → THREAT DETECTED
          ├─ Source IP identified: 10.0.0.100 (attacker)
          │
          ▼
Time 17s: RL Agent observes state:
          - throughput_ratio = 0.2 (low)
          - latency = 800ms (high)
          - packet_loss = 0.40 (high)
          - attack_confidence = 0.91 (high)
          - defense_active = False
          │
          ├─ State = (0, 2, 2, 2, 0) → looks up Q-table
          ├─ Best action: "drop_source" (Q-value = 3.2)
          │
          ▼
Time 17s: Mitigation Engine executes:
          ├─ Target: 10.0.0.100
          ├─ Safety check: is 10.0.0.100 a protected node? → NO (it's the attacker)
          ├─ Set attacker.is_isolated = True
          ├─ All future packets from 10.0.0.100 are DROPPED at network layer
          │
          ▼
Time 19s: Network recovers:
          ├─ No more attack packets reaching the bottleneck
          ├─ Buffer drains, no more overflow
          ├─ TCP flows recover: cwnd grows, RTO resets
          ├─ Throughput climbs back to ~4 Mbps
          ├─ Packet loss drops to ~0%
          │
          ▼
          Dashboard shows:
          - Status: ATTACK DETECTED → threat decaying
          - Attacker node: "⛔ ISOLATED" (grayed out in topology)
          - Throughput recovering on the chart
          - Event log: "Blocked all traffic from 10.0.0.100"
```

---

## 15. Key Configuration Parameters

**File:** `config.py`

| Category | Parameter | Value | Why This Value |
|----------|----------|-------|---------------|
| **Bottleneck** | Bandwidth | 10 Mbps | Standard bottleneck rate; attack burst must exceed this |
| **Bottleneck** | Latency | 20 ms one-way | Creates 40ms RTT; realistic for LAN |
| **Bottleneck** | Buffer size | 200 packets | Small enough to overflow during 50 Mbps bursts |
| **Normal Traffic** | Rate | 2 Mbps/client | Keeps bottleneck at ~40-50% utilization normally |
| **LDoS Attack** | Burst rate | 50 Mbps | 5× the bottleneck — guarantees overflow |
| **LDoS Attack** | Burst length | 30 ms | Just enough to fill the 200-packet buffer |
| **LDoS Attack** | Period | 800 ms | Close to TCP min RTO (1000ms) — disrupts retransmissions |
| **Detector** | Trees | 100 | Standard RF size; good balance of accuracy and speed |
| **Detector** | Max depth | 15 | Prevents overfitting on the 12-feature input |
| **Detector** | Confidence threshold | 55% | Low enough to catch attacks, high enough to avoid false positives |
| **RL Agent** | Learning rate | 0.1 | Standard for tabular Q-learning |
| **RL Agent** | Discount factor | 0.95 | Agent values future rewards (long-term defense is important) |
| **RL Agent** | Epsilon decay | 0.995 | Slow decay — thorough exploration during pre-training |
| **Simulation** | Tick interval | 100 ms | 10 ticks/second; fast enough to capture 30ms bursts |

---

## 16. Frequently Asked Questions

### Q: How is this different from a regular DDoS defense?

**A:** Traditional DDoS defenses use static thresholds (e.g., "block if traffic > 1 Gbps"). LDoS attacks use only 1.875 Mbps average — far below any threshold. Our system uses **ML to detect statistical patterns** (periodicity, burstiness, entropy) that threshold-based systems miss. Additionally, our system is **self-healing** — it autonomously detects, responds, and recovers without human intervention.

### Q: Why Random Forest instead of a Neural Network?

**A:** Random Forest achieves 99.9% accuracy on this problem and runs in milliseconds on a CPU. A neural network would need GPU resources, more training data, and offers marginal improvement. For a real-time defense system running every 2 seconds, inference speed matters. Random Forest is also more interpretable — we can see which features (periodicity, entropy) drove the decision.

### Q: Why Q-Learning instead of Deep RL (DQN, PPO)?

**A:** Our state space is small (162 states × 6 actions = 972 Q-values). Tabular Q-Learning perfectly handles this — no neural network needed. Deep RL (DQN, PPO) is overkill for this problem and would introduce unnecessary complexity. If our state space grew (e.g., per-flow actions for thousands of flows), we would switch to DQN.

### Q: What if the attacker changes their parameters?

**A:** The detector is trained on **randomized** attack parameters (different burst rates, lengths, and periods). So it generalizes to unseen parameter combinations. The key features — **periodicity**, **entropy**, **burstiness** — are characteristic of ALL LDoS attacks regardless of specific parameters. The RL agent also adapts through its epsilon-greedy exploration.

### Q: Can the system handle zero-day attacks?

**A:** Not directly. The Random Forest is trained on three known traffic profiles. A completely novel attack type might be misclassified. However, the **feature extraction approach** (statistical features rather than signature matching) means any attack exhibiting periodic bursts or abnormal entropy WILL trigger detection. The knowledge base also helps the system learn from new incidents.

### Q: What is the false positive rate?

**A:** The Flash Crowd class in the training data specifically trains the detector to distinguish legitimate traffic spikes from attacks. Key differentiators:
- Flash crowds come from **many unique IPs** (LDoS from one)
- Flash crowds are **not periodic** (LDoS has strong periodicity)
- Flash crowds have **varied packet sizes** (LDoS has uniform sizes)

In testing, accuracy exceeds 99.9%, implying a false positive rate below 0.1%.

### Q: Why do you have a safety guard in the mitigation engine?

**A:** Without it, the RL agent could accidentally learn that "isolate the server" reduces attack traffic (technically true — no traffic means no attack traffic). The safety guard ensures the AI can NEVER block legitimate clients or the server, even if the Q-table suggests it. This is a critical failsafe for any autonomous defense system.

### Q: What is the MAPE-K loop cycle time?

**A:** One full MAPE-K cycle takes approximately **100ms** (one simulation tick). However, the ML detector only produces meaningful results every **2 seconds** (it needs enough packets in the window to compute reliable features). The RL agent then responds within the same tick, and the mitigation action takes effect immediately.

### Q: How does the website reflect the network state?

**A:** The website (`CloudServe Pro` on port 8888) reads snapshot variables from the simulation engine. These variables are updated every tick and contain the current throughput, latency, and packet loss. When throughput drops below 50% or loss exceeds 20%, the website shows degraded status. Below 10% throughput or above 50% loss, it returns HTTP 503 (Service Unavailable).

### Q: Can this be deployed on a real network?

**A:** The architecture is designed for it. Replace:
1. `network.py` → Real SDN controller (Ryu/Floodlight) + OpenFlow switches
2. `traffic_generator.py` → Real network traffic captured via packet sniffing
3. `mitigation.py` → SDN flow rules (OpenFlow match-action rules)
4. Keep the ML detector, RL agent, and self-healing orchestrator as-is

The P4-based PLUTO system demonstrates this exact approach at line speed (6.5 Tbps).

---

## Summary — The Five Key Innovations

1. **LDoS-Specific Feature Engineering:** 12 features including FFT periodicity and Shannon entropy that specifically capture the LDoS attack signature
2. **Random Forest Detection:** 99.9% accuracy three-class classifier (normal/LDoS/flash crowd) with exponential decay for persistent threat visibility
3. **Q-Learning Mitigation:** Autonomous action selection that learns optimal defense strategies through reward-driven interaction
4. **Safety-Guarded Execution:** Mitigation engine that protects legitimate nodes from accidental isolation
5. **MAPE-K Self-Healing Loop:** Continuous autonomous cycle of monitoring, analysis, planning, and execution with a persistent knowledge base

---

*Document prepared for project presentation — AI-Based Self-Healing Low-Rate DDoS Defense System, SEM VIII EHNS*
