"""
Self-Healing Orchestrator — The MAPE-K master controller.
Ties together monitoring, analysis, planning, execution, and knowledge
into a continuous autonomous defense loop.
"""

import time
import threading
from collections import deque
from typing import List, Dict, Optional, Callable
import numpy as np

import config
from network import NetworkTopology, Packet
from feature_extractor import FeatureExtractor
from detector import AnomalyDetector, ThreatAssessment
from rl_agent import DefenseAgent
from mitigation import MitigationEngine, MitigationAction


class KnowledgeBase:
    """
    Maintains historical context of incidents and responses.
    Used by the RL agent and detection engine to improve over time.
    """

    def __init__(self):
        self.incidents: List[dict] = []
        self.actions_taken: List[dict] = []
        self.metric_snapshots: deque = deque(maxlen=1000)

    def record_incident(self, threat: ThreatAssessment, timestamp: float):
        self.incidents.append({
            "time": timestamp,
            "type": threat.threat_type,
            "confidence": threat.confidence,
            "sources": threat.source_ips,
        })

    def record_action(self, action: MitigationAction):
        self.actions_taken.append(action.to_dict())

    def record_metrics(self, metrics: dict, timestamp: float):
        self.metric_snapshots.append({
            "time": timestamp,
            **metrics,
        })

    def get_recent_incidents(self, n: int = 10) -> List[dict]:
        return self.incidents[-n:]

    def get_summary(self) -> dict:
        return {
            "total_incidents": len(self.incidents),
            "total_actions": len(self.actions_taken),
            "metric_snapshots": len(self.metric_snapshots),
        }


class SelfHealingOrchestrator:
    """
    The MAPE-K loop controller that manages the entire defense lifecycle:
    
    1. MONITOR — Collect telemetry from the network
    2. ANALYZE — Feed features to the ML detector
    3. PLAN    — Use RL agent to select optimal defense action
    4. EXECUTE — Apply the chosen mitigation action
    5. KNOWLEDGE — Log everything for learning and review
    
    Architecture mapping to the user's diagram:
        SENSE      → Monitor phase
        HYPOTHESIZE → Analyze phase  
        ACT        → Plan + Execute phase
        VERIFY     → Recovery verification loop
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology

        # MAPE-K components
        self.feature_extractor = FeatureExtractor()
        self.detector = AnomalyDetector()
        self.agent = DefenseAgent()
        self.mitigation_engine = MitigationEngine(topology)
        self.knowledge_base = KnowledgeBase()

        # State
        self.is_running = False
        self.is_defense_enabled = True
        self.current_phase = "idle"
        self.packet_window: deque = deque(maxlen=5000)

        # Metrics for dashboard
        self.current_metrics: dict = {}
        self.current_threat: Optional[ThreatAssessment] = None
        self.metrics_history: deque = deque(maxlen=600)
        self.buffer_history: deque = deque(maxlen=40)
        self.pre_attack_score: float = 0.0
        self.current_prediction: Optional[dict] = None
        self._last_pre_alert_time: float = -9999.0

        # Event callbacks (for WebSocket streaming)
        self._event_callbacks: List[Callable] = []

        # Threading
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Simulation clock
        self.sim_time: float = 0.0
        self.start_time: float = 0.0

    def initialize(self, train_detector: bool = True,
                   pre_train_agent: bool = True):
        """
        Initialize the defense system.
        Optionally train the detector and pre-train the RL agent.
        """
        print("=" * 60)
        print("  AI-Based Self-Healing LDoS Defense System")
        print("  Initializing MAPE-K Loop...")
        print("=" * 60)

        # Train or load detector
        if train_detector:
            if not self.detector.load_model():
                print("\n[INIT] Training anomaly detector...")
                results = self.detector.train()
                self.detector.save_model()
                print(f"[INIT] Detector accuracy: {results['accuracy']:.4f}")
            else:
                print("[INIT] Loaded pre-trained detector model")
        
        # Pre-train or load RL agent
        if pre_train_agent:
            if not self.agent.load():
                print("\n[INIT] Pre-training RL defense agent...")
                results = self.agent.pre_train(episodes=500)
                self.agent.save()
                print(f"[INIT] Agent Q-table: {results['q_table_size']} states")
            else:
                print("[INIT] Loaded pre-trained RL agent")

        print("\n[INIT] Self-Healing System Ready ✓")
        print("=" * 60)

    def start(self):
        """Start the MAPE-K loop in a background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.start_time = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._emit_event("system", "Self-healing orchestrator started")

    def stop(self):
        """Stop the MAPE-K loop."""
        self.is_running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._emit_event("system", "Self-healing orchestrator stopped")

    def ingest_packet(self, packet_record: dict):
        """Feed a packet record into the analysis window."""
        with self._lock:
            self.packet_window.append(packet_record)

    def set_defense_enabled(self, enabled: bool):
        """Toggle AI defense on/off."""
        self.is_defense_enabled = enabled
        state = "enabled" if enabled else "disabled"
        self._emit_event("defense", f"AI defense {state}")

    def register_event_callback(self, callback: Callable):
        """Register a callback for system events: callback(event_type, data)."""
        self._event_callbacks.append(callback)

    def _loop(self):
        """Main MAPE-K loop — runs continuously until stopped."""
        tick_interval = config.SIMULATION["tick_interval_ms"] / 1000

        while not self._stop_event.is_set():
            self.sim_time = time.time() - self.start_time

            try:
                # ─── 1. MONITOR ───────────────────────────
                self.current_phase = "monitor"
                packets = self._collect_telemetry()
                metrics = self._compute_network_metrics()

                # ─── 2. ANALYZE ───────────────────────────
                self.current_phase = "analyze"
                threat = self.detector.analyze(packets)
                self.current_threat = threat
                prediction = self._predict_pre_attack(packets, metrics, threat)
                self.current_prediction = prediction
                # ─── DEBUG LOG (every ~2 seconds) ────────
                if int(self.sim_time * 10) % 20 == 0:
                    n_attack = sum(1 for p in packets if p.get('type') == 'attack')
                    n_normal = sum(1 for p in packets if p.get('type') == 'normal')
                    srcs = {}
                    for p in packets:
                        s = p.get('src', '?')
                        srcs[s] = srcs.get(s, 0) + 1
                    src_summary = ', '.join(f"{ip}:{cnt}" for ip, cnt in sorted(srcs.items(), key=lambda x: -x[1])[:5])
                    probs = threat.raw_probabilities if threat.raw_probabilities else {}
                    print(f"[MAPE-K t={self.sim_time:.1f}] window={len(packets)} pkts "
                          f"(normal={n_normal}, attack={n_attack}) | "
                          f"top_src=[{src_summary}] | "
                          f"RF_pred={probs} conf={threat.confidence:.3f} "
                          f"detected={threat.threat_detected} type={threat.threat_type} "
                          f"sources={threat.source_ips}")
                    if prediction and prediction.get("predicted"):
                        print(f"  [PRE-ALERT] conf={prediction['confidence']:.2f} "
                              f"eta={prediction['horizon_sec']}s source={prediction['source_ip']}")
                if threat.threat_detected:
                    self.knowledge_base.record_incident(threat, self.sim_time)
                    self._emit_event("alert", {
                        "type": threat.threat_type,
                        "confidence": threat.confidence,
                        "sources": threat.source_ips,
                        "time": self.sim_time,
                    })

                # ─── 3. PLAN (RL Agent) ───────────────────
                self.current_phase = "plan"
                action_name = "no_action"

                # Only invoke the RL agent when a threat IS detected
                if (self.is_defense_enabled and self.detector.is_trained
                        and threat.threat_detected):
                    baseline_tp = config.NORMAL_TRAFFIC["rate_bps"]
                    throughput_ratio = metrics.get("throughput_bps", 0) / max(1, baseline_tp)

                    action_name = self.agent.step(
                        throughput_ratio=throughput_ratio,
                        latency_ms=metrics.get("latency_ms", 0),
                        packet_loss=metrics.get("packet_loss", 0),
                        attack_confidence=threat.confidence,
                        defense_active=len(self.mitigation_engine.active_mitigations) > 0,
                        false_positive=False,
                    )
                    print(f"  [RL] threat conf={threat.confidence:.2f} → action={action_name} target={threat.source_ips}")

                # ─── 4. EXECUTE ───────────────────────────
                self.current_phase = "execute"
                if action_name != "no_action" and self.is_defense_enabled:
                    target_ip = threat.source_ips[0] if threat.source_ips else ""
                    result = self.mitigation_engine.execute(
                        action_name, target_ip,
                        current_time=self.sim_time,
                    )
                    self.knowledge_base.record_action(result)
                    self._emit_event("mitigation", result.to_dict())
                    print(f"  [MITIGATE] {result.action_type} → {result.target} | success={result.success} | {result.description}")

                # ─── 5. VERIFY + KNOWLEDGE ────────────────
                self.current_phase = "verify"
                self.current_metrics = {
                    **metrics,
                    "threat": threat.to_dict() if threat else {},
                    "prediction": prediction,
                    "action": action_name,
                    "defense_enabled": self.is_defense_enabled,
                    "phase": self.current_phase,
                    "sim_time": round(self.sim_time, 2),
                }
                self.knowledge_base.record_metrics(metrics, self.sim_time)
                self.metrics_history.append(self.current_metrics)

                # Emit periodic metrics update
                self._emit_event("metrics", self.current_metrics)

            except Exception as e:
                self._emit_event("error", str(e))

            self._stop_event.wait(tick_interval)

    def _collect_telemetry(self) -> List[dict]:
        """MONITOR: Return recent packets as a sliding window.
        
        We do NOT clear the deque — the maxlen (5000 packets ≈ 5-7 seconds
        of traffic) naturally evicts old data.  This way every analysis
        cycle sees enough context to detect the periodic LDoS pattern
        instead of seeing only a single 100 ms tick's worth of data.
        """
        with self._lock:
            packets = list(self.packet_window)
        return packets

    def _compute_network_metrics(self) -> dict:
        """Compute aggregate network health metrics from per-tick packet data."""
        # Use the packets we already collected this cycle for more accurate metrics
        with self._lock:
            recent_packets = list(self.packet_window)

        # Calculate per-tick delivery rate from packet window
        total_pkts = len(recent_packets)

        # Get node-level latency and throughput from topology
        snapshot = self.topology.get_topology_snapshot()
        total_throughput = 0
        total_latency = 0
        n_clients = 0
        for node_data in snapshot["nodes"]:
            if node_data["type"] in ("client", "server"):
                total_throughput += node_data["throughput_bps"]
                total_latency += node_data["latency_ms"]
                n_clients += 1

        avg_throughput = total_throughput / max(1, n_clients)
        avg_latency = total_latency / max(1, n_clients)

        # Use topology-level cumulative drop rate only as a rough guide
        # (the dashboard uses per-tick from main.py for display)
        drop_rate = snapshot["totals"]["drop_rate"]

        # Link utilization
        max_utilization = 0
        for link_data in snapshot["links"]:
            max_utilization = max(max_utilization, link_data["utilization"])

        return {
            "throughput_bps": avg_throughput,
            "latency_ms": avg_latency,
            "packet_loss": drop_rate,
            "link_utilization": max_utilization,
            "total_packets": snapshot["totals"]["packets_sent"],
            "total_dropped": snapshot["totals"]["packets_dropped"],
        }

    def _predict_pre_attack(self, packets: List[dict], metrics: dict,
                            threat: ThreatAssessment) -> dict:
        """
        Micro-pattern predictor for early warning before hard attack detection.
        Detects subtle burstiness, timing irregularity, and bottleneck instability
        and emits a pre-alert when risk is high.
        """
        cfg = getattr(config, "PRE_ATTACK_PREDICTOR", {})

        horizon_sec = float(cfg.get("horizon_sec", 2.0))
        min_recent_packets = int(cfg.get("min_recent_packets", 100))
        min_source_packets = int(cfg.get("min_source_packets", 20))
        time_bin_sec = float(cfg.get("time_bin_sec", 0.05))

        spike_ratio_scale = float(cfg.get("spike_ratio_scale", 4.0))
        timing_irregularity_scale = float(cfg.get("timing_irregularity_scale", 3.0))
        source_share_scale = float(cfg.get("source_share_scale", 0.35))

        src_w = cfg.get("source_weights", {})
        w_spike = float(src_w.get("spike_ratio", 0.35))
        w_timing = float(src_w.get("timing_irregularity", 0.35))
        w_share = float(src_w.get("source_share", 0.30))

        buf_min_history = int(cfg.get("buffer_min_history", 5))
        buf_cq = float(cfg.get("buffer_coeff_std_queue", 2.0))
        buf_cu = float(cfg.get("buffer_coeff_std_util", 1.5))
        buf_mu = float(cfg.get("buffer_coeff_mean_util", 0.5))

        blend_w = cfg.get("blend_weights", {})
        w_source = float(blend_w.get("source_score", 0.45))
        w_buffer = float(blend_w.get("buffer_instability", 0.30))
        w_hint = float(blend_w.get("ldos_hint", 0.25))

        smoothing_keep = float(cfg.get("smoothing_keep", 0.65))
        smoothing_update = float(cfg.get("smoothing_update", 0.35))

        prediction_threshold = float(cfg.get("prediction_threshold", 0.58))
        pre_alert_cooldown = float(cfg.get("pre_alert_cooldown_sec", 3.0))
        decay_empty = float(cfg.get("score_decay_empty", 0.8))
        decay_low_data = float(cfg.get("score_decay_low_data", 0.85))

        eta_min = int(cfg.get("eta_min_sec", 3))
        eta_max = int(cfg.get("eta_max_sec", 10))
        eta_slope = float(cfg.get("eta_slope", 7.0))

        if not packets:
            self.pre_attack_score *= decay_empty
            return {
                "predicted": False,
                "confidence": round(self.pre_attack_score, 3),
                "horizon_sec": 0,
                "source_ip": "",
                "signals": {},
            }

        # Track bottleneck instability over time.
        bn_link = self.topology.links.get("switch-server")
        if bn_link:
            self.buffer_history.append({
                "queue": bn_link.get_queue_occupancy(),
                "util": bn_link.get_utilization(),
            })

        latest_t = max(p.get("time", 0.0) for p in packets)
        recent = [p for p in packets if latest_t - p.get("time", 0.0) <= horizon_sec]

        if len(recent) < min_recent_packets:
            self.pre_attack_score *= decay_low_data
            return {
                "predicted": False,
                "confidence": round(self.pre_attack_score, 3),
                "horizon_sec": 0,
                "source_ip": "",
                "signals": {},
            }

        legit_ips = set()
        for node_cfg in config.NETWORK.values():
            if node_cfg["type"] in ("client", "server"):
                legit_ips.add(node_cfg["ip"])

        # Per-source micro pattern scoring (focus on non-legitimate sources).
        source_counts = {}
        source_times = {}
        for pkt in recent:
            src = pkt.get("src", "")
            source_counts[src] = source_counts.get(src, 0) + 1
            source_times.setdefault(src, []).append(pkt.get("time", 0.0))

        total_recent = max(1, len(recent))
        best_source = ""
        best_source_score = 0.0
        best_spike = 0.0
        best_timing_irregularity = 0.0

        for src, times in source_times.items():
            if src in legit_ips or len(times) < min_source_packets:
                continue

            t_arr = np.array(sorted(times), dtype=np.float64)
            iats = np.diff(t_arr)
            if len(iats) == 0:
                continue

            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
            timing_irregularity = std_iat / max(1e-6, mean_iat)

            # Bin packets in 50ms to capture bursty probe behavior.
            bin_size = time_bin_sec
            n_bins = max(1, int(horizon_sec / bin_size))
            bins = np.zeros(n_bins)
            t0 = latest_t - horizon_sec
            for t in t_arr:
                idx = min(n_bins - 1, max(0, int((t - t0) / bin_size)))
                bins[idx] += 1
            spike_ratio = float(np.max(bins) / max(1e-6, float(np.mean(bins))))

            source_share = source_counts[src] / total_recent
            source_score = (
                w_spike * min(1.0, (spike_ratio - 1.0) / max(1e-6, spike_ratio_scale)) +
                w_timing * min(1.0, timing_irregularity / max(1e-6, timing_irregularity_scale)) +
                w_share * min(1.0, source_share / max(1e-6, source_share_scale))
            )

            if source_score > best_source_score:
                best_source_score = source_score
                best_source = src
                best_spike = spike_ratio
                best_timing_irregularity = timing_irregularity

        # Buffer instability signal.
        if len(self.buffer_history) >= buf_min_history:
            q = np.array([x["queue"] for x in self.buffer_history], dtype=np.float64)
            u = np.array([x["util"] for x in self.buffer_history], dtype=np.float64)
            buffer_instability = min(1.0, buf_cq * float(np.std(q)) + buf_cu * float(np.std(u)) + buf_mu * float(np.mean(u)))
        else:
            buffer_instability = 0.0

        # Blend micro-patterns with model hint (ldos probability) but keep
        # independent from hard detection threshold.
        ldos_hint = 0.0
        if threat and threat.raw_probabilities:
            ldos_hint = float(threat.raw_probabilities.get("ldos", 0.0))

        raw_score = w_source * best_source_score + w_buffer * buffer_instability + w_hint * ldos_hint
        self.pre_attack_score = smoothing_keep * self.pre_attack_score + smoothing_update * raw_score

        predicted = (
            not threat.threat_detected and
            self.pre_attack_score >= prediction_threshold and
            bool(best_source)
        )

        if predicted:
            eta_sec = int(round(eta_max - eta_slope * min(1.0, self.pre_attack_score)))
            eta_sec = max(eta_min, min(eta_max, eta_sec))
        else:
            eta_sec = 0

        payload = {
            "predicted": predicted,
            "confidence": round(self.pre_attack_score, 3),
            "horizon_sec": eta_sec,
            "source_ip": best_source,
            "signals": {
                "source_spike_ratio": round(best_spike, 3),
                "timing_irregularity": round(best_timing_irregularity, 3),
                "buffer_instability": round(buffer_instability, 3),
                "ldos_hint": round(ldos_hint, 3),
            },
        }

        # Avoid spamming alerts; emit at most once every ~3 seconds.
        if predicted and (self.sim_time - self._last_pre_alert_time) >= pre_alert_cooldown:
            self._last_pre_alert_time = self.sim_time
            self._emit_event("pre_alert", {
                "message": f"LDoS likely in next {eta_sec}s",
                **payload,
            })

        return payload

    def _emit_event(self, event_type: str, data):
        """Notify all registered listeners of a system event."""
        for callback in self._event_callbacks:
            try:
                callback(event_type, data)
            except Exception:
                pass

    def get_status(self) -> dict:
        """Get full system status for the dashboard."""
        return {
            "is_running": self.is_running,
            "defense_enabled": self.is_defense_enabled,
            "current_phase": self.current_phase,
            "sim_time": round(self.sim_time, 2),
            "metrics": self.current_metrics,
            "threat": self.current_threat.to_dict() if self.current_threat else None,
            "prediction": self.current_prediction,
            "agent": self.agent.get_status(),
            "mitigations": self.mitigation_engine.get_active_mitigations(),
            "knowledge": self.knowledge_base.get_summary(),
        }

    def manual_action(self, action_name: str, target_ip: str = "",
                      params: dict = None) -> dict:
        """Execute a manual defense action (from dashboard controls)."""
        result = self.mitigation_engine.execute(
            action_name, target_ip, params, self.sim_time
        )
        self.knowledge_base.record_action(result)
        self._emit_event("mitigation", result.to_dict())
        return result.to_dict()
