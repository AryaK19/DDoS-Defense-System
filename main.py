"""
Main Entry Point — Launches the full AI-Based Self-Healing LDoS Defense Simulation.

Usage:
    python main.py                    # Default settings
    python main.py --port 5000        # Custom port
    python main.py --no-ai            # Start without AI defense
    python main.py --fast             # 2x simulation speed
"""

import os
import sys
import time
import argparse
import threading
from collections import deque

# Ensure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from network import NetworkTopology, Packet, create_default_topology
from tcp_flow import TCPFlow
from traffic_generator import NormalTrafficGenerator, LDoSAttackGenerator
from self_healing import SelfHealingOrchestrator


class SimulationEngine:
    """
    Master simulation engine that coordinates:
    - Virtual network topology
    - Traffic generators (normal + attack)
    - TCP flow simulation
    - Self-healing orchestrator (MAPE-K loop)
    - Dashboard data serving
    """

    def __init__(self, enable_defense: bool = True, speed: float = 1.0):
        # Create network
        self.topology = create_default_topology()

        # Traffic generators
        self.normal_generators = []
        self.attack_generator = None
        self.setup_traffic_generators()

        # TCP flows
        self.tcp_flows = {}
        self.setup_tcp_flows()

        # Self-healing orchestrator
        self.orchestrator = SelfHealingOrchestrator(self.topology)
        self.orchestrator.is_defense_enabled = enable_defense

        # Simulation state
        self.is_running = False
        self.sim_time = 0.0
        self.speed = speed
        self._thread = None
        self._stop_event = threading.Event()

        # Metrics collection
        self.metrics_history = deque(maxlen=600)

        # Per-tick packet tracking (live — used by simulation thread)
        self._tick_packets = []
        self._tick_delivered = 0       # NORMAL traffic only
        self._tick_total = 0           # NORMAL traffic only
        self._tick_bytes_delivered = 0 # NORMAL traffic only
        self._tick_attack_total = 0    # Attack traffic (separate)
        self._tick_attack_delivered = 0

        # SNAPSHOT: last completed tick's values (read by HTTP handlers)
        # This avoids the race condition where HTTP reads mid-reset zeros
        self._snapshot_throughput = 0.0
        self._snapshot_throughput_instant = 0.0
        self._snapshot_latency = 20.0
        self._snapshot_loss = 0.0
        self._snapshot_loss_instant = 0.0
        self._snapshot_time = 0.0

        # Rolling window for dashboard display (smooths over burst spikes)
        # 10 ticks = 1 second – matches the dashboard poll interval
        self._recent_losses = deque(maxlen=10)
        self._recent_throughputs = deque(maxlen=10)

    def setup_traffic_generators(self):
        """Create traffic generators for all clients."""
        server_ip = config.NETWORK["server"]["ip"]

        for node_id, node_cfg in config.NETWORK.items():
            if node_cfg["type"] == "client":
                gen = NormalTrafficGenerator(
                    src_ip=node_cfg["ip"],
                    dst_ip=server_ip,
                )
                self.normal_generators.append(gen)

        # Attack generator (inactive until triggered)
        self.attack_generator = LDoSAttackGenerator(
            src_ip=config.NETWORK["attacker"]["ip"],
            dst_ip=server_ip,
        )

    def setup_tcp_flows(self):
        """Create TCP flows for each client."""
        server_ip = config.NETWORK["server"]["ip"]
        for node_id, node_cfg in config.NETWORK.items():
            if node_cfg["type"] == "client":
                flow = TCPFlow(
                    flow_id=f"flow_{node_id}",
                    src_ip=node_cfg["ip"],
                    dst_ip=server_ip,
                )
                self.tcp_flows[node_id] = flow

    def initialize(self):
        """Initialize all subsystems."""
        print("\n" + "=" * 60)
        print("  ╔═══════════════════════════════════════════════╗")
        print("  ║  AI-Based Self-Healing LDoS Defense System    ║")
        print("  ║  Interactive Simulation Environment           ║")
        print("  ╚═══════════════════════════════════════════════╝")
        print("=" * 60)

        self.orchestrator.initialize(
            train_detector=True,
            pre_train_agent=True,
        )

    def start(self):
        """Start the simulation loop."""
        if self.is_running:
            return

        self.is_running = True
        self._stop_event.clear()

        # Start self-healing orchestrator
        self.orchestrator.start()

        # Start simulation tick loop
        self._thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self._thread.start()

        print("\n[SIM] Simulation started! Generating normal traffic...")

    def stop(self):
        """Stop the simulation."""
        self.is_running = False
        self._stop_event.set()
        self.orchestrator.stop()
        if self._thread:
            self._thread.join(timeout=5)
        print("[SIM] Simulation stopped.")

    def _simulation_loop(self):
        """Main simulation tick loop."""
        tick_ms = config.SIMULATION["tick_interval_ms"]
        tick_sec = tick_ms / 1000

        while not self._stop_event.is_set():
            self.sim_time += tick_sec * self.speed

            # 0. Reset link bandwidth counters for this tick
            for link in self.topology.links.values():
                link.reset_tick(tick_ms)

            # 0.5 Reset per-tick byte counters on all nodes (for rate-limit enforcement)
            for node in self.topology.nodes.values():
                node._bytes_this_tick = 0

            # Track packets generated this tick
            tick_packets = []
            self._tick_delivered = 0
            self._tick_total = 0
            self._tick_bytes_delivered = 0
            self._tick_attack_total = 0
            self._tick_attack_delivered = 0

            # ── Collect ALL packets for this tick FIRST ──────────
            all_packets = []  # list of (kind, Packet)

            for gen in self.normal_generators:
                for pkt in gen.generate_tick(self.sim_time, tick_ms):
                    all_packets.append(('normal', pkt))

            if self.attack_generator.is_active:
                for pkt in self.attack_generator.generate_tick(self.sim_time, tick_ms):
                    all_packets.append(('attack', pkt))

            # ── Sort by timestamp so normal & attack INTERLEAVE ──
            # This is critical: without interleaving, normal packets
            # always go first and never experience buffer congestion
            # caused by the attack.
            all_packets.sort(key=lambda x: x[1].timestamp)

            # ── Send through the network in mixed order ──────────
            for kind, pkt in all_packets:
                delivered = self.topology.send_packet(pkt)

                if kind == 'normal':
                    self._tick_total += 1
                    if delivered:
                        self._tick_delivered += 1
                        self._tick_bytes_delivered += pkt.size
                    self._process_packet_result(pkt, delivered)
                else:
                    self._tick_attack_total += 1
                    if delivered:
                        self._tick_attack_delivered += 1

                tick_packets.append({
                    "time": pkt.timestamp,
                    "src": pkt.src_ip,
                    "dst": pkt.dst_ip,
                    "size": pkt.size,
                    "type": pkt.payload_type,
                    "protocol": pkt.protocol,
                })

            # 2.5 DRAIN link buffers — consume queued packets per-tick
            #     Without this, queues fill up and never empty → 100% drop
            for link_id, link in self.topology.links.items():
                drained = 0
                max_drain_bytes = link._tick_budget  # bytes we can move this tick
                drained_bytes = 0
                while drained_bytes < max_drain_bytes:
                    pkt = link.dequeue()
                    if pkt is None:
                        break
                    drained_bytes += pkt.size
                    drained += 1
                # Debug: log bottleneck link state during attack
                if link_id == "switch-server" and self.attack_generator.is_active:
                    remaining = len(link.queue)
                    if int(self.sim_time * 10) % 20 == 0:
                        print(f"  [DRAIN BN] drained={drained} ({drained_bytes}B) | "
                              f"remaining_queue={remaining} | budget={max_drain_bytes}B | "
                              f"bytes_enqueued_this_tick={link._bytes_this_tick}B")

            # 3. Update TCP flow states
            self._update_tcp_flows()

            # 4. Update node metrics
            self._update_node_metrics()

            # 5. Feed ONLY this tick's packets to orchestrator
            #    (prevents accumulation of stale data → fewer false positives)
            self._tick_packets = tick_packets
            for pkt_record in tick_packets:
                self.orchestrator.ingest_packet(pkt_record)

            # 6. Compute per-tick metrics
            tick_throughput = self._get_aggregate_throughput()
            tick_latency = self._get_aggregate_latency()
            tick_loss = self._get_packet_loss_rate()

            metrics = {
                "time": self.sim_time,
                "throughput_bps": tick_throughput,
                "latency_ms": tick_latency,
                "packet_loss": tick_loss,
                "attack_active": self.attack_generator.is_active,
            }
            self.metrics_history.append(metrics)

            # 6.5 Push per-tick values into orchestrator so WebSocket
            #     events also show live data (not cumulative averages)
            if self.orchestrator.current_metrics:
                self.orchestrator.current_metrics["throughput_bps"] = tick_throughput
                self.orchestrator.current_metrics["latency_ms"] = tick_latency
                self.orchestrator.current_metrics["packet_loss"] = tick_loss

            # 7. SNAPSHOT — use rolling 1-second average so the
            #    dashboard (polling at 1 Hz) reliably shows attack impact
            #    even when LDoS bursts only last one tick per period.
            self._recent_losses.append(tick_loss)
            self._recent_throughputs.append(tick_throughput)
            self._snapshot_throughput_instant = tick_throughput
            self._snapshot_throughput = sum(self._recent_throughputs) / len(self._recent_throughputs)
            self._snapshot_latency = tick_latency
            self._snapshot_loss_instant = tick_loss
            self._snapshot_loss = sum(self._recent_losses) / len(self._recent_losses)
            self._snapshot_time = self.sim_time

            # 8. DEBUG LOG every ~2 seconds
            if int(self.sim_time * 10) % 20 == 0:
                atk_flag = "ATK" if self.attack_generator.is_active else "---"
                bn_link = self.topology.links.get("switch-server")
                q_occ = f"{bn_link.get_queue_occupancy()*100:.0f}%" if bn_link else "?"
                print(f"[SIM t={self.sim_time:.1f}] {atk_flag} | "
                      f"normal={self._tick_total} del={self._tick_delivered} | "
                      f"attack={self._tick_attack_total} del={self._tick_attack_delivered} | "
                      f"loss={tick_loss*100:.1f}% tp={tick_throughput/1e6:.2f}Mbps | "
                      f"BN_queue={q_occ}")

            # Sleep for tick
            self._stop_event.wait(tick_sec / self.speed)

    def _process_packet_result(self, packet: Packet, delivered: bool):
        """Process the result of sending a packet through the network."""
        # Find the corresponding TCP flow
        for flow_id, flow in self.tcp_flows.items():
            if flow.src_ip == packet.src_ip:
                if delivered:
                    flow.on_ack(self.sim_time)
                else:
                    flow.on_loss(self.sim_time)
                break

    def _update_tcp_flows(self):
        """
        Update node metrics using direct per-tick delivery data.
        This bypasses TCP flow state (which can get stuck in RTO backoff)
        and uses actual packet delivery counts for a more accurate picture.
        """
        tick_sec = config.SIMULATION["tick_interval_ms"] / 1000

        # Per-tick throughput from delivered bytes
        per_tick_throughput = (self._tick_bytes_delivered * 8) / tick_sec if tick_sec > 0 else 0
        per_tick_loss = 0.0
        if self._tick_total > 0:
            per_tick_loss = (self._tick_total - self._tick_delivered) / self._tick_total

        # Distribute throughput across client nodes
        n_clients = len(self.tcp_flows)
        per_client_tp = per_tick_throughput / max(1, n_clients)

        for flow_id, flow in self.tcp_flows.items():
            node = None
            for n in self.topology.nodes.values():
                if n.ip == flow.src_ip:
                    node = n
                    break

            if node:
                node.throughput_bps = per_client_tp

                # Use link propagation delay, not TCP flow srtt (which gets
                # stuck at high values from RTO backoff)
                link = self.topology.find_link(node.id, "switch")
                bn_link = self.topology.links.get("switch-server")
                base_latency = 20.0  # default 2 × 10ms links
                if link:
                    base_latency = link.latency_ms * 2  # round-trip
                if bn_link:
                    # Add queueing delay proportional to queue occupancy
                    base_latency += bn_link.get_queue_occupancy() * 50

                node.latency_ms = base_latency
                node.packet_loss_rate = per_tick_loss

                # Health = throughput as ratio of baseline
                baseline = config.NORMAL_TRAFFIC["rate_bps"]
                node.health = min(1.0, max(0.0, per_client_tp / baseline))

    def _update_node_metrics(self):
        """Update server node health based on per-tick data."""
        server = self.topology.nodes.get("server")
        if server:
            if self._tick_total > 0:
                server.health = min(1.0, self._tick_delivered / self._tick_total)
            else:
                server.health = 1.0

    def _get_aggregate_throughput(self) -> float:
        """Current tick throughput in bps."""
        tick_sec = config.SIMULATION["tick_interval_ms"] / 1000
        return (self._tick_bytes_delivered * 8) / tick_sec if tick_sec > 0 else 0.0

    def _get_aggregate_latency(self) -> float:
        """Average latency based on network link delays (round-trip)."""
        # Sum up link latencies on the client→switch→server path × 2 for RTT
        total_link_latency = 0
        link_count = 0
        for link in self.topology.links.values():
            total_link_latency += link.latency_ms
            link_count += 1
        if link_count == 0:
            return 20.0
        # Average link latency × 2 hops (client→switch, switch→server) × 2 (round-trip)
        # But use a simpler model: just sum relevant path latencies
        path_latency = 0
        for link in self.topology.links.values():
            # Include links that form the client→switch→server path
            if link.node_a_id in ("client1", "client2") or link.node_b_id == "server":
                path_latency = max(path_latency, link.latency_ms * 2)  # RTT

        # Add queueing delay proportional to queue occupancy
        bn_link = self.topology.links.get("switch-server")
        queueing_delay = 0
        if bn_link:
            queueing_delay = bn_link.get_queue_occupancy() * 50  # up to 50ms at full queue

        return max(5.0, path_latency + queueing_delay)

    def _get_packet_loss_rate(self) -> float:
        """Per-tick packet loss rate."""
        if self._tick_total == 0:
            return 0.0
        return (self._tick_total - self._tick_delivered) / self._tick_total

    # ─── Dashboard API Methods ────────────────────────────

    def get_status(self) -> dict:
        """Full system status for dashboard."""
        # Start with orchestrator's metrics (has threat info, phase, etc.)
        orch_metrics = dict(self.orchestrator.current_metrics) if self.orchestrator.current_metrics else {}

        # Use SNAPSHOT values (written atomically at end of each tick)
        # This avoids the race where HTTP reads mid-tick zeros
        orch_metrics["throughput_bps"] = self._snapshot_throughput
        orch_metrics["latency_ms"] = self._snapshot_latency
        orch_metrics["packet_loss"] = self._snapshot_loss
        orch_metrics["sim_time"] = round(self._snapshot_time, 2)

        return {
            "is_running": self.is_running,
            "sim_time": round(self._snapshot_time, 2),
            "attack_active": self.attack_generator.is_active,
            "attack_status": self.attack_generator.get_status(),
            "orchestrator": self.orchestrator.get_status(),
            "flows": {fid: f.get_state_summary() for fid, f in self.tcp_flows.items()},
            "metrics": orch_metrics,
        }

    def get_topology(self) -> dict:
        """Network topology for dashboard visualization."""
        return self.topology.get_topology_snapshot()

    def get_metrics_history(self) -> list:
        """Time-series metrics for dashboard charts."""
        return list(self.metrics_history)

    def start_attack(self, burst_rate=None, burst_length=None, period=None):
        """Start the LDoS attack with optional custom params."""
        if burst_rate:
            self.attack_generator.burst_rate_bps = int(burst_rate)
        if burst_length:
            self.attack_generator.burst_length_ms = float(burst_length)
        if period:
            self.attack_generator.period_ms = float(period)

        self.attack_generator.start(self.sim_time)
        print(f"[SIM] ⚡ LDoS attack started! "
              f"Burst: {self.attack_generator.burst_rate_bps/1e6:.1f} Mbps, "
              f"Length: {self.attack_generator.burst_length_ms}ms, "
              f"Period: {self.attack_generator.period_ms}ms")

    def stop_attack(self):
        """Stop the current attack."""
        self.attack_generator.stop()
        print("[SIM] Attack stopped.")

    def set_defense(self, enabled: bool):
        """Toggle AI defense."""
        self.orchestrator.set_defense_enabled(enabled)
        print(f"[SIM] AI Defense {'ENABLED' if enabled else 'DISABLED'}")

    def manual_action(self, action: str, target_ip: str = "") -> dict:
        """Execute a manual defense action."""
        return self.orchestrator.manual_action(action, target_ip)

    def reset(self):
        """Reset the entire simulation."""
        self.stop()
        self.attack_generator.stop()
        self.topology.reset_metrics()
        self.orchestrator.mitigation_engine.clear_all()
        self.metrics_history.clear()

        # Reset TCP flows
        for flow in self.tcp_flows.values():
            flow.__init__(flow.flow_id, flow.src_ip, flow.dst_ip)

        self.sim_time = 0.0
        self.start()
        print("[SIM] Simulation reset and restarted.")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Based Self-Healing LDoS Defense Simulation"
    )
    parser.add_argument("--port", type=int, default=config.DASHBOARD["port"],
                        help="Dashboard port (default: 5000)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Start with AI defense disabled")
    parser.add_argument("--fast", action="store_true",
                        help="Run at 2x speed")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="Simulation speed multiplier")
    parser.add_argument("--website-port", type=int, default=config.WEBSITE["port"],
                        help=f"Website port (default: {config.WEBSITE['port']})")
    args = parser.parse_args()

    speed = 2.0 if args.fast else args.speed

    # Create simulation engine
    engine = SimulationEngine(
        enable_defense=not args.no_ai,
        speed=speed,
    )

    # Initialize (train models, etc.)
    engine.initialize()

    # Import and configure dashboard
    from dashboard.app import init_dashboard, run_dashboard, app, socketio
    init_dashboard(engine)

    # Import and configure user-facing website
    from website.app import init_website, run_website
    init_website(engine)

    # Start simulation
    engine.start()

    # Start website server in background thread
    website_thread = threading.Thread(
        target=run_website,
        kwargs={"port": args.website_port},
        daemon=True,
    )
    website_thread.start()

    # Run dashboard (blocking)
    print(f"\n[DASHBOARD] Starting on port {args.port}...")
    print(f"[DASHBOARD] Open http://localhost:{args.port} in your browser")
    print(f"[WEBSITE]   Open http://localhost:{args.website_port} for the user view")
    print(f"[TIP]       Use VS Code port-forward to share both with others\n")

    try:
        run_dashboard(port=args.port)
    except KeyboardInterrupt:
        print("\n[SIM] Shutting down...")
        engine.stop()


if __name__ == "__main__":
    main()

