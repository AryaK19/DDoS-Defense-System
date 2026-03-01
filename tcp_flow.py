"""
TCP Flow Simulator — Models TCP congestion control and RTO behavior.
This is the core of what LDoS attacks exploit: when packets are dropped
during a burst, the TCP sender enters RTO back-off and reduces throughput.
"""

import time
import random
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List

import config
from network import Packet


class TCPState(Enum):
    SLOW_START = "slow_start"
    CONGESTION_AVOIDANCE = "congestion_avoidance"
    FAST_RECOVERY = "fast_recovery"
    RTO_BACKOFF = "rto_backoff"
    IDLE = "idle"


@dataclass
class FlowMetrics:
    """Tracks per-flow performance over time for dashboard display."""
    throughput_history: List[float] = field(default_factory=list)
    latency_history: List[float] = field(default_factory=list)
    loss_history: List[float] = field(default_factory=list)
    state_history: List[str] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)

    def record(self, timestamp: float, throughput: float,
               latency: float, loss: float, state: str):
        self.timestamps.append(timestamp)
        self.throughput_history.append(throughput)
        self.latency_history.append(latency)
        self.loss_history.append(loss)
        self.state_history.append(state)

        # Keep last 600 entries (10 minutes at 1/sec)
        max_entries = 600
        if len(self.timestamps) > max_entries:
            self.timestamps = self.timestamps[-max_entries:]
            self.throughput_history = self.throughput_history[-max_entries:]
            self.latency_history = self.latency_history[-max_entries:]
            self.loss_history = self.loss_history[-max_entries:]
            self.state_history = self.state_history[-max_entries:]


class TCPFlow:
    """
    Simulates a single TCP flow with congestion control.
    
    Key behaviors:
    - Slow start: cwnd doubles every RTT until ssthresh
    - Congestion avoidance: cwnd grows linearly
    - RTO timeout: cwnd = 1, ssthresh = cwnd/2, wait RTO before retransmit
    - Fast recovery: on triple dup-ack, halve cwnd
    
    The LDoS attack forces flows into perpetual RTO_BACKOFF by causing
    packet drops right when the sender tries to retransmit.
    """

    def __init__(self, flow_id: str, src_ip: str, dst_ip: str):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        # TCP state machine
        self.state = TCPState.SLOW_START
        self.cwnd: float = config.TCP["initial_cwnd"]          # Congestion window (segments)
        self.ssthresh: float = config.TCP["initial_ssthresh"]  # Slow-start threshold
        self.mss: int = config.TCP["mss"]                      # Max segment size

        # RTO management
        self.srtt: float = config.LINK_LATENCY_MS * 2  # Smoothed RTT (ms)
        self.rttvar: float = self.srtt / 2              # RTT variance
        self.rto: float = config.TCP["min_rto_ms"]      # Current RTO (ms)
        self.rto_count: int = 0                         # Consecutive RTO timeouts
        self.last_rto_time: float = 0                   # When last RTO started

        # Sequence tracking
        self.seq_num: int = 0
        self.next_send_time: float = 0

        # Current metrics
        self.current_throughput: float = 0.0    # bps
        self.current_latency: float = 0.0       # ms
        self.current_loss_rate: float = 0.0

        # Counters
        self.packets_sent: int = 0
        self.packets_acked: int = 0
        self.packets_lost: int = 0
        self.dup_ack_count: int = 0

        # History
        self.metrics = FlowMetrics()
        self.is_active: bool = True

    def generate_packets(self, current_time: float) -> List[Packet]:
        """
        Generate packets according to the current TCP state.
        Returns a list of packets to send in this tick.
        """
        if not self.is_active:
            return []

        packets = []

        if self.state == TCPState.RTO_BACKOFF:
            # In RTO backoff — check if we can retransmit
            time_since_rto = (current_time - self.last_rto_time) * 1000  # ms
            if time_since_rto < self.rto:
                # Still waiting — NO packets sent (throughput = 0)
                return []
            else:
                # RTO expired, try to retransmit 1 segment
                self.state = TCPState.SLOW_START
                self.cwnd = 1
                pkt = self._make_packet(current_time)
                packets.append(pkt)
                return packets

        # Normal sending: generate cwnd packets per RTT
        # In a tick, we send proportional to cwnd
        rtt_seconds = (self.srtt / 1000) if self.srtt > 0 else 0.04
        packets_per_tick = max(1, int(self.cwnd / (rtt_seconds * 10)))  # 10 ticks per second

        for _ in range(packets_per_tick):
            pkt = self._make_packet(current_time)
            packets.append(pkt)

        return packets

    def on_ack(self, current_time: float):
        """Handle a successful ACK — grow the congestion window."""
        self.packets_acked += 1
        self.dup_ack_count = 0
        self.rto_count = 0

        if self.state == TCPState.SLOW_START:
            self.cwnd += 1  # Exponential growth
            if self.cwnd >= self.ssthresh:
                self.state = TCPState.CONGESTION_AVOIDANCE
        elif self.state == TCPState.CONGESTION_AVOIDANCE:
            self.cwnd += 1.0 / self.cwnd  # Linear growth
        elif self.state == TCPState.FAST_RECOVERY:
            self.cwnd = self.ssthresh
            self.state = TCPState.CONGESTION_AVOIDANCE

        # Update RTT estimate
        sample_rtt = (current_time - self.last_rto_time) * 1000 if self.last_rto_time > 0 else self.srtt
        self._update_rtt(sample_rtt)

    def on_loss(self, current_time: float):
        """
        Handle a packet loss event — this is what LDoS attacks trigger.
        The flow enters RTO backoff, killing throughput.
        """
        self.packets_lost += 1
        self.dup_ack_count += 1

        if self.dup_ack_count >= 3 and self.state != TCPState.RTO_BACKOFF:
            # Triple duplicate ACK → fast recovery
            self.ssthresh = max(2, self.cwnd / 2)
            self.cwnd = self.ssthresh + 3
            self.state = TCPState.FAST_RECOVERY
        else:
            # Timeout — enter RTO backoff (LDoS kills the flow here)
            self.ssthresh = max(2, self.cwnd / 2)
            self.cwnd = 1
            self.state = TCPState.RTO_BACKOFF
            self.rto_count += 1
            self.last_rto_time = current_time

            # Exponential backoff on RTO
            self.rto = min(
                config.TCP["max_rto_ms"],
                self.rto * (2 ** min(self.rto_count, 6))
            )
            self.rto = max(config.TCP["min_rto_ms"], self.rto)

    def update_metrics(self, current_time: float, delivered_bytes: int,
                       total_bytes: int, avg_latency: float):
        """Update the flow's current performance metrics."""
        self.current_throughput = delivered_bytes * 8  # bits/sec (per tick)
        self.current_latency = avg_latency
        self.current_loss_rate = (
            (total_bytes - delivered_bytes) / max(1, total_bytes)
        )

        # Update node health estimate
        if self.current_throughput > 0:
            baseline = config.NORMAL_TRAFFIC["rate_bps"]
            health = min(1.0, self.current_throughput / baseline)
        else:
            health = 0.0

        self.metrics.record(
            current_time,
            self.current_throughput,
            self.current_latency,
            self.current_loss_rate,
            self.state.value
        )

        return health

    def _make_packet(self, current_time: float) -> Packet:
        """Create a TCP data packet."""
        self.seq_num += 1
        self.packets_sent += 1
        return Packet(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            protocol="TCP",
            size=self.mss,
            timestamp=current_time,
            payload_type="normal",
            seq_num=self.seq_num,
        )

    def _update_rtt(self, sample_rtt: float):
        """Update SRTT and RTO per RFC 6298."""
        alpha = config.TCP["rto_alpha"]
        beta = config.TCP["rto_beta"]

        self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - sample_rtt)
        self.srtt = (1 - alpha) * self.srtt + alpha * sample_rtt
        self.rto = max(
            config.TCP["min_rto_ms"],
            self.srtt + 4 * self.rttvar
        )

    def get_state_summary(self) -> dict:
        """Get current state for dashboard display."""
        return {
            "flow_id": self.flow_id,
            "src": self.src_ip,
            "dst": self.dst_ip,
            "state": self.state.value,
            "cwnd": round(self.cwnd, 2),
            "ssthresh": round(self.ssthresh, 2),
            "rto_ms": round(self.rto, 1),
            "throughput_bps": round(self.current_throughput, 1),
            "latency_ms": round(self.current_latency, 2),
            "loss_rate": round(self.current_loss_rate, 4),
            "packets_sent": self.packets_sent,
            "packets_acked": self.packets_acked,
            "packets_lost": self.packets_lost,
            "active": self.is_active,
        }
