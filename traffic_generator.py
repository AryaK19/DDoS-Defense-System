"""
Traffic Generators — Normal traffic, LDoS attack pulses, and flash crowds.
Each generator produces Packet objects that feed into the virtual network.
"""

import time
import random
import math
from typing import List

import config
from network import Packet


class NormalTrafficGenerator:
    """
    Generates realistic background TCP traffic at a steady rate
    with some natural variation (jitter).
    """

    def __init__(self, src_ip: str, dst_ip: str,
                 rate_bps: int = None,
                 packet_size_range: tuple = None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.rate_bps = rate_bps or config.NORMAL_TRAFFIC["rate_bps"]
        self.packet_size_range = packet_size_range or tuple(config.NORMAL_TRAFFIC["packet_size_range"])
        self.is_active = True
        self.seq = 0
        self.total_packets = 0
        self.total_bytes = 0

    def generate_tick(self, current_time: float, tick_ms: float = 100) -> List[Packet]:
        """Generate packets for one simulation tick."""
        if not self.is_active:
            return []

        packets = []
        # Calculate how many bytes to send in this tick
        bytes_per_tick = (self.rate_bps / 8) * (tick_ms / 1000)

        # Add some natural jitter (±20%)
        jitter = random.uniform(0.8, 1.2)
        bytes_per_tick *= jitter

        bytes_sent = 0
        while bytes_sent < bytes_per_tick:
            size = random.randint(*self.packet_size_range)
            self.seq += 1
            pkt = Packet(
                src_ip=self.src_ip,
                dst_ip=self.dst_ip,
                protocol="TCP",
                size=size,
                timestamp=current_time + random.uniform(0, tick_ms / 1000),
                payload_type="normal",
                seq_num=self.seq,
            )
            packets.append(pkt)
            bytes_sent += size

        self.total_packets += len(packets)
        self.total_bytes += bytes_sent
        return packets


class LDoSAttackGenerator:
    """
    Generates Low-Rate DDoS (Shrew) attack pulses.
    
    The attack sends short, high-rate bursts timed to coincide with
    the victim's TCP RTO, forcing perpetual timeout backoff.
    
    Pattern: _____|████|___________________________|████|___________
             ^    ^    ^                           ^    ^
             quiet burst quiet (period T ≈ RTO)    burst
    
    Parameters:
        burst_rate_bps: Speed during burst (must exceed bottleneck BW)
        burst_length_ms: Duration of each pulse
        period_ms: Time between pulses (≈ TCP min RTO = 1000ms)
    """

    def __init__(self, src_ip: str, dst_ip: str,
                 burst_rate_bps: int = None,
                 burst_length_ms: float = None,
                 period_ms: float = None,
                 packet_size: int = None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.burst_rate_bps = burst_rate_bps or config.LDOS_ATTACK["burst_rate_bps"]
        self.burst_length_ms = burst_length_ms or config.LDOS_ATTACK["burst_length_ms"]
        self.period_ms = period_ms or config.LDOS_ATTACK["period_ms"]
        self.packet_size = packet_size or config.LDOS_ATTACK["packet_size"]

        self.is_active = False
        self.start_time: float = 0
        self.seq = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.pulses_sent = 0

    def start(self, current_time: float):
        """Begin the attack."""
        self.is_active = True
        self.start_time = current_time

    def stop(self):
        """Stop the attack."""
        self.is_active = False

    def generate_tick(self, current_time: float, tick_ms: float = 100) -> List[Packet]:
        """
        Generate attack packets for one simulation tick.
        Only produces traffic during the burst phase of the attack period.
        """
        if not self.is_active:
            return []

        packets = []
        tick_start_ms = (current_time - self.start_time) * 1000
        tick_end_ms = tick_start_ms + tick_ms

        # Compute how much of this tick overlaps the ON (burst) phase.
        # This prevents missing bursts when tick size (100ms) is larger than
        # burst length (e.g., 30ms) and phase offsets are not aligned.
        overlap_ms = 0.0
        period_start_idx = int(tick_start_ms // self.period_ms)
        period_end_idx = int(tick_end_ms // self.period_ms)

        for period_idx in range(period_start_idx, period_end_idx + 1):
            burst_start = period_idx * self.period_ms
            burst_end = burst_start + self.burst_length_ms
            seg_start = max(tick_start_ms, burst_start)
            seg_end = min(tick_end_ms, burst_end)
            if seg_end > seg_start:
                overlap_ms += (seg_end - seg_start)

        if overlap_ms > 0:
            burst_bytes_this_tick = (self.burst_rate_bps / 8) * (overlap_ms / 1000.0)

            bytes_sent = 0
            while bytes_sent < burst_bytes_this_tick:
                self.seq += 1
                pkt = Packet(
                    src_ip=self.src_ip,
                    dst_ip=self.dst_ip,
                    protocol="UDP",  # Attacks typically use UDP
                    size=self.packet_size,
                    timestamp=current_time + random.uniform(0, tick_ms / 1000),
                    payload_type="attack",
                    seq_num=self.seq,
                )
                packets.append(pkt)
                bytes_sent += self.packet_size

            self.pulses_sent += 1
            self.total_packets += len(packets)
            self.total_bytes += bytes_sent

        # else: QUIET PHASE — no packets (this is why average rate is low)
        return packets

    def get_average_rate_bps(self) -> float:
        """
        Calculate the average attack rate.
        This is intentionally low (10-20% of link BW) — the stealth factor.
        """
        duty_cycle = self.burst_length_ms / self.period_ms
        return self.burst_rate_bps * duty_cycle

    def get_status(self) -> dict:
        return {
            "active": self.is_active,
            "burst_rate_mbps": round(self.burst_rate_bps / 1_000_000, 2),
            "burst_length_ms": self.burst_length_ms,
            "period_ms": self.period_ms,
            "average_rate_mbps": round(self.get_average_rate_bps() / 1_000_000, 3),
            "duty_cycle_pct": round((self.burst_length_ms / self.period_ms) * 100, 1),
            "pulses_sent": self.pulses_sent,
            "total_packets": self.total_packets,
        }


class FlashCrowdGenerator:
    """
    Generates benign flash-crowd traffic — sudden spikes of legitimate
    users all accessing the server at once. Used to test false-positive
    rates in the detection engine.
    """

    def __init__(self, src_ips: List[str], dst_ip: str,
                 peak_rate_bps: int = 8_000_000,
                 duration_sec: float = 10.0,
                 ramp_up_sec: float = 2.0):
        self.src_ips = src_ips
        self.dst_ip = dst_ip
        self.peak_rate_bps = peak_rate_bps
        self.duration_sec = duration_sec
        self.ramp_up_sec = ramp_up_sec

        self.is_active = False
        self.start_time: float = 0
        self.total_packets = 0

    def start(self, current_time: float):
        self.is_active = True
        self.start_time = current_time

    def generate_tick(self, current_time: float, tick_ms: float = 100) -> List[Packet]:
        """Generate flash-crowd traffic with a ramp-up/ramp-down pattern."""
        if not self.is_active:
            return []

        elapsed = current_time - self.start_time
        if elapsed > self.duration_sec:
            self.is_active = False
            return []

        # Bell curve traffic pattern (gradual ramp up, peak, ramp down)
        mid = self.duration_sec / 2
        sigma = self.duration_sec / 4
        intensity = math.exp(-0.5 * ((elapsed - mid) / sigma) ** 2)

        current_rate = self.peak_rate_bps * intensity
        bytes_per_tick = (current_rate / 8) * (tick_ms / 1000)

        packets = []
        bytes_sent = 0
        while bytes_sent < bytes_per_tick:
            src = random.choice(self.src_ips)
            size = random.randint(64, 1460)
            pkt = Packet(
                src_ip=src,
                dst_ip=self.dst_ip,
                protocol="TCP",
                size=size,
                timestamp=current_time,
                payload_type="flash_crowd",
            )
            packets.append(pkt)
            bytes_sent += size

        self.total_packets += len(packets)
        return packets
