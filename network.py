"""
Virtual Network Layer — Nodes, Links, Packets, and Topology.
Simulates an SDN-like network environment without requiring Linux or Mininet.
"""

import time
import uuid
import random
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

import config


# ─── Data Structures ──────────────────────────────────────────────

@dataclass
class Packet:
    """Represents a network packet flowing through the virtual topology."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "TCP"          # TCP, UDP, ICMP
    size: int = 1460               # bytes
    timestamp: float = 0.0         # creation time (sim clock)
    payload_type: str = "normal"   # normal, attack, flash_crowd
    seq_num: int = 0
    is_ack: bool = False
    ttl: int = 64

    def __repr__(self):
        return (f"Pkt({self.id} {self.src_ip}→{self.dst_ip} "
                f"{self.protocol} {self.size}B {self.payload_type})")


@dataclass
class Node:
    """Represents a network host (server, client, or attacker)."""
    id: str
    ip: str
    mac: str
    node_type: str                  # server, client, attacker
    health: float = 1.0             # 0.0 (dead) to 1.0 (healthy)
    is_isolated: bool = False
    throughput_bps: float = 0.0     # current measured throughput
    latency_ms: float = 0.0        # current measured latency
    packet_loss_rate: float = 0.0   # current loss rate
    packets_sent: int = 0
    packets_received: int = 0
    packets_dropped: int = 0
    is_rate_limited: bool = False
    rate_limit_bps: float = 0       # 0 = unlimited
    _bytes_this_tick: int = 0       # for enforcing rate-limit per tick

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "type": self.node_type,
            "health": round(self.health, 3),
            "isolated": self.is_isolated,
            "throughput_bps": round(self.throughput_bps, 1),
            "latency_ms": round(self.latency_ms, 2),
            "packet_loss": round(self.packet_loss_rate, 4),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "packets_dropped": self.packets_dropped,
            "rate_limited": self.is_rate_limited,
        }


class Link:
    """
    Represents a network link between two nodes.
    Has a finite bandwidth, latency, and a packet queue (buffer).
    When the buffer overflows, packets are dropped — this is what
    LDoS attacks exploit.
    """

    def __init__(self, node_a_id: str, node_b_id: str,
                 bandwidth_bps: int = config.LINK_BANDWIDTH_BPS,
                 latency_ms: float = config.LINK_LATENCY_MS,
                 buffer_size: int = config.LINK_BUFFER_SIZE,
                 base_loss_rate: float = config.LINK_BASE_LOSS_RATE):
        self.node_a_id = node_a_id
        self.node_b_id = node_b_id
        self.bandwidth_bps = bandwidth_bps
        self.latency_ms = latency_ms
        self.buffer_size = buffer_size
        self.base_loss_rate = base_loss_rate

        # Queue + metrics
        self.queue: deque = deque(maxlen=buffer_size)
        self.bytes_in_transit: int = 0
        self.packets_forwarded: int = 0
        self.packets_dropped: int = 0
        self.utilization: float = 0.0     # 0.0 to 1.0
        self._lock = threading.Lock()

        # Bandwidth tracking — uses tick-based counters
        self._bytes_this_tick: int = 0
        self._tick_budget: int = 0  # set each tick from outside
        self._total_bytes_sec: int = 0
        self._last_bw_reset: float = time.time()

    def reset_tick(self, tick_ms: float = 100):
        """Reset per-tick bandwidth counter. Called at the start of each tick."""
        with self._lock:
            self._total_bytes_sec = max(self._total_bytes_sec, self._bytes_this_tick)
            self._bytes_this_tick = 0
            # Budget for this tick = bandwidth * tick_duration
            self._tick_budget = int((self.bandwidth_bps / 8) * (tick_ms / 1000))

    def enqueue(self, packet: Packet) -> bool:
        """
        Try to add a packet to the link's buffer.
        Returns True if accepted, False if dropped (buffer full or random loss).
        
        Admission is controlled ONLY by buffer capacity (like a real
        router FIFO queue).  The link-rate limit is enforced at the
        *output* side by the drain step in the simulation loop, so the
        buffer can genuinely overflow when input > capacity — which
        is exactly the mechanism LDoS attacks exploit.
        """
        with self._lock:
            # Random base loss
            if random.random() < self.base_loss_rate:
                self.packets_dropped += 1
                return False

            # Buffer overflow — this is the LDoS kill mechanism
            if len(self.queue) >= self.buffer_size:
                self.packets_dropped += 1
                return False

            # Track bytes for utilization display (informational only)
            self._bytes_this_tick += packet.size

            self.queue.append(packet)
            self.bytes_in_transit += packet.size
            self.packets_forwarded += 1
            return True

    def dequeue(self) -> Optional[Packet]:
        """Remove and return the next packet from the buffer."""
        with self._lock:
            if self.queue:
                pkt = self.queue.popleft()
                self.bytes_in_transit -= pkt.size
                return pkt
            return None

    def get_utilization(self) -> float:
        """Current link utilization as a fraction [0, 1]."""
        with self._lock:
            if self._tick_budget > 0:
                self.utilization = min(1.0, self._bytes_this_tick / self._tick_budget)
            else:
                self.utilization = 0.0
            return self.utilization

    def get_queue_occupancy(self) -> float:
        """Current queue fill as a fraction [0, 1]."""
        return len(self.queue) / self.buffer_size if self.buffer_size > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "from": self.node_a_id,
            "to": self.node_b_id,
            "bandwidth_bps": self.bandwidth_bps,
            "latency_ms": self.latency_ms,
            "utilization": round(self.get_utilization(), 3),
            "queue_occupancy": round(self.get_queue_occupancy(), 3),
            "packets_forwarded": self.packets_forwarded,
            "packets_dropped": self.packets_dropped,
        }


class NetworkTopology:
    """
    Manages the virtual network graph: nodes, links, and packet routing.
    Represents a simple star topology with a central switch/bottleneck.
    """

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.links: Dict[str, Link] = {}     # key = "nodeA-nodeB"
        self.packet_log: deque = deque(maxlen=10000)
        self._listeners: List[Callable] = []
        self._lock = threading.Lock()

        # Metrics tracking
        self.total_packets_sent = 0
        self.total_packets_dropped = 0
        self.total_packets_delivered = 0

    def add_node(self, node_id: str, ip: str, mac: str, node_type: str) -> Node:
        """Add a node to the topology."""
        node = Node(id=node_id, ip=ip, mac=mac, node_type=node_type)
        self.nodes[node_id] = node
        return node

    def add_link(self, node_a_id: str, node_b_id: str,
                 bandwidth_bps: int = config.LINK_BANDWIDTH_BPS,
                 latency_ms: float = config.LINK_LATENCY_MS) -> Link:
        """Add a bidirectional link between two nodes."""
        link_id = f"{node_a_id}-{node_b_id}"
        link = Link(node_a_id, node_b_id, bandwidth_bps, latency_ms)
        self.links[link_id] = link
        return link

    def find_link(self, src_id: str, dst_id: str) -> Optional[Link]:
        """Find the link connecting two nodes (checks both directions)."""
        fwd = f"{src_id}-{dst_id}"
        rev = f"{dst_id}-{src_id}"
        return self.links.get(fwd) or self.links.get(rev)

    def send_packet(self, packet: Packet) -> bool:
        """
        Send a packet through the network.
        Routes through the appropriate link and tracks metrics.
        Returns True if delivered, False if dropped.
        """
        with self._lock:
            self.total_packets_sent += 1

            # Find source and destination nodes
            src_node = self._find_node_by_ip(packet.src_ip)
            dst_node = self._find_node_by_ip(packet.dst_ip)

            if not src_node or not dst_node:
                self.total_packets_dropped += 1
                return False

            # Check if source is isolated
            if src_node.is_isolated:
                self.total_packets_dropped += 1
                src_node.packets_dropped += 1
                return False

            # Check if destination is isolated
            if dst_node.is_isolated:
                self.total_packets_dropped += 1
                dst_node.packets_dropped += 1
                return False

            # Check rate limiting on source
            if src_node.is_rate_limited and src_node.rate_limit_bps > 0:
                # Per-tick budget = rate_limit_bps / 8 * tick_sec
                # Use 100ms default tick
                tick_budget = (src_node.rate_limit_bps / 8) * 0.1
                if src_node._bytes_this_tick + packet.size > tick_budget:
                    self.total_packets_dropped += 1
                    src_node.packets_dropped += 1
                    return False
                src_node._bytes_this_tick += packet.size

            # Find the link (route through bottleneck)
            # In star topology: client → switch → server
            link = self._find_route(src_node.id, dst_node.id)
            if not link:
                self.total_packets_dropped += 1
                return False

            # Try to enqueue on the link
            if link.enqueue(packet):
                src_node.packets_sent += 1
                dst_node.packets_received += 1
                self.total_packets_delivered += 1

                # Log the packet
                self.packet_log.append({
                    "time": packet.timestamp,
                    "src": packet.src_ip,
                    "dst": packet.dst_ip,
                    "size": packet.size,
                    "type": packet.payload_type,
                    "protocol": packet.protocol,
                })

                # Notify listeners
                for listener in self._listeners:
                    listener(packet, "delivered")

                return True
            else:
                self.total_packets_dropped += 1
                src_node.packets_dropped += 1

                for listener in self._listeners:
                    listener(packet, "dropped")

                return False

    def _find_node_by_ip(self, ip: str) -> Optional[Node]:
        """Find a node by its IP address."""
        for node in self.nodes.values():
            if node.ip == ip:
                return node
        return None

    def _find_route(self, src_id: str, dst_id: str) -> Optional[Link]:
        """
        Simple routing: find any link connecting src to dst.
        In our star topology, all traffic goes through the bottleneck link.
        """
        # Direct link
        link = self.find_link(src_id, dst_id)
        if link:
            return link

        # Route through switch (bottleneck)
        for mid_id in self.nodes:
            if mid_id == src_id or mid_id == dst_id:
                continue
            link_a = self.find_link(src_id, mid_id)
            link_b = self.find_link(mid_id, dst_id)
            if link_a and link_b:
                # Use the bottleneck link (link_b toward server is the bottleneck)
                return link_b

        return None

    def add_listener(self, callback: Callable):
        """Register a callback for packet events: callback(packet, event_type)."""
        self._listeners.append(callback)

    def get_node_metrics(self, node_id: str) -> Optional[dict]:
        """Get current metrics for a specific node."""
        node = self.nodes.get(node_id)
        return node.to_dict() if node else None

    def get_topology_snapshot(self) -> dict:
        """Get a complete snapshot of the network state for the dashboard."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "links": [l.to_dict() for l in self.links.values()],
            "totals": {
                "packets_sent": self.total_packets_sent,
                "packets_dropped": self.total_packets_dropped,
                "packets_delivered": self.total_packets_delivered,
                "drop_rate": (self.total_packets_dropped / max(1, self.total_packets_sent)),
            }
        }

    def reset_metrics(self):
        """Reset all node and link metrics (for new scenario runs)."""
        for node in self.nodes.values():
            node.packets_sent = 0
            node.packets_received = 0
            node.packets_dropped = 0
            node.throughput_bps = 0
            node.latency_ms = 0
            node.packet_loss_rate = 0
            node.health = 1.0
            node.is_isolated = False
            node.is_rate_limited = False
            node._bytes_this_tick = 0
        for link in self.links.values():
            link.queue.clear()
            link.bytes_in_transit = 0
            link.packets_forwarded = 0
            link.packets_dropped = 0
            link._bytes_this_tick = 0
        self.total_packets_sent = 0
        self.total_packets_dropped = 0
        self.total_packets_delivered = 0


def create_default_topology() -> NetworkTopology:
    """
    Create the default simulation topology:
    
        client1 ─┐
                  ├── switch ── server
        client2 ─┤
                  │
        attacker ─┘
    
    The switch-server link is the bottleneck.
    """
    topo = NetworkTopology()

    # Add nodes from config
    for node_id, node_cfg in config.NETWORK.items():
        topo.add_node(node_id, node_cfg["ip"], node_cfg["mac"], node_cfg["type"])

    # Add the switch (central node)
    topo.add_node("switch", "10.0.0.254", "00:00:00:00:00:FE", "switch")

    # Connect everyone to the switch
    # Client/attacker → switch links (high bandwidth, these are NOT the bottleneck)
    for node_id in config.NETWORK:
        topo.add_link(node_id, "switch",
                      bandwidth_bps=100_000_000,  # 100 Mbit/s
                      latency_ms=config.LINK_LATENCY_MS / 2)

    # Switch → server link (THIS is the bottleneck)
    topo.add_link("switch", "server",
                  bandwidth_bps=config.LINK_BANDWIDTH_BPS,  # 10 Mbit/s
                  latency_ms=config.LINK_LATENCY_MS / 2)

    return topo
