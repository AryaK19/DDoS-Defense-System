"""
Mitigation Engine — Executes defense actions on the virtual network.
Translates RL agent decisions into actual network modifications.
"""

import time
from typing import List, Optional
from dataclasses import dataclass, field

import config
from network import NetworkTopology, Node


@dataclass
class MitigationAction:
    """Record of a mitigation action for logging and dashboard display."""
    timestamp: float
    action_type: str
    target: str
    parameters: dict = field(default_factory=dict)
    success: bool = True
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": round(self.timestamp, 3),
            "action": self.action_type,
            "target": self.target,
            "params": self.parameters,
            "success": self.success,
            "description": self.description,
        }


class MitigationEngine:
    """
    Executes defense actions on the virtual network topology.
    
    Available actions:
    - rate_limit: Throttle traffic from a specific source
    - drop_source: Block all traffic from a source
    - reroute_traffic: Redirect legitimate flows
    - isolate_node: Quarantine a compromised node
    - scale_bandwidth: Increase bottleneck capacity
    - restore_node: Re-integrate a quarantined node
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self.action_log: List[MitigationAction] = []
        self.active_mitigations: dict = {}  # track active defenses

    def execute(self, action_name: str, target_ip: str = "",
                params: dict = None, current_time: float = None) -> MitigationAction:
        """
        Execute a mitigation action on the network.
        Returns a MitigationAction record.
        """
        if current_time is None:
            current_time = time.time()
        if params is None:
            params = {}

        # === SAFETY GUARD ===
        # Never isolate, rate-limit, or block legitimate clients/servers
        destructive_actions = {"rate_limit", "drop_source", "isolate_node"}
        if action_name in destructive_actions and target_ip:
            protected_ips = set()
            for node_cfg in config.NETWORK.values():
                if node_cfg["type"] in ("client", "server"):
                    protected_ips.add(node_cfg["ip"])
            if target_ip in protected_ips:
                return MitigationAction(
                    timestamp=current_time,
                    action_type=action_name,
                    target=target_ip,
                    success=False,
                    description=f"BLOCKED: {target_ip} is a protected node",
                )

        action_map = {
            "no_action": self._no_action,
            "rate_limit": self._rate_limit,
            "drop_source": self._drop_source,
            "reroute_traffic": self._reroute_traffic,
            "isolate_node": self._isolate_node,
            "scale_bandwidth": self._scale_bandwidth,
            "restore_node": self._restore_node,
        }

        handler = action_map.get(action_name, self._no_action)
        result = handler(target_ip, params, current_time)

        self.action_log.append(result)
        if len(self.action_log) > 500:
            self.action_log = self.action_log[-500:]

        return result

    def _no_action(self, target_ip: str, params: dict,
                   current_time: float) -> MitigationAction:
        """Do nothing — monitoring only."""
        return MitigationAction(
            timestamp=current_time,
            action_type="no_action",
            target="",
            description="Monitoring — no action taken",
        )

    def _rate_limit(self, target_ip: str, params: dict,
                    current_time: float) -> MitigationAction:
        """Throttle traffic from a specific source IP."""
        max_rate = params.get("max_rate_bps", 500_000)  # Default 500 Kbps

        node = self._find_node(target_ip)
        if node:
            node.is_rate_limited = True
            node.rate_limit_bps = max_rate
            self.active_mitigations[target_ip] = {
                "type": "rate_limit",
                "rate": max_rate,
                "since": current_time,
            }
            return MitigationAction(
                timestamp=current_time,
                action_type="rate_limit",
                target=target_ip,
                parameters={"max_rate_bps": max_rate},
                success=True,
                description=f"Rate-limited {target_ip} to {max_rate/1000:.0f} Kbps",
            )

        return MitigationAction(
            timestamp=current_time,
            action_type="rate_limit",
            target=target_ip,
            success=False,
            description=f"Node {target_ip} not found",
        )

    def _drop_source(self, target_ip: str, params: dict,
                     current_time: float) -> MitigationAction:
        """Block all traffic from a source by isolating it."""
        node = self._find_node(target_ip)
        if node:
            node.is_isolated = True
            node.health = 0.0
            self.active_mitigations[target_ip] = {
                "type": "blocked",
                "since": current_time,
            }
            return MitigationAction(
                timestamp=current_time,
                action_type="drop_source",
                target=target_ip,
                success=True,
                description=f"Blocked all traffic from {target_ip}",
            )

        return MitigationAction(
            timestamp=current_time,
            action_type="drop_source",
            target=target_ip,
            success=False,
            description=f"Node {target_ip} not found",
        )

    def _reroute_traffic(self, target_ip: str, params: dict,
                         current_time: float) -> MitigationAction:
        """
        Reroute traffic — in our simulation, this increases bandwidth
        on the bottleneck link to simulate adding an alternate path.
        """
        extra_bw = params.get("extra_bandwidth_bps", 5_000_000)  # +5 Mbps

        # Find the bottleneck link and increase its capacity
        for link in self.topology.links.values():
            if "server" in link.node_b_id or "server" in link.node_a_id:
                link.bandwidth_bps += extra_bw
                self.active_mitigations["reroute"] = {
                    "type": "reroute",
                    "extra_bw": extra_bw,
                    "since": current_time,
                }
                return MitigationAction(
                    timestamp=current_time,
                    action_type="reroute_traffic",
                    target="bottleneck",
                    parameters={"extra_bandwidth_bps": extra_bw},
                    success=True,
                    description=f"Added {extra_bw/1_000_000:.1f} Mbps alternate path",
                )

        return MitigationAction(
            timestamp=current_time,
            action_type="reroute_traffic",
            target="bottleneck",
            success=False,
            description="No bottleneck link found to reroute",
        )

    def _isolate_node(self, target_ip: str, params: dict,
                      current_time: float) -> MitigationAction:
        """Quarantine a node completely."""
        node = self._find_node(target_ip)
        if node:
            node.is_isolated = True
            node.health = 0.0
            self.active_mitigations[target_ip] = {
                "type": "isolated",
                "since": current_time,
            }
            return MitigationAction(
                timestamp=current_time,
                action_type="isolate_node",
                target=target_ip,
                success=True,
                description=f"Quarantined node {target_ip}",
            )

        return MitigationAction(
            timestamp=current_time,
            action_type="isolate_node",
            target=target_ip,
            success=False,
            description=f"Node {target_ip} not found",
        )

    def _scale_bandwidth(self, target_ip: str, params: dict,
                         current_time: float) -> MitigationAction:
        """Increase the bottleneck link bandwidth (capped at 100 Mbps)."""
        scale_factor = params.get("scale_factor", 2.0)
        MAX_BANDWIDTH_BPS = 100_000_000  # 100 Mbps cap

        for link in self.topology.links.values():
            if "server" in link.node_b_id or "server" in link.node_a_id:
                old_bw = link.bandwidth_bps
                if old_bw >= MAX_BANDWIDTH_BPS:
                    return MitigationAction(
                        timestamp=current_time,
                        action_type="scale_bandwidth",
                        target="bottleneck",
                        parameters={"old_bps": old_bw, "max_reached": True},
                        success=False,
                        description=f"Bottleneck already at max {MAX_BANDWIDTH_BPS/1_000_000:.0f} Mbps",
                    )
                new_bw = min(int(old_bw * scale_factor), MAX_BANDWIDTH_BPS)
                link.bandwidth_bps = new_bw
                return MitigationAction(
                    timestamp=current_time,
                    action_type="scale_bandwidth",
                    target="bottleneck",
                    parameters={"old_bps": old_bw, "new_bps": new_bw},
                    success=True,
                    description=f"Scaled bottleneck from {old_bw/1_000_000:.1f} to {new_bw/1_000_000:.1f} Mbps",
                )

        return MitigationAction(
            timestamp=current_time,
            action_type="scale_bandwidth",
            target="bottleneck",
            success=False,
            description="No bottleneck link found",
        )

    def _restore_node(self, target_ip: str, params: dict,
                      current_time: float) -> MitigationAction:
        """Re-integrate a quarantined node."""
        node = self._find_node(target_ip)
        if node:
            node.is_isolated = False
            node.is_rate_limited = False
            node.rate_limit_bps = 0
            node.health = 1.0
            self.active_mitigations.pop(target_ip, None)
            return MitigationAction(
                timestamp=current_time,
                action_type="restore_node",
                target=target_ip,
                success=True,
                description=f"Restored node {target_ip} to full operation",
            )

        return MitigationAction(
            timestamp=current_time,
            action_type="restore_node",
            target=target_ip,
            success=False,
            description=f"Node {target_ip} not found",
        )

    def _find_node(self, ip: str) -> Optional[Node]:
        """Find a node by IP address."""
        for node in self.topology.nodes.values():
            if node.ip == ip:
                return node
        return None

    def get_active_mitigations(self) -> dict:
        return dict(self.active_mitigations)

    def get_recent_actions(self, n: int = 20) -> List[dict]:
        return [a.to_dict() for a in self.action_log[-n:]]

    def clear_all(self):
        """Remove all active mitigations and restore all nodes."""
        for node in self.topology.nodes.values():
            node.is_isolated = False
            node.is_rate_limited = False
            node.rate_limit_bps = 0
        self.active_mitigations.clear()

        # Reset bandwidth on bottleneck
        for link in self.topology.links.values():
            if "server" in link.node_b_id or "server" in link.node_a_id:
                link.bandwidth_bps = config.LINK_BANDWIDTH_BPS
