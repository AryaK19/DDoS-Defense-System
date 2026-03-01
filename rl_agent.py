"""
Reinforcement Learning Agent — Tabular Q-Learning for autonomous defense.
Learns optimal mitigation strategies through interaction with the simulated
network environment.
"""

import os
import json
import random
import numpy as np
from typing import List, Tuple, Optional
from dataclasses import dataclass, field

import config


@dataclass
class AgentAction:
    """Represents a defense action taken by the RL agent."""
    action_name: str
    target_ip: str = ""
    parameters: dict = field(default_factory=dict)
    timestamp: float = 0.0
    reward: float = 0.0
    state_before: str = ""
    state_after: str = ""


class DefenseAgent:
    """
    Tabular Q-Learning agent for autonomous network defense.
    
    State space (discretized):
        - throughput_level: low(0), medium(1), high(2)
        - latency_level: low(0), medium(1), high(2)
        - packet_loss_level: none(0), low(1), high(2)
        - attack_confidence: none(0), low(1), high(2)
        - defense_active: no(0), yes(1)
    
    Action space:
        0 = no_action
        1 = rate_limit (throttle suspected source)
        2 = drop_source (block suspected source)
        3 = reroute_traffic (redirect legitimate flows)
        4 = isolate_node (quarantine compromised node)
        5 = scale_bandwidth (increase bottleneck capacity)
    """

    ACTIONS = config.RL_AGENT["actions"]

    def __init__(self):
        # Q-table: maps state tuples to action values
        self.q_table = {}

        # Hyperparameters
        self.learning_rate = config.RL_AGENT["learning_rate"]
        self.discount_factor = config.RL_AGENT["discount_factor"]
        self.epsilon = config.RL_AGENT["epsilon_start"]
        self.epsilon_end = config.RL_AGENT["epsilon_end"]
        self.epsilon_decay = config.RL_AGENT["epsilon_decay"]
        self.reward_weights = config.RL_AGENT["reward_weights"]

        # History
        self.action_history: List[AgentAction] = []
        self.total_reward: float = 0.0
        self.episodes: int = 0

        # Current state tracking
        self._last_state = None
        self._last_action = None

    def discretize_state(self, throughput_ratio: float, latency_ms: float,
                         packet_loss: float, attack_confidence: float,
                         defense_active: bool) -> Tuple:
        """
        Convert continuous state values to discrete buckets for Q-table.
        """
        # Throughput ratio (current/baseline): 0=low, 1=medium, 2=high
        if throughput_ratio < 0.3:
            tp = 0
        elif throughput_ratio < 0.7:
            tp = 1
        else:
            tp = 2

        # Latency: 0=low (<50ms), 1=medium (<200ms), 2=high (>200ms)
        if latency_ms < 50:
            lat = 0
        elif latency_ms < 200:
            lat = 1
        else:
            lat = 2

        # Packet loss: 0=none (<1%), 1=low (<10%), 2=high (>10%)
        if packet_loss < 0.01:
            loss = 0
        elif packet_loss < 0.1:
            loss = 1
        else:
            loss = 2

        # Attack confidence: 0=none (<30%), 1=low (<70%), 2=high (>70%)
        if attack_confidence < 0.3:
            conf = 0
        elif attack_confidence < 0.7:
            conf = 1
        else:
            conf = 2

        defense = 1 if defense_active else 0

        return (tp, lat, loss, conf, defense)

    def select_action(self, state: Tuple) -> int:
        """
        Select an action using epsilon-greedy policy.
        
        With probability epsilon: random action (exploration)
        Otherwise: best Q-value action (exploitation)
        """
        if random.random() < self.epsilon:
            return random.randint(0, len(self.ACTIONS) - 1)

        # Get Q-values for this state
        q_values = self._get_q_values(state)
        return int(np.argmax(q_values))

    def compute_reward(self, throughput_ratio: float, latency_ms: float,
                       packet_loss: float, false_positive: bool) -> float:
        """
        Compute the reward signal for the current network state.
        
        Reward = w1*throughput - w2*latency - w3*loss - w4*false_positive
        
        The reward incentivizes maintaining high throughput for legitimate
        users while penalizing high latency, packet loss, and false alarms.
        """
        w = self.reward_weights

        # Normalize throughput to [0, 1]
        tp_reward = w["throughput"] * throughput_ratio

        # Normalize latency penalty (higher latency = more negative)
        lat_penalty = w["latency"] * (latency_ms / 1000.0)

        # Packet loss penalty
        loss_penalty = w["packet_loss"] * packet_loss

        # False positive penalty
        fp_penalty = w["false_positive"] * (1.0 if false_positive else 0.0)

        reward = tp_reward + lat_penalty + loss_penalty + fp_penalty

        return reward

    def update(self, state: Tuple, action: int, reward: float, next_state: Tuple):
        """
        Update Q-table using the Q-learning update rule:
        Q(s,a) = Q(s,a) + α * [r + γ * max_a' Q(s',a') - Q(s,a)]
        """
        state_key = str(state)
        next_key = str(next_state)

        # Ensure states exist in Q-table
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(len(self.ACTIONS))
        if next_key not in self.q_table:
            self.q_table[next_key] = np.zeros(len(self.ACTIONS))

        # Q-learning update
        current_q = self.q_table[state_key][action]
        max_next_q = np.max(self.q_table[next_key])
        td_target = reward + self.discount_factor * max_next_q
        td_error = td_target - current_q

        self.q_table[state_key][action] += self.learning_rate * td_error

        # Track
        self.total_reward += reward

    def step(self, throughput_ratio: float, latency_ms: float,
             packet_loss: float, attack_confidence: float,
             defense_active: bool, false_positive: bool = False) -> str:
        """
        Full RL step: observe state → select action → learn from previous step.
        
        Returns the name of the chosen action.
        """
        # Discretize current state
        state = self.discretize_state(
            throughput_ratio, latency_ms,
            packet_loss, attack_confidence, defense_active
        )

        # Learn from previous step
        if self._last_state is not None and self._last_action is not None:
            reward = self.compute_reward(
                throughput_ratio, latency_ms, packet_loss, false_positive
            )
            self.update(self._last_state, self._last_action, reward, state)

        # Select action
        action_idx = self.select_action(state)
        action_name = self.ACTIONS[action_idx]

        # Record
        self._last_state = state
        self._last_action = action_idx

        agent_action = AgentAction(
            action_name=action_name,
            state_before=str(state),
        )
        self.action_history.append(agent_action)
        if len(self.action_history) > 500:
            self.action_history = self.action_history[-500:]

        # Decay exploration
        self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)

        return action_name

    def _get_q_values(self, state: Tuple) -> np.ndarray:
        """Get Q-values for a state, initializing if needed."""
        state_key = str(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(len(self.ACTIONS))
        return self.q_table[state_key]

    def get_best_action(self, state: Tuple) -> str:
        """Get the best action for a state (no exploration)."""
        q_values = self._get_q_values(state)
        return self.ACTIONS[int(np.argmax(q_values))]

    def pre_train(self, episodes: int = 1000) -> dict:
        """
        Pre-train the agent on simulated scenarios to give it
        a baseline policy before live deployment.
        """
        print(f"[RL Agent] Pre-training for {episodes} episodes...")

        rewards = []
        for ep in range(episodes):
            ep_reward = 0
            # Simulate a scenario
            # Phase 1: Normal traffic
            for t in range(10):
                action = self.step(
                    throughput_ratio=random.uniform(0.8, 1.0),
                    latency_ms=random.uniform(20, 50),
                    packet_loss=random.uniform(0, 0.01),
                    attack_confidence=random.uniform(0, 0.1),
                    defense_active=False,
                )
                ep_reward += self.compute_reward(
                    random.uniform(0.8, 1.0), random.uniform(20, 50),
                    random.uniform(0, 0.01), action == "drop_source"
                )

            # Phase 2: Attack
            for t in range(20):
                # Attack degrades metrics
                attack_severity = min(1.0, t / 10)
                action = self.step(
                    throughput_ratio=max(0.05, 1.0 - 0.8 * attack_severity),
                    latency_ms=50 + 500 * attack_severity,
                    packet_loss=0.02 + 0.4 * attack_severity,
                    attack_confidence=min(1.0, 0.3 + 0.05 * t),
                    defense_active=action in ["drop_source", "rate_limit", "isolate_node"],
                )

                # Good actions improve metrics
                if action in ["drop_source", "rate_limit"]:
                    ep_reward += 0.5
                elif action == "no_action" and attack_severity > 0.5:
                    ep_reward -= 1.0

            rewards.append(ep_reward)
            self.episodes += 1

            # Reset for next episode
            self._last_state = None
            self._last_action = None

        avg_reward = sum(rewards[-100:]) / min(100, len(rewards))
        print(f"[RL Agent] Pre-training complete. Avg reward (last 100): {avg_reward:.2f}")
        print(f"[RL Agent] Q-table size: {len(self.q_table)} states")
        print(f"[RL Agent] Epsilon: {self.epsilon:.4f}")

        return {
            "episodes": episodes,
            "avg_reward": avg_reward,
            "q_table_size": len(self.q_table),
            "epsilon": self.epsilon,
        }

    def save(self, path: str = "models/q_table.json"):
        """Save Q-table to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        serializable = {k: v.tolist() for k, v in self.q_table.items()}
        with open(path, "w") as f:
            json.dump({
                "q_table": serializable,
                "epsilon": self.epsilon,
                "episodes": self.episodes,
                "total_reward": self.total_reward,
            }, f, indent=2)
        print(f"[RL Agent] Saved to {path}")

    def load(self, path: str = "models/q_table.json") -> bool:
        """Load Q-table from disk."""
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
            self.q_table = {k: np.array(v) for k, v in data["q_table"].items()}
            self.epsilon = data.get("epsilon", self.epsilon_end)
            self.episodes = data.get("episodes", 0)
            self.total_reward = data.get("total_reward", 0)
            print(f"[RL Agent] Loaded from {path} ({len(self.q_table)} states)")
            return True
        return False

    def get_status(self) -> dict:
        return {
            "q_table_size": len(self.q_table),
            "epsilon": round(self.epsilon, 4),
            "total_reward": round(self.total_reward, 2),
            "episodes": self.episodes,
            "last_action": self.action_history[-1].action_name if self.action_history else "none",
            "recent_actions": [a.action_name for a in self.action_history[-10:]],
        }
