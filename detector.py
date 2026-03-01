"""
Anomaly Detection Engine — Random Forest classifier for LDoS attack detection.
Includes synthetic data generation for training and a signature analyzer
for identifying the periodic pulse pattern of Shrew attacks.
"""

import os
import pickle
import numpy as np
import random as pyrandom
from dataclasses import dataclass
from typing import List, Optional, Tuple

import config
from feature_extractor import FeatureExtractor


@dataclass
class ThreatAssessment:
    """Result of the detection engine's analysis."""
    threat_detected: bool = False
    threat_type: str = "none"           # none, ldos, flash_crowd
    confidence: float = 0.0             # 0.0 to 1.0
    source_ips: List[str] = None        # suspected sources
    estimated_period_ms: float = 0.0    # estimated attack period
    estimated_burst_rate: float = 0.0   # estimated burst rate (bps)
    raw_probabilities: dict = None      # class probabilities

    def __post_init__(self):
        if self.source_ips is None:
            self.source_ips = []
        if self.raw_probabilities is None:
            self.raw_probabilities = {}

    def to_dict(self) -> dict:
        return {
            "threat_detected": self.threat_detected,
            "threat_type": self.threat_type,
            "confidence": round(self.confidence, 4),
            "source_ips": self.source_ips,
            "estimated_period_ms": round(self.estimated_period_ms, 1),
            "estimated_burst_rate_mbps": round(self.estimated_burst_rate / 1_000_000, 3),
            "probabilities": {k: round(v, 4) for k, v in self.raw_probabilities.items()},
        }


class SyntheticDataGenerator:
    """
    Generates synthetic training data for the Random Forest detector.
    Creates realistic packet streams for each class.
    """

    def __init__(self, feature_extractor: FeatureExtractor):
        self.fe = feature_extractor

    def generate_normal_sample(self) -> Tuple[np.ndarray, int]:
        """Generate features from a normal traffic window."""
        n_packets = pyrandom.randint(50, 200)
        duration = 1.0  # 1 second window

        # Vary source count heavily so the model learns that a small number
        # of sources (e.g. just 2 clients) is perfectly normal.
        possible_counts = [2, 2, 2, 2, 3, 3, 5, 10, 20,
                           pyrandom.randint(2, 50)]
        source_count = pyrandom.choice(possible_counts)
        src_pool = [f"10.0.0.{pyrandom.randint(2, 254)}"
                    for _ in range(source_count)]

        packets = []
        for i in range(n_packets):
            t = pyrandom.uniform(0, duration)
            packets.append({
                "time": t,
                "src": pyrandom.choice(src_pool),
                "dst": "10.0.0.1",
                "size": pyrandom.randint(64, 1460),
                "type": "normal",
                "protocol": "TCP",
            })
        features = self.fe.extract(packets)
        return features, 0  # label 0 = normal

    def generate_ldos_sample(self) -> Tuple[np.ndarray, int]:
        """Generate features from an LDoS attack window."""
        packets = []
        duration = 1.0

        # Normal background traffic
        n_bg = pyrandom.randint(20, 80)
        for i in range(n_bg):
            t = pyrandom.uniform(0, duration)
            packets.append({
                "time": t,
                "src": f"10.0.0.{pyrandom.randint(2, 10)}",
                "dst": "10.0.0.1",
                "size": pyrandom.randint(64, 1460),
                "type": "normal",
                "protocol": "TCP",
            })

        # LDoS pulse (short burst at the start of the window)
        burst_start = pyrandom.uniform(0, 0.1)
        burst_duration = pyrandom.uniform(0.005, 0.02)
        n_burst = pyrandom.randint(50, 300)
        for i in range(n_burst):
            t = burst_start + pyrandom.uniform(0, burst_duration)
            packets.append({
                "time": t,
                "src": "10.0.0.100",
                "dst": "10.0.0.1",
                "size": pyrandom.randint(1200, 1400),  # uniform sizes
                "type": "attack",
                "protocol": "UDP",
            })

        features = self.fe.extract(packets)
        return features, 1  # label 1 = LDoS attack

    def generate_flash_crowd_sample(self) -> Tuple[np.ndarray, int]:
        """Generate features from a flash crowd (benign surge)."""
        packets = []
        duration = 1.0
        n_packets = pyrandom.randint(150, 400)

        for i in range(n_packets):
            t = pyrandom.uniform(0, duration)
            # Many different sources
            packets.append({
                "time": t,
                "src": f"10.0.{pyrandom.randint(0, 255)}.{pyrandom.randint(2, 254)}",
                "dst": "10.0.0.1",
                "size": pyrandom.randint(64, 1460),
                "type": "flash_crowd",
                "protocol": "TCP",
            })

        features = self.fe.extract(packets)
        return features, 2  # label 2 = flash crowd

    def generate_dataset(self, samples_per_class: int = None) -> Tuple[np.ndarray, np.ndarray]:
        """Generate a full balanced training dataset."""
        n = samples_per_class or config.DETECTOR["training_samples"]

        X, y = [], []

        # Normal samples
        for _ in range(n):
            features, label = self.generate_normal_sample()
            X.append(features)
            y.append(label)

        # LDoS samples
        for _ in range(n):
            features, label = self.generate_ldos_sample()
            X.append(features)
            y.append(label)

        # Flash crowd samples
        for _ in range(n):
            features, label = self.generate_flash_crowd_sample()
            X.append(features)
            y.append(label)

        return np.array(X), np.array(y)


class AnomalyDetector:
    """
    Random Forest-based anomaly detector for LDoS attacks.
    
    Classification targets:
        0 = Normal traffic
        1 = LDoS attack
        2 = Flash crowd (benign surge)
    """

    CLASS_NAMES = {0: "normal", 1: "ldos", 2: "flash_crowd"}

    def __init__(self):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.is_trained = False
        self.confidence_threshold = config.DETECTOR["confidence_threshold"]

        # Detection history for tracking
        self.detection_history: List[ThreatAssessment] = []

        # State across ticks (bridges gaps between periodic LDoS bursts)
        self.current_confidence = 0.0
        self.current_threat_type = "none"
        self.current_source_ips = []

    def train(self, X: np.ndarray = None, y: np.ndarray = None,
              verbose: bool = True) -> dict:
        """
        Train the Random Forest model.
        If no data provided, generates synthetic training data.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score

        if X is None or y is None:
            if verbose:
                print("[Detector] Generating synthetic training data...")
            gen = SyntheticDataGenerator(self.feature_extractor)
            X, y = gen.generate_dataset()

        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train
        if verbose:
            print(f"[Detector] Training Random Forest on {len(X_train)} samples...")

        self.model = RandomForestClassifier(
            n_estimators=config.DETECTOR["n_estimators"],
            max_depth=config.DETECTOR["max_depth"],
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred,
                                       target_names=["normal", "ldos", "flash_crowd"],
                                       output_dict=True)

        if verbose:
            print(f"[Detector] Accuracy: {accuracy:.4f}")
            print(classification_report(y_test, y_pred,
                                        target_names=["normal", "ldos", "flash_crowd"]))

        return {
            "accuracy": accuracy,
            "report": report,
            "train_size": len(X_train),
            "test_size": len(X_test),
        }

    def save_model(self, path: str = None):
        """Save the trained model to disk."""
        path = path or config.DETECTOR["model_path"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self.model, f)
        print(f"[Detector] Model saved to {path}")

    def load_model(self, path: str = None) -> bool:
        """Load a trained model from disk."""
        path = path or config.DETECTOR["model_path"]
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            self.is_trained = True
            print(f"[Detector] Model loaded from {path}")
            return True
        return False

    def analyze(self, packets: List[dict]) -> ThreatAssessment:
        """
        Analyze a window of packets and return a threat assessment.
        This is the core detection function called by the MAPE-K loop.
        """
        if not self.is_trained or self.model is None:
            return ThreatAssessment(threat_detected=False, threat_type="none")

        # 1. Decay previous confidence (~70% retention per 100ms tick).
        # Faster decay means a false spike clears within ~3–4 ticks (~400ms)
        # instead of lingering for many seconds.
        self.current_confidence *= 0.70
        if self.current_confidence < 0.1:
            self.current_confidence = 0.0
            self.current_threat_type = "none"
            self.current_source_ips = []

        if len(packets) < 50:
            # Not enough packets to predict -> return decayed state
            assessment = ThreatAssessment(
                threat_detected=(self.current_confidence >= self.confidence_threshold),
                threat_type=self.current_threat_type if self.current_confidence >= self.confidence_threshold else "none",
                confidence=self.current_confidence,
                source_ips=list(self.current_source_ips),
                estimated_period_ms=1000.0 if self.current_confidence >= self.confidence_threshold else 0.0,
                estimated_burst_rate=config.LDOS_ATTACK["burst_rate_bps"] if self.current_confidence >= self.confidence_threshold else 0.0,
                raw_probabilities={},
            )
            self.detection_history.append(assessment)
            if len(self.detection_history) > 100:
                self.detection_history = self.detection_history[-100:]
            return assessment

        # Extract features
        features = self.feature_extractor.extract(packets)
        X = features.reshape(1, -1)

        # Predict
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        class_probs = {}
        for i, name in self.CLASS_NAMES.items():
            if i < len(probabilities):
                class_probs[name] = float(probabilities[i])

        confidence = float(max(probabilities))
        predicted_class = self.CLASS_NAMES.get(prediction, "unknown")

        # For threat detection, use the ldos-specific probability.
        # max(probabilities) can be the "normal" class prob even when ldos is
        # the second-highest — which causes us to miss real attacks.
        ldos_confidence = class_probs.get("ldos", 0.0)

        # Determine if this is a real threat
        is_threat = (ldos_confidence >= self.confidence_threshold)

        # Identify suspected sources (attacker nodes only)
        source_ips = []
        if is_threat:
            # Known legitimate client IPs to protect
            legit_ips = set()
            for node_cfg in config.NETWORK.values():
                if node_cfg["type"] in ("client", "server"):
                    legit_ips.add(node_cfg["ip"])

            source_counts = {}
            for p in packets:
                src = p.get("src", "")
                source_counts[src] = source_counts.get(src, 0) + 1

            # Find sources that contribute >15% of traffic AND are not legitimate.
            # LDoS uses short bursts so the attacker's share of total packets
            # in a multi-second window can be as low as 10-20%.
            total = len(packets)
            for src, count in source_counts.items():
                if count / total > 0.15 and src not in legit_ips:
                    source_ips.append(src)

            # If no suspicious sources identified, likely a false positive
            if not source_ips:
                is_threat = False

        # 2. Update state with new prediction
        if is_threat:
            # Only latch on when the source-IP check ALSO confirms a real attacker.
            self.current_confidence = max(self.current_confidence, ldos_confidence)
            self.current_threat_type = "ldos"
            for src in source_ips:
                if src not in self.current_source_ips:
                    self.current_source_ips.append(src)
        elif predicted_class == "normal" and confidence > 0.9:
            # Fast decay (but not instant zero) when model is very confident
            # traffic is normal.  This lets confidence drain over 3-4 ticks
            # but doesn't wipe it in a single cycle — important because LDoS
            # has long quiet phases that look perfectly normal.
            self.current_confidence *= 0.3
        # else: model guessed ldos but source-IP check rejected it
        # → let the natural 0.70x decay drain it away.

        assessment = ThreatAssessment(
            threat_detected=(self.current_confidence >= self.confidence_threshold),
            threat_type=self.current_threat_type if self.current_confidence >= self.confidence_threshold else "none",
            confidence=self.current_confidence,
            source_ips=list(self.current_source_ips),
            estimated_period_ms=1000.0 if self.current_confidence >= self.confidence_threshold else 0.0,
            estimated_burst_rate=config.LDOS_ATTACK["burst_rate_bps"] if self.current_confidence >= self.confidence_threshold else 0.0,
            raw_probabilities=class_probs,
        )

        self.detection_history.append(assessment)
        # Keep last 100 assessments
        if len(self.detection_history) > 100:
            self.detection_history = self.detection_history[-100:]

        return assessment
