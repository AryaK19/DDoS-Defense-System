"""
Feature Extractor — Extracts statistical features from the packet stream
for the ML detection engine. Processes raw packets into per-window feature
vectors that can distinguish normal traffic, LDoS attacks, and flash crowds.
"""

import math
import numpy as np
from collections import defaultdict
from typing import List, Dict, Tuple

import config


class FeatureExtractor:
    """
    Processes a window of packets and extracts features for anomaly detection.
    
    Features extracted per window:
    1. Packet count
    2. Byte count
    3. Packets per second
    4. Bytes per second
    5. Packet length entropy (Shannon)
    6. Mean inter-arrival time
    7. Std of inter-arrival time
    8. Periodicity score (FFT-based)
    9. Flow symmetry ratio
    10. Unique source IPs
    11. Peak-to-average packet ratio
    12. Max burst size
    """

    FEATURE_NAMES = [
        "packet_count",
        "byte_count",
        "packets_per_sec",
        "bytes_per_sec",
        "pkt_len_entropy",
        "mean_iat",
        "std_iat",
        "periodicity_score",
        "flow_symmetry",
        "unique_sources",
        "peak_to_avg_ratio",
        "max_burst_size",
    ]

    def __init__(self, window_size_ms: int = None):
        self.window_size_ms = window_size_ms or config.FEATURES["window_size_ms"]
        self.fft_threshold = config.FEATURES["fft_threshold"]

    def extract(self, packets: List[dict]) -> np.ndarray:
        """
        Extract features from a list of packet records.
        Each packet record should have: time, src, dst, size, type, protocol
        
        Returns a 1D numpy array of features.
        """
        if not packets:
            return np.zeros(len(self.FEATURE_NAMES))

        # Basic counts
        packet_count = len(packets)
        sizes = [p.get("size", 0) for p in packets]
        byte_count = sum(sizes)
        timestamps = sorted([p.get("time", 0) for p in packets])

        # Duration
        duration_sec = max(0.001, (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else self.window_size_ms / 1000)

        # Rates
        packets_per_sec = packet_count / duration_sec
        bytes_per_sec = byte_count / duration_sec

        # 1) Packet length entropy (Shannon)
        pkt_len_entropy = self._shannon_entropy(sizes)

        # 2) Inter-arrival time statistics
        iats = self._compute_iats(timestamps)
        mean_iat = float(np.mean(iats)) if len(iats) > 0 else 0.0
        std_iat = float(np.std(iats)) if len(iats) > 0 else 0.0

        # 3) Periodicity score via FFT
        periodicity_score = self._periodicity_fft(timestamps, duration_sec)

        # 4) Flow symmetry (ratio of unique src to unique dst)
        src_ips = set(p.get("src", "") for p in packets)
        dst_ips = set(p.get("dst", "") for p in packets)
        flow_symmetry = len(src_ips) / max(1, len(dst_ips))

        # 5) Unique sources
        unique_sources = len(src_ips)

        # 6) Peak-to-average ratio (burstiness)
        peak_to_avg, max_burst = self._burstiness(timestamps, sizes, duration_sec)

        return np.array([
            packet_count,
            byte_count,
            packets_per_sec,
            bytes_per_sec,
            pkt_len_entropy,
            mean_iat,
            std_iat,
            periodicity_score,
            flow_symmetry,
            unique_sources,
            peak_to_avg,
            max_burst,
        ], dtype=np.float64)

    def extract_labeled(self, packets: List[dict]) -> Dict[str, float]:
        """Extract features and return as a labeled dictionary."""
        features = self.extract(packets)
        return dict(zip(self.FEATURE_NAMES, features))

    @staticmethod
    def _shannon_entropy(values: List[int]) -> float:
        """Calculate Shannon entropy of a list of values."""
        if not values:
            return 0.0
        total = len(values)
        counts = defaultdict(int)
        for v in values:
            counts[v] += 1
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _compute_iats(timestamps: List[float]) -> np.ndarray:
        """Compute inter-arrival times from sorted timestamps."""
        if len(timestamps) < 2:
            return np.array([])
        ts = np.array(timestamps)
        return np.diff(ts)

    def _periodicity_fft(self, timestamps: List[float], duration_sec: float) -> float:
        """
        Detect periodicity in packet arrival times using FFT.
        
        LDoS attacks have a strong periodic component at frequency = 1/T
        (typically 1 Hz for T=1s period). Normal traffic and flash crowds
        don't show this periodic pattern.
        
        Returns a score [0, 1] where higher = more periodic.
        """
        if len(timestamps) < 10:
            return 0.0

        # Create a time-binned signal (packets per bin)
        bin_size_ms = 10  # 10ms bins
        n_bins = max(1, int(duration_sec * 1000 / bin_size_ms))
        bins = np.zeros(n_bins)

        t_start = timestamps[0]
        for t in timestamps:
            idx = min(int((t - t_start) * 1000 / bin_size_ms), n_bins - 1)
            bins[idx] += 1

        # Remove DC component (mean)
        bins = bins - np.mean(bins)

        if np.std(bins) < 0.01:
            return 0.0

        # FFT
        fft_vals = np.abs(np.fft.rfft(bins))
        if len(fft_vals) < 2:
            return 0.0

        # Exclude DC component (index 0)
        fft_vals[0] = 0

        # Periodicity = max peak / total energy
        total_energy = np.sum(fft_vals)
        if total_energy < 0.01:
            return 0.0

        peak_energy = np.max(fft_vals)
        score = peak_energy / total_energy

        return min(1.0, score)

    @staticmethod
    def _burstiness(timestamps: List[float], sizes: List[int],
                    duration_sec: float) -> Tuple[float, float]:
        """
        Measure traffic burstiness using peak-to-average ratio.
        LDoS attacks have extreme burstiness due to the pulse pattern.
        """
        if not timestamps or duration_sec < 0.01:
            return 0.0, 0.0

        # Bin traffic into 50ms windows
        bin_size = 0.05  # 50ms
        n_bins = max(1, int(duration_sec / bin_size))
        bins = np.zeros(n_bins)

        t_start = timestamps[0]
        for t, s in zip(timestamps, sizes):
            idx = min(int((t - t_start) / bin_size), n_bins - 1)
            bins[idx] += s

        avg = np.mean(bins)
        peak = np.max(bins)
        max_burst = float(peak)

        if avg > 0:
            ratio = float(peak / avg)
        else:
            ratio = 0.0

        return ratio, max_burst
