"""
Train the anomaly detector and pre-train the RL agent.
Run this standalone to generate and save the models.

Usage:
    python train_detector.py            # Train both models
    python train_detector.py --test     # Train and run validation
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector import AnomalyDetector
from rl_agent import DefenseAgent


def main():
    parser = argparse.ArgumentParser(description="Train detection and defense models")
    parser.add_argument("--test", action="store_true", help="Run validation tests")
    parser.add_argument("--samples", type=int, default=5000, help="Training samples per class")
    args = parser.parse_args()

    print("=" * 60)
    print("  Model Training Pipeline")
    print("=" * 60)

    # 1. Train anomaly detector
    print("\n[1/2] Training Random Forest Anomaly Detector...")
    detector = AnomalyDetector()
    results = detector.train(verbose=True)
    detector.save_model()

    print(f"\n  ✓ Accuracy: {results['accuracy']:.4f}")
    print(f"  ✓ Train size: {results['train_size']}")
    print(f"  ✓ Test size: {results['test_size']}")

    # 2. Pre-train RL agent
    print("\n[2/2] Pre-training Q-Learning Defense Agent...")
    agent = DefenseAgent()
    rl_results = agent.pre_train(episodes=1000)
    agent.save()

    print(f"\n  ✓ Q-table: {rl_results['q_table_size']} states")
    print(f"  ✓ Avg reward: {rl_results['avg_reward']:.2f}")
    print(f"  ✓ Epsilon: {rl_results['epsilon']:.4f}")

    if args.test:
        print("\n" + "=" * 60)
        print("  Validation Tests")
        print("=" * 60)

        # Test detection on fresh samples
        from feature_extractor import FeatureExtractor
        from detector import SyntheticDataGenerator
        import numpy as np

        fe = FeatureExtractor()
        gen = SyntheticDataGenerator(fe)

        correct = 0
        total = 300
        for _ in range(100):
            features, label = gen.generate_normal_sample()
            pred = detector.model.predict(features.reshape(1, -1))[0]
            if pred == label:
                correct += 1

        for _ in range(100):
            features, label = gen.generate_ldos_sample()
            pred = detector.model.predict(features.reshape(1, -1))[0]
            if pred == label:
                correct += 1

        for _ in range(100):
            features, label = gen.generate_flash_crowd_sample()
            pred = detector.model.predict(features.reshape(1, -1))[0]
            if pred == label:
                correct += 1

        val_accuracy = correct / total
        print(f"\n  Validation accuracy: {val_accuracy:.4f} ({correct}/{total})")
        assert val_accuracy > 0.90, f"Validation failed: {val_accuracy:.4f} < 0.90"
        print("  ✓ All validation tests passed!")

    print("\n" + "=" * 60)
    print("  Training Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
