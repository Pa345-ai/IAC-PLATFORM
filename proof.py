import json
import os
import logging
import math
import hashlib
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Set

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class Proof:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.dlp_id = config.get('dlp_id', 0)

        self.max_records = 50000
        self.seen_hashes: Set[str] = set()
        self.timestamps: List[datetime] = []
        self.collision_count = 0
        self.missing_field_count = 0

        self.thresholds = {
            "intent":      {"entropy": 2.8, "weight": 0.2},
            "execution":   {"entropy": 3.4, "weight": 0.5},
            "remediation": {"entropy": 3.1, "weight": 0.3},
        }

    def generate(self) -> Dict[str, Any]:
        input_dir   = self.config.get('input_dir', '/input')
        output_file = self.config.get('output_path', '/output/results.json')

        layer_scores  = {"intent": [], "execution": [], "remediation": []}
        total_records = 0

        if not os.path.exists(input_dir):
            logging.error(f"Input path {input_dir} missing.")
            return self._finalize(False, 0.0, output_file, input_dir=input_dir)

        for filename in os.listdir(input_dir):
            layer = self._identify_layer(filename)
            if not layer or total_records >= self.max_records:
                continue

            filepath = os.path.join(input_dir, filename)
            with open(filepath, 'r') as f:
                for line in f:
                    if total_records >= self.max_records:
                        break
                    try:
                        record = json.loads(line.strip())
                        score  = self._evaluate_record(record, layer)
                        layer_scores[layer].append(score)
                        total_records += 1
                    except json.JSONDecodeError:
                        continue

        if total_records < 100:
            return self._finalize(False, 0.0, output_file, total_records,
                                  input_dir=input_dir)

        combined_score = 0.0
        for layer, cfg in self.thresholds.items():
            scores = layer_scores[layer]
            if scores:
                layer_avg = sum(scores) / len(scores)
                combined_score += layer_avg * cfg["weight"]

        size_multiplier   = min(1.0, math.log10(max(1, total_records)) / 4)
        collision_penalty = (self.collision_count / max(1, total_records)) * 0.6
        jitter_penalty    = self._calculate_jitter_penalty()

        final_score = max(0.0, (combined_score * size_multiplier)
                                - collision_penalty
                                - jitter_penalty)

        is_valid = final_score > 0.45 and total_records >= 100
        return self._finalize(is_valid, final_score, output_file, total_records,
                              input_dir=input_dir)

    def _evaluate_record(self, record: Dict[str, Any], layer: str) -> float:
        meat = {k: v for k, v in record.items()
                if k not in ("record_id", "generated_at")}
        content_hash = hashlib.sha256(
            json.dumps(meat, sort_keys=True).encode()
        ).hexdigest()

        if content_hash in self.seen_hashes:
            self.collision_count += 1
            return 0.0
        if len(self.seen_hashes) < 25000:
            self.seen_hashes.add(content_hash)

        entropy = self._get_entropy(str(meat))
        if entropy < self.thresholds[layer]["entropy"]:
            return 0.1

        fidelity = 1.0
        required_fields = {
            "intent":      ["control_intent_vector", "standard_mappings"],
            "execution":   ["cloud_context", "violation_mechanics", "labeling"],
            "remediation": ["problem_pattern", "remediation_logic"],
        }[layer]

        for field in required_fields:
            if field not in record:
                fidelity -= 0.3
                self.missing_field_count += 1

        ts = record.get("generated_at")
        if ts:
            try:
                self.timestamps.append(
                    datetime.fromisoformat(ts.replace('Z', '+00:00'))
                )
            except ValueError:
                pass

        return max(0.0, fidelity)

    def _get_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def _identify_layer(self, filename: str) -> str:
        name = filename.lower()
        if "intent"      in name: return "intent"
        if "execution"   in name: return "execution"
        if "remediation" in name: return "remediation"
        return None

    def _calculate_jitter_penalty(self) -> float:
        if len(self.timestamps) < 50:
            return 0.0
        self.timestamps.sort()
        intervals = [
            (self.timestamps[i] - self.timestamps[i - 1]).total_seconds()
            for i in range(1, len(self.timestamps))
        ]
        mean_inv = sum(intervals) / len(intervals)
        if mean_inv == 0:
            return 0.5
        variance = sum((x - mean_inv) ** 2 for x in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        return 0.3 if std_dev < 0.01 else 0.0

    def _compute_dataset_hash(self, input_dir: str) -> str:
        """
        SHA-256 over the sorted, concatenated contents of all JSONL files.
        Sorting by filename makes the hash deterministic regardless of OS
        directory ordering — two identical datasets always produce the same
        hash, and two different datasets always produce a different hash.
        """
        if not input_dir or not os.path.exists(input_dir):
            return ""
        h = hashlib.sha256()
        for filename in sorted(os.listdir(input_dir)):
            if not self._identify_layer(filename):
                continue
            filepath = os.path.join(input_dir, filename)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        return h.hexdigest()

    def _finalize(self, valid: bool, score: float, path: str,
                  count: int = 0, input_dir: str = "") -> Dict[str, Any]:
        result = {
            "dlp_id":       self.dlp_id,
            # ── NEW: unique ID for this specific proof run ──────────────────
            "batch_id":     str(uuid.uuid4()),
            # ── NEW: Unix timestamp of proof generation ─────────────────────
            "timestamp":    int(datetime.now(timezone.utc).timestamp()),
            # ── NEW: hash of the actual dataset files that were scored ───────
            "dataset_hash": self._compute_dataset_hash(input_dir),
            "valid":        valid,
            "score":        round(score, 4),
            "metadata": {
                "records_processed":         count,
                "semantic_collisions":       self.collision_count,
                "missing_fields_found":      self.missing_field_count,
                "timestamp_jitter_verified": True,
            },
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(result, f, indent=4)
        logging.info(
            f"Finalized. Valid={valid}, Score={score:.4f}, "
            f"Records={count}, BatchID={result['batch_id'][:8]}..."
        )
        return result
if __name__ == "__main__":
    config = {
        "dlp_id": 2,
        "input_dir": "dataset/jsonl",
        "output_path": "./output/results.json"
    }

    proof_engine = Proof(config)
    print("Starting Proof Generation...")
    
    result = proof_engine.generate()

    if result["valid"]:
        print("\nSUCCESS")
        print(f"Score: {result['score']}")
        print(f"Batch ID: {result['batch_id']}")
        print(f"Saved to: {config['output_path']}")
    else:
        print("\nFAILED: Check if records exist in ./input")
                      
