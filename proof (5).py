#!/usr/bin/env python3
"""
CCEG Proof Engine — Validator-Hardened Production Build v2.0
═════════════════════════════════════════════════════════════
Fixes applied vs v1:
  🔴 CRITICAL  : 25k hash cap removed (full dedup always), fidelity clamped
                 to 0.0, bad_json_count tracked, jitter computed over ALL
                 timestamps (not just first 50)
  🟡 STRUCTURAL: nested field validation via dot-path, per-layer record counts,
                 per-layer entropy + collision stats, enriched metadata block
  🟢 CRYPTO    : optional Merkle root per layer, dataset hash always computed,
                 jitter_verified is a real boolean (not hardcoded)
  🧠 REALISM   : layer-aware jitter penalty, dynamic size scaling note,
                 collision_rate in metadata, min/max/mean entropy per layer
  📦 ARCH      : deterministic mode flag via env DETERMINISTIC=1,
                 regex-based layer identification, graceful output-dir creation,
                 full per-layer stat block in final result
"""

import json
import os
import re
import logging
import math
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
)

DETERMINISTIC_MODE = os.environ.get("DETERMINISTIC", "0") == "1"

_LAYER_PATTERNS = {
    "intent":      re.compile(r"intent",        re.IGNORECASE),
    "execution":   re.compile(r"exec(ution)?",  re.IGNORECASE),
    "remediation": re.compile(r"remed(iation)?", re.IGNORECASE),
}

_REQUIRED_FIELDS = {
    "intent": [
        "control_intent_vector",
        "control_intent_vector.objective",
        "control_intent_vector.asset_class",
        "control_intent_vector.risk_domain",
        "standard_mappings",
        "standard_mappings.nist_800_53",
    ],
    "execution": [
        "cloud_context",
        "cloud_context.provider",
        "cloud_context.service",
        "cloud_context.resource_type",
        "violation_mechanics",
        "violation_mechanics.failure_mode",
        "labeling",
        "labeling.severity",
        "labeling.cvss_score",
    ],
    "remediation": [
        "problem_pattern",
        "problem_pattern.failure_mode",
        "problem_pattern.affected_resource",
        "remediation_logic",
        "remediation_logic.strategy",
        "remediation_logic.implementation_steps",
    ],
}

_ENTROPY_THRESHOLDS = {
    "intent":      2.8,
    "execution":   3.4,
    "remediation": 3.1,
}

_LAYER_WEIGHTS = {
    "intent":      0.20,
    "execution":   0.50,
    "remediation": 0.30,
}


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _get_nested(record: Dict, dotpath: str) -> Any:
    val = record
    for key in dotpath.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val


def _check_required_fields(record: Dict, layer: str) -> int:
    missing = 0
    for field in _REQUIRED_FIELDS.get(layer, []):
        if _get_nested(record, field) is None:
            missing += 1
    return missing


def _record_entropy(record: Dict) -> float:
    values = []
    stack = list(record.values())
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
        elif v is not None:
            values.append(str(v))
    if not values:
        return 0.0
    def _ent(s):
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)
    return sum(_ent(v) for v in values) / len(values)


def _identify_layer(filename: str) -> Optional[str]:
    for layer, pattern in _LAYER_PATTERNS.items():
        if pattern.search(filename):
            return layer
    logging.debug(f"Unmatched filename (skipped): {filename}")
    return None


def build_merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return _sha256("")
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def _compute_dataset_hash(input_dir: str) -> str:
    if not input_dir or not os.path.exists(input_dir):
        return ""
    h = hashlib.sha256()
    for filename in sorted(os.listdir(input_dir)):
        if _identify_layer(filename) is None:
            continue
        filepath = os.path.join(input_dir, filename)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


class LayerStats:
    def __init__(self, name: str):
        self.name        = name
        self.scores:     List[float]    = []
        self.entropies:  List[float]    = []
        self.timestamps: List[datetime] = []
        self.collisions: int = 0
        self.missing:    int = 0
        self.bad_json:   int = 0

    def avg_score(self) -> float:
        return sum(self.scores) / len(self.scores) if self.scores else 0.0

    def entropy_stats(self) -> Dict[str, float]:
        if not self.entropies:
            return {"min": 0.0, "max": 0.0, "mean": 0.0}
        return {
            "min":  round(min(self.entropies), 4),
            "max":  round(max(self.entropies), 4),
            "mean": round(sum(self.entropies) / len(self.entropies), 4),
        }

    def jitter_stats(self) -> Dict[str, Any]:
        ts = sorted(self.timestamps)
        if len(ts) < 2:
            return {"mean_s": 0.0, "std_dev_s": 0.0, "verified": False,
                    "sample_size": len(ts)}
        intervals = [(ts[i] - ts[i - 1]).total_seconds() for i in range(1, len(ts))]
        mean = sum(intervals) / len(intervals)
        var  = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std  = math.sqrt(var)
        return {
            "mean_s":      round(mean, 4),
            "std_dev_s":   round(std, 4),
            "verified":    std >= 0.01,
            "sample_size": len(intervals),
        }

    def collision_rate(self) -> float:
        total = len(self.scores) + self.collisions
        return round(self.collisions / max(1, total), 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_count":   len(self.scores),
            "avg_score":      round(self.avg_score(), 4),
            "entropy":        self.entropy_stats(),
            "jitter":         self.jitter_stats(),
            "collisions":     self.collisions,
            "collision_rate": self.collision_rate(),
            "missing_fields": self.missing,
            "bad_json_lines": self.bad_json,
        }


class Proof:

    def __init__(self, config: Dict[str, Any]):
        self.config  = config
        self.dlp_id  = config.get("dlp_id", 0)

        self.max_records = 50000

        self.seen_hashes: Set[str] = set()   # NO cap
        self.collision_count:    int = 0
        self.missing_field_count: int = 0
        self.bad_json_count:     int = 0

        self._layers: Dict[str, LayerStats] = {
            name: LayerStats(name)
            for name in ("intent", "execution", "remediation")
        }
        self._merkle_leaves: Dict[str, List[str]] = {
            name: [] for name in ("intent", "execution", "remediation")
        }

    def generate(self) -> Dict[str, Any]:
        input_dir   = self.config.get("input_dir", "/input")
        output_file = self.config.get("output_path", "/output/results.json")
        total_records = 0

        if not os.path.exists(input_dir):
            logging.error(f"Input path {input_dir} missing.")
            return self._finalize(False, 0.0, output_file, 0, input_dir)

        for filename in sorted(os.listdir(input_dir)):
            layer = _identify_layer(filename)
            if not layer or total_records >= self.max_records:
                if layer is None and filename.endswith(".jsonl"):
                    logging.warning(f"Could not map '{filename}' to any layer.")
                continue

            filepath    = os.path.join(input_dir, filename)
            layer_stats = self._layers[layer]

            with open(filepath, "r") as f:
                for line in f:
                    if total_records >= self.max_records:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        layer_stats.bad_json += 1
                        self.bad_json_count  += 1
                        continue

                    score = self._evaluate_record(record, layer, layer_stats)
                    layer_stats.scores.append(score)
                    total_records += 1

        if total_records < 100:
            logging.warning(f"Only {total_records} records — below minimum 100.")
            return self._finalize(False, 0.0, output_file, total_records, input_dir)

        combined_score = sum(
            self._layers[layer].avg_score() * _LAYER_WEIGHTS[layer]
            for layer in _LAYER_WEIGHTS
            if self._layers[layer].scores
        )

        size_multiplier   = min(1.0, math.log10(max(1, total_records)) / 4)
        collision_penalty = (self.collision_count / max(1, total_records)) * 0.6
        jitter_penalty    = self._calculate_jitter_penalty()

        final_score = max(0.0,
                          combined_score * size_multiplier
                          - collision_penalty
                          - jitter_penalty)

        is_valid = final_score > 0.45 and total_records >= 100
        return self._finalize(is_valid, final_score, output_file,
                              total_records, input_dir)

    def _evaluate_record(
        self,
        record: Dict[str, Any],
        layer: str,
        layer_stats: LayerStats,
    ) -> float:
        meat = {k: v for k, v in record.items()
                if k not in ("record_id", "generated_at")}
        content_hash = _sha256(json.dumps(meat, sort_keys=True))

        if content_hash in self.seen_hashes:
            self.collision_count   += 1
            layer_stats.collisions += 1
            return 0.0
        self.seen_hashes.add(content_hash)
        self._merkle_leaves[layer].append(content_hash)

        entropy = _record_entropy(record)
        layer_stats.entropies.append(entropy)
        if entropy < _ENTROPY_THRESHOLDS[layer]:
            return 0.1

        missing = _check_required_fields(record, layer)
        self.missing_field_count += missing
        layer_stats.missing      += missing
        fidelity = max(0.0, 1.0 - missing * 0.3)   # clamped

        ts_str = record.get("generated_at")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                layer_stats.timestamps.append(ts)
            except ValueError:
                pass

        return fidelity

    def _calculate_jitter_penalty(self) -> float:
        penalty = 0.0
        for layer, stats in self._layers.items():
            js = stats.jitter_stats()
            if js["sample_size"] >= 10 and not js["verified"]:
                penalty = max(penalty, 0.3 * _LAYER_WEIGHTS[layer])
        return round(penalty, 4)

    def _finalize(
        self,
        valid: bool,
        score: float,
        path: str,
        count: int = 0,
        input_dir: str = "",
    ) -> Dict[str, Any]:

        layer_merkle = {
            name: build_merkle_root(self._merkle_leaves[name])
            for name in self._merkle_leaves
        }
        dataset_merkle = build_merkle_root(
            [layer_merkle[name] for name in sorted(layer_merkle)]
        )

        all_ts = []
        for stats in self._layers.values():
            all_ts.extend(stats.timestamps)
        all_ts.sort()
        global_jitter_verified = False
        if len(all_ts) >= 2:
            intervals = [(all_ts[i] - all_ts[i - 1]).total_seconds()
                         for i in range(1, len(all_ts))]
            mean = sum(intervals) / len(intervals)
            var  = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            global_jitter_verified = math.sqrt(var) >= 0.01

        result = {
            "dlp_id":    self.dlp_id,
            "batch_id":  str(uuid.uuid4()),
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "dataset_hash": _compute_dataset_hash(input_dir),

            "dataset_merkle_root": dataset_merkle,
            "layer_merkle_roots":  layer_merkle,

            "valid": valid,
            "score": round(score, 4),

            "metadata": {
                "records_processed":         count,
                "semantic_collisions":       self.collision_count,
                "collision_rate":            round(
                    self.collision_count / max(1, count), 4
                ),
                "missing_fields_found":      self.missing_field_count,
                "bad_json_lines":            self.bad_json_count,
                "timestamp_jitter_verified": global_jitter_verified,
                "deterministic_mode":        DETERMINISTIC_MODE,

                "per_layer": {
                    name: self._layers[name].to_dict()
                    for name in ("intent", "execution", "remediation")
                },
                "layer_counts": {
                    name: self._layers[name].to_dict()["record_count"]
                    for name in ("intent", "execution", "remediation")
                },
            },
        }

        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w") as f:
                json.dump(result, f, indent=4)
        except OSError as e:
            logging.error(f"Could not write output to {path}: {e}")

        logging.info(
            f"Finalized. Valid={valid}, Score={score:.4f}, "
            f"Records={count}, Collisions={self.collision_count}, "
            f"BadJSON={self.bad_json_count}, "
            f"BatchID={result['batch_id'][:8]}..."
        )
        return result


if __name__ == "__main__":
    config = {
        "dlp_id":      2,
        "input_dir":   "dataset/jsonl",
        "output_path": "./output/results.json",
    }

    print("CCEG Proof Engine v2.0")
    print("=" * 52)
    print(f"  Input dir      : {config['input_dir']}")
    print(f"  Output path    : {config['output_path']}")
    print(f"  Deterministic  : {DETERMINISTIC_MODE}")
    print()

    engine = Proof(config)
    result = engine.generate()

    print()
    if result["valid"]:
        print("SUCCESS  PROOF VALID")
    else:
        print("FAILED   PROOF INVALID — check if enough records exist in input dir")

    print(f"    Score          : {result['score']}")
    print(f"    Batch ID       : {result['batch_id']}")
    print(f"    Dataset hash   : {result['dataset_hash'][:24]}...")
    print(f"    Merkle root    : {result['dataset_merkle_root'][:24]}...")
    print(f"    Records        : {result['metadata']['records_processed']}")
    print(f"    Layer counts   : {result['metadata']['layer_counts']}")
    print(f"    Collisions     : {result['metadata']['semantic_collisions']}"
          f"  (rate={result['metadata']['collision_rate']})")
    print(f"    Bad JSON lines : {result['metadata']['bad_json_lines']}")
    print(f"    Missing fields : {result['metadata']['missing_fields_found']}")
    print(f"    Jitter verified: {result['metadata']['timestamp_jitter_verified']}")
    print()
    print("  Per-layer stats:")
    for layer, stats in result["metadata"]["per_layer"].items():
        j = stats["jitter"]
        e = stats["entropy"]
        print(f"    [{layer:12s}]  records={stats['record_count']:5d}  "
              f"score={stats['avg_score']:.3f}  "
              f"entropy(mean={e['mean']:.2f})  "
              f"jitter_std={j['std_dev_s']:.4f}s  "
              f"verified={j['verified']}  "
              f"collisions={stats['collisions']}  "
              f"bad_json={stats['bad_json_lines']}")
    print()
    print(f"    Results saved to: {config['output_path']}")
