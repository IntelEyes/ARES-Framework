"""
ARES-Bench Dataset Writer.

Writes evaluation records to JSON/JSONL/CSV files and optionally to PostgreSQL.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.config import Config
from shared.shared_models import EvalRecord

config = Config()


class DatasetWriter:
    """Writes evaluation records to various output formats."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.records: List[Dict] = []

    def add_record(self, record: Dict) -> None:
        """Add a single evaluation record."""
        self.records.append(record)

    def add_records(self, records: List[Dict]) -> None:
        """Add multiple evaluation records."""
        self.records.extend(records)

    def write_jsonl(self, filename: str = "ares_bench_dataset.jsonl") -> str:
        """Write records as JSONL (one JSON object per line)."""
        filepath = self.output_dir / filename
        with open(filepath, "w") as f:
            for record in self.records:
                f.write(json.dumps(record, default=str) + "\n")
        return str(filepath)

    def write_json(self, filename: str = "ares_bench_dataset.json") -> str:
        """Write records as a single JSON array."""
        filepath = self.output_dir / filename
        with open(filepath, "w") as f:
            json.dump(self.records, f, indent=2, default=str)
        return str(filepath)

    def write_csv(self, filename: str = "ares_bench_dataset.csv") -> str:
        """Write records as CSV with flattened columns."""
        if not self.records:
            return ""

        filepath = self.output_dir / filename

        # Flatten records for CSV
        flat_records = [self._flatten_record(r) for r in self.records]

        # Get all unique keys
        all_keys = set()
        for r in flat_records:
            all_keys.update(r.keys())
        fieldnames = sorted(all_keys)

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for record in flat_records:
                writer.writerow(record)

        return str(filepath)

    def write_summary(self, filename: str = "ares_bench_summary.json") -> str:
        """Write aggregate summary statistics."""
        filepath = self.output_dir / filename
        summary = self._compute_summary()
        with open(filepath, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        return str(filepath)

    def _flatten_record(self, record: Dict) -> Dict:
        """Flatten nested record for CSV output."""
        flat = {}
        for key, val in record.items():
            if key == "mismatch_vector" and isinstance(val, dict):
                for mk, mv in val.items():
                    flat[mk] = mv
            elif key == "taxonomy_codes" and isinstance(val, dict):
                for tk, tv in val.items():
                    flat[f"taxonomy_{tk}"] = tv
            elif isinstance(val, (dict, list)):
                flat[key] = json.dumps(val, default=str)
            else:
                flat[key] = val
        return flat

    def _compute_summary(self) -> Dict:
        """Compute summary statistics."""
        if not self.records:
            return {"total": 0}

        ars_scores = [r.get("ars_score", 0) for r in self.records]
        e_gaps = [r.get("epistemic_gap", 0) for r in self.records]

        n = len(ars_scores)
        mean_ars = sum(ars_scores) / n
        std_ars = (sum((a - mean_ars) ** 2 for a in ars_scores) / n) ** 0.5

        return {
            "total_records": n,
            "generated_at": datetime.utcnow().isoformat(),
            "ars": {
                "mean": round(mean_ars, 4),
                "std": round(std_ars, 4),
                "min": round(min(ars_scores), 4),
                "max": round(max(ars_scores), 4),
            },
            "epistemic_gap": {
                "mean": round(sum(e_gaps) / n, 4),
            },
            "anomaly_rate": round(
                sum(1 for r in self.records if r.get("anomaly_flag")) / n, 4
            ),
            "by_architecture": self._group_stats("agent_arch"),
            "by_threat_type": self._group_stats("threat_type"),
        }

    def _group_stats(self, group_key: str) -> Dict:
        """Compute grouped statistics."""
        groups: Dict[str, List[float]] = {}
        for r in self.records:
            g = r.get(group_key, "unknown")
            if g not in groups:
                groups[g] = []
            groups[g].append(r.get("ars_score", 0))

        result = {}
        for g, scores in groups.items():
            n = len(scores)
            mean = sum(scores) / n
            result[g] = {
                "count": n,
                "mean_ars": round(mean, 4),
                "min_ars": round(min(scores), 4),
                "max_ars": round(max(scores), 4),
            }
        return result

    def get_record_count(self) -> int:
        return len(self.records)


# ---------------------------------------------------------------------------
# FastAPI service
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench Dataset Writer", version="1.0.0")
    writer = DatasetWriter(output_dir=config.output_dir)

    class RecordRequest(BaseModel):
        record: dict

    class BatchRequest(BaseModel):
        records: List[dict]

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "dataset_writer",
                "record_count": writer.get_record_count()}

    @app.post("/add")
    async def add(req: RecordRequest):
        writer.add_record(req.record)
        return {"status": "ok", "total": writer.get_record_count()}

    @app.post("/add_batch")
    async def add_batch(req: BatchRequest):
        writer.add_records(req.records)
        return {"status": "ok", "total": writer.get_record_count()}

    @app.post("/flush")
    async def flush():
        jsonl_path = writer.write_jsonl()
        json_path = writer.write_json()
        csv_path = writer.write_csv()
        summary_path = writer.write_summary()
        return {
            "jsonl": jsonl_path,
            "json": json_path,
            "csv": csv_path,
            "summary": summary_path,
        }

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[DatasetWriter] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.dataset_writer_port)
