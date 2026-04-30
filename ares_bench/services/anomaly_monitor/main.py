"""
ARES-Bench Anomaly Monitor.

Evaluates agent outputs and computes ARS, epistemic gap, anomaly flags,
and taxonomy codes. Central evaluation service.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.config import Config
from shared.shared_models import (
    AgentProfile,
    TaskProfile,
    MismatchVector,
    EvalRecord,
    AgentArch,
    ThreatType,
    compute_ars,
    compute_delta_R,
    compute_delta_T,
    compute_delta_S,
    compute_delta_K,
    compute_delta_C,
    compute_epistemic_gap,
    compute_anomaly_flag,
    compute_cascade_ars,
    simulate_uncertainty,
    simulate_delta_R,
    ARS_THRESHOLD,
    EPISTEMIC_THRESHOLD,
)
from shared.taxonomy import assign_taxonomy

config = Config()


class AnomalyMonitor:
    """Evaluates agent outputs and produces scored evaluation records."""

    def evaluate(
        self,
        run_id: str,
        agent: AgentProfile,
        task: TaskProfile,
        agent_result: Dict,
        timestamp: str = "",
    ) -> EvalRecord:
        """Full evaluation of an agent run.

        Args:
            run_id: unique run identifier
            agent: the (potentially degraded) agent profile
            task: the task profile with ground truth
            agent_result: output from agent.run()
            timestamp: ISO timestamp

        Returns:
            EvalRecord with all computed metrics
        """
        agent_output = agent_result.get("agent_output", {})

        # Compute mismatch vector
        delta_S = compute_delta_S(agent, task)
        delta_K = compute_delta_K(agent, task)
        delta_C = compute_delta_C(agent, task)
        delta_R_val = compute_delta_R(agent_output, task.y_star)
        delta_T = compute_delta_T(agent, task)

        mismatch = MismatchVector(
            delta_S=delta_S,
            delta_K=delta_K,
            delta_C=delta_C,
            delta_R=delta_R_val,
            delta_T=delta_T,
        )

        # Compute ARS
        threat_type = task.threat_type.value
        ars = compute_ars(mismatch, threat_type)

        # Compute uncertainty and epistemic gap
        uncertainty = agent_result.get("uncertainty", simulate_uncertainty(agent.arch, delta_K))
        e_gap = compute_epistemic_gap(delta_K, uncertainty)

        # Anomaly flag
        anomaly = compute_anomaly_flag(ars, e_gap)

        # Taxonomy - use a deterministic rng seeded from the record content
        is_cascade = agent_result.get("cascade_ars") is not None
        import random as _random_mod
        import hashlib as _hashlib
        _tax_seed_str = f"{run_id}_{delta_S}_{delta_K}_{delta_C}_{delta_R_val}"
        _tax_seed = int(_hashlib.sha256(_tax_seed_str.encode()).hexdigest()[:8], 16)
        _tax_rng = _random_mod.Random(_tax_seed)
        taxonomy = assign_taxonomy(
            delta_S, delta_K, delta_C, delta_R_val, delta_T,
            is_cascade=is_cascade,
            agent_output=agent_result,
            rng=_tax_rng,
        )

        # Cascade ARS (if pipeline agent)
        cascade_ars = agent_result.get("cascade_ars")

        return EvalRecord(
            run_id=run_id,
            scenario_id=task.scenario_id,
            threat_type=threat_type,
            agent_arch=agent.arch.value,
            mismatch_vector=mismatch,
            ars_score=ars,
            epistemic_gap=e_gap,
            anomaly_flag=anomaly,
            taxonomy_codes=taxonomy,
            agent_output=agent_output,
            ground_truth=task.y_star,
            cascade_ars=cascade_ars,
            uncertainty=uncertainty,
            latency_ms=agent_result.get("latency_ms", 0.0),
            timestamp=timestamp,
        )

    def evaluate_batch(
        self,
        records: List[Dict],
    ) -> Dict:
        """Compute aggregate statistics over a batch of EvalRecords."""
        if not records:
            return {}

        ars_scores = [r["ars_score"] for r in records]
        e_gaps = [r["epistemic_gap"] for r in records]
        anomaly_rate = sum(1 for r in records if r["anomaly_flag"]) / len(records)

        # Per-architecture stats
        arch_stats = {}
        for arch in ["AUT-1", "AUT-2", "AUT-3", "AUT-4"]:
            arch_records = [r for r in records if r["agent_arch"] == arch]
            if arch_records:
                arch_ars = [r["ars_score"] for r in arch_records]
                arch_stats[arch] = {
                    "count": len(arch_records),
                    "mean_ars": sum(arch_ars) / len(arch_ars),
                    "min_ars": min(arch_ars),
                    "max_ars": max(arch_ars),
                    "anomaly_rate": sum(1 for r in arch_records if r["anomaly_flag"]) / len(arch_records),
                }

        # Per-threat-type stats
        threat_stats = {}
        for tt in ["T1", "T2", "T3", "T4", "T5"]:
            tt_records = [r for r in records if r["threat_type"] == tt]
            if tt_records:
                tt_ars = [r["ars_score"] for r in tt_records]
                threat_stats[tt] = {
                    "count": len(tt_records),
                    "mean_ars": sum(tt_ars) / len(tt_ars),
                    "min_ars": min(tt_ars),
                    "anomaly_rate": sum(1 for r in tt_records if r["anomaly_flag"]) / len(tt_records),
                }

        # Taxonomy distribution
        taxonomy_dist = {}
        for r in records:
            codes = r.get("taxonomy_codes", {})
            for code_type in ["origin", "manifestation", "impact"]:
                code = codes.get(code_type, "unknown")
                key = f"{code_type}:{code}"
                taxonomy_dist[key] = taxonomy_dist.get(key, 0) + 1

        return {
            "total_records": len(records),
            "mean_ars": sum(ars_scores) / len(ars_scores),
            "std_ars": (sum((a - sum(ars_scores)/len(ars_scores))**2 for a in ars_scores) / len(ars_scores)) ** 0.5,
            "mean_epistemic_gap": sum(e_gaps) / len(e_gaps),
            "anomaly_rate": anomaly_rate,
            "by_architecture": arch_stats,
            "by_threat_type": threat_stats,
            "taxonomy_distribution": taxonomy_dist,
        }


# ---------------------------------------------------------------------------
# FastAPI service
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench Anomaly Monitor", version="1.0.0")
    monitor = AnomalyMonitor()

    class EvalRequest(BaseModel):
        run_id: str
        agent: dict
        task: dict
        agent_result: dict
        timestamp: str = ""

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "anomaly_monitor"}

    @app.post("/evaluate")
    async def evaluate(req: EvalRequest):
        agent = AgentProfile(
            agent_id=req.agent["agent_id"],
            arch=AgentArch(req.agent["arch"]),
            S=set(req.agent.get("S", [])),
            K=set(req.agent.get("K", [])),
            C=set(req.agent.get("C", [])),
            R=req.agent.get("R", 1.0),
            T_age=req.agent.get("T_age", 0.0),
        )
        task = TaskProfile(
            scenario_id=req.task["scenario_id"],
            threat_type=ThreatType(req.task["threat_type"]),
            S_star=set(req.task.get("S_star", [])),
            K_star=set(req.task.get("K_star", [])),
            C_star=set(req.task.get("C_star", [])),
            y_star=req.task.get("y_star", {}),
        )
        record = monitor.evaluate(
            req.run_id, agent, task, req.agent_result, req.timestamp
        )
        return record.to_dict()

    @app.post("/batch_stats")
    async def batch_stats(records: List[dict]):
        return monitor.evaluate_batch(records)

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[AnomalyMonitor] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.anomaly_monitor_port)
