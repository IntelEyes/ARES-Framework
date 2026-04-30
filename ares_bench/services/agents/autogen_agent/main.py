"""
ARES-Bench AUT-2: AutoGen Agent.

3-stage pipeline (triage -> enrichment -> recommendation) for cascade testing.
In Docker mode, uses Ollama. In simulation mode, deterministic functions.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import sys
import time
from typing import Dict, List, Optional, Set

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from shared.config import Config
from shared.shared_models import (
    AgentArch,
    AgentProfile,
    TaskProfile,
    MismatchVector,
    simulate_delta_R,
    simulate_uncertainty,
    compute_delta_S,
    compute_delta_K,
    compute_delta_C,
    compute_cascade_ars,
    compute_ars,
)

config = Config()
ARCH = AgentArch.AUT2_AUTOGEN


def _deterministic_hash(data: str, mod: int = 1000) -> int:
    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16) % mod


class AutoGenAgentSim:
    """Simulates AutoGen 3-stage pipeline under mismatch conditions.

    Stage 1 (Triage): Primarily uses S (skills/tools) for initial detection
    Stage 2 (Enrichment): Primarily uses K (knowledge) for context
    Stage 3 (Recommendation): Primarily uses C (capabilities) for response
    """

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def run(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        misleading_context: Optional[Dict] = None,
    ) -> Dict:
        start_time = time.time()

        delta_S = compute_delta_S(agent, task)
        delta_K = compute_delta_K(agent, task)
        delta_C = compute_delta_C(agent, task)

        # Run 3-stage pipeline
        triage_result = self._stage_triage(agent, task, delta_S, delta_K)
        enrich_result = self._stage_enrichment(
            agent, task, delta_K, triage_result, misleading_context
        )
        recommend_result = self._stage_recommendation(
            agent, task, delta_C, triage_result, enrich_result
        )

        # Compute per-stage ARS for cascade analysis
        stage_mismatch_triage = MismatchVector(
            delta_S=delta_S, delta_K=delta_K * 0.3, delta_C=0.0, delta_R=0.0, delta_T=0.0
        )
        stage_mismatch_enrich = MismatchVector(
            delta_S=0.0, delta_K=delta_K, delta_C=delta_C * 0.3, delta_R=0.0, delta_T=0.0
        )
        stage_mismatch_recommend = MismatchVector(
            delta_S=0.0, delta_K=delta_K * 0.3, delta_C=delta_C, delta_R=0.0, delta_T=0.0
        )

        threat_type = task.threat_type.value
        stage_ars = [
            compute_ars(stage_mismatch_triage, threat_type),
            compute_ars(stage_mismatch_enrich, threat_type),
            compute_ars(stage_mismatch_recommend, threat_type),
        ]

        # Coupling matrix: sequential pipeline
        coupling = [
            [0.0, 0.8, 0.3],  # triage -> enrich (strong), triage -> recommend (weak)
            [0.0, 0.0, 0.9],  # enrich -> recommend (strong)
            [0.0, 0.0, 0.0],  # recommend -> none
        ]

        cascade_ars = compute_cascade_ars(stage_ars, coupling)

        # Merge outputs from all stages
        output = self._merge_outputs(triage_result, enrich_result, recommend_result)

        # Latency: sum of stages
        base_latency = config.sim_latency_base_ms * 1.5  # Pipeline overhead
        retry_factor = 1.0 + 1.5 * max(delta_S, delta_K, delta_C)
        noise = self.rng.gauss(0, config.sim_noise_std * base_latency)
        latency_ms = base_latency * retry_factor + noise

        uncertainty = simulate_uncertainty(ARCH, delta_K)

        return {
            "agent_arch": ARCH.value,
            "agent_output": output,
            "pipeline_stages": {
                "triage": triage_result,
                "enrichment": enrich_result,
                "recommendation": recommend_result,
            },
            "stage_ars": stage_ars,
            "cascade_ars": cascade_ars,
            "latency_ms": max(80.0, latency_ms),
            "uncertainty": uncertainty,
            "hallucinated_indicators": enrich_result.get("hallucinated", False),
            "missed_detections": triage_result.get("missed", False),
        }

    def _stage_triage(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_S: float,
        delta_K: float,
    ) -> Dict:
        """Stage 1: Triage - initial detection and classification."""
        y_star = task.y_star
        seed_str = f"triage_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        detected_type = y_star.get("threat_type", "unknown")
        if delta_S > 0.5 and local_rng.random() < delta_S * 0.6:
            detected_type = "unknown"

        detected_severity = y_star.get("severity", "medium")
        if delta_K > 0.4 and local_rng.random() < delta_K * 0.5:
            severities = ["low", "medium", "high", "critical"]
            detected_severity = local_rng.choice(severities)

        return {
            "threat_type": detected_type,
            "severity": detected_severity,
            "confidence": max(0.1, 1.0 - delta_S * 0.6 - delta_K * 0.3),
            "missed": delta_S > 0.6 or (delta_S > 0.3 and delta_K > 0.5),
        }

    def _stage_enrichment(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_K: float,
        triage_result: Dict,
        misleading_context: Optional[Dict],
    ) -> Dict:
        """Stage 2: Enrichment - knowledge lookup and context."""
        y_star = task.y_star
        seed_str = f"enrich_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        techniques = y_star.get("techniques", [])
        if isinstance(techniques, list):
            kept = [t for t in techniques if local_rng.random() > delta_K * 0.6]
        else:
            kept = [techniques] if local_rng.random() > delta_K else []

        iocs = {}
        if "iocs" in y_star and isinstance(y_star["iocs"], dict):
            for k, v in y_star["iocs"].items():
                if isinstance(v, list):
                    iocs[k] = [i for i in v if local_rng.random() > delta_K * 0.5]
                elif local_rng.random() > delta_K * 0.3:
                    iocs[k] = v

        hallucinated = False
        if misleading_context and delta_K > 0.3:
            if "false_iocs" in misleading_context:
                iocs["suspicious_unverified"] = misleading_context["false_iocs"][:2]
                hallucinated = True
            if "false_techniques" in misleading_context and local_rng.random() < delta_K:
                kept.extend(misleading_context["false_techniques"][:1])
                hallucinated = True

        # Cascade: if triage missed, enrichment quality drops further
        if triage_result.get("missed", False):
            kept = kept[:max(1, len(kept) // 2)]
            hallucinated = hallucinated or (delta_K > 0.3)

        return {
            "techniques": kept,
            "iocs": iocs,
            "hallucinated": hallucinated,
            "knowledge_coverage": max(0.0, 1.0 - delta_K),
        }

    def _stage_recommendation(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_C: float,
        triage_result: Dict,
        enrich_result: Dict,
    ) -> Dict:
        """Stage 3: Recommendation - response actions."""
        y_star = task.y_star
        seed_str = f"recommend_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        containment = y_star.get("containment", [])
        if isinstance(containment, list):
            kept = [c for c in containment if local_rng.random() > delta_C * 0.5]
        else:
            kept = [containment] if local_rng.random() > delta_C else []

        # Cascade: poor triage/enrichment degrades recommendations
        if triage_result.get("missed", False) or enrich_result.get("hallucinated", False):
            kept = kept[:max(1, len(kept) // 2)]
            if enrich_result.get("hallucinated", False) and local_rng.random() < 0.4:
                kept.append("investigate_false_positive")  # Wrong action

        return {
            "containment": kept if kept else ["escalate_to_human"],
            "actionable": delta_C < 0.5 and not triage_result.get("missed", False),
        }

    def _merge_outputs(self, triage: Dict, enrich: Dict, recommend: Dict) -> Dict:
        """Merge pipeline stage outputs into final output."""
        output = {
            "threat_type": triage.get("threat_type", "unknown"),
            "severity": triage.get("severity", "medium"),
        }
        if enrich.get("techniques"):
            output["techniques"] = enrich["techniques"]
        if enrich.get("iocs"):
            output["iocs"] = enrich["iocs"]
        if recommend.get("containment"):
            output["containment"] = recommend["containment"]
        return output


# ---------------------------------------------------------------------------
# FastAPI service
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench AutoGen Agent", version="1.0.0")
    agent_sim = AutoGenAgentSim(seed=config.random_seed)

    class RunRequest(BaseModel):
        agent: dict
        task: dict
        misleading_context: Optional[dict] = None

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "autogen_agent", "arch": "AUT-2"}

    @app.post("/run")
    async def run(req: RunRequest):
        agent = AgentProfile(
            agent_id=req.agent["agent_id"],
            arch=AgentArch(req.agent["arch"]),
            S=set(req.agent.get("S", [])),
            K=set(req.agent.get("K", [])),
            C=set(req.agent.get("C", [])),
            R=req.agent.get("R", 1.0),
            T_age=req.agent.get("T_age", 0.0),
        )
        from shared.shared_models import ThreatType
        task = TaskProfile(
            scenario_id=req.task["scenario_id"],
            threat_type=ThreatType(req.task["threat_type"]),
            S_star=set(req.task.get("S_star", [])),
            K_star=set(req.task.get("K_star", [])),
            C_star=set(req.task.get("C_star", [])),
            y_star=req.task.get("y_star", {}),
        )
        return agent_sim.run(agent, task, req.misleading_context)

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[AutoGen Agent] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.autogen_agent_port)
