"""
ARES-Bench AUT-3: CrewAI Agent.

Role-based multi-agent: analyst + TI enricher + incident commander.
In simulation mode, deterministic functions model role-based collaboration.
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
)

config = Config()
ARCH = AgentArch.AUT3_CREWAI


def _deterministic_hash(data: str, mod: int = 1000) -> int:
    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16) % mod


class CrewAIAgentSim:
    """Simulates CrewAI role-based agent under mismatch conditions.

    Roles:
    - Analyst: detection and initial analysis (uses S primarily)
    - TI Enricher: threat intelligence enrichment (uses K primarily)
    - Incident Commander: response coordination (uses C primarily)

    Each role has access to the full agent profile but specializes
    in one dimension. Role-based collaboration can compensate for
    individual weaknesses.
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

        # Run each role
        analyst_result = self._role_analyst(agent, task, delta_S, delta_K)
        enricher_result = self._role_enricher(
            agent, task, delta_K, analyst_result, misleading_context
        )
        commander_result = self._role_commander(
            agent, task, delta_C, analyst_result, enricher_result
        )

        # CrewAI advantage: roles can cross-validate and compensate
        output = self._collaborative_merge(
            analyst_result, enricher_result, commander_result,
            delta_S, delta_K, delta_C,
        )

        # Latency: parallel roles + coordination overhead
        base_latency = config.sim_latency_base_ms * 1.3
        retry_factor = 1.0 + 1.2 * max(delta_S, delta_K, delta_C)
        noise = self.rng.gauss(0, config.sim_noise_std * base_latency)
        latency_ms = base_latency * retry_factor + noise

        uncertainty = simulate_uncertainty(ARCH, delta_K)

        # CrewAI has slightly better uncertainty calibration due to
        # cross-role validation
        uncertainty = min(1.0, uncertainty * 1.1)

        return {
            "agent_arch": ARCH.value,
            "agent_output": output,
            "role_outputs": {
                "analyst": analyst_result,
                "enricher": enricher_result,
                "commander": commander_result,
            },
            "latency_ms": max(70.0, latency_ms),
            "uncertainty": uncertainty,
            "hallucinated_indicators": enricher_result.get("hallucinated", False),
            "missed_detections": analyst_result.get("missed", False),
        }

    def _role_analyst(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_S: float,
        delta_K: float,
    ) -> Dict:
        """Analyst role: detection and initial analysis."""
        y_star = task.y_star
        seed_str = f"analyst_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        # Analyst relies heavily on skills/tools
        detected_type = y_star.get("threat_type", "unknown")
        if delta_S > 0.6 and local_rng.random() < delta_S * 0.5:
            detected_type = "unknown"

        severity = y_star.get("severity", "medium")
        if delta_S > 0.4 and local_rng.random() < delta_S * 0.4:
            severities = ["low", "medium", "high", "critical"]
            severity = local_rng.choice(severities)

        # Analyst can detect some IOCs through tools
        iocs = {}
        if "iocs" in y_star and isinstance(y_star["iocs"], dict):
            for k, v in y_star["iocs"].items():
                if isinstance(v, list):
                    iocs[k] = [i for i in v if local_rng.random() > delta_S * 0.5]
                elif local_rng.random() > delta_S * 0.3:
                    iocs[k] = v

        return {
            "threat_type": detected_type,
            "severity": severity,
            "detected_iocs": iocs,
            "confidence": max(0.1, 1.0 - delta_S * 0.5 - delta_K * 0.2),
            "missed": delta_S > 0.5,
        }

    def _role_enricher(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_K: float,
        analyst_result: Dict,
        misleading_context: Optional[Dict],
    ) -> Dict:
        """TI Enricher role: threat intelligence enrichment."""
        y_star = task.y_star
        seed_str = f"enricher_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        techniques = y_star.get("techniques", [])
        if isinstance(techniques, list):
            kept = [t for t in techniques if local_rng.random() > delta_K * 0.55]
        else:
            kept = [techniques] if local_rng.random() > delta_K else []

        hallucinated = False
        if misleading_context and delta_K > 0.35:
            if "false_techniques" in misleading_context:
                if local_rng.random() < delta_K * 0.45:
                    kept.extend(misleading_context["false_techniques"][:1])
                    hallucinated = True

        return {
            "techniques": kept if kept else [],
            "enrichment_quality": max(0.0, 1.0 - delta_K),
            "hallucinated": hallucinated,
        }

    def _role_commander(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_C: float,
        analyst_result: Dict,
        enricher_result: Dict,
    ) -> Dict:
        """Incident Commander role: response coordination."""
        y_star = task.y_star
        seed_str = f"commander_{agent.agent_id}_{task.scenario_id}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        containment = y_star.get("containment", [])
        if isinstance(containment, list):
            kept = [c for c in containment if local_rng.random() > delta_C * 0.45]
        else:
            kept = [containment] if local_rng.random() > delta_C else []

        return {
            "containment": kept if kept else ["escalate_to_human"],
            "response_quality": max(0.0, 1.0 - delta_C * 0.8),
        }

    def _collaborative_merge(
        self,
        analyst: Dict,
        enricher: Dict,
        commander: Dict,
        delta_S: float,
        delta_K: float,
        delta_C: float,
    ) -> Dict:
        """Merge role outputs with cross-validation.

        CrewAI's advantage: roles can compensate for each other.
        If analyst missed something but enricher has context, partial recovery.
        """
        output = {
            "threat_type": analyst.get("threat_type", "unknown"),
            "severity": analyst.get("severity", "medium"),
        }

        # Cross-validation: if analyst has low confidence but enricher has
        # good coverage, boost the output
        if analyst.get("confidence", 0) < 0.5 and enricher.get("enrichment_quality", 0) > 0.6:
            # Enricher can partially compensate for analyst's weakness
            if enricher.get("techniques"):
                output["techniques"] = enricher["techniques"]
        elif enricher.get("techniques"):
            output["techniques"] = enricher["techniques"]

        # Merge IOCs from analyst
        if analyst.get("detected_iocs"):
            output["iocs"] = analyst["detected_iocs"]

        # Commander's containment actions
        if commander.get("containment"):
            output["containment"] = commander["containment"]

        return output


# ---------------------------------------------------------------------------
# FastAPI service
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench CrewAI Agent", version="1.0.0")
    agent_sim = CrewAIAgentSim(seed=config.random_seed)

    class RunRequest(BaseModel):
        agent: dict
        task: dict
        misleading_context: Optional[dict] = None

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "crewai_agent", "arch": "AUT-3"}

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
        print("[CrewAI Agent] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.crewai_agent_port)
