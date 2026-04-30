"""
ARES-Bench AUT-4: Rule-Based Agent.

Deterministic YARA/Sigma baseline. delta_R = 0, no hallucination.
Output is strictly determined by available tools, knowledge, and capabilities.
"""

from __future__ import annotations

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
    simulate_uncertainty,
    compute_delta_S,
    compute_delta_K,
    compute_delta_C,
)

config = Config()
ARCH = AgentArch.AUT4_RULEBASED


class RuleBasedAgentSim:
    """Simulates a deterministic rule-based agent.

    Key properties:
    - delta_R = 0 always (no hallucination)
    - Output is strictly determined by available S, K, C
    - Higher uncertainty awareness (well-calibrated)
    - Cannot reason beyond its rules -- hard cutoff
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

        # Rule-based agent ignores misleading context entirely
        # (rules don't get "tricked" by injected context)

        output = self._deterministic_output(agent, task, delta_S, delta_K, delta_C)

        # Latency: rule-based is fast, but slows with missing tools
        base_latency = config.sim_latency_base_ms * 0.3  # Much faster
        factor = 1.0 + 0.5 * delta_S  # Slight slowdown when tools are missing
        noise = self.rng.gauss(0, config.sim_noise_std * base_latency * 0.5)
        latency_ms = base_latency * factor + noise

        # Rule-based has high uncertainty calibration
        uncertainty = simulate_uncertainty(ARCH, delta_K)

        return {
            "agent_arch": ARCH.value,
            "agent_output": output,
            "latency_ms": max(20.0, latency_ms),
            "uncertainty": uncertainty,
            "hallucinated_indicators": False,  # Never hallucinates
            "missed_detections": delta_S > 0.3 or delta_K > 0.4,
        }

    def _deterministic_output(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_S: float,
        delta_K: float,
        delta_C: float,
    ) -> Dict:
        """Generate strictly deterministic output.

        For each field in ground truth, the rule-based agent can only
        produce it if it has the relevant tools/knowledge/capabilities.
        No guessing, no interpolation.
        """
        y_star = task.y_star
        output = {}

        # Available resources
        available_S = agent.S & task.S_star
        available_K = agent.K & task.K_star
        available_C = agent.C & task.C_star

        # Threat type: need at least some knowledge to classify
        if delta_K <= 0.5:
            output["threat_type"] = y_star.get("threat_type", "unknown")
        else:
            output["threat_type"] = "unclassified"

        # Severity: need tools to assess
        if delta_S <= 0.4 and delta_K <= 0.4:
            output["severity"] = y_star.get("severity", "unknown")
        else:
            output["severity"] = "unknown"

        # Techniques: only report what we have rules for
        techniques = y_star.get("techniques", [])
        if isinstance(techniques, list) and delta_K < 1.0:
            # Keep techniques proportional to available knowledge
            coverage = 1.0 - delta_K
            n_keep = max(0, round(len(techniques) * coverage))
            output["techniques"] = sorted(techniques)[:n_keep]
        else:
            output["techniques"] = []

        # IOCs: strictly from tool output, no fabrication
        if "iocs" in y_star and isinstance(y_star["iocs"], dict):
            iocs = {}
            for key, val in y_star["iocs"].items():
                if isinstance(val, list):
                    # Keep IOCs proportional to available skills
                    coverage = 1.0 - delta_S
                    n_keep = max(0, round(len(val) * coverage))
                    if n_keep > 0:
                        iocs[key] = sorted(str(v) for v in val)[:n_keep]
                elif delta_S <= 0.5:
                    iocs[key] = val
            if iocs:
                output["iocs"] = iocs

        # Containment: need capabilities to recommend
        containment = y_star.get("containment", [])
        if isinstance(containment, list) and delta_C < 1.0:
            coverage = 1.0 - delta_C
            n_keep = max(0, round(len(containment) * coverage))
            output["containment"] = containment[:n_keep]
        else:
            output["containment"] = []

        # Additional fields: copy if all dimensions are available
        for key, val in y_star.items():
            if key not in output:
                overall = (delta_S + delta_K + delta_C) / 3
                if overall <= 0.3:
                    output[key] = val

        return output


# ---------------------------------------------------------------------------
# FastAPI service
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench Rule-Based Agent", version="1.0.0")
    agent_sim = RuleBasedAgentSim(seed=config.random_seed)

    class RunRequest(BaseModel):
        agent: dict
        task: dict
        misleading_context: Optional[dict] = None

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "rulebased_agent", "arch": "AUT-4"}

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
        print("[Rule-Based Agent] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.rulebased_agent_port)
