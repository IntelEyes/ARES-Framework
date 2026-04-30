"""
ARES-Bench Mismatch Injector.

Injects controlled SKC mismatches into agent profiles.
4 levels per dimension: {0.0, 0.33, 0.66, 1.0}

- delta_S: disable tool/skill nodes
- delta_K: filter ATT&CK knowledge context
- delta_C: block API/tool access
- delta_R: inject misleading context (indirect, via degraded inputs)
"""

from __future__ import annotations

import math
import os
import random
import sys
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.config import Config
from shared.shared_models import (
    AgentProfile,
    TaskProfile,
    MismatchVector,
    AgentArch,
    MISMATCH_LEVELS,
)

config = Config()


class MismatchInjector:
    """Injects controlled mismatches into agent profiles."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def inject(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        target_delta_S: float = 0.0,
        target_delta_K: float = 0.0,
        target_delta_C: float = 0.0,
        target_T_age: float = 0.0,
    ) -> AgentProfile:
        """Inject mismatches by degrading agent capabilities.

        Returns a new AgentProfile with capabilities removed to match
        the target mismatch levels.
        """
        new_S = self._degrade_set(agent.S, task.S_star, target_delta_S)
        new_K = self._degrade_set(agent.K, task.K_star, target_delta_K)
        new_C = self._degrade_set(agent.C, task.C_star, target_delta_C)

        return AgentProfile(
            agent_id=agent.agent_id,
            arch=agent.arch,
            S=new_S,
            K=new_K,
            C=new_C,
            R=agent.R,
            T_age=target_T_age,
        )

    def _degrade_set(
        self,
        agent_set: Set[str],
        required_set: Set[str],
        target_delta: float,
    ) -> Set[str]:
        """Remove items from agent_set to achieve target delta.

        delta = |required \\ agent| / |required|
        To achieve target_delta, we need to remove
        target_delta * |required| items from agent that are in required.
        """
        if not required_set:
            return set(agent_set)

        # Items the agent has that are also required
        overlap = agent_set & required_set
        # Items not in required (keep these)
        non_required = agent_set - required_set

        # Number of required items to remove
        n_remove = round(target_delta * len(required_set))
        n_remove = min(n_remove, len(overlap))

        if n_remove == 0:
            return set(agent_set)

        # Randomly select items to remove (deterministic via seeded rng)
        overlap_list = sorted(overlap)
        self.rng.shuffle(overlap_list)
        to_remove = set(overlap_list[:n_remove])

        return (agent_set - to_remove)

    def inject_reasoning_noise(
        self,
        agent: AgentProfile,
        target_delta_R: float,
    ) -> Dict:
        """Generate misleading context to inject into agent's input.

        Returns a dict of misleading elements proportional to target_delta_R.
        """
        if target_delta_R <= 0.0:
            return {}

        misleading_elements = {
            "false_iocs": [
                "192.168.1.100",  # Internal IP presented as C2
                "sha256:deadbeef" * 4,  # Fake hash
                "evil-domain.example.com",  # Non-existent domain
            ],
            "wrong_attribution": [
                "APT29/Cozy Bear",
                "Lazarus Group",
                "FIN7",
            ],
            "false_techniques": [
                "T1190",  # Wrong technique for scenario
                "T1566",
                "T1498",
            ],
            "misleading_context": [
                "Previous analysis confirmed this is a false positive",
                "Vendor advisory states this CVE is not exploitable",
                "Threat intel indicates campaign ended 6 months ago",
            ],
        }

        # Select proportion of misleading elements based on target_delta_R
        result = {}
        for key, items in misleading_elements.items():
            n_select = max(1, round(target_delta_R * len(items)))
            result[key] = items[:n_select]

        return result

    def compute_actual_deltas(
        self,
        degraded_agent: AgentProfile,
        task: TaskProfile,
    ) -> Dict[str, float]:
        """Compute actual mismatch levels after injection."""
        from shared.shared_models import (
            compute_delta_S,
            compute_delta_K,
            compute_delta_C,
            compute_delta_T,
        )
        return {
            "delta_S": compute_delta_S(degraded_agent, task),
            "delta_K": compute_delta_K(degraded_agent, task),
            "delta_C": compute_delta_C(degraded_agent, task),
            "delta_T": compute_delta_T(degraded_agent, task),
        }

    def generate_injection_plan(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        target_delta_S: float,
        target_delta_K: float,
        target_delta_C: float,
    ) -> Dict:
        """Generate a detailed injection plan showing what will be removed."""
        overlap_S = agent.S & task.S_star
        overlap_K = agent.K & task.K_star
        overlap_C = agent.C & task.C_star

        n_remove_S = round(target_delta_S * len(task.S_star)) if task.S_star else 0
        n_remove_K = round(target_delta_K * len(task.K_star)) if task.K_star else 0
        n_remove_C = round(target_delta_C * len(task.C_star)) if task.C_star else 0

        return {
            "skills": {
                "total_required": len(task.S_star),
                "agent_has": len(overlap_S),
                "will_remove": min(n_remove_S, len(overlap_S)),
                "target_delta": target_delta_S,
            },
            "knowledge": {
                "total_required": len(task.K_star),
                "agent_has": len(overlap_K),
                "will_remove": min(n_remove_K, len(overlap_K)),
                "target_delta": target_delta_K,
            },
            "capabilities": {
                "total_required": len(task.C_star),
                "agent_has": len(overlap_C),
                "will_remove": min(n_remove_C, len(overlap_C)),
                "target_delta": target_delta_C,
            },
        }


# ---------------------------------------------------------------------------
# FastAPI service (Docker mode)
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench Mismatch Injector", version="1.0.0")
    injector = MismatchInjector(seed=config.random_seed)

    class InjectRequest(BaseModel):
        agent: dict
        task: dict
        target_delta_S: float = 0.0
        target_delta_K: float = 0.0
        target_delta_C: float = 0.0
        target_T_age: float = 0.0

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "mismatch_injector"}

    @app.post("/inject")
    async def inject(req: InjectRequest):
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
        degraded = injector.inject(
            agent, task,
            req.target_delta_S, req.target_delta_K,
            req.target_delta_C, req.target_T_age,
        )
        actuals = injector.compute_actual_deltas(degraded, task)
        return {
            "degraded_agent": degraded.to_dict(),
            "actual_deltas": actuals,
        }

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[MismatchInjector] Running in simulation mode")
        injector = MismatchInjector()
        print("  Mismatch levels:", MISMATCH_LEVELS)
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.mismatch_injector_port)
