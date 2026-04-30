"""
ARES-Bench Scenario Engine.

Generates and serves threat scenarios for evaluation. In Docker mode, runs
as a FastAPI service. In simulation mode, can be imported directly.
"""

from __future__ import annotations

import json
import os
import sys
import random
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.config import Config
from shared.shared_models import TaskProfile, ThreatType, AgentArch, AgentProfile
from shared.attack_data import (
    THREAT_SCENARIOS,
    ThreatScenario,
    build_task_profile,
    get_scenarios_for_type,
)

config = Config()


# ---------------------------------------------------------------------------
# Agent baseline profiles (full capabilities)
# ---------------------------------------------------------------------------
def _build_full_agent(arch: AgentArch, task: TaskProfile) -> AgentProfile:
    """Build a fully-capable agent profile for a given task."""
    return AgentProfile(
        agent_id=f"{arch.value}_{task.scenario_id}",
        arch=arch,
        S=set(task.S_star),
        K=set(task.K_star),
        C=set(task.C_star),
        R=1.0 if arch == AgentArch.AUT4_RULEBASED else 0.95,
        T_age=0.0,
    )


# ---------------------------------------------------------------------------
# Scenario generation
# ---------------------------------------------------------------------------
class ScenarioEngine:
    """Generates evaluation scenarios (task + agent profile pairs)."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.scenarios = THREAT_SCENARIOS

    def get_all_scenario_ids(self) -> List[str]:
        return sorted(self.scenarios.keys())

    def get_scenario(self, scenario_id: str) -> ThreatScenario:
        return self.scenarios[scenario_id]

    def build_task(self, scenario_id: str) -> TaskProfile:
        return build_task_profile(self.scenarios[scenario_id])

    def build_agent(self, arch: AgentArch, task: TaskProfile) -> AgentProfile:
        return _build_full_agent(arch, task)

    def generate_eval_matrix(self) -> List[Dict]:
        """Generate the full evaluation matrix:
        scenarios x agents x mismatch_levels.

        Returns list of dicts with scenario_id, agent_arch,
        and target mismatch levels.
        """
        from shared.shared_models import MISMATCH_LEVELS

        matrix = []
        for scenario_id in self.get_all_scenario_ids():
            for arch in AgentArch:
                for ds in MISMATCH_LEVELS:
                    for dk in MISMATCH_LEVELS:
                        for dc in MISMATCH_LEVELS:
                            matrix.append({
                                "scenario_id": scenario_id,
                                "agent_arch": arch.value,
                                "target_delta_S": ds,
                                "target_delta_K": dk,
                                "target_delta_C": dc,
                            })
        return matrix

    def generate_sparse_matrix(self, samples_per_cell: int = 3) -> List[Dict]:
        """Generate a sparse evaluation matrix suitable for experiments.

        Instead of full grid, sample representative combinations.
        """
        from shared.shared_models import MISMATCH_LEVELS

        matrix = []
        for scenario_id in self.get_all_scenario_ids():
            for arch in AgentArch:
                # Single-dimension sweeps (hold others at 0)
                for dim in ["S", "K", "C"]:
                    for level in MISMATCH_LEVELS:
                        entry = {
                            "scenario_id": scenario_id,
                            "agent_arch": arch.value,
                            "target_delta_S": level if dim == "S" else 0.0,
                            "target_delta_K": level if dim == "K" else 0.0,
                            "target_delta_C": level if dim == "C" else 0.0,
                        }
                        matrix.append(entry)

                # Compound mismatches (random combinations)
                for _ in range(samples_per_cell):
                    entry = {
                        "scenario_id": scenario_id,
                        "agent_arch": arch.value,
                        "target_delta_S": self.rng.choice(MISMATCH_LEVELS),
                        "target_delta_K": self.rng.choice(MISMATCH_LEVELS),
                        "target_delta_C": self.rng.choice(MISMATCH_LEVELS),
                    }
                    matrix.append(entry)

        return matrix


# ---------------------------------------------------------------------------
# FastAPI service (Docker mode)
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI

    app = FastAPI(title="ARES-Bench Scenario Engine", version="1.0.0")
    engine = ScenarioEngine(seed=config.random_seed)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "scenario_engine"}

    @app.get("/scenarios")
    async def list_scenarios():
        return {"scenario_ids": engine.get_all_scenario_ids()}

    @app.get("/scenarios/{scenario_id}")
    async def get_scenario(scenario_id: str):
        scenario = engine.get_scenario(scenario_id)
        task = engine.build_task(scenario_id)
        return {
            "scenario": {
                "scenario_id": scenario.scenario_id,
                "name": scenario.name,
                "threat_type": scenario.threat_type.value,
                "description": scenario.description,
                "difficulty": scenario.difficulty,
                "attack_techniques": scenario.attack_techniques,
            },
            "task": task.to_dict(),
        }

    @app.get("/eval_matrix")
    async def eval_matrix(sparse: bool = True, samples: int = 3):
        if sparse:
            return {"matrix": engine.generate_sparse_matrix(samples)}
        return {"matrix": engine.generate_eval_matrix()}

    @app.post("/agent_profile")
    async def agent_profile(scenario_id: str, arch: str):
        task = engine.build_task(scenario_id)
        agent = engine.build_agent(AgentArch(arch), task)
        return agent.to_dict()

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[ScenarioEngine] Running in simulation mode")
        engine = ScenarioEngine()
        scenarios = engine.get_all_scenario_ids()
        print(f"  Available scenarios: {scenarios}")
        matrix = engine.generate_sparse_matrix(samples_per_cell=2)
        print(f"  Sparse matrix entries: {len(matrix)}")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.scenario_engine_port)
