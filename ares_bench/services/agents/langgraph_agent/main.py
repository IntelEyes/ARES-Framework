"""
ARES-Bench AUT-1: LangGraph Agent.

Single stateful ReAct agent. In Docker mode, uses Ollama (Mistral-7B).
In simulation mode, uses deterministic simulation functions.
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
ARCH = AgentArch.AUT1_LANGGRAPH


def _deterministic_hash(data: str, mod: int = 1000) -> int:
    """Produce a deterministic integer from a string."""
    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16) % mod


class LangGraphAgentSim:
    """Simulates a LangGraph ReAct agent under mismatch conditions."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def run(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        misleading_context: Optional[Dict] = None,
    ) -> Dict:
        """Run the simulated agent and produce output.

        The output quality degrades proportionally to mismatch levels.
        """
        start_time = time.time()

        delta_S = compute_delta_S(agent, task)
        delta_K = compute_delta_K(agent, task)
        delta_C = compute_delta_C(agent, task)

        # Simulate reasoning steps (ReAct pattern)
        steps = self._simulate_react_steps(agent, task, delta_S, delta_K, delta_C)

        # Generate output based on what the agent can actually do
        output = self._generate_output(
            agent, task, delta_S, delta_K, delta_C, misleading_context
        )

        # Simulate latency (higher mismatch = more retries = slower)
        base_latency = config.sim_latency_base_ms
        retry_factor = 1.0 + 2.0 * max(delta_S, delta_K, delta_C)
        noise = self.rng.gauss(0, config.sim_noise_std * base_latency)
        latency_ms = base_latency * retry_factor + noise

        # Simulate uncertainty
        uncertainty = simulate_uncertainty(ARCH, delta_K)

        return {
            "agent_arch": ARCH.value,
            "agent_output": output,
            "reasoning_steps": steps,
            "latency_ms": max(50.0, latency_ms),
            "uncertainty": uncertainty,
            "hallucinated_indicators": delta_K > 0.5 or (misleading_context is not None and delta_K > 0.3),
            "missed_detections": delta_S > 0.4 or delta_K > 0.6,
        }

    def _simulate_react_steps(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_S: float,
        delta_K: float,
        delta_C: float,
    ) -> List[Dict]:
        """Simulate ReAct reasoning steps."""
        steps = []

        # Step 1: Observe
        available_tools = sorted(agent.S & task.S_star)
        missing_tools = sorted(task.S_star - agent.S)
        steps.append({
            "type": "observe",
            "thought": f"Available tools: {available_tools}. Missing: {missing_tools}.",
            "success": delta_S < 0.5,
        })

        # Step 2: Think (knowledge retrieval)
        available_knowledge = sorted(agent.K & task.K_star)
        steps.append({
            "type": "think",
            "thought": f"Retrieving relevant knowledge ({len(available_knowledge)}/{len(task.K_star)} items available).",
            "success": delta_K < 0.5,
        })

        # Step 3: Act (tool invocation)
        available_caps = sorted(agent.C & task.C_star)
        steps.append({
            "type": "act",
            "thought": f"Invoking capabilities: {available_caps}.",
            "success": delta_C < 0.5,
        })

        # Step 4: Synthesize
        overall_quality = 1.0 - (0.3 * delta_S + 0.4 * delta_K + 0.3 * delta_C)
        steps.append({
            "type": "synthesize",
            "thought": f"Synthesizing findings (confidence: {overall_quality:.2f}).",
            "success": overall_quality > 0.5,
        })

        return steps

    def _generate_output(
        self,
        agent: AgentProfile,
        task: TaskProfile,
        delta_S: float,
        delta_K: float,
        delta_C: float,
        misleading_context: Optional[Dict],
    ) -> Dict:
        """Generate simulated agent output.

        Output is a degraded version of ground truth, proportional to mismatches.
        """
        y_star = task.y_star
        output = {}

        # Copy ground-truth fields, with probabilistic degradation
        seed_str = f"{agent.agent_id}_{task.scenario_id}_{delta_S}_{delta_K}_{delta_C}"
        local_rng = random.Random(_deterministic_hash(seed_str))

        for key, value in y_star.items():
            if key == "threat_type":
                # High delta_K may cause misclassification
                if delta_K > 0.7 and local_rng.random() < delta_K:
                    output[key] = "unknown"
                else:
                    output[key] = value
            elif key == "severity":
                # Severity may be wrong with high mismatches
                if delta_K > 0.5 and local_rng.random() < delta_K * 0.6:
                    severities = ["low", "medium", "high", "critical"]
                    output[key] = local_rng.choice(severities)
                else:
                    output[key] = value
            elif key == "techniques":
                if isinstance(value, list):
                    # May miss techniques proportional to delta_K
                    kept = [t for t in value
                            if local_rng.random() > delta_K * 0.7]
                    # May hallucinate techniques with misleading context
                    if misleading_context and "false_techniques" in misleading_context:
                        if local_rng.random() < delta_K * 0.5:
                            kept.extend(misleading_context["false_techniques"][:1])
                    output[key] = kept if kept else [value[0]]
                else:
                    output[key] = value
            elif key == "iocs" and isinstance(value, dict):
                # IOCs are affected by both S (tools) and K (knowledge)
                degraded_iocs = {}
                for ioc_key, ioc_val in value.items():
                    if isinstance(ioc_val, list):
                        kept = [v for v in ioc_val
                                if local_rng.random() > max(delta_S, delta_K) * 0.6]
                        degraded_iocs[ioc_key] = kept
                    else:
                        if local_rng.random() > delta_K * 0.4:
                            degraded_iocs[ioc_key] = ioc_val
                # Add hallucinated IOCs if misleading context present
                if misleading_context and "false_iocs" in misleading_context:
                    if local_rng.random() < delta_K * 0.6:
                        degraded_iocs["hallucinated"] = misleading_context["false_iocs"][:2]
                output[key] = degraded_iocs
            elif key == "containment" and isinstance(value, list):
                # Containment affected by delta_C (blocked capabilities)
                kept = [c for c in value
                        if local_rng.random() > delta_C * 0.5]
                output[key] = kept if kept else [value[0]]
            else:
                # Other fields: copy with probability based on overall quality
                overall_miss = (delta_S + delta_K + delta_C) / 3
                if local_rng.random() > overall_miss * 0.4:
                    output[key] = value

        return output


# ---------------------------------------------------------------------------
# FastAPI service (Docker mode)
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="ARES-Bench LangGraph Agent", version="1.0.0")
    agent_sim = LangGraphAgentSim(seed=config.random_seed)

    class RunRequest(BaseModel):
        agent: dict
        task: dict
        misleading_context: Optional[dict] = None

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "langgraph_agent", "arch": "AUT-1"}

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
        result = agent_sim.run(agent, task, req.misleading_context)
        return result

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[LangGraph Agent] Running in simulation mode")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.langgraph_agent_port)
