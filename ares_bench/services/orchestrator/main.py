"""
ARES-Bench Orchestrator.

Central coordinator that drives the evaluation pipeline:
1. Generate scenarios (ScenarioEngine)
2. Inject mismatches (MismatchInjector)
3. Run agents
4. Evaluate results (AnomalyMonitor)
5. Write dataset (DatasetWriter)

In simulation mode, imports modules directly.
In Docker mode, calls service APIs.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.config import Config
from shared.shared_models import (
    AgentArch,
    AgentProfile,
    TaskProfile,
    MismatchVector,
    ThreatType,
    MISMATCH_LEVELS,
    compute_ars,
    compute_mismatch_vector,
    simulate_delta_R,
)
from shared.attack_data import build_task_profile

config = Config()


class Orchestrator:
    """Orchestrates the full evaluation pipeline in simulation mode."""

    def __init__(self, seed: int = 42):
        from services.scenario_engine.main import ScenarioEngine
        from services.mismatch_injector.main import MismatchInjector
        from services.agents.langgraph_agent.main import LangGraphAgentSim
        from services.agents.autogen_agent.main import AutoGenAgentSim
        from services.agents.crewai_agent.main import CrewAIAgentSim
        from services.agents.rulebased_agent.main import RuleBasedAgentSim
        from services.anomaly_monitor.main import AnomalyMonitor
        from services.dataset_writer.main import DatasetWriter

        self.scenario_engine = ScenarioEngine(seed=seed)
        self.injector = MismatchInjector(seed=seed)
        self.agents = {
            AgentArch.AUT1_LANGGRAPH: LangGraphAgentSim(seed=seed),
            AgentArch.AUT2_AUTOGEN: AutoGenAgentSim(seed=seed),
            AgentArch.AUT3_CREWAI: CrewAIAgentSim(seed=seed),
            AgentArch.AUT4_RULEBASED: RuleBasedAgentSim(seed=seed),
        }
        self.monitor = AnomalyMonitor()
        self.writer = DatasetWriter(
            output_dir=os.path.join(
                os.path.dirname(__file__), "..", "..", config.output_dir
            )
        )
        self.seed = seed

    def run_single(
        self,
        scenario_id: str,
        arch: AgentArch,
        target_delta_S: float = 0.0,
        target_delta_K: float = 0.0,
        target_delta_C: float = 0.0,
        target_T_age: float = 0.0,
        repetition: int = 0,
    ) -> Dict:
        """Run a single evaluation."""
        run_id = f"{scenario_id}_{arch.value}_dS{target_delta_S}_dK{target_delta_K}_dC{target_delta_C}_rep{repetition}"

        # 1. Build task and full agent
        task = self.scenario_engine.build_task(scenario_id)
        full_agent = self.scenario_engine.build_agent(arch, task)

        # 2. Inject mismatches
        degraded_agent = self.injector.inject(
            full_agent, task,
            target_delta_S, target_delta_K, target_delta_C,
            target_T_age,
        )

        # 3. Generate misleading context if reasoning mismatch desired
        misleading = None
        if target_delta_K > 0.3 or target_delta_S > 0.5:
            misleading = self.injector.inject_reasoning_noise(
                degraded_agent, target_delta_K * 0.5
            )

        # 4. Run agent
        agent_sim = self.agents[arch]
        agent_result = agent_sim.run(degraded_agent, task, misleading)

        # 5. Evaluate
        timestamp = datetime.now(timezone.utc).isoformat()
        record = self.monitor.evaluate(
            run_id, degraded_agent, task, agent_result, timestamp
        )

        return record.to_dict()

    def run_experiment(
        self,
        scenario_ids: Optional[List[str]] = None,
        architectures: Optional[List[AgentArch]] = None,
        mismatch_levels: Optional[List[float]] = None,
        num_repetitions: int = 3,
        t_age_values: Optional[List[float]] = None,
        progress_callback=None,
    ) -> List[Dict]:
        """Run a full experiment across the specified parameter space."""
        if scenario_ids is None:
            scenario_ids = self.scenario_engine.get_all_scenario_ids()
        if architectures is None:
            architectures = list(AgentArch)
        if mismatch_levels is None:
            mismatch_levels = MISMATCH_LEVELS
        if t_age_values is None:
            t_age_values = [0.0]

        total = (
            len(scenario_ids) * len(architectures) *
            len(mismatch_levels) ** 3 * len(t_age_values) * num_repetitions
        )
        count = 0
        results = []

        for scenario_id in scenario_ids:
            for arch in architectures:
                for ds in mismatch_levels:
                    for dk in mismatch_levels:
                        for dc in mismatch_levels:
                            for t_age in t_age_values:
                                for rep in range(num_repetitions):
                                    record = self.run_single(
                                        scenario_id, arch,
                                        ds, dk, dc, t_age, rep
                                    )
                                    results.append(record)
                                    self.writer.add_record(record)
                                    count += 1
                                    if progress_callback and count % 100 == 0:
                                        progress_callback(count, total)

        return results

    def run_sparse_experiment(
        self,
        scenario_ids: Optional[List[str]] = None,
        architectures: Optional[List[AgentArch]] = None,
        num_repetitions: int = 3,
        samples_per_compound: int = 3,
        progress_callback=None,
    ) -> List[Dict]:
        """Run a sparse experiment with single-dimension sweeps + compound samples."""
        if scenario_ids is None:
            scenario_ids = self.scenario_engine.get_all_scenario_ids()
        if architectures is None:
            architectures = list(AgentArch)

        import random
        rng = random.Random(self.seed)
        results = []
        count = 0

        for scenario_id in scenario_ids:
            for arch in architectures:
                for rep in range(num_repetitions):
                    # Single-dimension sweeps
                    for dim in ["S", "K", "C"]:
                        for level in MISMATCH_LEVELS:
                            ds = level if dim == "S" else 0.0
                            dk = level if dim == "K" else 0.0
                            dc = level if dim == "C" else 0.0
                            record = self.run_single(
                                scenario_id, arch, ds, dk, dc, 0.0, rep
                            )
                            results.append(record)
                            self.writer.add_record(record)
                            count += 1

                    # Compound mismatch samples
                    for _ in range(samples_per_compound):
                        ds = rng.choice(MISMATCH_LEVELS)
                        dk = rng.choice(MISMATCH_LEVELS)
                        dc = rng.choice(MISMATCH_LEVELS)
                        record = self.run_single(
                            scenario_id, arch, ds, dk, dc, 0.0, rep
                        )
                        results.append(record)
                        self.writer.add_record(record)
                        count += 1

                    if progress_callback:
                        progress_callback(count, -1)

        return results

    def run_temporal_experiment(
        self,
        scenario_ids: Optional[List[str]] = None,
        architectures: Optional[List[AgentArch]] = None,
        t_age_values: Optional[List[float]] = None,
        num_repetitions: int = 3,
    ) -> List[Dict]:
        """Run temporal decay experiment with varying T_age."""
        if scenario_ids is None:
            scenario_ids = self.scenario_engine.get_all_scenario_ids()
        if architectures is None:
            architectures = list(AgentArch)
        if t_age_values is None:
            t_age_values = [0, 24, 72, 168, 336, 720, 2160]  # hours

        results = []
        for scenario_id in scenario_ids:
            for arch in architectures:
                for t_age in t_age_values:
                    for rep in range(num_repetitions):
                        record = self.run_single(
                            scenario_id, arch,
                            0.0, 0.0, 0.0, float(t_age), rep
                        )
                        results.append(record)
                        self.writer.add_record(record)

        return results

    def run_cascade_experiment(
        self,
        scenario_ids: Optional[List[str]] = None,
        num_repetitions: int = 3,
    ) -> List[Dict]:
        """Run cascade experiment specifically for AUT-2 (AutoGen pipeline)."""
        if scenario_ids is None:
            scenario_ids = self.scenario_engine.get_all_scenario_ids()

        arch = AgentArch.AUT2_AUTOGEN
        results = []

        for scenario_id in scenario_ids:
            for ds in MISMATCH_LEVELS:
                for dk in MISMATCH_LEVELS:
                    for dc in MISMATCH_LEVELS:
                        for rep in range(num_repetitions):
                            record = self.run_single(
                                scenario_id, arch,
                                ds, dk, dc, 0.0, rep
                            )
                            results.append(record)
                            self.writer.add_record(record)

        return results

    def flush_dataset(self) -> Dict[str, str]:
        """Write all accumulated records to disk."""
        paths = {
            "jsonl": self.writer.write_jsonl(),
            "json": self.writer.write_json(),
            "csv": self.writer.write_csv(),
            "summary": self.writer.write_summary(),
        }
        return paths


# ---------------------------------------------------------------------------
# FastAPI service (Docker mode)
# ---------------------------------------------------------------------------
def create_app():
    from fastapi import FastAPI, BackgroundTasks

    app = FastAPI(title="ARES-Bench Orchestrator", version="1.0.0")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "orchestrator"}

    @app.post("/run_experiment")
    async def run_experiment(background_tasks: BackgroundTasks):
        # In Docker mode, would coordinate via HTTP calls to other services
        return {"status": "use simulation mode for experiments"}

    return app


if __name__ == "__main__":
    if config.simulation_mode:
        print("[Orchestrator] Running in simulation mode")
        print("=" * 60)

        orch = Orchestrator(seed=config.random_seed)

        def progress(done, total):
            if total > 0:
                print(f"  Progress: {done}/{total} ({100*done/total:.1f}%)")
            else:
                print(f"  Records generated: {done}")

        # Run sparse experiment
        print("\nRunning sparse experiment...")
        results = orch.run_sparse_experiment(
            num_repetitions=config.num_repetitions,
            samples_per_compound=2,
            progress_callback=progress,
        )
        print(f"  Generated {len(results)} records")

        # Flush to disk
        paths = orch.flush_dataset()
        print(f"\nDataset written:")
        for fmt, path in paths.items():
            print(f"  {fmt}: {path}")
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=config.orchestrator_port)
