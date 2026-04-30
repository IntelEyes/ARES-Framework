"""
ARES-Bench Shared Configuration.

Reads from environment variables with sensible defaults.
Supports SIMULATION_MODE for running without Docker services.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    """Central configuration for ARES-Bench."""

    # Mode
    simulation_mode: bool = field(
        default_factory=lambda: os.getenv("SIMULATION_MODE", "true").lower() == "true"
    )

    # Service endpoints (Docker mode)
    postgres_dsn: str = field(
        default_factory=lambda: os.getenv(
            "POSTGRES_DSN",
            "postgresql://ares:ares_bench@localhost:5432/ares_bench",
        )
    )
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    opensearch_url: str = field(
        default_factory=lambda: os.getenv(
            "OPENSEARCH_URL", "https://localhost:9200"
        )
    )
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "mistral:7b")
    )

    # Service ports
    scenario_engine_port: int = field(
        default_factory=lambda: int(os.getenv("SCENARIO_ENGINE_PORT", "8001"))
    )
    mismatch_injector_port: int = field(
        default_factory=lambda: int(os.getenv("MISMATCH_INJECTOR_PORT", "8002"))
    )
    orchestrator_port: int = field(
        default_factory=lambda: int(os.getenv("ORCHESTRATOR_PORT", "8010"))
    )
    anomaly_monitor_port: int = field(
        default_factory=lambda: int(os.getenv("ANOMALY_MONITOR_PORT", "8006"))
    )
    dataset_writer_port: int = field(
        default_factory=lambda: int(os.getenv("DATASET_WRITER_PORT", "8007"))
    )

    # Agent ports
    langgraph_agent_port: int = field(
        default_factory=lambda: int(os.getenv("LANGGRAPH_AGENT_PORT", "8003"))
    )
    autogen_agent_port: int = field(
        default_factory=lambda: int(os.getenv("AUTOGEN_AGENT_PORT", "8004"))
    )
    crewai_agent_port: int = field(
        default_factory=lambda: int(os.getenv("CREWAI_AGENT_PORT", "8005"))
    )
    rulebased_agent_port: int = field(
        default_factory=lambda: int(os.getenv("RULEBASED_AGENT_PORT", "8008"))
    )

    # Experiment parameters
    random_seed: int = field(
        default_factory=lambda: int(os.getenv("RANDOM_SEED", "42"))
    )
    num_repetitions: int = field(
        default_factory=lambda: int(os.getenv("NUM_REPETITIONS", "3"))
    )
    output_dir: str = field(
        default_factory=lambda: os.getenv("OUTPUT_DIR", "output")
    )

    # Simulation parameters
    sim_noise_std: float = field(
        default_factory=lambda: float(os.getenv("SIM_NOISE_STD", "0.02"))
    )
    sim_latency_base_ms: float = field(
        default_factory=lambda: float(os.getenv("SIM_LATENCY_BASE_MS", "150.0"))
    )

    def service_url(self, service: str) -> str:
        """Get the URL for a service."""
        port_map = {
            "scenario_engine": self.scenario_engine_port,
            "mismatch_injector": self.mismatch_injector_port,
            "orchestrator": self.orchestrator_port,
            "anomaly_monitor": self.anomaly_monitor_port,
            "dataset_writer": self.dataset_writer_port,
            "langgraph_agent": self.langgraph_agent_port,
            "autogen_agent": self.autogen_agent_port,
            "crewai_agent": self.crewai_agent_port,
            "rulebased_agent": self.rulebased_agent_port,
        }
        port = port_map.get(service)
        if port is None:
            raise ValueError(f"Unknown service: {service}")
        return f"http://localhost:{port}"
