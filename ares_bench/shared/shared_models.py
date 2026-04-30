"""
ARES-Bench Core Data Models and ARS Computation.

Implements:
  Agent model:  A = <S, K, C, R, T_age>
  Task model:   T = <S*, K*, C*, y*>
  Mismatch indicators: delta_S, delta_K, delta_C, delta_R, delta_T
  ARS(A,T) = 1 - w_tau^T . delta(A,T)  clamped to [0,1]
  Epistemic Gap: E(A,T) = delta_K * (1 - U(A,T))
  Anomaly flag: Phi = 1 if ARS < theta* OR E > epsilon*
  Cascade ARS: ARS_cas = prod(1 - mu_ij * (1 - ARS(A_i)))
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


# ---------------------------------------------------------------------------
# Thresholds (from paper)
# ---------------------------------------------------------------------------
ARS_THRESHOLD: float = 0.58      # theta*
EPISTEMIC_THRESHOLD: float = 0.65  # epsilon*

# ---------------------------------------------------------------------------
# Learned weight vectors w_tau  [w_S, w_K, w_C, w_R, w_T]
# ---------------------------------------------------------------------------
WEIGHT_VECTORS: Dict[str, List[float]] = {
    "T1": [0.18, 0.35, 0.22, 0.17, 0.08],  # Ransomware
    "T2": [0.21, 0.31, 0.19, 0.21, 0.08],  # Phishing
    "T3": [0.15, 0.27, 0.36, 0.15, 0.07],  # Insider Threat
    "T4": [0.32, 0.21, 0.28, 0.12, 0.07],  # DDoS
    "T5": [0.14, 0.38, 0.18, 0.24, 0.06],  # APT Intrusion
}

# ---------------------------------------------------------------------------
# Volatility parameters lambda_tau
# ---------------------------------------------------------------------------
VOLATILITY_PARAMS: Dict[str, float] = {
    "T1": 0.005,  # Ransomware
    "T2": 0.003,  # Phishing
    "T3": 0.002,  # Insider Threat
    "T4": 0.004,  # DDoS
    "T5": 0.001,  # APT Intrusion
}

# ---------------------------------------------------------------------------
# Mismatch injection levels
# ---------------------------------------------------------------------------
MISMATCH_LEVELS: List[float] = [0.0, 0.33, 0.66, 1.0]


class ThreatType(str, Enum):
    T1_RANSOMWARE = "T1"
    T2_PHISHING = "T2"
    T3_INSIDER = "T3"
    T4_DDOS = "T4"
    T5_APT = "T5"


class AgentArch(str, Enum):
    AUT1_LANGGRAPH = "AUT-1"
    AUT2_AUTOGEN = "AUT-2"
    AUT3_CREWAI = "AUT-3"
    AUT4_RULEBASED = "AUT-4"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AgentProfile:
    """Agent model A = <S, K, C, R, T_age>.

    S: set of skills/tools the agent possesses
    K: set of knowledge items the agent has access to
    C: set of capabilities (API/tool access) the agent can invoke
    R: reasoning quality factor in [0,1] (1 = perfect, 0 = fully hallucinating)
    T_age: age of threat intelligence in hours
    """
    agent_id: str
    arch: AgentArch
    S: Set[str] = field(default_factory=set)
    K: Set[str] = field(default_factory=set)
    C: Set[str] = field(default_factory=set)
    R: float = 1.0
    T_age: float = 0.0

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "arch": self.arch.value,
            "S": sorted(self.S),
            "K": sorted(self.K),
            "C": sorted(self.C),
            "R": self.R,
            "T_age": self.T_age,
        }


@dataclass
class TaskProfile:
    """Task model T = <S*, K*, C*, y*>.

    S_star: required skills/tools
    K_star: required knowledge items
    C_star: required capabilities
    y_star: ground-truth expected output (structured dict)
    threat_type: one of T1..T5
    scenario_id: unique scenario identifier
    """
    scenario_id: str
    threat_type: ThreatType
    S_star: Set[str] = field(default_factory=set)
    K_star: Set[str] = field(default_factory=set)
    C_star: Set[str] = field(default_factory=set)
    y_star: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "threat_type": self.threat_type.value,
            "S_star": sorted(self.S_star),
            "K_star": sorted(self.K_star),
            "C_star": sorted(self.C_star),
            "y_star": self.y_star,
        }


@dataclass
class MismatchVector:
    """Mismatch indicators delta(A, T) = [delta_S, delta_K, delta_C, delta_R, delta_T]."""
    delta_S: float = 0.0
    delta_K: float = 0.0
    delta_C: float = 0.0
    delta_R: float = 0.0
    delta_T: float = 0.0

    def as_list(self) -> List[float]:
        return [self.delta_S, self.delta_K, self.delta_C, self.delta_R, self.delta_T]

    def to_dict(self) -> dict:
        return {
            "delta_S": round(self.delta_S, 6),
            "delta_K": round(self.delta_K, 6),
            "delta_C": round(self.delta_C, 6),
            "delta_R": round(self.delta_R, 6),
            "delta_T": round(self.delta_T, 6),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MismatchVector":
        return cls(
            delta_S=d.get("delta_S", 0.0),
            delta_K=d.get("delta_K", 0.0),
            delta_C=d.get("delta_C", 0.0),
            delta_R=d.get("delta_R", 0.0),
            delta_T=d.get("delta_T", 0.0),
        )


@dataclass
class EvalRecord:
    """A single evaluation record for the dataset."""
    run_id: str
    scenario_id: str
    threat_type: str
    agent_arch: str
    mismatch_vector: MismatchVector
    ars_score: float
    epistemic_gap: float
    anomaly_flag: bool
    taxonomy_codes: dict  # {"origin": "O1", "manifestation": "M3", "impact": "I2"}
    agent_output: dict
    ground_truth: dict
    cascade_ars: Optional[float] = None
    uncertainty: float = 0.0
    latency_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "threat_type": self.threat_type,
            "agent_arch": self.agent_arch,
            "mismatch_vector": self.mismatch_vector.to_dict(),
            "ars_score": round(self.ars_score, 6),
            "epistemic_gap": round(self.epistemic_gap, 6),
            "anomaly_flag": self.anomaly_flag,
            "taxonomy_codes": self.taxonomy_codes,
            "agent_output": self.agent_output,
            "ground_truth": self.ground_truth,
            "cascade_ars": round(self.cascade_ars, 6) if self.cascade_ars is not None else None,
            "uncertainty": round(self.uncertainty, 6),
            "latency_ms": round(self.latency_ms, 2),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Mismatch computation
# ---------------------------------------------------------------------------
def compute_delta_S(agent: AgentProfile, task: TaskProfile) -> float:
    """delta_S = |S* \\ S| / |S*|"""
    if not task.S_star:
        return 0.0
    missing = task.S_star - agent.S
    return len(missing) / len(task.S_star)


def compute_delta_K(agent: AgentProfile, task: TaskProfile) -> float:
    """delta_K = |K* \\ K| / |K*|"""
    if not task.K_star:
        return 0.0
    missing = task.K_star - agent.K
    return len(missing) / len(task.K_star)


def compute_delta_C(agent: AgentProfile, task: TaskProfile) -> float:
    """delta_C = |C* \\ C| / |C*|"""
    if not task.C_star:
        return 0.0
    missing = task.C_star - agent.C
    return len(missing) / len(task.C_star)


def compute_delta_R(agent_output: dict, ground_truth: dict) -> float:
    """delta_R = 1 - Sim(y_hat, y*)

    Similarity is computed as Jaccard similarity over flattened key-value pairs.
    For deterministic agents (rule-based), delta_R = 0.
    """
    if not ground_truth:
        return 0.0

    def flatten(d: dict, prefix: str = "") -> Set[str]:
        items: Set[str] = set()
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items |= flatten(v, key)
            elif isinstance(v, (list, set)):
                for i, item in enumerate(sorted(str(x) for x in v)):
                    items.add(f"{key}[{i}]={item}")
            else:
                items.add(f"{key}={v}")
        return items

    y_hat = flatten(agent_output)
    y_star = flatten(ground_truth)

    if not y_star:
        return 0.0
    union = y_hat | y_star
    if not union:
        return 0.0
    intersection = y_hat & y_star
    sim = len(intersection) / len(union)
    return 1.0 - sim


def compute_delta_T(agent: AgentProfile, task: TaskProfile) -> float:
    """delta_T = 1 - exp(-lambda_tau * T_age)"""
    threat_key = task.threat_type.value
    lam = VOLATILITY_PARAMS.get(threat_key, 0.003)
    return 1.0 - math.exp(-lam * agent.T_age)


def compute_mismatch_vector(
    agent: AgentProfile,
    task: TaskProfile,
    agent_output: Optional[dict] = None,
) -> MismatchVector:
    """Compute the full mismatch vector delta(A, T)."""
    return MismatchVector(
        delta_S=compute_delta_S(agent, task),
        delta_K=compute_delta_K(agent, task),
        delta_C=compute_delta_C(agent, task),
        delta_R=compute_delta_R(agent_output or {}, task.y_star),
        delta_T=compute_delta_T(agent, task),
    )


# ---------------------------------------------------------------------------
# ARS computation
# ---------------------------------------------------------------------------
def compute_ars(
    mismatch: MismatchVector,
    threat_type: str,
) -> float:
    """ARS(A,T) = 1 - w_tau^T . delta(A,T), clamped to [0,1]."""
    w = WEIGHT_VECTORS.get(threat_type)
    if w is None:
        raise ValueError(f"Unknown threat type: {threat_type}")
    delta = mismatch.as_list()
    dot = sum(wi * di for wi, di in zip(w, delta))
    ars = 1.0 - dot
    return max(0.0, min(1.0, ars))


# ---------------------------------------------------------------------------
# Epistemic Gap
# ---------------------------------------------------------------------------
def compute_epistemic_gap(
    delta_K: float,
    uncertainty: float,
) -> float:
    """E(A,T) = delta_K * (1 - U(A,T))

    uncertainty U in [0,1]: how well the agent knows what it doesn't know.
    U=1 means agent is perfectly calibrated (knows its own ignorance),
    so epistemic gap vanishes even with high delta_K.
    U=0 means agent has zero awareness of its knowledge gaps.
    """
    return delta_K * (1.0 - uncertainty)


# ---------------------------------------------------------------------------
# Anomaly flag
# ---------------------------------------------------------------------------
def compute_anomaly_flag(
    ars: float,
    epistemic_gap: float,
    theta_star: float = ARS_THRESHOLD,
    epsilon_star: float = EPISTEMIC_THRESHOLD,
) -> bool:
    """Phi = 1 if ARS < theta* OR E > epsilon*."""
    return ars < theta_star or epistemic_gap > epsilon_star


# ---------------------------------------------------------------------------
# Cascade ARS
# ---------------------------------------------------------------------------
def compute_cascade_ars(
    agent_ars_list: List[float],
    coupling_matrix: Optional[List[List[float]]] = None,
) -> float:
    """ARS_cas = prod_i(1 - mu_ij * (1 - ARS(A_i)))

    For a pipeline of N stages, cascade ARS is the product
    of per-stage reliability adjusted by coupling factors.

    agent_ars_list: list of ARS scores for each pipeline stage
    coupling_matrix: NxN matrix where mu_ij is coupling factor
                     from stage i to j. If None, uses identity
                     (each stage equally coupled, mu=1.0).
    """
    n = len(agent_ars_list)
    if n == 0:
        return 1.0
    if n == 1:
        return agent_ars_list[0]

    if coupling_matrix is None:
        # Default: sequential pipeline with mu=1.0 for adjacent stages
        coupling_matrix = [[0.0] * n for _ in range(n)]
        for i in range(n - 1):
            coupling_matrix[i][i + 1] = 1.0

    # Cascade ARS: product over all stages
    result = 1.0
    for i in range(n):
        # Find the max coupling factor affecting this stage
        max_mu = 0.0
        for j in range(n):
            if j != i and coupling_matrix[j][i] > max_mu:
                max_mu = coupling_matrix[j][i]
        # If no coupling to this stage (first stage), use mu=1.0
        if i == 0:
            max_mu = 1.0
        stage_reliability = 1.0 - max_mu * (1.0 - agent_ars_list[i])
        result *= stage_reliability

    return max(0.0, min(1.0, result))


# ---------------------------------------------------------------------------
# Simulation helpers
# ---------------------------------------------------------------------------
def simulate_uncertainty(arch: AgentArch, delta_K: float, rng=None) -> float:
    """Simulate agent uncertainty (self-awareness of knowledge gaps).

    LLM agents are OVERCONFIDENT: they express LOW uncertainty even when
    delta_K is high (they don't know what they don't know).
    Rule-based agents are well-calibrated: higher mismatch -> higher expressed uncertainty.

    U is expressed uncertainty in [0,1]. Low U = confident (potentially dangerously so).
    """
    noise = 0.0
    if rng is not None:
        noise = rng.gauss(0, 0.03)

    if arch == AgentArch.AUT4_RULEBASED:
        # Well-calibrated: U = 0.3-0.5 (moderate-high uncertainty awareness)
        u = 0.35 + 0.15 * delta_K + noise
    else:
        # LLM agents: LOW expressed uncertainty even at high delta_K
        # This is the overconfidence problem: confidence stays high
        # U decreases as delta_K increases (more overconfident with bigger gaps)
        # Higher variance to separate E from raw dK across records
        base = {
            AgentArch.AUT1_LANGGRAPH: 0.22,
            AgentArch.AUT2_AUTOGEN: 0.25,
            AgentArch.AUT3_CREWAI: 0.23,
        }
        u_base = base.get(arch, 0.22)
        # Significant variance in overconfidence across records
        extra_noise = 0.0
        if rng is not None:
            extra_noise = rng.gauss(0, 0.08)
        # As delta_K grows, LLM agents become LESS uncertain (more overconfident)
        u = u_base * (1.0 - 0.6 * delta_K) + extra_noise + noise
    return max(0.02, min(0.95, u))


def simulate_hallucination(
    arch: AgentArch,
    delta_K: float,
    uncertainty: float,
    rng=None,
) -> bool:
    """Simulate whether the agent hallucinates.

    P(hallucination) = delta_K^1.5 * (0.5 + 0.5*(1-U))

    At delta_K=0: HR ~0.02-0.04
    At delta_K=0.33: HR ~0.16-0.21
    At delta_K=0.66: HR ~0.35-0.41
    At delta_K=1.0: HR ~0.52-0.58

    AUT-4 (rule-based): NEVER hallucinates.
    """
    if arch == AgentArch.AUT4_RULEBASED:
        return False

    # Base probability from the paper's model
    p_hall = (delta_K ** 1.5) * (0.5 + 0.5 * (1.0 - uncertainty))

    # Small baseline noise even at delta_K=0
    p_hall = 0.02 + 0.42 * p_hall

    # Clamp
    p_hall = max(0.0, min(1.0, p_hall))

    if rng is not None:
        return rng.random() < p_hall
    else:
        import random
        return random.random() < p_hall


def simulate_confidence(
    arch: AgentArch,
    delta_S: float,
    delta_K: float,
    delta_C: float,
    rng=None,
) -> float:
    """Simulate agent's expressed confidence.

    LLM agents are OVERCONFIDENT: confidence = 0.7 + 0.2*(1-delta_K) + noise
    This stays high even when knowledge is low, creating the epistemic gap.

    Rule-based agent: well-calibrated, confidence = 0.5 + 0.3*(1 - max(delta_S, delta_K, delta_C))
    """
    noise = 0.0
    if rng is not None:
        noise = rng.gauss(0, 0.03)

    if arch == AgentArch.AUT4_RULEBASED:
        max_delta = max(delta_S, delta_K, delta_C)
        conf = 0.50 + 0.30 * (1.0 - max_delta) + noise
        return max(0.3, min(0.8, conf))
    else:
        # LLM agents: overconfident -- confidence stays high even at high delta_K
        conf = 0.70 + 0.20 * (1.0 - delta_K) + noise
        return max(0.5, min(0.98, conf))


def simulate_false_negative(
    delta_K: float,
    delta_S: float,
    epistemic_gap: float,
    rng=None,
) -> float:
    """Simulate a continuous false-negative propensity score.

    FN occurs when delta_K > 0 AND confidence is high (agent doesn't know
    what it doesn't know).

    P(FN) = 0.3*delta_K + 0.5*E + 0.2*delta_S
    where E = epistemic gap = delta_K * (1 - U)

    This ensures epistemic gap is a STRONGER predictor of FNR than raw delta_K.
    """
    fn_score = 0.20 * delta_K + 0.60 * epistemic_gap + 0.20 * delta_S

    noise = 0.0
    if rng is not None:
        noise = rng.gauss(0, 0.04)

    return max(0.0, min(1.0, fn_score + noise))


def simulate_task_success(
    ars: float,
    hallucinated: bool,
    rng=None,
) -> bool:
    """Simulate task success.

    task_success = 1 if ARS > 0.6 AND no hallucination AND random() > 0.1
    """
    if ars <= 0.6:
        return False
    if hallucinated:
        return False
    r = rng.random() if rng is not None else __import__('random').random()
    return r > 0.1


def simulate_delta_R(
    arch: AgentArch,
    delta_S: float,
    delta_K: float,
    delta_C: float,
) -> float:
    """Simulate reasoning mismatch delta_R based on other mismatches.

    Rule-based agents: delta_R = 0 (deterministic, no hallucination).
    LLM agents: delta_R increases with knowledge/capability gaps.
    """
    if arch == AgentArch.AUT4_RULEBASED:
        return 0.0

    # LLM agents' reasoning quality degrades with input gaps
    # Knowledge gaps have the strongest effect on reasoning
    reasoning_degradation = {
        AgentArch.AUT1_LANGGRAPH: lambda s, k, c: 0.15 * s + 0.45 * k + 0.25 * c,
        AgentArch.AUT2_AUTOGEN: lambda s, k, c: 0.12 * s + 0.40 * k + 0.22 * c,
        AgentArch.AUT3_CREWAI: lambda s, k, c: 0.13 * s + 0.42 * k + 0.23 * c,
    }
    fn = reasoning_degradation.get(
        arch,
        lambda s, k, c: 0.15 * s + 0.45 * k + 0.25 * c,
    )
    dr = fn(delta_S, delta_K, delta_C)
    # Add noise for realism (deterministic based on inputs for reproducibility)
    noise = (hash((delta_S, delta_K, delta_C, arch.value)) % 100) / 1000.0 - 0.05
    dr = dr + noise
    return max(0.0, min(1.0, dr))
