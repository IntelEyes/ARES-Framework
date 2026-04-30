"""
Unit tests for ARES-Bench shared models (shared/shared_models.py).

Covers:
  1. ARS computation: ARS = 1 - w_tau^T . delta, clamped to [0,1]
  2. Epistemic Gap: E = delta_K * (1 - U)
  3. Anomaly flag: Phi = 1 when ARS < 0.58 OR E > 0.65
  4. Cascade ARS: result <= min(individual ARS scores)
  5. Mismatch indicators: delta_S, delta_K, delta_C as set-difference fractions
  6. Temporal drift: delta_T = 1 - exp(-lambda_tau * T_age)
  7. Edge cases: zero mismatch -> ARS=1, full mismatch -> ARS near 0
"""

import math
import pytest

from shared.shared_models import (
    ARS_THRESHOLD,
    EPISTEMIC_THRESHOLD,
    VOLATILITY_PARAMS,
    WEIGHT_VECTORS,
    AgentArch,
    AgentProfile,
    MismatchVector,
    TaskProfile,
    ThreatType,
    compute_ars,
    compute_anomaly_flag,
    compute_cascade_ars,
    compute_delta_C,
    compute_delta_K,
    compute_delta_S,
    compute_delta_T,
    compute_epistemic_gap,
    compute_mismatch_vector,
)


# -----------------------------------------------------------------------
# Helpers to build agents/tasks quickly
# -----------------------------------------------------------------------
def _agent(S=None, K=None, C=None, T_age=0.0, arch=AgentArch.AUT1_LANGGRAPH):
    return AgentProfile(
        agent_id="test-agent",
        arch=arch,
        S=set(S or []),
        K=set(K or []),
        C=set(C or []),
        T_age=T_age,
    )


def _task(S_star=None, K_star=None, C_star=None, threat=ThreatType.T1_RANSOMWARE):
    return TaskProfile(
        scenario_id="test-scenario",
        threat_type=threat,
        S_star=set(S_star or []),
        K_star=set(K_star or []),
        C_star=set(C_star or []),
    )


# =======================================================================
# 1. ARS computation
# =======================================================================
class TestARSComputation:
    """ARS = 1 - w_tau^T . delta, clamped to [0,1]."""

    def test_ars_zero_mismatch_equals_one(self):
        """Zero mismatch vector => ARS = 1.0 for every threat class."""
        mv = MismatchVector(0.0, 0.0, 0.0, 0.0, 0.0)
        for threat_key in WEIGHT_VECTORS:
            assert compute_ars(mv, threat_key) == 1.0

    def test_ars_full_mismatch_near_zero(self):
        """All deltas = 1.0 => ARS = 1 - sum(w) = 0.0 (weights sum to 1)."""
        mv = MismatchVector(1.0, 1.0, 1.0, 1.0, 1.0)
        for threat_key, weights in WEIGHT_VECTORS.items():
            expected = max(0.0, 1.0 - sum(weights))
            assert compute_ars(mv, threat_key) == pytest.approx(expected, abs=1e-9)

    def test_ars_manual_dot_product_T1(self):
        """Hand-computed ARS for T1 (Ransomware)."""
        # w = [0.18, 0.35, 0.22, 0.17, 0.08]
        # delta = [0.5, 0.3, 0.0, 0.2, 0.1]
        # dot = 0.18*0.5 + 0.35*0.3 + 0.22*0 + 0.17*0.2 + 0.08*0.1
        #     = 0.09 + 0.105 + 0 + 0.034 + 0.008 = 0.237
        # ARS = 1 - 0.237 = 0.763
        mv = MismatchVector(0.5, 0.3, 0.0, 0.2, 0.1)
        ars = compute_ars(mv, "T1")
        assert ars == pytest.approx(0.763, abs=1e-6)

    def test_ars_manual_dot_product_T5(self):
        """Hand-computed ARS for T5 (APT Intrusion)."""
        # w = [0.14, 0.38, 0.18, 0.24, 0.06]
        # delta = [1.0, 1.0, 0.0, 0.0, 0.0]
        # dot = 0.14 + 0.38 = 0.52
        # ARS = 0.48
        mv = MismatchVector(1.0, 1.0, 0.0, 0.0, 0.0)
        ars = compute_ars(mv, "T5")
        assert ars == pytest.approx(0.48, abs=1e-6)

    def test_ars_clamp_lower_bound(self):
        """ARS never goes below 0 even if dot product exceeds 1."""
        # Artificially large deltas (> 1) to force clamping
        mv = MismatchVector(2.0, 2.0, 2.0, 2.0, 2.0)
        ars = compute_ars(mv, "T1")
        assert ars == 0.0

    def test_ars_clamp_upper_bound(self):
        """ARS never exceeds 1 even with negative deltas (shouldn't occur, but robustness)."""
        mv = MismatchVector(-1.0, -1.0, -1.0, -1.0, -1.0)
        ars = compute_ars(mv, "T1")
        assert ars == 1.0

    def test_ars_unknown_threat_raises(self):
        mv = MismatchVector()
        with pytest.raises(ValueError, match="Unknown threat type"):
            compute_ars(mv, "T99")

    @pytest.mark.parametrize("threat_key", ["T1", "T2", "T3", "T4", "T5"])
    def test_weights_sum_to_one(self, threat_key):
        """All weight vectors must sum to 1.0."""
        assert sum(WEIGHT_VECTORS[threat_key]) == pytest.approx(1.0, abs=1e-9)

    @pytest.mark.parametrize("threat_key", ["T1", "T2", "T3", "T4", "T5"])
    def test_ars_monotonically_decreases_with_mismatch(self, threat_key):
        """ARS should decrease as mismatch increases (all else equal)."""
        scores = []
        for level in [0.0, 0.33, 0.66, 1.0]:
            mv = MismatchVector(level, level, level, level, level)
            scores.append(compute_ars(mv, threat_key))
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1]


# =======================================================================
# 2. Epistemic Gap
# =======================================================================
class TestEpistemicGap:
    """E = delta_K * (1 - U)."""

    def test_basic_computation(self):
        # delta_K=0.5, U=0.3 => E = 0.5 * 0.7 = 0.35
        assert compute_epistemic_gap(0.5, 0.3) == pytest.approx(0.35)

    def test_delta_K_zero(self):
        """No knowledge gap => no epistemic gap regardless of uncertainty."""
        assert compute_epistemic_gap(0.0, 0.0) == 0.0
        assert compute_epistemic_gap(0.0, 0.5) == 0.0
        assert compute_epistemic_gap(0.0, 1.0) == 0.0

    def test_uncertainty_one(self):
        """Perfect calibration (U=1) => epistemic gap vanishes."""
        assert compute_epistemic_gap(1.0, 1.0) == 0.0
        assert compute_epistemic_gap(0.5, 1.0) == 0.0

    def test_uncertainty_zero(self):
        """Zero awareness (U=0) => E equals delta_K."""
        assert compute_epistemic_gap(0.7, 0.0) == pytest.approx(0.7)
        assert compute_epistemic_gap(1.0, 0.0) == pytest.approx(1.0)

    def test_full_gap_max(self):
        """delta_K=1, U=0 => maximum epistemic gap of 1.0."""
        assert compute_epistemic_gap(1.0, 0.0) == pytest.approx(1.0)

    def test_intermediate_values(self):
        # delta_K=0.8, U=0.2 => 0.8*0.8 = 0.64
        assert compute_epistemic_gap(0.8, 0.2) == pytest.approx(0.64)


# =======================================================================
# 3. Anomaly flag
# =======================================================================
class TestAnomalyFlag:
    """Phi = 1 when ARS < 0.58 OR E > 0.65."""

    def test_no_anomaly_safe_values(self):
        assert compute_anomaly_flag(0.80, 0.30) is False

    def test_anomaly_low_ars(self):
        assert compute_anomaly_flag(0.50, 0.30) is True

    def test_anomaly_high_epistemic(self):
        assert compute_anomaly_flag(0.90, 0.70) is True

    def test_anomaly_both_triggers(self):
        assert compute_anomaly_flag(0.40, 0.80) is True

    def test_boundary_ars_exactly_threshold(self):
        """ARS == 0.58 is NOT below threshold => no anomaly from ARS alone."""
        assert compute_anomaly_flag(ARS_THRESHOLD, 0.0) is False

    def test_boundary_ars_just_below(self):
        assert compute_anomaly_flag(ARS_THRESHOLD - 1e-9, 0.0) is True

    def test_boundary_epistemic_exactly_threshold(self):
        """E == 0.65 is NOT above threshold => no anomaly from E alone."""
        assert compute_anomaly_flag(1.0, EPISTEMIC_THRESHOLD) is False

    def test_boundary_epistemic_just_above(self):
        assert compute_anomaly_flag(1.0, EPISTEMIC_THRESHOLD + 1e-9) is True

    def test_custom_thresholds(self):
        assert compute_anomaly_flag(0.70, 0.30, theta_star=0.75) is True
        assert compute_anomaly_flag(0.70, 0.30, epsilon_star=0.25) is True
        assert compute_anomaly_flag(0.70, 0.30, theta_star=0.60, epsilon_star=0.40) is False


# =======================================================================
# 4. Cascade ARS
# =======================================================================
class TestCascadeARS:
    """Cascade ARS <= min(individual ARS) -- the theorem bound."""

    def test_single_agent(self):
        assert compute_cascade_ars([0.85]) == pytest.approx(0.85)

    def test_empty_list(self):
        assert compute_cascade_ars([]) == 1.0

    def test_cascade_le_min_individual(self):
        """Cascade ARS must be <= min of individual scores (default coupling)."""
        scores = [0.95, 0.80, 0.70]
        cascade = compute_cascade_ars(scores)
        assert cascade <= min(scores) + 1e-9

    def test_cascade_le_min_many_stages(self):
        scores = [0.90, 0.85, 0.75, 0.60]
        cascade = compute_cascade_ars(scores)
        assert cascade <= min(scores) + 1e-9

    def test_cascade_all_perfect(self):
        """All ARS=1.0 => cascade = 1.0."""
        assert compute_cascade_ars([1.0, 1.0, 1.0]) == pytest.approx(1.0)

    def test_cascade_one_zero(self):
        """One ARS=0 should bring cascade to 0."""
        cascade = compute_cascade_ars([1.0, 0.0, 1.0])
        assert cascade == pytest.approx(0.0, abs=1e-9)

    def test_cascade_with_custom_coupling(self):
        """Custom coupling matrix should affect cascade result."""
        scores = [0.9, 0.8]
        # mu=0.5 coupling
        coupling = [[0.0, 0.5], [0.0, 0.0]]
        cascade = compute_cascade_ars(scores, coupling)
        # stage 0: mu=1.0 (first stage default) => 1 - 1*(1-0.9) = 0.9
        # stage 1: max_mu from col 1 = coupling[0][1] = 0.5 => 1 - 0.5*(1-0.8) = 0.9
        # cascade = 0.9 * 0.9 = 0.81
        assert cascade == pytest.approx(0.81, abs=1e-6)

    def test_cascade_clamped_to_zero_one(self):
        cascade = compute_cascade_ars([0.1, 0.1, 0.1, 0.1])
        assert 0.0 <= cascade <= 1.0

    def test_cascade_two_equal_stages(self):
        scores = [0.8, 0.8]
        cascade = compute_cascade_ars(scores)
        # stage 0: 1 - 1*(0.2) = 0.8
        # stage 1: coupling[0][1]=1.0 => 1 - 1*(0.2) = 0.8
        # cascade = 0.64
        assert cascade == pytest.approx(0.64, abs=1e-6)
        assert cascade <= min(scores) + 1e-9


# =======================================================================
# 5. Mismatch indicators (set-difference fractions)
# =======================================================================
class TestMismatchIndicators:
    """delta_S, delta_K, delta_C = |X* \\ X| / |X*|."""

    # --- delta_S ---
    def test_delta_S_no_mismatch(self):
        agent = _agent(S=["a", "b", "c"])
        task = _task(S_star=["a", "b", "c"])
        assert compute_delta_S(agent, task) == 0.0

    def test_delta_S_full_mismatch(self):
        agent = _agent(S=[])
        task = _task(S_star=["a", "b"])
        assert compute_delta_S(agent, task) == 1.0

    def test_delta_S_partial_mismatch(self):
        agent = _agent(S=["a", "c"])
        task = _task(S_star=["a", "b", "c", "d"])
        # missing = {b, d}, |S*| = 4 => 2/4 = 0.5
        assert compute_delta_S(agent, task) == pytest.approx(0.5)

    def test_delta_S_empty_requirement(self):
        agent = _agent(S=["a"])
        task = _task(S_star=[])
        assert compute_delta_S(agent, task) == 0.0

    def test_delta_S_agent_has_extras(self):
        """Extra skills don't reduce mismatch."""
        agent = _agent(S=["a", "b", "c", "d", "e"])
        task = _task(S_star=["a", "b"])
        assert compute_delta_S(agent, task) == 0.0

    # --- delta_K ---
    def test_delta_K_no_mismatch(self):
        agent = _agent(K=["k1", "k2"])
        task = _task(K_star=["k1", "k2"])
        assert compute_delta_K(agent, task) == 0.0

    def test_delta_K_full_mismatch(self):
        agent = _agent(K=[])
        task = _task(K_star=["k1", "k2", "k3"])
        assert compute_delta_K(agent, task) == 1.0

    def test_delta_K_partial(self):
        agent = _agent(K=["k1"])
        task = _task(K_star=["k1", "k2", "k3"])
        assert compute_delta_K(agent, task) == pytest.approx(2.0 / 3.0)

    def test_delta_K_empty_requirement(self):
        agent = _agent(K=[])
        task = _task(K_star=[])
        assert compute_delta_K(agent, task) == 0.0

    # --- delta_C ---
    def test_delta_C_no_mismatch(self):
        agent = _agent(C=["c1"])
        task = _task(C_star=["c1"])
        assert compute_delta_C(agent, task) == 0.0

    def test_delta_C_full_mismatch(self):
        agent = _agent(C=[])
        task = _task(C_star=["c1", "c2"])
        assert compute_delta_C(agent, task) == 1.0

    def test_delta_C_partial(self):
        agent = _agent(C=["c1", "c3"])
        task = _task(C_star=["c1", "c2", "c3", "c4"])
        assert compute_delta_C(agent, task) == pytest.approx(0.5)

    def test_delta_C_empty_requirement(self):
        agent = _agent(C=[])
        task = _task(C_star=[])
        assert compute_delta_C(agent, task) == 0.0


# =======================================================================
# 6. Temporal drift
# =======================================================================
class TestTemporalDrift:
    """delta_T = 1 - exp(-lambda_tau * T_age)."""

    def test_zero_age(self):
        """Fresh intel => delta_T = 0."""
        agent = _agent(T_age=0.0)
        for threat in ThreatType:
            task = _task(threat=threat)
            assert compute_delta_T(agent, task) == pytest.approx(0.0)

    @pytest.mark.parametrize("threat", list(ThreatType))
    def test_formula_matches(self, threat):
        """Verify delta_T = 1 - exp(-lambda * T_age) for each class."""
        T_age = 100.0
        agent = _agent(T_age=T_age)
        task = _task(threat=threat)
        lam = VOLATILITY_PARAMS[threat.value]
        expected = 1.0 - math.exp(-lam * T_age)
        assert compute_delta_T(agent, task) == pytest.approx(expected, abs=1e-9)

    def test_large_age_approaches_one(self):
        """Very old intel => delta_T close to 1."""
        agent = _agent(T_age=10000.0)
        task = _task(threat=ThreatType.T1_RANSOMWARE)
        dt = compute_delta_T(agent, task)
        assert dt > 0.99

    def test_volatility_ordering(self):
        """Higher lambda => faster drift for the same age."""
        T_age = 200.0
        agent = _agent(T_age=T_age)
        # T1 has lambda=0.005, T5 has lambda=0.001
        dt_T1 = compute_delta_T(agent, _task(threat=ThreatType.T1_RANSOMWARE))
        dt_T5 = compute_delta_T(agent, _task(threat=ThreatType.T5_APT))
        assert dt_T1 > dt_T5

    def test_monotonic_increase_with_age(self):
        """delta_T increases with T_age."""
        task = _task(threat=ThreatType.T2_PHISHING)
        ages = [0, 50, 100, 500, 1000]
        deltas = [compute_delta_T(_agent(T_age=a), task) for a in ages]
        for i in range(len(deltas) - 1):
            assert deltas[i] < deltas[i + 1]


# =======================================================================
# 7. Edge cases: zero and full mismatch end-to-end
# =======================================================================
class TestEdgeCases:
    """Integration-style tests combining mismatch -> ARS."""

    def test_perfect_agent_ars_one(self):
        """Agent with everything the task needs => ARS = 1.0."""
        agent = _agent(
            S=["s1", "s2"],
            K=["k1", "k2"],
            C=["c1"],
            T_age=0.0,
        )
        task = _task(
            S_star=["s1", "s2"],
            K_star=["k1", "k2"],
            C_star=["c1"],
            threat=ThreatType.T1_RANSOMWARE,
        )
        mv = compute_mismatch_vector(agent, task, agent_output=task.y_star)
        ars = compute_ars(mv, task.threat_type.value)
        # delta_S=0, delta_K=0, delta_C=0, delta_R=0 (same output), delta_T=0
        assert ars == pytest.approx(1.0, abs=1e-6)

    def test_completely_unfit_agent_ars_near_zero(self):
        """Agent missing everything => ARS near 0."""
        agent = _agent(S=[], K=[], C=[], T_age=5000.0)
        task = _task(
            S_star=["s1", "s2", "s3"],
            K_star=["k1", "k2", "k3"],
            C_star=["c1", "c2"],
            threat=ThreatType.T1_RANSOMWARE,
        )
        mv = compute_mismatch_vector(agent, task, agent_output={})
        ars = compute_ars(mv, task.threat_type.value)
        assert ars < 0.20

    def test_mismatch_vector_as_list_length(self):
        mv = MismatchVector(0.1, 0.2, 0.3, 0.4, 0.5)
        assert len(mv.as_list()) == 5
        assert mv.as_list() == [0.1, 0.2, 0.3, 0.4, 0.5]

    def test_mismatch_vector_roundtrip_dict(self):
        mv = MismatchVector(0.123456, 0.654321, 0.111111, 0.999999, 0.000001)
        d = mv.to_dict()
        mv2 = MismatchVector.from_dict(d)
        for a, b in zip(mv.as_list(), mv2.as_list()):
            assert a == pytest.approx(b, abs=1e-5)

    def test_anomaly_triggered_by_unfit_agent(self):
        """Full mismatch should trigger anomaly flag."""
        mv = MismatchVector(1.0, 1.0, 1.0, 1.0, 1.0)
        ars = compute_ars(mv, "T1")
        eg = compute_epistemic_gap(1.0, 0.0)  # U=0 => E=1.0
        flag = compute_anomaly_flag(ars, eg)
        assert flag is True

    def test_no_anomaly_for_perfect_agent(self):
        mv = MismatchVector(0.0, 0.0, 0.0, 0.0, 0.0)
        ars = compute_ars(mv, "T1")
        eg = compute_epistemic_gap(0.0, 0.5)
        flag = compute_anomaly_flag(ars, eg)
        assert flag is False
