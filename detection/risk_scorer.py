"""
AEGIX Risk Scorer — Composite Risk Score with Evidence Weighting (F29)
Produces a 0–100 risk score for each incident with individually
explainable components.
"""
import logging
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger("aegix.detection.risk_scorer")


@dataclass
class RiskScore:
    """Composite risk score with breakdown."""
    total_score: float = 0.0           # 0-100
    risk_level: str = "LOW"            # LOW, MEDIUM, HIGH, CRITICAL

    # Individual components (0.0 to 1.0 each)
    base_severity: float = 0.0         # Severity of the detected anomaly
    attack_chain_completeness: float = 0.0  # How many kill-chain stages seen
    lateral_spread: float = 0.0        # Number of hosts affected
    data_sensitivity: float = 0.0      # Sensitivity of accessed data
    confidence: float = 0.0            # Detection confidence
    historical_pattern: float = 0.0    # Match with known attack patterns

    # Evidence
    evidence_summary: str = ""
    contributing_factors: list = field(default_factory=list)

    def compute(self):
        """Compute the weighted composite score."""
        weights = {
            "base_severity": 0.25,
            "attack_chain_completeness": 0.20,
            "lateral_spread": 0.15,
            "data_sensitivity": 0.15,
            "confidence": 0.15,
            "historical_pattern": 0.10,
        }

        self.total_score = (
            self.base_severity * weights["base_severity"] +
            self.attack_chain_completeness * weights["attack_chain_completeness"] +
            self.lateral_spread * weights["lateral_spread"] +
            self.data_sensitivity * weights["data_sensitivity"] +
            self.confidence * weights["confidence"] +
            self.historical_pattern * weights["historical_pattern"]
        ) * 100

        self.total_score = min(100, max(0, self.total_score))

        if self.total_score >= 80:
            self.risk_level = "CRITICAL"
        elif self.total_score >= 60:
            self.risk_level = "HIGH"
        elif self.total_score >= 40:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

        self._build_evidence()
        return self

    def _build_evidence(self):
        """Build human-readable evidence summary."""
        factors = []

        if self.base_severity > 0.5:
            factors.append(f"High base severity ({self.base_severity:.0%})")
        if self.attack_chain_completeness > 0.3:
            factors.append(f"Attack chain {self.attack_chain_completeness:.0%} complete")
        if self.lateral_spread > 0.2:
            factors.append(f"Lateral spread detected ({self.lateral_spread:.0%})")
        if self.data_sensitivity > 0.5:
            factors.append(f"Sensitive data at risk ({self.data_sensitivity:.0%})")
        if self.confidence > 0.7:
            factors.append(f"High detection confidence ({self.confidence:.0%})")
        if self.historical_pattern > 0.5:
            factors.append(f"Matches known attack pattern ({self.historical_pattern:.0%})")

        self.contributing_factors = factors
        self.evidence_summary = (
            f"Risk Score: {self.total_score:.0f}/100 ({self.risk_level}). "
            f"Contributing factors: {'; '.join(factors) if factors else 'None significant'}."
        )


_SEVERITY_SCORES = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
    "INFO": 0.1,
}


def score_anomalies(anomalies: List[dict]) -> RiskScore:
    """
    Score a set of related anomalies as a single incident.
    """
    risk = RiskScore()

    if not anomalies:
        risk.compute()
        return risk

    # Base severity — highest severity among anomalies
    severities = [a.get("severity", "LOW") for a in anomalies]
    risk.base_severity = max(_SEVERITY_SCORES.get(s, 0.1) for s in severities)

    # Attack chain completeness — how many kill-chain stages are represented
    attack_types = set(a.get("anomaly_type", "") for a in anomalies)
    kill_chain_stages = {
        "port_scan": "reconnaissance",
        "brute_force": "initial_access",
        "brute_force_success": "initial_access",
        "privilege_escalation": "privilege_escalation",
        "lateral_movement": "lateral_movement",
        "data_exfiltration": "exfiltration",
        "suspicious_process": "execution",
    }
    stages_seen = set()
    for atype in attack_types:
        if atype in kill_chain_stages:
            stages_seen.add(kill_chain_stages[atype])
    risk.attack_chain_completeness = min(1.0, len(stages_seen) / 6.0)

    # Lateral spread — unique targets
    all_targets = set()
    for a in anomalies:
        targets = a.get("targets", [])
        all_targets.update(targets)
        if a.get("dest_ip"):
            all_targets.add(a["dest_ip"])
    risk.lateral_spread = min(1.0, len(all_targets) / 5.0)

    # Confidence — average of all anomaly confidences
    confidences = [a.get("confidence", 0.5) for a in anomalies]
    risk.confidence = sum(confidences) / len(confidences)

    # Data sensitivity — if exfiltration is involved
    if "data_exfiltration" in attack_types:
        risk.data_sensitivity = 0.8

    # Historical pattern match — based on how many anomaly types match known patterns
    known_patterns = {"brute_force", "port_scan", "lateral_movement", "data_exfiltration"}
    matching = attack_types.intersection(known_patterns)
    risk.historical_pattern = min(1.0, len(matching) / 3.0)

    risk.compute()
    logger.info(f"Risk scored: {risk.total_score:.0f}/100 ({risk.risk_level}) — {len(anomalies)} anomalies")
    return risk
