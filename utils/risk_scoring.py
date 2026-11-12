
"""
VulnScope - Unified Risk Scoring Engine

Converts scanner findings into a consistent risk score
and severity classification.

This is a prioritization model, not an official CVSS calculator.
"""

import math
from typing import Any


# --------------------------------------------------
# RISK CONFIGURATION
# --------------------------------------------------

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "informational": 0.5
}

CONFIDENCE_WEIGHTS = {
    "confirmed": 1.0,
    "high": 1.0,
    "medium": 0.8,
    "low": 0.6,
    "false positive": 0.0
}

SEVERITY_SUMMARY_KEYS = (
    "critical",
    "high",
    "medium",
    "low",
    "informational"
)


# --------------------------------------------------
# INPUT NORMALIZATION
# --------------------------------------------------

def normalize_severity(severity: Any) -> str:
    """Normalize severity labels from different scanners."""

    if severity is None:
        return "informational"

    value = str(severity).strip().lower()

    aliases = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "informational": "informational",
        "info": "informational",
        "none": "informational",
        "0": "informational",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical"
    }

    return aliases.get(value, "informational")


def normalize_confidence(confidence: Any) -> str:
    """Normalize confidence labels."""

    if confidence is None or str(confidence).strip() == "":
        return "medium"

    value = str(confidence).strip().lower()

    aliases = {
        "confirmed": "confirmed",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "false positive": "false positive",
        "false_positive": "false positive"
    }

    return aliases.get(value, "medium")


# --------------------------------------------------
# SCORE VALIDATION
# --------------------------------------------------

def validate_score(score: Any) -> float:
    """Validate and normalize a numerical risk score."""

    if isinstance(score, bool):
        raise ValueError("Risk score must be a number between 0 and 10.")

    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        raise ValueError("Risk score must be a valid number.")

    if not math.isfinite(numeric_score):
        raise ValueError("Risk score must be finite.")

    if not 0.0 <= numeric_score <= 10.0:
        raise ValueError("Risk score must be between 0 and 10.")

    return numeric_score


# --------------------------------------------------
# INDIVIDUAL FINDING SCORE
# --------------------------------------------------

def calculate_finding_score(finding: dict) -> dict:
    """
    Calculate a prioritization score for one finding.

    Score range: 0 to 10.

    Confidence adjusts the priority score. It does not
    establish whether a finding is exploitable.
    """

    if not isinstance(finding, dict):
        raise TypeError("Each finding must be a dictionary.")

    raw_severity = (
        finding.get("risk")
        or finding.get("severity")
        or finding.get("risk_level")
    )

    raw_confidence = finding.get("confidence")

    severity = normalize_severity(raw_severity)
    confidence = normalize_confidence(raw_confidence)

    severity_weight = SEVERITY_WEIGHTS[severity]
    confidence_weight = CONFIDENCE_WEIGHTS[confidence]

    score = round(
        severity_weight * confidence_weight,
        2
    )

    return {
        "name": finding.get(
            "name",
            finding.get("header", "Unknown finding")
        ),
        "severity": severity.title(),
        "confidence": confidence.title(),
        "score": score,
        "priority": get_risk_rating(score),
        "url": finding.get("url", ""),
        "description": finding.get("description", ""),
        "solution": finding.get("solution", ""),
        "cwe_id": finding.get("cwe_id", ""),
        "method": finding.get("method", ""),
        "parameter": finding.get("parameter", ""),
        "reference": finding.get("reference", ""),
        "wasc_id": finding.get("wasc_id", ""),
        "plugin_id": finding.get("plugin_id", "")
    }


# --------------------------------------------------
# OVERALL RISK CLASSIFICATION
# --------------------------------------------------

def get_risk_rating(score: float) -> str:
    """Convert a numerical score into a risk category."""

    score = validate_score(score)

    if score >= 9.0:
        return "Critical"

    if score >= 7.0:
        return "High"

    if score >= 4.0:
        return "Medium"

    if score >= 1.0:
        return "Low"

    return "Informational"


# --------------------------------------------------
# SUMMARY GENERATION
# --------------------------------------------------

def generate_risk_summary(scored_findings: list) -> dict:
    """Generate severity counts and overall risk statistics."""

    if not isinstance(scored_findings, list):
        raise TypeError("scored_findings must be a list.")

    summary = {
        key: 0 for key in SEVERITY_SUMMARY_KEYS
    }

    validated_scores = []

    for finding in scored_findings:

        if not isinstance(finding, dict):
            raise TypeError(
                "Each scored finding must be a dictionary."
            )

        severity = normalize_severity(
            finding.get("severity")
        )

        score = validate_score(
            finding.get("score")
        )

        summary[severity] += 1
        validated_scores.append(score)

    total = len(validated_scores)

    if total == 0:
        average_score = 0.0
        highest_score = 0.0
        overall_risk = "Informational"

    else:
        average_score = round(
            sum(validated_scores) / total,
            2
        )

        highest_score = max(validated_scores)

        # The highest finding score determines overall risk.
        overall_risk = get_risk_rating(highest_score)

    return {
        "total_findings": total,
        "severity_summary": summary,
        "average_score": average_score,
        "highest_score": highest_score,
        "overall_risk": overall_risk
    }


# --------------------------------------------------
# MAIN SCORING FUNCTION
# --------------------------------------------------

def score_findings(findings: list) -> dict:
    """
    Score a list of findings and return a unified report.
    """

    if not isinstance(findings, list):
        raise TypeError("findings must be a list.")

    scored_findings = []

    for finding in findings:

        scored_findings.append(
            calculate_finding_score(finding)
        )

    summary = generate_risk_summary(scored_findings)

    # Sort findings from highest to lowest score.
    scored_findings.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return {
        "findings": scored_findings,
        "summary": summary
    }
