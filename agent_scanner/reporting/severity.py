"""Severity scoring inspired by CVSS.

Provides numeric severity calculation and labeling for
security findings in AI agent scans.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SeverityLevel(Enum):
    """Severity level labels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class SeverityFactors:
    """Factors used to calculate severity score.

    Attributes:
        exploitability: How easy the vulnerability is to exploit (0-10).
        impact: The damage caused if exploited (0-10).
        scope: Whether exploitation affects resources beyond the vulnerable component (0-10).
        remediation_difficulty: How difficult the fix is (0-10, lower = easier).
    """

    exploitability: float = 5.0
    impact: float = 5.0
    scope: float = 5.0
    remediation_difficulty: float = 5.0

    def validate(self) -> None:
        """Ensure all factors are within valid range."""
        for field_name in ("exploitability", "impact", "scope", "remediation_difficulty"):
            val = getattr(self, field_name)
            if not 0.0 <= val <= 10.0:
                raise ValueError(f"{field_name} must be between 0 and 10, got {val}")


def calculate_severity(
    finding: Optional[object] = None,
    *,
    exploitability: float = 5.0,
    impact: float = 5.0,
    scope: float = 5.0,
) -> float:
    """Calculate a severity score from 0 to 10.

    Uses a weighted formula inspired by CVSS v3.1 base score
    calculation, adapted for AI agent vulnerabilities.

    Args:
        finding: Optional finding object with severity_score attribute.
        exploitability: How easy the vulnerability is to exploit (0-10).
        impact: The damage if exploited (0-10).
        scope: Whether exploitation crosses component boundaries (0-10).

    Returns:
        Severity score between 0.0 and 10.0.
    """
    if finding is not None and hasattr(finding, "severity_score"):
        return float(finding.severity_score)

    factors = SeverityFactors(
        exploitability=exploitability,
        impact=impact,
        scope=scope,
    )
    factors.validate()

    # Weighted combination
    raw = (
        factors.exploitability * 0.35
        + factors.impact * 0.40
        + factors.scope * 0.25
    )

    return round(min(10.0, max(0.0, raw)), 1)


def severity_label(score: float) -> str:
    """Convert a numeric severity score to a human-readable label.

    Args:
        score: Severity score between 0.0 and 10.0.

    Returns:
        Severity label string.
    """
    if score >= 9.0:
        return SeverityLevel.CRITICAL.value
    elif score >= 7.0:
        return SeverityLevel.HIGH.value
    elif score >= 4.0:
        return SeverityLevel.MEDIUM.value
    elif score >= 0.1:
        return SeverityLevel.LOW.value
    else:
        return SeverityLevel.INFO.value


def severity_color(score: float) -> str:
    """Return a Rich-compatible color name for a severity score.

    Args:
        score: Severity score between 0.0 and 10.0.

    Returns:
        Color name string for Rich console output.
    """
    if score >= 9.0:
        return "red"
    elif score >= 7.0:
        return "orange1"
    elif score >= 4.0:
        return "yellow"
    elif score >= 0.1:
        return "blue"
    else:
        return "dim"
