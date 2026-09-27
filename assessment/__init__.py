"""
NETWATCH Security Assessment package.

Provides centralized aggregation and assessment of results
from the network discovery, scanning, DNS, HTTP/HTTPS,
traffic, IDS, firewall, and topology modules.
"""

from assessment.assessment_engine import (
    AssessmentEngine,
    AssessmentResult,
    FindingSummary,
    format_assessment_result,
)

__all__ = [
    "AssessmentEngine",
    "AssessmentResult",
    "FindingSummary",
    "format_assessment_result",
]