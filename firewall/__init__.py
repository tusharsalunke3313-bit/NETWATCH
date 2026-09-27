"""
NETWATCH Firewall Analysis Package.

Phase 8 - Firewall Configuration Analyzer
"""

from .firewall_analyzer import (
    FirewallAnalyzer,
    FirewallAnalysisResult,
    FirewallFinding,
    FirewallRule,
    FirewallAnalyzerError,
    format_firewall_results,
)

__all__ = [
    "FirewallAnalyzer",
    "FirewallAnalysisResult",
    "FirewallFinding",
    "FirewallRule",
    "FirewallAnalyzerError",
    "format_firewall_results",
]