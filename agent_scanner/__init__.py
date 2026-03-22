"""
AI Agent Security Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~

Static and dynamic security analysis for AI agent implementations.
Detect prompt injection vulnerabilities, data exfiltration risks,
and unsafe tool usage in LangChain, CrewAI, and AutoGen agents.

Usage:
    >>> from agent_scanner import AgentSecurityScanner
    >>> scanner = AgentSecurityScanner()
    >>> report = scanner.scan_code("./my_agent/")
    >>> print(report.summary())
"""

__version__ = "0.1.0"
__author__ = "kadirou12333"

from agent_scanner.scanner import AgentSecurityScanner
from agent_scanner.config import ScannerConfig

__all__ = ["AgentSecurityScanner", "ScannerConfig"]
