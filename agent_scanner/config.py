"""Scanner configuration module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ScanMode(Enum):
    """Scan execution mode."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    FULL = "full"


class Framework(Enum):
    """Supported AI agent frameworks."""
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    GENERIC = "generic"


@dataclass
class ScannerConfig:
    """Configuration for the AI Agent Security Scanner.

    Attributes:
        mode: Scan mode (static, dynamic, or full).
        framework: Target framework for framework-specific scanning.
        severity_threshold: Minimum severity level to report (0-10).
        max_file_size_kb: Maximum file size to scan in kilobytes.
        scan_extensions: File extensions to scan.
        timeout_seconds: HTTP timeout for dynamic analysis.
        max_fuzz_iterations: Maximum fuzzing iterations.
        output_format: Report output format.
        custom_patterns: Path to custom vulnerability patterns file.
        exclude_patterns: Glob patterns for files to exclude.
        enable_secret_scanning: Whether to scan for hardcoded secrets.
        enable_prompt_analysis: Whether to analyze system prompts.
    """

    mode: ScanMode = ScanMode.STATIC
    framework: Framework = Framework.GENERIC
    severity_threshold: float = 0.0
    max_file_size_kb: int = 1024
    scan_extensions: list[str] = field(default_factory=lambda: [".py"])
    timeout_seconds: int = 30
    max_fuzz_iterations: int = 100
    output_format: str = "markdown"
    custom_patterns: Optional[Path] = None
    exclude_patterns: list[str] = field(
        default_factory=lambda: ["__pycache__", ".git", "*.pyc", "node_modules"]
    )
    enable_secret_scanning: bool = True
    enable_prompt_analysis: bool = True

    def validate(self) -> list[str]:
        """Validate configuration and return list of warnings."""
        warnings: list[str] = []
        if self.severity_threshold < 0 or self.severity_threshold > 10:
            warnings.append("severity_threshold should be between 0 and 10")
        if self.max_fuzz_iterations > 10000:
            warnings.append("max_fuzz_iterations > 10000 may take very long")
        if self.timeout_seconds < 1:
            warnings.append("timeout_seconds should be at least 1")
        return warnings
