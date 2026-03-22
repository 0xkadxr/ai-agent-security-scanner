"""Main scanner orchestrator module.

Coordinates static analysis, dynamic analysis, and framework-specific
scanning to produce a unified security report.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from agent_scanner.config import Framework, ScanMode, ScannerConfig
from agent_scanner.static_analysis.code_scanner import CodeScanner
from agent_scanner.static_analysis.prompt_analyzer import PromptAnalyzer
from agent_scanner.static_analysis.tool_analyzer import ToolAnalyzer
from agent_scanner.dynamic_analysis.fuzzer import AgentFuzzer
from agent_scanner.dynamic_analysis.injection_tester import InjectionTester
from agent_scanner.dynamic_analysis.exfiltration_tester import ExfiltrationTester
from agent_scanner.dynamic_analysis.privilege_tester import PrivilegeTester
from agent_scanner.reporting.severity import calculate_severity, severity_label
from agent_scanner.reporting.generator import ReportGenerator
from agent_scanner.frameworks.langchain_adapter import LangChainAdapter
from agent_scanner.frameworks.crewai_adapter import CrewAIAdapter
from agent_scanner.frameworks.autogen_adapter import AutoGenAdapter


@dataclass
class Finding:
    """A single security finding from a scan.

    Attributes:
        vuln_id: Vulnerability identifier (e.g. AGENT-001).
        title: Short title of the finding.
        description: Detailed description.
        severity_score: Numeric severity 0-10.
        file_path: Source file where the issue was found.
        line_number: Line number in the source file.
        code_snippet: Relevant code snippet.
        recommendation: Remediation guidance.
        category: Finding category (static, dynamic, framework).
    """

    vuln_id: str
    title: str
    description: str
    severity_score: float
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""
    category: str = "static"

    @property
    def severity(self) -> str:
        """Human-readable severity label."""
        return severity_label(self.severity_score)


@dataclass
class ScanReport:
    """Complete scan report containing all findings.

    Attributes:
        findings: List of all findings.
        scan_duration_seconds: Time taken for the scan.
        files_scanned: Number of files scanned.
        config: Scanner configuration used.
        metadata: Additional scan metadata.
    """

    findings: list[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    files_scanned: int = 0
    config: Optional[ScannerConfig] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        """Overall risk score (0-10) based on findings."""
        if not self.findings:
            return 0.0
        max_score = max(f.severity_score for f in self.findings)
        avg_score = sum(f.severity_score for f in self.findings) / len(self.findings)
        # Weight towards the maximum severity but consider volume
        return min(10.0, max_score * 0.7 + avg_score * 0.3)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity_score >= 9.0)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if 7.0 <= f.severity_score < 9.0)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if 4.0 <= f.severity_score < 7.0)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if 0.1 <= f.severity_score < 4.0)

    def summary(self) -> str:
        """Generate a short textual summary of the scan."""
        lines = [
            f"Scan Report Summary",
            f"{'=' * 40}",
            f"Files scanned: {self.files_scanned}",
            f"Duration: {self.scan_duration_seconds:.2f}s",
            f"Total findings: {len(self.findings)}",
            f"  Critical: {self.critical_count}",
            f"  High: {self.high_count}",
            f"  Medium: {self.medium_count}",
            f"  Low: {self.low_count}",
            f"Overall risk score: {self.risk_score:.1f}/10",
        ]
        return "\n".join(lines)

    def filtered(self, min_severity: float = 0.0) -> list[Finding]:
        """Return findings at or above the given severity threshold."""
        return [f for f in self.findings if f.severity_score >= min_severity]


class AgentSecurityScanner:
    """Main orchestrator for AI agent security scanning.

    Coordinates static analysis, dynamic testing, and framework-specific
    checks to produce a comprehensive security report.

    Args:
        config: Scanner configuration. Uses defaults if None.

    Example:
        >>> scanner = AgentSecurityScanner()
        >>> report = scanner.scan_code("./my_agent/")
        >>> print(report.summary())
    """

    def __init__(self, config: Optional[ScannerConfig] = None) -> None:
        self.config = config or ScannerConfig()
        self._code_scanner = CodeScanner()
        self._prompt_analyzer = PromptAnalyzer()
        self._tool_analyzer = ToolAnalyzer()
        self._report_generator = ReportGenerator()
        self._framework_adapters: dict[Framework, Any] = {
            Framework.LANGCHAIN: LangChainAdapter(),
            Framework.CREWAI: CrewAIAdapter(),
            Framework.AUTOGEN: AutoGenAdapter(),
        }

    def scan_code(self, file_path_or_dir: str) -> ScanReport:
        """Perform static analysis on source code.

        Scans Python files for vulnerability patterns including unsafe
        exec/eval, hardcoded secrets, unvalidated inputs, and more.

        Args:
            file_path_or_dir: Path to a Python file or directory.

        Returns:
            ScanReport with all static analysis findings.
        """
        start = time.time()
        path = Path(file_path_or_dir)
        findings: list[Finding] = []
        files_scanned = 0

        if path.is_file():
            file_findings = self._code_scanner.scan_file(str(path))
            findings.extend(file_findings)
            files_scanned = 1
        elif path.is_dir():
            dir_findings, count = self._code_scanner.scan_directory(str(path))
            findings.extend(dir_findings)
            files_scanned = count
        else:
            raise FileNotFoundError(f"Path not found: {file_path_or_dir}")

        # Filter by severity threshold
        findings = [
            f for f in findings if f.severity_score >= self.config.severity_threshold
        ]

        return ScanReport(
            findings=findings,
            scan_duration_seconds=time.time() - start,
            files_scanned=files_scanned,
            config=self.config,
            metadata={"scan_type": "static", "target": str(path)},
        )

    def scan_agent(
        self,
        agent_endpoint: str,
        test_suite: Optional[str] = None,
    ) -> ScanReport:
        """Perform dynamic analysis against a running agent endpoint.

        Runs fuzzing, injection testing, exfiltration testing, and
        privilege escalation testing against the agent.

        Args:
            agent_endpoint: HTTP endpoint of the running agent.
            test_suite: Optional test suite name to run.

        Returns:
            ScanReport with dynamic analysis findings.
        """
        start = time.time()
        findings: list[Finding] = []

        fuzzer = AgentFuzzer(
            endpoint=agent_endpoint,
            timeout=self.config.timeout_seconds,
        )
        injection_tester = InjectionTester(
            endpoint=agent_endpoint,
            timeout=self.config.timeout_seconds,
        )
        exfil_tester = ExfiltrationTester(
            endpoint=agent_endpoint,
            timeout=self.config.timeout_seconds,
        )
        privilege_tester = PrivilegeTester(
            endpoint=agent_endpoint,
            timeout=self.config.timeout_seconds,
        )

        findings.extend(fuzzer.fuzz_inputs(max_iterations=self.config.max_fuzz_iterations))
        findings.extend(injection_tester.run_all_tests())
        findings.extend(exfil_tester.run_all_tests())
        findings.extend(privilege_tester.run_all_tests())

        findings = [
            f for f in findings if f.severity_score >= self.config.severity_threshold
        ]

        return ScanReport(
            findings=findings,
            scan_duration_seconds=time.time() - start,
            config=self.config,
            metadata={
                "scan_type": "dynamic",
                "endpoint": agent_endpoint,
                "test_suite": test_suite,
            },
        )

    def scan_framework(
        self,
        framework: Framework,
        agent_config: dict[str, Any],
    ) -> ScanReport:
        """Run framework-specific security analysis.

        Uses framework adapters to extract and analyze tools, prompts,
        and chain configurations from framework-specific agent code.

        Args:
            framework: The target framework (langchain, crewai, autogen).
            agent_config: Framework-specific agent configuration dict.

        Returns:
            ScanReport with framework-specific findings.
        """
        start = time.time()
        adapter = self._framework_adapters.get(framework)
        if adapter is None:
            raise ValueError(f"Unsupported framework: {framework}")

        findings: list[Finding] = []
        code_path = agent_config.get("code_path", "")

        if code_path:
            tools = adapter.extract_tools(code_path)
            for tool_code in tools:
                findings.extend(self._tool_analyzer.analyze_tool_definition(tool_code))

            prompts = adapter.extract_prompts(code_path)
            for prompt_text in prompts:
                findings.extend(self._prompt_analyzer.analyze_system_prompt(prompt_text))

        findings = [
            f for f in findings if f.severity_score >= self.config.severity_threshold
        ]

        return ScanReport(
            findings=findings,
            scan_duration_seconds=time.time() - start,
            config=self.config,
            metadata={
                "scan_type": "framework",
                "framework": framework.value,
            },
        )

    def full_scan(
        self,
        code_path: str,
        endpoint: Optional[str] = None,
    ) -> ScanReport:
        """Run a combined static and dynamic scan.

        Performs static analysis on the code path and optionally runs
        dynamic analysis against an agent endpoint.

        Args:
            code_path: Path to source code for static analysis.
            endpoint: Optional HTTP endpoint for dynamic analysis.

        Returns:
            Combined ScanReport with all findings.
        """
        start = time.time()
        all_findings: list[Finding] = []
        total_files = 0

        # Static analysis
        static_report = self.scan_code(code_path)
        all_findings.extend(static_report.findings)
        total_files = static_report.files_scanned

        # Framework-specific analysis
        if self.config.framework != Framework.GENERIC:
            fw_report = self.scan_framework(
                self.config.framework,
                {"code_path": code_path},
            )
            all_findings.extend(fw_report.findings)

        # Dynamic analysis
        if endpoint:
            dynamic_report = self.scan_agent(endpoint)
            all_findings.extend(dynamic_report.findings)

        # Deduplicate by (vuln_id, file_path, line_number)
        seen: set[tuple] = set()
        unique: list[Finding] = []
        for f in all_findings:
            key = (f.vuln_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return ScanReport(
            findings=unique,
            scan_duration_seconds=time.time() - start,
            files_scanned=total_files,
            config=self.config,
            metadata={"scan_type": "full", "code_path": code_path, "endpoint": endpoint},
        )
