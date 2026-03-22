"""Example: Scanning a custom AI agent with both static and dynamic analysis.

Demonstrates full_scan combining static code analysis with dynamic
endpoint testing.
"""

from agent_scanner import AgentSecurityScanner
from agent_scanner.config import ScannerConfig, ScanMode
from agent_scanner.reporting.generator import ReportGenerator


def main():
    # Configure for full scan (static + dynamic)
    config = ScannerConfig(
        mode=ScanMode.FULL,
        max_fuzz_iterations=50,
        timeout_seconds=15,
    )

    scanner = AgentSecurityScanner(config=config)

    # Run combined static + dynamic scan
    report = scanner.full_scan(
        code_path="./my_agent/",
        endpoint="http://localhost:8000/api/chat",
    )

    print(report.summary())
    print()

    # Generate JSON report for CI/CD integration
    generator = ReportGenerator()
    json_report = generator.generate_json(report)

    with open("scan_results.json", "w") as f:
        f.write(json_report)

    # Exit with non-zero if critical issues found
    if report.critical_count > 0:
        print(f"CRITICAL: {report.critical_count} critical vulnerabilities found!")
        exit(1)


if __name__ == "__main__":
    main()
