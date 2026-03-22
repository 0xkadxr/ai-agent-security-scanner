"""Example: Scanning a LangChain agent for security vulnerabilities.

Demonstrates how to use the scanner with framework-specific analysis
for LangChain-based agents.
"""

from agent_scanner import AgentSecurityScanner
from agent_scanner.config import Framework, ScannerConfig
from agent_scanner.reporting.generator import ReportGenerator


def main():
    # Configure scanner for LangChain
    config = ScannerConfig(
        framework=Framework.LANGCHAIN,
        severity_threshold=4.0,  # Only report Medium and above
    )

    scanner = AgentSecurityScanner(config=config)

    # Run static analysis on a LangChain agent directory
    report = scanner.scan_code("./my_langchain_agent/")

    # Display results
    print(report.summary())
    print()

    # Generate detailed markdown report
    generator = ReportGenerator()
    markdown = generator.generate_markdown(report)

    # Write report to file
    with open("langchain_scan_report.md", "w") as f:
        f.write(markdown)

    print(f"Detailed report written to langchain_scan_report.md")
    print(f"Found {len(report.findings)} issues with risk score {report.risk_score:.1f}/10")


if __name__ == "__main__":
    main()
