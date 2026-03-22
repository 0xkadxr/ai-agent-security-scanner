![CI](https://github.com/kadirou12333/ai-agent-security-scanner/actions/workflows/ci.yml/badge.svg)

# AI Agent Security Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security Scanner](https://img.shields.io/badge/type-security%20scanner-red.svg)]()

**Static and dynamic security analysis for AI agent implementations.** Detect prompt injection vulnerabilities, data exfiltration risks, and unsafe tool usage in LangChain, CrewAI, and AutoGen agents.

## Vulnerability Catalog

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| AGENT-001 | Unvalidated Tool Inputs | High (8.5) | Tool accepts user input without validation |
| AGENT-002 | Prompt Injection | Critical (9.0) | User input concatenated into prompts |
| AGENT-003 | Missing Output Sanitization | High (7.0) | Raw output returned without filtering |
| AGENT-004 | Hardcoded API Keys | High (8.0) | Secrets hardcoded in source code |
| AGENT-005 | Unrestricted File Access | High (8.5) | File operations with unvalidated paths |
| AGENT-006 | SQL Injection in Tools | Critical (9.5) | SQL queries built with string formatting |
| AGENT-007 | Command Injection via Tools | Critical (9.5) | System commands with user input |
| AGENT-008 | Excessive Permissions | High (7.5) | Overly broad agent permissions |
| AGENT-009 | Missing Rate Limiting | Medium (5.0) | No rate limiting on endpoints |
| AGENT-010 | Data Exfiltration Vectors | High (8.0) | Unrestricted outbound network access |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Scan a Python file or directory
python cli.py scan --path ./my_agent/

# Scan with framework-specific analysis
python cli.py scan --path ./my_agent/ --framework langchain

# Dynamic analysis against a running agent
python cli.py scan --endpoint http://localhost:8000 --dynamic

# Combined static + dynamic scan
python cli.py scan --path ./my_agent/ --endpoint http://localhost:8000 --dynamic

# Output to file
python cli.py scan --path ./my_agent/ --output report.md --format markdown

# View vulnerability catalog
python cli.py catalog
```

## Static Analysis

The AST-based static analyzer parses Python source code and detects:

- **Dangerous builtins**: `eval()`, `exec()`, `compile()` usage
- **SQL injection**: String formatting in `cursor.execute()` calls
- **Command injection**: `os.system()`, `subprocess` with `shell=True`
- **Hardcoded secrets**: API keys, tokens, passwords in source
- **Prompt concatenation**: f-strings and `.format()` building prompts
- **Unsafe tools**: `@tool` functions without input validation
- **Path traversal**: File operations with unvalidated user paths
- **Excessive permissions**: Overly broad permission flags

```python
from agent_scanner import AgentSecurityScanner

scanner = AgentSecurityScanner()
report = scanner.scan_code("./my_agent/")

print(report.summary())
print(f"Risk Score: {report.risk_score}/10")
print(f"Critical: {report.critical_count}, High: {report.high_count}")
```

## Dynamic Analysis

Test running agents for runtime vulnerabilities:

- **Input fuzzing**: Type confusion, boundary values, encoding tricks
- **Prompt injection**: Direct, indirect, multi-turn, and encoding bypass
- **Data exfiltration**: System prompt extraction, canary tokens, cross-session leakage
- **Privilege escalation**: Role manipulation, capability expansion, access control bypass

```python
report = scanner.scan_agent("http://localhost:8000/api/chat")
```

## Framework Support

| Framework | Tool Extraction | Prompt Extraction | Chain Analysis |
|-----------|:-:|:-:|:-:|
| LangChain | Yes | Yes | Yes |
| CrewAI | Yes | Yes | Yes |
| AutoGen | Yes | Yes | Yes |

```python
from agent_scanner.config import Framework, ScannerConfig

config = ScannerConfig(framework=Framework.LANGCHAIN)
scanner = AgentSecurityScanner(config=config)
report = scanner.full_scan("./my_langchain_agent/")
```

## Prompt Security Scoring

Analyze system prompts for security quality:

```python
from agent_scanner.static_analysis.prompt_analyzer import PromptAnalyzer

analyzer = PromptAnalyzer()
score = analyzer.score_prompt(my_system_prompt)

print(f"Overall: {score.overall}/10")
print(f"Injection Resistance: {score.injection_resistance}/10")
print(f"Boundary Clarity: {score.boundary_clarity}/10")
print(f"Data Handling: {score.data_handling}/10")
```

## Sample Report

```
Scan Report Summary
========================================
Files scanned: 1
Duration: 0.03s
Total findings: 12
  Critical: 3
  High: 6
  Medium: 2
  Low: 1
Overall risk score: 8.7/10

Top Issues:
  [Critical] AGENT-006: SQL injection via string formatting
  [Critical] AGENT-007: Dangerous builtin: eval()
  [Critical] AGENT-007: Command injection via string formatting
  [High]     AGENT-004: Hardcoded secret in 'api_key'
  [High]     AGENT-001: Tool 'search_tool' lacks input validation
```

## Adding Custom Rules

```python
from agent_scanner.static_analysis.patterns import VulnerabilityPattern, VulnerabilityPatterns

patterns = VulnerabilityPatterns()
patterns.add_pattern(VulnerabilityPattern(
    vuln_id="CUSTOM-001",
    name="Unsafe Deserialization",
    description="Pickle or YAML deserialization of untrusted data",
    severity=9.0,
    regex_patterns=[r"pickle\.loads?\(", r"yaml\.(?:unsafe_)?load\("],
    recommendation="Use json.loads() or yaml.safe_load() instead.",
))
```

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Ethical Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning systems you do not own. The dynamic analysis features send test payloads to agent endpoints -- only use against systems you have permission to test. The vulnerability examples and test payloads are provided for educational and defensive purposes.

## License

MIT License -- see [LICENSE](LICENSE) for details.
