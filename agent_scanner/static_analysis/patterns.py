"""Vulnerability patterns database for static analysis.

Contains regex and AST-based patterns for detecting common security
vulnerabilities in AI agent implementations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VulnerabilityPattern:
    """A single vulnerability detection pattern.

    Attributes:
        vuln_id: Unique vulnerability identifier.
        name: Human-readable name.
        description: Detailed description of the vulnerability.
        severity: Base severity score (0-10).
        regex_patterns: List of regex patterns that match vulnerable code.
        ast_node_types: AST node types to inspect.
        ast_signatures: Function/attribute names that indicate the vulnerability.
        recommendation: Remediation guidance.
    """

    vuln_id: str
    name: str
    description: str
    severity: float
    regex_patterns: list[str] = field(default_factory=list)
    ast_node_types: list[str] = field(default_factory=list)
    ast_signatures: list[str] = field(default_factory=list)
    recommendation: str = ""
    category: str = "general"


class VulnerabilityPatterns:
    """Database of known vulnerability patterns for AI agents.

    Provides pattern-matching capabilities for both regex-based and
    AST-based detection of security vulnerabilities.
    """

    def __init__(self) -> None:
        self._patterns: list[VulnerabilityPattern] = self._build_default_patterns()

    def _build_default_patterns(self) -> list[VulnerabilityPattern]:
        """Build the default set of vulnerability patterns."""
        return [
            VulnerabilityPattern(
                vuln_id="AGENT-001",
                name="Unvalidated Tool Inputs",
                description=(
                    "Tool function accepts user-controlled input without validation "
                    "or sanitization, allowing injection attacks through tool parameters."
                ),
                severity=8.5,
                regex_patterns=[
                    r"def\s+\w+tool\w*\s*\([^)]*\)\s*:",
                    r"@tool\s*\n\s*def\s+\w+\s*\([^)]*user_input[^)]*\)",
                ],
                ast_node_types=["FunctionDef"],
                ast_signatures=["tool", "run", "execute"],
                recommendation=(
                    "Add input validation using Pydantic models or custom validators. "
                    "Sanitize all user-controlled inputs before passing to tools."
                ),
                category="input_validation",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-002",
                name="Direct Prompt Concatenation",
                description=(
                    "User input is directly concatenated into prompt strings without "
                    "sanitization, enabling prompt injection attacks."
                ),
                severity=9.0,
                regex_patterns=[
                    r'f["\'].*\{.*user.*\}.*["\']',
                    r'f["\'].*\{.*input.*\}.*["\']',
                    r'f["\'].*\{.*query.*\}.*["\']',
                    r'prompt\s*\+\s*user',
                    r'prompt\s*\+\s*input',
                    r'prompt\s*=.*format\(.*user',
                    r'\.format\(.*user_input',
                    r'%\s*\(.*user',
                ],
                ast_node_types=["JoinedStr", "BinOp"],
                ast_signatures=[],
                recommendation=(
                    "Never concatenate user input directly into prompts. Use "
                    "parameterized prompt templates with clear delimiters between "
                    "system instructions and user content."
                ),
                category="prompt_injection",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-003",
                name="Missing Output Sanitization",
                description=(
                    "Agent or tool output is returned to users without sanitization, "
                    "potentially leaking sensitive data or enabling XSS in web UIs."
                ),
                severity=7.0,
                regex_patterns=[
                    r"return\s+result\s*$",
                    r"return\s+response\.text",
                    r"return\s+output\s*$",
                    r"print\(.*result.*\)",
                ],
                ast_node_types=["Return"],
                ast_signatures=[],
                recommendation=(
                    "Sanitize all outputs before returning to users. Filter sensitive "
                    "data patterns (API keys, internal paths, PII) from responses."
                ),
                category="output_sanitization",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-004",
                name="Hardcoded API Keys",
                description=(
                    "API keys, tokens, or credentials are hardcoded in source code "
                    "instead of being loaded from secure environment variables."
                ),
                severity=8.0,
                regex_patterns=[
                    r'(?:api[_-]?key|apikey)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
                    r'(?:secret|token|password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
                    r'(?:OPENAI|ANTHROPIC|GOOGLE|AWS|AZURE)[_A-Z]*KEY\s*=\s*["\'][^"\']+["\']',
                    r'sk-[A-Za-z0-9]{20,}',
                    r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
                ],
                ast_node_types=["Assign"],
                ast_signatures=[],
                recommendation=(
                    "Never hardcode secrets. Use environment variables, a secrets "
                    "manager, or a .env file (excluded from version control)."
                ),
                category="secrets",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-005",
                name="Unrestricted File System Access",
                description=(
                    "Agent tools have unrestricted file system access without "
                    "path validation, allowing directory traversal attacks."
                ),
                severity=8.5,
                regex_patterns=[
                    r'open\s*\(.*user.*\)',
                    r'open\s*\(.*input.*\)',
                    r'Path\s*\(.*user.*\)',
                    r'os\.path\.join\(.*user',
                    r'shutil\.\w+\(.*user',
                    r'os\.remove\(.*user',
                    r'os\.unlink\(.*user',
                ],
                ast_node_types=["Call"],
                ast_signatures=["open", "read", "write", "unlink", "remove", "rmtree"],
                recommendation=(
                    "Implement path allowlisting and validate all file paths. "
                    "Use chroot or sandboxed file access. Reject paths with '..' components."
                ),
                category="file_access",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-006",
                name="SQL Injection in Tool Calls",
                description=(
                    "SQL queries are constructed using string concatenation or "
                    "formatting with user-controlled input, enabling SQL injection."
                ),
                severity=9.5,
                regex_patterns=[
                    r'execute\s*\(\s*f["\']',
                    r'execute\s*\(\s*["\'].*%s',
                    r'execute\s*\(\s*["\'].*\+',
                    r'cursor\.\w+\(.*format\(',
                    r'query\s*=\s*f["\'].*SELECT',
                    r'query\s*=\s*f["\'].*INSERT',
                    r'query\s*=\s*f["\'].*UPDATE',
                    r'query\s*=\s*f["\'].*DELETE',
                ],
                ast_node_types=["Call", "JoinedStr"],
                ast_signatures=["execute", "executemany", "raw"],
                recommendation=(
                    "Always use parameterized queries. Never concatenate user input "
                    "into SQL strings. Use an ORM where possible."
                ),
                category="injection",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-007",
                name="Command Injection via Tools",
                description=(
                    "Agent tools execute system commands with user-controlled input "
                    "without proper sanitization, enabling command injection."
                ),
                severity=9.5,
                regex_patterns=[
                    r'os\.system\s*\(',
                    r'os\.popen\s*\(',
                    r'subprocess\.\w+\(.*shell\s*=\s*True',
                    r'subprocess\.call\s*\(\s*f["\']',
                    r'subprocess\.run\s*\(\s*f["\']',
                    r'exec\s*\(',
                    r'eval\s*\(',
                    r'__import__\s*\(',
                    r'compile\s*\(.*exec',
                ],
                ast_node_types=["Call"],
                ast_signatures=[
                    "system", "popen", "exec", "eval", "compile",
                    "subprocess.call", "subprocess.run", "subprocess.Popen",
                ],
                recommendation=(
                    "Avoid executing system commands with user input. If necessary, "
                    "use subprocess with shell=False and a strict allowlist of commands. "
                    "Never use eval() or exec() with user-controlled data."
                ),
                category="injection",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-008",
                name="Excessive Permissions",
                description=(
                    "Agent or tools are granted overly broad permissions "
                    "(e.g., unrestricted network access, admin privileges) "
                    "violating the principle of least privilege."
                ),
                severity=7.5,
                regex_patterns=[
                    r'allow_dangerous_requests\s*=\s*True',
                    r'permissions\s*=\s*\[?\s*["\']all["\']',
                    r'admin\s*=\s*True',
                    r'root\s*=\s*True',
                    r'privileged\s*=\s*True',
                    r'unrestricted\s*=\s*True',
                ],
                ast_node_types=["Assign", "keyword"],
                ast_signatures=[],
                recommendation=(
                    "Follow the principle of least privilege. Grant only the minimum "
                    "permissions needed. Use role-based access control."
                ),
                category="permissions",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-009",
                name="Missing Rate Limiting",
                description=(
                    "Agent endpoints or tool calls lack rate limiting, enabling "
                    "denial of service or resource exhaustion attacks."
                ),
                severity=5.0,
                regex_patterns=[
                    r'while\s+True\s*:',
                    r'for\s+\w+\s+in\s+range\s*\(\s*\d{4,}',
                ],
                ast_node_types=["While", "For"],
                ast_signatures=[],
                recommendation=(
                    "Implement rate limiting on all agent endpoints and tool calls. "
                    "Set maximum iteration counts and timeout limits."
                ),
                category="availability",
            ),
            VulnerabilityPattern(
                vuln_id="AGENT-010",
                name="Data Exfiltration Vectors",
                description=(
                    "Agent has network access patterns that could enable data "
                    "exfiltration through tool calls or prompt manipulation."
                ),
                severity=8.0,
                regex_patterns=[
                    r'requests\.\w+\s*\(.*user',
                    r'httpx\.\w+\s*\(.*user',
                    r'urllib\.request',
                    r'aiohttp\.\w+\s*\(',
                    r'fetch\s*\(.*user',
                    r'webhook\s*=',
                    r'\.post\s*\(.*\bdata\b.*=',
                ],
                ast_node_types=["Call"],
                ast_signatures=["get", "post", "put", "patch", "request", "fetch"],
                recommendation=(
                    "Restrict outbound network access to an allowlist of domains. "
                    "Monitor and log all outbound requests. Validate URLs before making requests."
                ),
                category="exfiltration",
            ),
        ]

    @property
    def patterns(self) -> list[VulnerabilityPattern]:
        """Return all registered patterns."""
        return list(self._patterns)

    def get_pattern(self, vuln_id: str) -> Optional[VulnerabilityPattern]:
        """Look up a pattern by vulnerability ID."""
        for p in self._patterns:
            if p.vuln_id == vuln_id:
                return p
        return None

    def get_by_category(self, category: str) -> list[VulnerabilityPattern]:
        """Return all patterns in a given category."""
        return [p for p in self._patterns if p.category == category]

    def add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Register a custom vulnerability pattern."""
        self._patterns.append(pattern)

    def match_regex(self, code: str) -> list[tuple[VulnerabilityPattern, list[re.Match]]]:
        """Match all regex patterns against a code string.

        Args:
            code: Source code string to scan.

        Returns:
            List of (pattern, matches) tuples for patterns with hits.
        """
        results: list[tuple[VulnerabilityPattern, list[re.Match]]] = []
        for pattern in self._patterns:
            all_matches: list[re.Match] = []
            for regex in pattern.regex_patterns:
                try:
                    matches = list(re.finditer(regex, code, re.MULTILINE))
                    all_matches.extend(matches)
                except re.error:
                    continue
            if all_matches:
                results.append((pattern, all_matches))
        return results
