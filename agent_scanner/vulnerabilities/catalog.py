"""Vulnerability catalog and taxonomy for AI agents.

Defines AGENT-001 through AGENT-010 with full metadata including
severity, attack vectors, impact, and remediation guidance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VulnerabilityEntry:
    """A single entry in the vulnerability catalog.

    Attributes:
        vuln_id: Unique identifier (e.g. AGENT-001).
        name: Short name.
        description: Detailed description.
        severity: Severity label (Critical, High, Medium, Low).
        severity_score: Numeric severity 0-10.
        attack_vector: How the vulnerability is exploited.
        impact: What happens if exploited.
        remediation: How to fix it.
        references: Related references and resources.
        cwe: Related CWE identifiers.
    """

    vuln_id: str
    name: str
    description: str
    severity: str
    severity_score: float
    attack_vector: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)


class VulnerabilityCatalog:
    """Catalog of known AI agent vulnerability types.

    Provides lookup and search over the vulnerability taxonomy
    covering AGENT-001 through AGENT-010.
    """

    def __init__(self) -> None:
        self._entries: dict[str, VulnerabilityEntry] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load vulnerability entries from the JSON database."""
        db_path = Path(__file__).parent / "data" / "vulnerability_db.json"
        if db_path.exists():
            try:
                data = json.loads(db_path.read_text(encoding="utf-8"))
                for entry_data in data.get("vulnerabilities", []):
                    entry = VulnerabilityEntry(
                        vuln_id=entry_data["id"],
                        name=entry_data["name"],
                        description=entry_data["description"],
                        severity=entry_data["severity"],
                        severity_score=entry_data["severity_score"],
                        attack_vector=entry_data["attack_vector"],
                        impact=entry_data["impact"],
                        remediation=entry_data["remediation"],
                        references=entry_data.get("references", []),
                        cwe=entry_data.get("cwe", []),
                    )
                    self._entries[entry.vuln_id] = entry
            except (json.JSONDecodeError, KeyError):
                self._load_defaults()
        else:
            self._load_defaults()

    def _load_defaults(self) -> None:
        """Load hardcoded default vulnerability entries."""
        defaults = [
            VulnerabilityEntry(
                vuln_id="AGENT-001", name="Unvalidated Tool Inputs",
                description="Tool function accepts user-controlled input without validation.",
                severity="High", severity_score=8.5,
                attack_vector="Attacker sends crafted input through tool parameters.",
                impact="Arbitrary code execution, data manipulation, or system compromise.",
                remediation="Add input validation using Pydantic models or custom validators.",
                cwe=["CWE-20"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-002", name="Prompt Injection",
                description="User input is incorporated into prompts without sanitization.",
                severity="Critical", severity_score=9.0,
                attack_vector="Attacker injects instructions via user input or data sources.",
                impact="Complete control over agent behavior, data exfiltration.",
                remediation="Use parameterized templates, add injection defense instructions.",
                cwe=["CWE-74"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-003", name="Missing Output Sanitization",
                description="Agent outputs are not filtered before display.",
                severity="High", severity_score=7.0,
                attack_vector="Attacker triggers error messages or raw data in output.",
                impact="Information disclosure, XSS in web interfaces.",
                remediation="Sanitize all outputs, filter sensitive data patterns.",
                cwe=["CWE-116"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-004", name="Hardcoded Secrets",
                description="API keys or credentials are hardcoded in source.",
                severity="High", severity_score=8.0,
                attack_vector="Attacker reads source code or repository history.",
                impact="Unauthorized API access, account compromise.",
                remediation="Use environment variables or a secrets manager.",
                cwe=["CWE-798"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-005", name="Unrestricted File Access",
                description="File operations use unvalidated user-controlled paths.",
                severity="High", severity_score=8.5,
                attack_vector="Attacker uses path traversal to access arbitrary files.",
                impact="Read/write arbitrary files, data exfiltration.",
                remediation="Implement path allowlisting and reject '..' components.",
                cwe=["CWE-22"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-006", name="SQL Injection in Tools",
                description="SQL queries are built with string formatting from user input.",
                severity="Critical", severity_score=9.5,
                attack_vector="Attacker injects SQL via tool parameters.",
                impact="Database compromise, data theft, data destruction.",
                remediation="Use parameterized queries; never concatenate user input into SQL.",
                cwe=["CWE-89"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-007", name="Command Injection via Tools",
                description="System commands are executed with user-controlled input.",
                severity="Critical", severity_score=9.5,
                attack_vector="Attacker injects shell commands through tool inputs.",
                impact="Full system compromise, arbitrary code execution.",
                remediation="Avoid shell=True; use subprocess with argument lists and allowlists.",
                cwe=["CWE-78"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-008", name="Excessive Permissions",
                description="Agent or tools have overly broad permissions.",
                severity="High", severity_score=7.5,
                attack_vector="Attacker leverages over-privileged tools to access restricted resources.",
                impact="Unauthorized access, lateral movement.",
                remediation="Apply least-privilege principle; use role-based access control.",
                cwe=["CWE-250"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-009", name="Missing Rate Limiting",
                description="Agent endpoints lack rate limiting or resource controls.",
                severity="Medium", severity_score=5.0,
                attack_vector="Attacker sends high volume of requests to exhaust resources.",
                impact="Denial of service, excessive API costs.",
                remediation="Implement rate limiting, set iteration caps, add timeouts.",
                cwe=["CWE-770"],
            ),
            VulnerabilityEntry(
                vuln_id="AGENT-010", name="Data Exfiltration Vectors",
                description="Agent can leak data through network access or prompt manipulation.",
                severity="High", severity_score=8.0,
                attack_vector="Attacker manipulates agent to send data to external services.",
                impact="Data theft, privacy violations, regulatory non-compliance.",
                remediation="Restrict outbound network to allowlisted domains; filter outputs.",
                cwe=["CWE-200"],
            ),
        ]
        for entry in defaults:
            self._entries[entry.vuln_id] = entry

    def get(self, vuln_id: str) -> Optional[VulnerabilityEntry]:
        """Look up a vulnerability by its ID."""
        return self._entries.get(vuln_id)

    def all_entries(self) -> list[VulnerabilityEntry]:
        """Return all vulnerability entries sorted by ID."""
        return sorted(self._entries.values(), key=lambda e: e.vuln_id)

    def by_severity(self, severity: str) -> list[VulnerabilityEntry]:
        """Return entries matching a severity label."""
        return [e for e in self._entries.values() if e.severity == severity]

    def search(self, query: str) -> list[VulnerabilityEntry]:
        """Search entries by keyword in name or description."""
        q = query.lower()
        return [
            e for e in self._entries.values()
            if q in e.name.lower() or q in e.description.lower()
        ]
