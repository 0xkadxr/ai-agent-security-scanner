"""Tool definition security analyzer.

Analyzes AI agent tool definitions for security issues including
missing input validation, output sanitization, and excessive permissions.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_scanner.scanner import Finding


def _make_finding(
    vuln_id: str,
    title: str,
    description: str,
    severity: float,
    recommendation: str,
    code_snippet: str = "",
    line: int = 0,
) -> "Finding":
    from agent_scanner.scanner import Finding

    return Finding(
        vuln_id=vuln_id,
        title=title,
        description=description,
        severity_score=severity,
        recommendation=recommendation,
        code_snippet=code_snippet,
        line_number=line,
        category="static",
    )


class ToolAnalyzer:
    """Analyzes AI agent tool definitions for security vulnerabilities.

    Inspects tool source code to verify that inputs are validated,
    outputs are sanitized, and permissions follow least-privilege.
    """

    # Network-related function names
    _NETWORK_CALLS = {
        "get", "post", "put", "patch", "delete", "request",
        "urlopen", "fetch", "aopen",
    }

    # File operation function names
    _FILE_CALLS = {
        "open", "read", "write", "unlink", "remove", "rmtree",
        "rename", "makedirs", "mkdir",
    }

    def analyze_tool_definition(self, tool_code: str) -> list["Finding"]:
        """Analyze a tool's source code for security issues.

        Runs all sub-checks: input validation, output sanitization,
        permissions, and dangerous operations.

        Args:
            tool_code: Python source code of the tool.

        Returns:
            List of findings from the analysis.
        """
        findings: list["Finding"] = []

        try:
            tree = ast.parse(tool_code)
        except SyntaxError:
            return findings

        findings.extend(self.check_input_validation(tree, tool_code))
        findings.extend(self.check_output_sanitization(tree, tool_code))
        findings.extend(self.check_permissions(tree, tool_code))
        findings.extend(self._check_dangerous_operations(tree, tool_code))

        return findings

    def check_input_validation(
        self, tree: ast.AST, source: str = ""
    ) -> list["Finding"]:
        """Verify that tool inputs are validated before use.

        Checks for the presence of type checking, assertion, or
        validation logic in tool function bodies.

        Args:
            tree: Parsed AST of the tool code.
            source: Original source code (for snippets).

        Returns:
            List of findings for missing input validation.
        """
        findings: list["Finding"] = []
        lines = source.splitlines() if source else []

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not self._is_tool_func(node):
                continue
            if len(node.args.args) <= 1:
                # Only self or no args -- skip
                continue

            has_validation = False
            for child in ast.walk(node):
                if isinstance(child, (ast.Assert, ast.Raise)):
                    has_validation = True
                    break
                if isinstance(child, ast.Call):
                    name = _call_name(child)
                    if name in ("isinstance", "validate", "check_type", "check"):
                        has_validation = True
                        break

            if not has_validation:
                line = getattr(node, "lineno", 0)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                findings.append(
                    _make_finding(
                        vuln_id="AGENT-001",
                        title=f"Tool '{node.name}' has no input validation",
                        description=(
                            f"Function '{node.name}' accepts parameters but does not "
                            "validate them before use."
                        ),
                        severity=7.5,
                        recommendation=(
                            "Add input validation using isinstance checks, "
                            "Pydantic models, or raise ValueError on bad input."
                        ),
                        code_snippet=snippet,
                        line=line,
                    )
                )

        return findings

    def check_output_sanitization(
        self, tree: ast.AST, source: str = ""
    ) -> list["Finding"]:
        """Verify that tool outputs are sanitized before returning.

        Checks that return values pass through some form of sanitization
        or filtering.

        Args:
            tree: Parsed AST of the tool code.
            source: Original source code.

        Returns:
            List of findings for missing output sanitization.
        """
        findings: list["Finding"] = []
        lines = source.splitlines() if source else []
        sanitize_names = {"sanitize", "escape", "clean", "filter", "strip_tags", "bleach"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not self._is_tool_func(node):
                continue

            returns_raw = False
            has_sanitize = False

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _call_name(child)
                    if name in sanitize_names:
                        has_sanitize = True
                if isinstance(child, ast.Return) and child.value is not None:
                    # Check if return value is a raw variable (not a sanitized call)
                    if isinstance(child.value, ast.Name):
                        returns_raw = True

            if returns_raw and not has_sanitize:
                line = getattr(node, "lineno", 0)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                findings.append(
                    _make_finding(
                        vuln_id="AGENT-003",
                        title=f"Tool '{node.name}' returns unsanitized output",
                        description=(
                            f"Function '{node.name}' returns data without visible "
                            "sanitization, potentially exposing sensitive information."
                        ),
                        severity=6.0,
                        recommendation=(
                            "Sanitize outputs by filtering sensitive data patterns "
                            "(API keys, PII, internal paths) before returning."
                        ),
                        code_snippet=snippet,
                        line=line,
                    )
                )

        return findings

    def check_permissions(
        self, tree: ast.AST, source: str = ""
    ) -> list["Finding"]:
        """Verify that tool functions follow least-privilege principles.

        Checks for unrestricted file access, network calls, and
        overly broad permission flags.

        Args:
            tree: Parsed AST of the tool code.
            source: Original source code.

        Returns:
            List of findings for excessive permissions.
        """
        findings: list["Finding"] = []
        lines = source.splitlines() if source else []

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not self._is_tool_func(node):
                continue

            has_file_ops = False
            has_network_ops = False

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _call_name(child)
                    if name in self._FILE_CALLS:
                        has_file_ops = True
                    if name in self._NETWORK_CALLS:
                        has_network_ops = True

            if has_file_ops and has_network_ops:
                line = getattr(node, "lineno", 0)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                findings.append(
                    _make_finding(
                        vuln_id="AGENT-008",
                        title=f"Tool '{node.name}' has both file and network access",
                        description=(
                            f"Function '{node.name}' performs both file I/O and "
                            "network operations, creating a potential data exfiltration path."
                        ),
                        severity=7.5,
                        recommendation=(
                            "Separate file and network operations into distinct tools "
                            "with independent permissions."
                        ),
                        code_snippet=snippet,
                        line=line,
                    )
                )

        return findings

    def _check_dangerous_operations(
        self, tree: ast.AST, source: str = ""
    ) -> list["Finding"]:
        """Check for inherently dangerous operations in tools."""
        findings: list["Finding"] = []
        lines = source.splitlines() if source else []
        dangerous = {"eval", "exec", "compile", "system", "popen"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name not in dangerous:
                continue

            line = getattr(node, "lineno", 0)
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            findings.append(
                _make_finding(
                    vuln_id="AGENT-007",
                    title=f"Dangerous call to {name}() in tool",
                    description=(
                        f"Tool code calls {name}() at line {line}, which can "
                        "execute arbitrary code if input is not strictly controlled."
                    ),
                    severity=9.5,
                    recommendation=(
                        f"Remove {name}() and use a safer alternative. "
                        "If unavoidable, use strict input allowlisting."
                    ),
                    code_snippet=snippet,
                    line=line,
                )
            )

        return findings

    @staticmethod
    def _is_tool_func(node: ast.FunctionDef) -> bool:
        """Check if a FunctionDef is likely a tool definition."""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "tool":
                return True
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name) and dec.func.id == "tool":
                    return True
        if "tool" in node.name.lower():
            return True
        return False


def _call_name(node: ast.Call) -> str:
    """Extract function name from a Call AST node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""
