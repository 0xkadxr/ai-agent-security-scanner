"""AST-based code scanner for detecting security vulnerabilities.

Uses Python's ast module to parse source code and walk the abstract
syntax tree, identifying dangerous patterns common in AI agent code.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

from agent_scanner.static_analysis.patterns import VulnerabilityPatterns

if TYPE_CHECKING:
    from agent_scanner.scanner import Finding


def _make_finding(
    vuln_id: str,
    title: str,
    description: str,
    severity: float,
    file_path: str,
    line: int,
    snippet: str,
    recommendation: str,
) -> "Finding":
    """Create a Finding without circular import at module level."""
    from agent_scanner.scanner import Finding

    return Finding(
        vuln_id=vuln_id,
        title=title,
        description=description,
        severity_score=severity,
        file_path=file_path,
        line_number=line,
        code_snippet=snippet,
        recommendation=recommendation,
        category="static",
    )


class CodeScanner:
    """AST-based Python code scanner for AI agent vulnerabilities.

    Parses Python source files into ASTs and inspects them for
    dangerous patterns including eval/exec usage, unsanitized inputs,
    hardcoded secrets, and unsafe tool definitions.
    """

    def __init__(self) -> None:
        self._patterns = VulnerabilityPatterns()

    def scan_file(self, file_path: str) -> list["Finding"]:
        """Scan a single Python file for vulnerabilities.

        Args:
            file_path: Path to the Python file.

        Returns:
            List of findings from the file.
        """
        path = Path(file_path)
        if not path.exists() or not path.suffix == ".py":
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []

        findings: list["Finding"] = []
        source_lines = source.splitlines()

        findings.extend(self.find_unsafe_exec(tree, file_path, source_lines))
        findings.extend(self.find_unsanitized_inputs(tree, file_path, source_lines))
        findings.extend(self.find_unsafe_tool_definitions(tree, file_path, source_lines))
        findings.extend(self.find_secret_exposure(tree, file_path, source_lines))
        findings.extend(self._regex_scan(source, file_path))

        return findings

    def scan_directory(self, dir_path: str) -> tuple[list["Finding"], int]:
        """Scan all Python files in a directory recursively.

        Args:
            dir_path: Path to the directory.

        Returns:
            Tuple of (findings list, number of files scanned).
        """
        root = Path(dir_path)
        if not root.is_dir():
            return [], 0

        findings: list["Finding"] = []
        count = 0

        for py_file in root.rglob("*.py"):
            # Skip common non-source directories
            parts = py_file.parts
            if any(
                skip in parts
                for skip in ("__pycache__", ".git", "node_modules", ".venv", "venv")
            ):
                continue
            file_findings = self.scan_file(str(py_file))
            findings.extend(file_findings)
            count += 1

        return findings, count

    def find_unsafe_exec(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list["Finding"]:
        """Detect eval(), exec(), and compile() calls in the AST.

        Args:
            tree: Parsed AST.
            file_path: Source file path for reporting.
            source_lines: Source code lines for snippet extraction.

        Returns:
            List of findings for unsafe exec patterns.
        """
        findings: list["Finding"] = []
        dangerous_builtins = {"eval", "exec", "compile", "__import__"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node)
            if func_name not in dangerous_builtins:
                continue

            line = getattr(node, "lineno", 0)
            snippet = self._get_snippet(source_lines, line)

            # Check if the argument contains user-controlled data
            has_user_input = self._args_reference_user_input(node)
            severity = 9.5 if has_user_input else 7.0

            findings.append(
                _make_finding(
                    vuln_id="AGENT-007",
                    title=f"Dangerous builtin: {func_name}()",
                    description=(
                        f"Call to {func_name}() detected at line {line}. "
                        f"{'Arguments appear to contain user-controlled data.' if has_user_input else 'Verify that arguments are not user-controlled.'}"
                    ),
                    severity=severity,
                    file_path=file_path,
                    line=line,
                    snippet=snippet,
                    recommendation=(
                        f"Remove {func_name}() or replace with a safe alternative. "
                        "Never pass user-controlled data to code execution functions."
                    ),
                )
            )

        return findings

    def find_unsanitized_inputs(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list["Finding"]:
        """Detect user input flowing into sensitive operations without sanitization.

        Looks for f-strings and string concatenation in calls to
        sensitive functions (execute, system, open, etc.).

        Args:
            tree: Parsed AST.
            file_path: Source file path for reporting.
            source_lines: Source code lines for snippet extraction.

        Returns:
            List of findings for unsanitized input patterns.
        """
        findings: list["Finding"] = []
        sensitive_calls = {
            "execute", "executemany", "system", "popen", "run",
            "call", "check_output", "open", "Popen",
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node)
            if func_name not in sensitive_calls:
                continue

            # Check if any argument is an f-string or concatenation
            for arg in node.args:
                is_fstring = isinstance(arg, ast.JoinedStr)
                is_concat = (
                    isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add)
                )
                is_format_call = (
                    isinstance(arg, ast.Call)
                    and self._get_call_name(arg) == "format"
                )

                if is_fstring or is_concat or is_format_call:
                    line = getattr(node, "lineno", 0)
                    snippet = self._get_snippet(source_lines, line)

                    # Determine specific vuln_id based on function
                    if func_name in ("execute", "executemany"):
                        vuln_id = "AGENT-006"
                        title = "SQL injection via string formatting"
                        sev = 9.5
                    elif func_name in ("system", "popen", "run", "call", "Popen", "check_output"):
                        vuln_id = "AGENT-007"
                        title = "Command injection via string formatting"
                        sev = 9.5
                    elif func_name == "open":
                        vuln_id = "AGENT-005"
                        title = "Path injection via string formatting"
                        sev = 8.0
                    else:
                        vuln_id = "AGENT-001"
                        title = "Unsanitized input in sensitive call"
                        sev = 8.0

                    findings.append(
                        _make_finding(
                            vuln_id=vuln_id,
                            title=title,
                            description=(
                                f"String formatting used in {func_name}() call at line {line}. "
                                "User-controlled data may flow into this operation."
                            ),
                            severity=sev,
                            file_path=file_path,
                            line=line,
                            snippet=snippet,
                            recommendation=(
                                "Use parameterized queries, allowlists, or "
                                "input validation instead of string formatting."
                            ),
                        )
                    )

        return findings

    def find_unsafe_tool_definitions(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list["Finding"]:
        """Detect tool functions that lack input validation.

        Looks for functions decorated with @tool or containing 'tool'
        in their name that don't perform input validation.

        Args:
            tree: Parsed AST.
            file_path: Source file path for reporting.
            source_lines: Source code lines for snippet extraction.

        Returns:
            List of findings for unsafe tool definitions.
        """
        findings: list["Finding"] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            is_tool = self._is_tool_function(node)
            if not is_tool:
                continue

            has_validation = self._has_input_validation(node)
            if has_validation:
                continue

            line = getattr(node, "lineno", 0)
            snippet = self._get_snippet(source_lines, line)

            findings.append(
                _make_finding(
                    vuln_id="AGENT-001",
                    title=f"Tool '{node.name}' lacks input validation",
                    description=(
                        f"Tool function '{node.name}' at line {line} does not appear "
                        "to validate its inputs. This could allow injection attacks."
                    ),
                    severity=7.5,
                    file_path=file_path,
                    line=line,
                    snippet=snippet,
                    recommendation=(
                        "Add input validation using type checks, Pydantic models, "
                        "or custom validators before processing tool inputs."
                    ),
                )
            )

        return findings

    def find_secret_exposure(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list["Finding"]:
        """Detect hardcoded secrets, API keys, and tokens.

        Uses both AST analysis for assignments and regex patterns
        for common secret formats.

        Args:
            tree: Parsed AST.
            file_path: Source file path for reporting.
            source_lines: Source code lines for snippet extraction.

        Returns:
            List of findings for exposed secrets.
        """
        findings: list["Finding"] = []

        secret_name_patterns = re.compile(
            r"(?:api[_-]?key|secret|token|password|passwd|pwd|credential|auth)",
            re.IGNORECASE,
        )
        api_key_value_pattern = re.compile(r"^[A-Za-z0-9_\-]{16,}$")

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:
                var_name = ""
                if isinstance(target, ast.Name):
                    var_name = target.id
                elif isinstance(target, ast.Attribute):
                    var_name = target.attr

                if not secret_name_patterns.search(var_name):
                    continue

                # Check if value is a hardcoded string (not env var lookup)
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    val = node.value.value
                    if len(val) >= 8 and api_key_value_pattern.match(val):
                        line = getattr(node, "lineno", 0)
                        snippet = self._get_snippet(source_lines, line)

                        findings.append(
                            _make_finding(
                                vuln_id="AGENT-004",
                                title=f"Hardcoded secret in '{var_name}'",
                                description=(
                                    f"Variable '{var_name}' at line {line} contains "
                                    "what appears to be a hardcoded secret value."
                                ),
                                severity=8.0,
                                file_path=file_path,
                                line=line,
                                snippet=snippet,
                                recommendation=(
                                    "Move secrets to environment variables or a "
                                    "secrets manager. Use os.environ.get() or "
                                    "python-dotenv to load secrets at runtime."
                                ),
                            )
                        )

        return findings

    def _regex_scan(self, source: str, file_path: str) -> list["Finding"]:
        """Run regex patterns against source code for additional detection.

        Complements AST analysis with regex-based pattern matching for
        patterns that are difficult to detect via AST alone.
        """
        findings: list["Finding"] = []
        lines = source.splitlines()

        # Prompt concatenation patterns (AGENT-002)
        prompt_concat = re.compile(
            r'(?:prompt|system_message|instructions)\s*(?:\+|=.*format\(|=\s*f["\'])',
            re.IGNORECASE,
        )
        for i, line in enumerate(lines, 1):
            if prompt_concat.search(line):
                findings.append(
                    _make_finding(
                        vuln_id="AGENT-002",
                        title="Direct prompt concatenation",
                        description=(
                            f"Prompt string appears to be constructed via concatenation "
                            f"or formatting at line {i}."
                        ),
                        severity=9.0,
                        file_path=file_path,
                        line=i,
                        snippet=line.strip(),
                        recommendation=(
                            "Use parameterized prompt templates with clear delimiters "
                            "between system instructions and user content."
                        ),
                    )
                )

        # Excessive permissions (AGENT-008)
        perms_pattern = re.compile(
            r'(?:allow_dangerous|permissions\s*=\s*\[?\s*["\']all|'
            r"admin\s*=\s*True|unrestricted\s*=\s*True)",
            re.IGNORECASE,
        )
        for i, line in enumerate(lines, 1):
            if perms_pattern.search(line):
                findings.append(
                    _make_finding(
                        vuln_id="AGENT-008",
                        title="Excessive permissions detected",
                        description=(
                            f"Overly broad permission setting detected at line {i}."
                        ),
                        severity=7.5,
                        file_path=file_path,
                        line=i,
                        snippet=line.strip(),
                        recommendation=(
                            "Apply the principle of least privilege. Grant only "
                            "the minimum permissions required."
                        ),
                    )
                )

        return findings

    # ------------------------------------------------------------------ #
    # Helper methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _get_snippet(lines: list[str], lineno: int, context: int = 0) -> str:
        """Extract a code snippet around the given line number."""
        if lineno < 1 or lineno > len(lines):
            return ""
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        return "\n".join(lines[start:end])

    @staticmethod
    def _args_reference_user_input(node: ast.Call) -> bool:
        """Check if any call argument references user-input-like variables."""
        user_input_names = {
            "user_input", "query", "prompt", "message", "request",
            "input", "user_message", "user_query", "data", "payload",
        }
        for arg in node.args:
            for child in ast.walk(arg):
                if isinstance(child, ast.Name) and child.id in user_input_names:
                    return True
        return False

    @staticmethod
    def _is_tool_function(node: ast.FunctionDef) -> bool:
        """Check if a function is likely a tool definition."""
        # Check decorators for @tool
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "tool":
                return True
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name) and dec.func.id == "tool":
                    return True
                if isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool":
                    return True
        # Check name pattern
        if "tool" in node.name.lower():
            return True
        return False

    @staticmethod
    def _has_input_validation(node: ast.FunctionDef) -> bool:
        """Check if a function body contains input validation patterns."""
        validation_indicators = {
            "isinstance", "validate", "check", "assert", "raise",
            "ValueError", "TypeError", "ValidationError",
        }
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in validation_indicators:
                return True
            if isinstance(child, ast.Attribute) and child.attr in validation_indicators:
                return True
            # if/raise pattern
            if isinstance(child, ast.Raise):
                return True
            # assert statement
            if isinstance(child, ast.Assert):
                return True
        return False
