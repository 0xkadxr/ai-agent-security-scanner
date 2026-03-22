"""CrewAI framework adapter for security scanning.

Extracts agents, tasks, tools, and crew definitions from CrewAI
agent code for security analysis.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path


class CrewAIAdapter:
    """Adapter for scanning CrewAI agent implementations.

    Extracts CrewAI-specific constructs (Agent, Task, Crew, tools)
    from source code for security analysis.
    """

    _TOOL_PATTERNS = [
        r"@tool",
        r"Tool\s*\(",
        r"BaseTool",
    ]

    _AGENT_PATTERNS = [
        r"Agent\s*\(",
        r"CrewAgent\s*\(",
    ]

    _TASK_PATTERNS = [
        r"Task\s*\(",
    ]

    def extract_tools(self, code_path: str) -> list[str]:
        """Extract tool definitions from CrewAI source code.

        Args:
            code_path: Path to a Python file or directory.

        Returns:
            List of source code strings for each tool found.
        """
        path = Path(code_path)
        sources = self._collect_sources(path)
        tools: list[str] = []

        for source in sources:
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if self._has_tool_decorator(node):
                        segment = ast.get_source_segment(source, node)
                        if segment:
                            tools.append(segment)

                if isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        name = ""
                        if isinstance(base, ast.Name):
                            name = base.id
                        elif isinstance(base, ast.Attribute):
                            name = base.attr
                        if name in ("BaseTool", "Tool"):
                            segment = ast.get_source_segment(source, node)
                            if segment:
                                tools.append(segment)

        return tools

    def extract_prompts(self, code_path: str) -> list[str]:
        """Extract prompts and role definitions from CrewAI code.

        In CrewAI, prompts come from Agent role/goal/backstory and
        Task descriptions.

        Args:
            code_path: Path to a Python file or directory.

        Returns:
            List of prompt text strings found.
        """
        path = Path(code_path)
        sources = self._collect_sources(path)
        prompts: list[str] = []

        for source in sources:
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func_name = _call_name(node)
                if func_name not in ("Agent", "Task"):
                    continue

                for kw in node.keywords:
                    if kw.arg in (
                        "role", "goal", "backstory", "description",
                        "expected_output", "system_prompt",
                    ):
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            prompts.append(kw.value.value)

        return prompts

    def extract_crews(self, code_path: str) -> list[dict[str, str]]:
        """Extract Crew definitions from CrewAI code.

        Args:
            code_path: Path to a Python file or directory.

        Returns:
            List of dicts with crew structure information.
        """
        path = Path(code_path)
        sources = self._collect_sources(path)
        crews: list[dict[str, str]] = []

        for source in sources:
            crew_pattern = re.compile(r"Crew\s*\(", re.DOTALL)
            for match in crew_pattern.finditer(source):
                start = match.start()
                end = self._find_block_end(source, start)
                crews.append({
                    "type": "Crew",
                    "source": source[start:end],
                })

        return crews

    def _collect_sources(self, path: Path) -> list[str]:
        sources: list[str] = []
        if path.is_file() and path.suffix == ".py":
            try:
                sources.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        elif path.is_dir():
            for py_file in path.rglob("*.py"):
                try:
                    sources.append(py_file.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
        return sources

    @staticmethod
    def _has_tool_decorator(node: ast.FunctionDef) -> bool:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "tool":
                return True
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "tool":
                return True
        return False

    @staticmethod
    def _find_block_end(source: str, start: int, max_chars: int = 500) -> int:
        depth = 0
        i = start
        while i < len(source) and i < start + max_chars:
            if source[i] == "(":
                depth += 1
            elif source[i] == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return min(start + max_chars, len(source))


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""
