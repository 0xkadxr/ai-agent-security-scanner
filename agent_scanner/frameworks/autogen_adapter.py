"""AutoGen framework adapter for security scanning.

Extracts agent configurations, tool registrations, and conversation
patterns from AutoGen agent code for security analysis.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path


class AutoGenAdapter:
    """Adapter for scanning AutoGen agent implementations.

    Extracts AutoGen-specific constructs (AssistantAgent, UserProxyAgent,
    function registrations, and group chats) from source code.
    """

    _AGENT_CLASSES = [
        "AssistantAgent", "UserProxyAgent", "ConversableAgent",
        "GroupChat", "GroupChatManager",
    ]

    def extract_tools(self, code_path: str) -> list[str]:
        """Extract tool/function registrations from AutoGen code.

        In AutoGen, tools are registered via register_for_llm(),
        register_for_execution(), or function_map.

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
                # Functions decorated with register_for_llm/register_for_execution
                if isinstance(node, ast.FunctionDef):
                    for dec in node.decorator_list:
                        dec_name = ""
                        if isinstance(dec, ast.Attribute):
                            dec_name = dec.attr
                        elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                        if dec_name in ("register_for_llm", "register_for_execution"):
                            segment = ast.get_source_segment(source, node)
                            if segment:
                                tools.append(segment)

            # function_map assignments
            func_map_pattern = re.compile(
                r"function_map\s*=\s*\{[^}]+\}", re.DOTALL
            )
            for match in func_map_pattern.finditer(source):
                tools.append(match.group(0))

        return tools

    def extract_prompts(self, code_path: str) -> list[str]:
        """Extract system prompts from AutoGen agent configurations.

        AutoGen agents use system_message parameter for their prompts.

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
                if func_name not in self._AGENT_CLASSES:
                    continue

                for kw in node.keywords:
                    if kw.arg in ("system_message", "description", "instructions"):
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            prompts.append(kw.value.value)

        return prompts

    def extract_agent_configs(self, code_path: str) -> list[dict[str, str]]:
        """Extract agent configuration details from AutoGen code.

        Args:
            code_path: Path to a Python file or directory.

        Returns:
            List of dicts with agent configuration info.
        """
        path = Path(code_path)
        sources = self._collect_sources(path)
        configs: list[dict[str, str]] = []

        for source in sources:
            for agent_class in self._AGENT_CLASSES:
                pattern = re.compile(rf"{agent_class}\s*\(", re.DOTALL)
                for match in pattern.finditer(source):
                    start = match.start()
                    end = self._find_block_end(source, start)
                    configs.append({
                        "type": agent_class,
                        "source": source[start:end],
                    })

            # code_execution_config detection
            code_exec_pattern = re.compile(
                r"code_execution_config\s*=\s*\{[^}]+\}", re.DOTALL
            )
            for match in code_exec_pattern.finditer(source):
                configs.append({
                    "type": "code_execution_config",
                    "source": match.group(0),
                })

        return configs

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
