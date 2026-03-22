"""LangChain framework adapter for security scanning.

Extracts tools, prompts, and chain structures from LangChain
agent code for security analysis.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional


class LangChainAdapter:
    """Adapter for scanning LangChain agent implementations.

    Extracts LangChain-specific constructs (tools, prompt templates,
    chains, and agents) from source code for security analysis.
    """

    # LangChain tool decorators and classes
    _TOOL_PATTERNS = [
        r"@tool",
        r"@langchain\.tools\.tool",
        r"Tool\s*\(",
        r"StructuredTool\s*\(",
        r"BaseTool",
    ]

    # LangChain prompt patterns
    _PROMPT_PATTERNS = [
        r"PromptTemplate\s*\(",
        r"ChatPromptTemplate\s*\(",
        r"SystemMessagePromptTemplate",
        r"HumanMessagePromptTemplate",
        r"MessagesPlaceholder",
        r"SystemMessage\s*\(",
    ]

    # LangChain chain/agent patterns
    _CHAIN_PATTERNS = [
        r"LLMChain\s*\(",
        r"SequentialChain\s*\(",
        r"AgentExecutor\s*\(",
        r"create_react_agent",
        r"create_openai_functions_agent",
        r"create_structured_chat_agent",
        r"initialize_agent",
        r"StateGraph\s*\(",
        r"LangGraph",
    ]

    def extract_tools(self, code_path: str) -> list[str]:
        """Extract tool definitions from LangChain agent source code.

        Finds functions decorated with @tool, Tool() instantiations,
        and BaseTool subclasses.

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
                # @tool decorated functions
                if isinstance(node, ast.FunctionDef):
                    if self._has_tool_decorator(node):
                        tools.append(ast.get_source_segment(source, node) or "")

                # BaseTool subclasses
                if isinstance(node, ast.ClassDef):
                    if self._is_tool_class(node):
                        tools.append(ast.get_source_segment(source, node) or "")

            # Tool() and StructuredTool() instantiations (via regex)
            for pattern in [r"Tool\s*\([^)]*\)", r"StructuredTool\.from_function\s*\([^)]*\)"]:
                for match in re.finditer(pattern, source, re.DOTALL):
                    tools.append(match.group(0))

        return [t for t in tools if t.strip()]

    def extract_prompts(self, code_path: str) -> list[str]:
        """Extract prompt templates from LangChain agent source code.

        Finds PromptTemplate, ChatPromptTemplate, SystemMessage,
        and string-based prompt definitions.

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

                func_name = self._get_call_name(node)

                # PromptTemplate(template="...")
                if func_name in ("PromptTemplate", "ChatPromptTemplate", "SystemMessage"):
                    for kw in node.keywords:
                        if kw.arg in ("template", "content", "prompt"):
                            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                prompts.append(kw.value.value)

                    # Positional string argument
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if len(arg.value) > 20:
                                prompts.append(arg.value)

            # Regex fallback for f-strings and multi-line prompts
            prompt_var_pattern = re.compile(
                r'(?:system_prompt|system_message|prompt_template|instructions)\s*=\s*(?:f?"""(.*?)"""|f?\'\'\'(.*?)\'\'\'|f?"(.*?)"|f?\'(.*?)\')',
                re.DOTALL,
            )
            for match in prompt_var_pattern.finditer(source):
                text = next((g for g in match.groups() if g is not None), None)
                if text and len(text) > 20:
                    prompts.append(text)

        return prompts

    def extract_chains(self, code_path: str) -> list[dict[str, str]]:
        """Extract chain and graph structures from LangChain code.

        Identifies LLMChain, SequentialChain, AgentExecutor, and
        LangGraph StateGraph definitions.

        Args:
            code_path: Path to a Python file or directory.

        Returns:
            List of dicts with 'type' and 'source' keys.
        """
        path = Path(code_path)
        sources = self._collect_sources(path)
        chains: list[dict[str, str]] = []

        for source in sources:
            for pattern_str in self._CHAIN_PATTERNS:
                pattern = re.compile(pattern_str)
                for match in pattern.finditer(source):
                    start = match.start()
                    # Extract a reasonable chunk around the match
                    end = self._find_block_end(source, start)
                    chains.append({
                        "type": match.group(0).rstrip("(").strip(),
                        "source": source[start:end],
                    })

        return chains

    def _collect_sources(self, path: Path) -> list[str]:
        """Collect Python source code from a file or directory."""
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
        """Check if a function has a @tool decorator."""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "tool":
                return True
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name) and dec.func.id == "tool":
                    return True
            if isinstance(dec, ast.Attribute) and dec.attr == "tool":
                return True
        return False

    @staticmethod
    def _is_tool_class(node: ast.ClassDef) -> bool:
        """Check if a class inherits from BaseTool."""
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "BaseTool":
                return True
            if isinstance(base, ast.Attribute) and base.attr == "BaseTool":
                return True
        return False

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _find_block_end(source: str, start: int, max_chars: int = 500) -> int:
        """Find the end of a code block starting from an opening paren."""
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
