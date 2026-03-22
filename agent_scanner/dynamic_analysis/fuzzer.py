"""Input fuzzer for AI agent endpoints.

Generates mutated inputs to test agent robustness against
unexpected, malformed, or adversarial inputs.
"""

from __future__ import annotations

import json
import random
import string
import time
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from agent_scanner.scanner import Finding


def _make_finding(
    vuln_id: str,
    title: str,
    description: str,
    severity: float,
    recommendation: str,
) -> "Finding":
    from agent_scanner.scanner import Finding

    return Finding(
        vuln_id=vuln_id,
        title=title,
        description=description,
        severity_score=severity,
        recommendation=recommendation,
        category="dynamic",
    )


class MutationStrategy(Enum):
    """Mutation strategies for fuzzing."""
    TYPE_CONFUSION = "type_confusion"
    BOUNDARY_VALUES = "boundary_values"
    ENCODING_TRICKS = "encoding_tricks"
    SPECIAL_CHARS = "special_chars"
    OVERSIZED_INPUT = "oversized_input"
    NULL_INJECTION = "null_injection"
    FORMAT_STRING = "format_string"


class AgentFuzzer:
    """Fuzzer for AI agent HTTP endpoints.

    Generates mutated inputs using multiple mutation strategies and
    sends them to the agent endpoint to detect anomalous behavior.

    Args:
        endpoint: The agent HTTP endpoint URL.
        auth: Optional authentication headers.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: str,
        auth: Optional[dict[str, str]] = None,
        timeout: int = 30,
    ) -> None:
        self.endpoint = endpoint
        self.auth = auth or {}
        self.timeout = timeout
        self._strategies = list(MutationStrategy)

    def fuzz_inputs(
        self,
        seed_inputs: Optional[list[str]] = None,
        max_iterations: int = 100,
    ) -> list["Finding"]:
        """Fuzz the agent endpoint with mutated inputs.

        Args:
            seed_inputs: Base inputs to mutate. Uses defaults if None.
            max_iterations: Maximum number of fuzzing iterations.

        Returns:
            List of findings from anomalous responses.
        """
        if seed_inputs is None:
            seed_inputs = self._default_seeds()

        findings: list["Finding"] = []
        mutations = self._generate_all_mutations(seed_inputs)

        for i, (mutation, strategy) in enumerate(mutations[:max_iterations]):
            response = self._send_request(mutation)
            if response is None:
                continue

            anomalies = self.detect_anomaly(response, mutation, strategy)
            findings.extend(anomalies)

        return findings

    def generate_mutations(self, seed: str) -> list[tuple[str, MutationStrategy]]:
        """Generate all mutation variants for a single seed input.

        Args:
            seed: The base input string to mutate.

        Returns:
            List of (mutated_input, strategy) tuples.
        """
        mutations: list[tuple[str, MutationStrategy]] = []

        # Type confusion
        mutations.append((json.dumps({"message": 12345}), MutationStrategy.TYPE_CONFUSION))
        mutations.append((json.dumps({"message": True}), MutationStrategy.TYPE_CONFUSION))
        mutations.append((json.dumps({"message": None}), MutationStrategy.TYPE_CONFUSION))
        mutations.append((json.dumps({"message": [seed]}), MutationStrategy.TYPE_CONFUSION))
        mutations.append((json.dumps({"message": {"nested": seed}}), MutationStrategy.TYPE_CONFUSION))

        # Boundary values
        mutations.append(("", MutationStrategy.BOUNDARY_VALUES))
        mutations.append((" ", MutationStrategy.BOUNDARY_VALUES))
        mutations.append(("A" * 10000, MutationStrategy.BOUNDARY_VALUES))
        mutations.append(("A" * 100000, MutationStrategy.BOUNDARY_VALUES))
        mutations.append(("\n" * 1000, MutationStrategy.BOUNDARY_VALUES))

        # Encoding tricks
        mutations.append((seed.encode("unicode_escape").decode(), MutationStrategy.ENCODING_TRICKS))
        mutations.append((_to_hex_escapes(seed), MutationStrategy.ENCODING_TRICKS))
        mutations.append((f"\\u0000{seed}", MutationStrategy.ENCODING_TRICKS))
        mutations.append((_insert_zwsp(seed), MutationStrategy.ENCODING_TRICKS))

        # Special characters
        special = '!@#$%^&*(){}[]|\\:";\'<>?,./~`'
        mutations.append((f"{special}{seed}{special}", MutationStrategy.SPECIAL_CHARS))
        mutations.append((f"' OR 1=1 --{seed}", MutationStrategy.SPECIAL_CHARS))
        mutations.append((f"<script>{seed}</script>", MutationStrategy.SPECIAL_CHARS))
        mutations.append((f"{{{{seed}}}}", MutationStrategy.SPECIAL_CHARS))

        # Null injection
        mutations.append((f"\x00{seed}", MutationStrategy.NULL_INJECTION))
        mutations.append((f"{seed}\x00additional", MutationStrategy.NULL_INJECTION))

        # Format string
        mutations.append(("%s%s%s%s%s", MutationStrategy.FORMAT_STRING))
        mutations.append(("{0}{1}{2}{3}", MutationStrategy.FORMAT_STRING))
        mutations.append((f"%n%n%n%n{seed}", MutationStrategy.FORMAT_STRING))

        return mutations

    def detect_anomaly(
        self,
        response: dict[str, Any],
        input_sent: str,
        strategy: MutationStrategy,
    ) -> list["Finding"]:
        """Detect anomalous behavior in an agent response.

        Checks for error leakage, unexpected data exposure,
        timeout-like responses, and other anomalies.

        Args:
            response: The parsed response from the agent.
            input_sent: The input that was sent.
            strategy: The mutation strategy used.

        Returns:
            List of findings for detected anomalies.
        """
        findings: list["Finding"] = []
        status = response.get("status_code", 200)
        body = str(response.get("body", ""))
        body_lower = body.lower()

        # Check for stack traces / internal errors
        error_indicators = [
            "traceback", "exception", "error:", "file \"",
            "line ", "syntaxerror", "valueerror", "typeerror",
            "keyerror", "attributeerror", "modulenotfounderror",
        ]
        if any(ind in body_lower for ind in error_indicators):
            findings.append(
                _make_finding(
                    vuln_id="AGENT-003",
                    title=f"Error information leakage ({strategy.value})",
                    description=(
                        f"Agent leaked internal error details when sent a "
                        f"{strategy.value} mutation. Error info in responses "
                        "can help attackers map the system."
                    ),
                    severity=6.0,
                    recommendation=(
                        "Implement proper error handling that returns generic "
                        "error messages. Never expose stack traces to users."
                    ),
                )
            )

        # Check for system prompt leakage
        system_indicators = [
            "system prompt", "you are", "your instructions",
            "as an ai", "i am programmed",
        ]
        if any(ind in body_lower for ind in system_indicators):
            findings.append(
                _make_finding(
                    vuln_id="AGENT-010",
                    title=f"Possible system prompt leakage ({strategy.value})",
                    description=(
                        f"Agent response to {strategy.value} mutation may contain "
                        "system prompt content or internal instructions."
                    ),
                    severity=7.0,
                    recommendation=(
                        "Ensure the agent never reveals its system prompt. "
                        "Add output filtering to catch prompt-like content."
                    ),
                )
            )

        # Check for 5xx errors (server instability)
        if status >= 500:
            findings.append(
                _make_finding(
                    vuln_id="AGENT-009",
                    title=f"Server error from {strategy.value} input",
                    description=(
                        f"Agent returned HTTP {status} when sent a {strategy.value} "
                        "mutation, indicating insufficient input validation."
                    ),
                    severity=5.0,
                    recommendation=(
                        "Add input validation and error handling to prevent "
                        "server errors from malformed input."
                    ),
                )
            )

        return findings

    def _generate_all_mutations(
        self, seeds: list[str]
    ) -> list[tuple[str, MutationStrategy]]:
        """Generate mutations for all seeds."""
        all_mutations: list[tuple[str, MutationStrategy]] = []
        for seed in seeds:
            all_mutations.extend(self.generate_mutations(seed))
        random.shuffle(all_mutations)
        return all_mutations

    def _send_request(self, payload: str) -> Optional[dict[str, Any]]:
        """Send a fuzz request to the agent endpoint."""
        if httpx is None:
            return None

        headers = {"Content-Type": "application/json", **self.auth}
        data = payload if payload.startswith("{") else json.dumps({"message": payload})

        try:
            client = httpx.Client(timeout=self.timeout)
            resp = client.post(self.endpoint, content=data, headers=headers)
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "headers": dict(resp.headers),
            }
        except Exception:
            return None

    @staticmethod
    def _default_seeds() -> list[str]:
        """Return default seed inputs for fuzzing."""
        return [
            "Hello, how can you help me?",
            "What are your capabilities?",
            "Tell me about yourself",
            "Can you help me with a task?",
            "Please summarize this document",
        ]


def _to_hex_escapes(s: str) -> str:
    """Convert a string to hex escape representation."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def _insert_zwsp(s: str) -> str:
    """Insert zero-width spaces between characters."""
    return "\u200b".join(s)
