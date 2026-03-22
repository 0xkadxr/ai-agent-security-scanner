"""Tests for the vulnerability patterns database."""

import pytest

from agent_scanner.static_analysis.patterns import VulnerabilityPatterns, VulnerabilityPattern


class TestVulnerabilityPatterns:
    """Tests for VulnerabilityPatterns class."""

    def setup_method(self):
        self.patterns = VulnerabilityPatterns()

    def test_default_patterns_loaded(self):
        """All 10 default patterns should be loaded."""
        assert len(self.patterns.patterns) == 10

    def test_all_vuln_ids_present(self):
        """AGENT-001 through AGENT-010 should all exist."""
        ids = {p.vuln_id for p in self.patterns.patterns}
        for i in range(1, 11):
            assert f"AGENT-{i:03d}" in ids

    def test_get_pattern_by_id(self):
        """Should return pattern by vulnerability ID."""
        p = self.patterns.get_pattern("AGENT-002")
        assert p is not None
        assert p.name == "Direct Prompt Concatenation"
        assert p.severity == 9.0

    def test_get_pattern_nonexistent(self):
        """Should return None for unknown ID."""
        assert self.patterns.get_pattern("AGENT-999") is None

    def test_get_by_category(self):
        """Should filter patterns by category."""
        injection = self.patterns.get_by_category("injection")
        assert len(injection) >= 2
        assert all(p.category == "injection" for p in injection)

    def test_add_custom_pattern(self):
        """Should allow adding custom patterns."""
        custom = VulnerabilityPattern(
            vuln_id="CUSTOM-001",
            name="Custom Test Pattern",
            description="Test",
            severity=5.0,
        )
        self.patterns.add_pattern(custom)
        assert self.patterns.get_pattern("CUSTOM-001") is not None

    def test_regex_match_eval(self):
        """Should detect eval() in code."""
        code = "result = eval(user_input)"
        matches = self.patterns.match_regex(code)
        vuln_ids = {p.vuln_id for p, _ in matches}
        assert "AGENT-007" in vuln_ids

    def test_regex_match_hardcoded_key(self):
        """Should detect hardcoded API keys."""
        code = 'api_key = "sk-1234567890abcdefghij"'
        matches = self.patterns.match_regex(code)
        vuln_ids = {p.vuln_id for p, _ in matches}
        assert "AGENT-004" in vuln_ids

    def test_regex_match_fstring_prompt(self):
        """Should detect f-string prompt concatenation."""
        code = 'prompt = f"System: {user_input}"'
        matches = self.patterns.match_regex(code)
        vuln_ids = {p.vuln_id for p, _ in matches}
        assert "AGENT-002" in vuln_ids

    def test_regex_match_sql_injection(self):
        """Should detect SQL injection patterns."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        matches = self.patterns.match_regex(code)
        vuln_ids = {p.vuln_id for p, _ in matches}
        assert "AGENT-006" in vuln_ids

    def test_regex_match_subprocess_shell(self):
        """Should detect subprocess with shell=True."""
        code = 'subprocess.run(cmd, shell=True)'
        matches = self.patterns.match_regex(code)
        vuln_ids = {p.vuln_id for p, _ in matches}
        assert "AGENT-007" in vuln_ids

    def test_regex_no_false_positive_env_var(self):
        """Should not flag os.environ.get() as hardcoded secret."""
        code = 'api_key = os.environ.get("API_KEY")'
        matches = self.patterns.match_regex(code)
        # AGENT-004 should not match since value is not a hardcoded string
        agent004_matches = [p for p, _ in matches if p.vuln_id == "AGENT-004"]
        assert len(agent004_matches) == 0

    def test_all_patterns_have_recommendations(self):
        """Every pattern should include a recommendation."""
        for p in self.patterns.patterns:
            assert p.recommendation, f"{p.vuln_id} missing recommendation"

    def test_all_patterns_have_severity(self):
        """Every pattern should have a severity score between 0 and 10."""
        for p in self.patterns.patterns:
            assert 0.0 <= p.severity <= 10.0, f"{p.vuln_id} severity out of range"
