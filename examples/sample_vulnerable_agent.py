"""Sample intentionally vulnerable LangChain-style agent.

WARNING: This file is intentionally vulnerable for demonstration purposes.
DO NOT use this code in production. Each vulnerability is marked with a comment.

Run the scanner against this file to see it in action:
    python cli.py scan --path examples/sample_vulnerable_agent.py
"""

import os
import sqlite3
import subprocess

# VULNERABILITY: AGENT-004 - Hardcoded API key
api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678"  # noqa: S105
secret_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # noqa: S105


def search_tool(user_query):
    """Search tool with no input validation.

    VULNERABILITY: AGENT-001 - No input validation on user_query
    VULNERABILITY: AGENT-003 - Returns raw results without sanitization
    """
    # Directly uses user input without any validation
    results = perform_search(user_query)
    return results  # Raw output returned without filtering


def database_tool(user_input):
    """Database query tool vulnerable to SQL injection.

    VULNERABILITY: AGENT-006 - SQL injection via f-string
    """
    conn = sqlite3.connect("agent.db")
    cursor = conn.cursor()
    # Direct string interpolation in SQL query
    cursor.execute(f"SELECT * FROM documents WHERE content LIKE '%{user_input}%'")
    return cursor.fetchall()


def file_reader_tool(file_path):
    """File reader tool with path traversal vulnerability.

    VULNERABILITY: AGENT-005 - No path validation, allows directory traversal
    """
    # No path validation -- user can read any file
    with open(file_path, "r") as f:
        return f.read()


def shell_tool(command):
    """Shell command tool with command injection vulnerability.

    VULNERABILITY: AGENT-007 - Command injection via shell=True
    """
    # Direct command execution with shell=True
    result = subprocess.run(f"echo {command}", shell=True, capture_output=True, text=True)
    return result.stdout


def code_executor_tool(user_input):
    """Code execution tool using eval.

    VULNERABILITY: AGENT-007 - eval() with user-controlled input
    """
    return eval(user_input)


# VULNERABILITY: AGENT-002 - Direct prompt concatenation
system_prompt = "You are a helpful assistant."
prompt = f"System: {system_prompt}\nUser: {user_query}\nAssist with the above request."


# VULNERABILITY: AGENT-008 - Excessive permissions
agent_config = {
    "allow_dangerous_requests": True,
    "permissions": ["all"],
    "admin": True,
    "unrestricted": True,
}


# VULNERABILITY: AGENT-010 - Unrestricted outbound network access
def webhook_notifier(data):
    """Sends data to an external webhook without validation.

    VULNERABILITY: AGENT-010 - Data exfiltration vector
    """
    import requests
    webhook = "https://hooks.external-service.com/notify"
    requests.post(webhook, data={"payload": str(data)})


def perform_search(query):
    """Stub search function."""
    return [{"result": f"Search result for: {query}"}]


# This is how NOT to build an agent -- use the scanner to find these issues!
if __name__ == "__main__":
    print("This is an intentionally vulnerable agent for demo purposes.")
    print("Run: python cli.py scan --path examples/sample_vulnerable_agent.py")
