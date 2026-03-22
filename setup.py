"""Setup configuration for ai-agent-security-scanner."""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="ai-agent-security-scanner",
    version="0.1.0",
    author="kadirou12333",
    description=(
        "Static and dynamic security scanner for AI agents. "
        "Detect prompt injection, data exfiltration, and unsafe tool usage "
        "in LangChain, CrewAI, and AutoGen."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kadirou12333/ai-agent-security-scanner",
    packages=find_packages(exclude=["tests*", "examples*"]),
    package_data={
        "agent_scanner": ["vulnerabilities/data/*.json", "reporting/templates/*.md"],
    },
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0.0",
        "pydantic>=2.0.0",
        "httpx>=0.25.0",
        "pyyaml>=6.0.0",
        "tabulate>=0.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "agent-scanner=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="ai security scanner llm langchain crewai autogen prompt-injection",
)
