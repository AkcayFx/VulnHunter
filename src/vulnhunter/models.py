"""Data models for VulnHunter."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    DONE = "done"
    FAILED = "failed"


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    EXPLOIT = "exploit"
    REPORTER = "reporter"


@dataclass
class ScanTarget:
    host: str
    ports: list[int] = field(default_factory=list)
    custom_task: str = ""

    @property
    def display_name(self) -> str:
        return self.host


@dataclass
class Vulnerability:
    title: str
    severity: Severity
    tool: str
    description: str
    evidence: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    remediation: str = ""


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    duration_seconds: float = 0.0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str = ""


@dataclass
class AgentAction:
    agent: AgentRole
    action_type: str  # "tool_call", "thinking", "delegation", "result"
    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_output: str = ""
    thought: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now())


@dataclass
class SubTask:
    name: str
    agent: AgentRole
    description: str
    status: str = "pending"  # pending, running, completed, failed
    actions: list[AgentAction] = field(default_factory=list)
    result: str = ""


@dataclass
class AttackChain:
    name: str
    steps: list[Vulnerability]
    impact: str
    combined_cvss: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    narrative: str = ""


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str = ""


@dataclass
class ScanReport:
    target: ScanTarget
    timestamp: datetime = field(default_factory=lambda: datetime.now())
    phase: ScanPhase = ScanPhase.INIT
    subtasks: list[SubTask] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    mitre_tactics: dict[str, list[str]] = field(default_factory=dict)
    ai_summary: str = ""
    risk_score: float = 0.0
    threat_level: str = "Unknown"
    remediation_steps: list[str] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    @property
    def vuln_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts

    @property
    def total_vulns(self) -> int:
        return len(self.vulnerabilities)
