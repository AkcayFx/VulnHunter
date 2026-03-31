"""Execution monitor — detects loops, stuck agents, and supports cancellation."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from vulnhunter.models import AgentAction

logger = logging.getLogger("vulnhunter.monitor")


@dataclass
class MonitorState:
    """Tracks the health of an ongoing agent execution."""
    scan_id: str = ""
    started_at: float = field(default_factory=time.monotonic)
    actions: list[AgentAction] = field(default_factory=list)
    cancelled: bool = False
    warnings: list[str] = field(default_factory=list)


class ExecutionMonitor:
    """Observes agent actions in real-time and flags anomalies.

    Capabilities:
    - Loop detection: same tool called with same args too many times
    - Stuck detection: no new actions within a timeout
    - Cancellation: cooperative flag checked by the agent loop
    - Progress tracking: counts actions per agent
    """

    LOOP_THRESHOLD = 3
    STUCK_TIMEOUT_SECONDS = 120

    def __init__(self, scan_id: str = ""):
        self.state = MonitorState(scan_id=scan_id)
        self._last_action_time: float = time.monotonic()
        self._tool_call_history: list[str] = []

    @property
    def is_cancelled(self) -> bool:
        return self.state.cancelled

    def cancel(self) -> None:
        self.state.cancelled = True
        logger.info(f"Scan {self.state.scan_id} cancelled by user")

    def record_action(self, action: AgentAction) -> None:
        """Record an action and run health checks."""
        self.state.actions.append(action)
        self._last_action_time = time.monotonic()

        if action.action_type == "tool_call" and action.tool_name:
            sig = f"{action.tool_name}:{_stable_hash(action.tool_input)}"
            self._tool_call_history.append(sig)
            self._check_loop()

    def _check_loop(self) -> None:
        """Detect if the same tool+args is called repeatedly."""
        if len(self._tool_call_history) < self.LOOP_THRESHOLD:
            return

        recent = self._tool_call_history[-self.LOOP_THRESHOLD:]
        if len(set(recent)) == 1:
            warning = (
                f"Loop detected: {recent[0].split(':')[0]} called "
                f"{self.LOOP_THRESHOLD} times with identical arguments"
            )
            if warning not in self.state.warnings:
                self.state.warnings.append(warning)
                logger.warning(warning)

    def check_stuck(self) -> bool:
        """Return True if no actions have been recorded within the timeout."""
        elapsed = time.monotonic() - self._last_action_time
        if elapsed > self.STUCK_TIMEOUT_SECONDS:
            warning = f"Agent appears stuck — no activity for {elapsed:.0f}s"
            if warning not in self.state.warnings:
                self.state.warnings.append(warning)
                logger.warning(warning)
            return True
        return False

    def get_progress(self) -> dict[str, Any]:
        """Return a snapshot of execution progress."""
        agent_counts: Counter[str] = Counter()
        tool_counts: Counter[str] = Counter()
        for a in self.state.actions:
            agent_counts[a.agent.value] += 1
            if a.tool_name:
                tool_counts[a.tool_name] += 1

        return {
            "scan_id": self.state.scan_id,
            "elapsed_seconds": time.monotonic() - self.state.started_at,
            "total_actions": len(self.state.actions),
            "actions_by_agent": dict(agent_counts),
            "actions_by_tool": dict(tool_counts),
            "warnings": self.state.warnings,
            "cancelled": self.state.cancelled,
        }


def _stable_hash(obj: Any) -> str:
    """Deterministic short hash for comparing tool arguments."""
    import hashlib
    import json
    try:
        raw = json.dumps(obj, sort_keys=True, default=str)
    except (TypeError, ValueError):
        raw = str(obj)
    return hashlib.md5(raw.encode()).hexdigest()[:8]
