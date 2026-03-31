"""Orchestrator agent — coordinates the full penetration test with multi-agent delegation."""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable

from vulnhunter.agents.base import BaseAgent


def _extract_balanced_json_object(text: str, start: int | None = None) -> str | None:
    """Return the first complete `{...}` JSON object from text (handles nested braces)."""
    if start is None:
        start = text.find("{")
        if start < 0:
            return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _unwrap_nested_report_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Models often return {\"report\": {...}}; flatten so risk_score and summary are top-level."""
    if not isinstance(data, dict):
        return {}
    for wrap in ("report", "assessment", "scan_report"):
        inner = data.get(wrap)
        if isinstance(inner, dict) and any(
            k in inner
            for k in ("risk_score", "executive_summary", "threat_level", "remediation_steps")
        ):
            outer = {k: v for k, v in data.items() if k != wrap}
            return {**outer, **inner}
    return data


def _strip_nested_json_fences(summary: str) -> str:
    """If executive_summary contains a ```json / nested report blob, extract plain summary text."""
    if not summary or "```" not in summary:
        return summary.strip()
    m = re.search(r"```(?:json)?\s*", summary, re.IGNORECASE)
    if not m:
        return summary.strip()
    blob = summary[m.end() :]
    js = _extract_balanced_json_object(blob, 0)
    if not js:
        return summary.strip()
    try:
        sub = json.loads(js)
    except (json.JSONDecodeError, TypeError):
        return summary.strip()
    if not isinstance(sub, dict):
        return summary.strip()
    flat = _unwrap_nested_report_payload(sub)
    inner_es = flat.get("executive_summary")
    if isinstance(inner_es, str) and inner_es.strip():
        return inner_es.strip()
    return summary.strip()
from vulnhunter.agents.exploit import ExploitAgent
from vulnhunter.agents.monitor import ExecutionMonitor
from vulnhunter.agents.planner import TaskPlanner
from vulnhunter.agents.recon import ReconAgent
from vulnhunter.agents.reporter import ReporterAgent
from vulnhunter.ai.provider import LLMProvider
from vulnhunter.ai.prompts import ORCHESTRATOR_PROMPT
from vulnhunter.config import AppConfig
from vulnhunter.intelligence.chain_analyzer import AttackChainAnalyzer
from vulnhunter.intelligence.mitre_attack import MitreMapper
from vulnhunter.models import (
    AgentAction, AgentRole, ScanPhase, ScanReport, ScanTarget, SubTask, Vulnerability,
)
from vulnhunter.reporting.cvss import calculate_base_score, estimate_vector_from_vuln
from vulnhunter.tools import ALL_TOOLS
from vulnhunter.tools.base import BaseTool

logger = logging.getLogger("vulnhunter.orchestrator")


class OrchestratorAgent:
    """Top-level agent that plans, delegates to sub-agents, and compiles results.

    Flow:
    1. TaskPlanner decomposes the target into subtasks
    2. ReconAgent executes reconnaissance subtasks
    3. ExploitAgent executes vulnerability analysis subtasks
    4. ReporterAgent compiles the final report
    5. (Optional) PDF report generation
    """

    def __init__(
        self,
        config: AppConfig,
        on_action: Callable[[AgentAction], None] | None = None,
        on_phase: Callable[[ScanPhase], None] | None = None,
        scope_manager: Any | None = None,
    ):
        self.config = config
        self.on_action = on_action
        self.on_phase = on_phase
        self.scope_manager = scope_manager
        self.monitor = ExecutionMonitor()

    def cancel(self) -> None:
        """Cancel the current scan cooperatively."""
        self.monitor.cancel()

    async def run(self, target: ScanTarget) -> ScanReport:
        start_time = time.monotonic()
        report = ScanReport(target=target)
        report.phase = ScanPhase.INIT
        self._emit_phase(ScanPhase.INIT)

        llm = LLMProvider(self.config.ai)

        # Set up rate limiter based on stealth config
        rate_limiter = None
        stealth_mode = self.config.stealth_mode
        if stealth_mode != "aggressive":
            from vulnhunter.stealth.rate_limiter import AdaptiveRateLimiter
            rps_map = {"quiet": 3.0, "normal": 10.0}
            jitter_map = {"quiet": (0.3, 1.0), "normal": (0.1, 0.5)}
            max_rps = rps_map.get(stealth_mode, 10.0)
            if self.scope_manager is not None:
                max_rps = min(max_rps, float(self.scope_manager.max_rps))
            rate_limiter = AdaptiveRateLimiter(
                max_rps=max_rps,
                jitter_range=jitter_map.get(stealth_mode, (0.1, 0.5)),
                user_agent_mode="rotate" if stealth_mode == "quiet" else "static",
            )

        tools: list[BaseTool] = []
        for tool_cls in ALL_TOOLS:
            tool = tool_cls()
            if self.config.tool_enabled(tool.name):
                if self.scope_manager is not None:
                    tool.scope_manager = self.scope_manager
                if rate_limiter is not None:
                    tool.rate_limiter = rate_limiter
                tools.append(tool)

        sandbox_mgr = None
        if self.config.sandbox.enabled:
            try:
                from vulnhunter.sandbox.manager import ContainerManager
                from vulnhunter.sandbox.executor import SandboxedExecutor

                sandbox_mgr = ContainerManager(self.config.sandbox)
                await sandbox_mgr.start()
                executor = SandboxedExecutor(sandbox_mgr)
                for t in tools:
                    t.sandbox = executor
                logger.info("Sandbox mode enabled — tools will run inside container")
            except Exception as e:
                logger.warning(f"Sandbox init failed ({e}), running tools on host")
                sandbox_mgr = None

        try:
            report = await self._run_scan(llm, tools, target, report)
        finally:
            if sandbox_mgr:
                await sandbox_mgr.destroy()

        report.total_duration_seconds = time.monotonic() - start_time

        self._enrich_cvss(report)
        self._generate_pdf_if_configured(report)

        return report

    async def _run_scan(
        self,
        llm: LLMProvider,
        tools: list[BaseTool],
        target: ScanTarget,
        report: ScanReport,
    ) -> ScanReport:

        # ── Phase 1: Planning ───────────────────────────────────────────
        self._emit_action(AgentAction(
            agent=AgentRole.ORCHESTRATOR, action_type="thinking",
            thought=f"Planning penetration test for {target.host}",
        ))

        planner = TaskPlanner(llm)
        subtasks = await planner.plan(target, self.config.stealth_mode)
        report.subtasks = subtasks

        for st in subtasks:
            self._emit_action(AgentAction(
                agent=AgentRole.ORCHESTRATOR, action_type="delegation",
                thought=f"Planned: [{st.agent.value}] {st.name} — {st.description[:120]}",
            ))

        # ── Phase 2: Reconnaissance ────────────────────────────────────
        if self.monitor.is_cancelled:
            report.phase = ScanPhase.FAILED
            return report

        report.phase = ScanPhase.RECON
        self._emit_phase(ScanPhase.RECON)

        recon_subtasks = [s for s in subtasks if s.agent == AgentRole.RECON]
        recon_summary = ""
        is_focused = bool(target.custom_task)
        focused_iters = min(self.config.ai.max_tool_calls, 12)

        if recon_subtasks:
            recon_agent = ReconAgent(
                tools=tools, llm=llm,
                max_iterations=focused_iters if is_focused else self.config.ai.max_tool_calls,
                on_action=self._handle_action,
            )
            for st in recon_subtasks:
                if self.monitor.is_cancelled:
                    break
                st.status = "running"
                result = await recon_agent.run(st, target.host)
                st.status = "completed"
                st.result = result
                recon_summary += f"\n## {st.name}\n{result[:2000]}\n"

            report.tool_results.extend(recon_agent.all_tool_results)
            for tr in recon_agent.all_tool_results:
                report.vulnerabilities.extend(tr.vulnerabilities)

        # ── Phase 3: Vulnerability Analysis ────────────────────────────
        if self.monitor.is_cancelled:
            report.phase = ScanPhase.FAILED
            return report

        report.phase = ScanPhase.ANALYSIS
        self._emit_phase(ScanPhase.ANALYSIS)

        exploit_subtasks = [s for s in subtasks if s.agent == AgentRole.EXPLOIT]
        exploit_summary = ""

        if exploit_subtasks:
            exploit_agent = ExploitAgent(
                tools=tools, llm=llm,
                max_iterations=focused_iters if is_focused else self.config.ai.max_tool_calls,
                recon_context=recon_summary,
                on_action=self._handle_action,
            )
            for st in exploit_subtasks:
                if self.monitor.is_cancelled:
                    break
                st.status = "running"
                result = await exploit_agent.run(st, target.host)
                st.status = "completed"
                st.result = result
                exploit_summary += f"\n## {st.name}\n{result[:2000]}\n"

            report.tool_results.extend(exploit_agent.all_tool_results)
            for tr in exploit_agent.all_tool_results:
                report.vulnerabilities.extend(tr.vulnerabilities)

        # ── Phase 3.5: Attack Chain Intelligence ─────────────────────
        self._emit_action(AgentAction(
            agent=AgentRole.ORCHESTRATOR, action_type="thinking",
            thought="Analyzing attack chains and MITRE ATT&CK mapping...",
        ))

        chain_analyzer = AttackChainAnalyzer()
        report.attack_chains = chain_analyzer.analyze(report.vulnerabilities)
        chain_summary = chain_analyzer.generate_chain_summary(report.attack_chains)

        mitre_mapper = MitreMapper()
        report.mitre_tactics = mitre_mapper.get_tactic_summary(report.vulnerabilities)

        if report.attack_chains:
            self._emit_action(AgentAction(
                agent=AgentRole.ORCHESTRATOR, action_type="result",
                thought=f"Found {len(report.attack_chains)} attack chain(s). Top: {report.attack_chains[0].name} (CVSS {report.attack_chains[0].combined_cvss})",
            ))

        # ── Phase 4: Reporting ─────────────────────────────────────────
        if self.monitor.is_cancelled:
            report.phase = ScanPhase.FAILED
            return report

        report.phase = ScanPhase.REPORTING
        self._emit_phase(ScanPhase.REPORTING)

        reporter = ReporterAgent(llm=llm, on_action=self._handle_action)
        final_response = await reporter.run(
            target_host=target.host,
            recon_summary=recon_summary,
            exploit_summary=exploit_summary + "\n\n" + chain_summary,
            vulnerabilities=report.vulnerabilities,
            tool_results=report.tool_results,
        )

        reporter_subtasks = [s for s in subtasks if s.agent == AgentRole.REPORTER]
        for st in reporter_subtasks:
            st.status = "completed"
            st.result = final_response[:500]

        self._parse_ai_response(final_response, report)

        # ── Finalize ───────────────────────────────────────────────────
        report.phase = ScanPhase.DONE
        self._emit_phase(ScanPhase.DONE)

        return report

    # ── Helpers ────────────────────────────────────────────────────────

    def _handle_action(self, action: AgentAction) -> None:
        self.monitor.record_action(action)
        if self.on_action:
            self.on_action(action)

    def _emit_action(self, action: AgentAction) -> None:
        self.monitor.record_action(action)
        if self.on_action:
            self.on_action(action)

    def _emit_phase(self, phase: ScanPhase) -> None:
        if self.on_phase:
            self.on_phase(phase)

    @staticmethod
    def _enrich_cvss(report: ScanReport) -> None:
        """Compute CVSS v3.1 scores for each vulnerability if not already set."""
        for v in report.vulnerabilities:
            if v.cvss_score > 0 and v.cvss_vector:
                continue
            vec = estimate_vector_from_vuln(v.title, v.description)
            v.cvss_vector = vec.to_string()
            v.cvss_score = calculate_base_score(vec)

    def _generate_pdf_if_configured(self, report: ScanReport) -> None:
        """Generate a PDF report if "pdf" is in configured output formats."""
        formats = self.config.reporting.formats
        if "pdf" not in formats:
            return
        try:
            from vulnhunter.reporting.pdf_report import generate_pdf

            out_dir = Path(self.config.reporting.output_dir)
            ts = report.timestamp.strftime("%Y%m%d_%H%M%S")
            safe_host = re.sub(r"[^\w\-.]", "_", report.target.host)
            pdf_path = out_dir / f"vulnhunter_{safe_host}_{ts}.pdf"
            generate_pdf(report, pdf_path)
        except Exception as e:
            logger.warning(f"PDF generation failed: {e}")

    def _parse_ai_response(self, text: str, report: ScanReport) -> None:
        json_str: str | None = None
        fence = re.search(r"```(?:json)?\s*", text, re.IGNORECASE)
        if fence:
            json_str = _extract_balanced_json_object(text[fence.end() :], 0)
        if not json_str:
            st = text.find("{")
            if st >= 0:
                json_str = _extract_balanced_json_object(text, st)

        if json_str:
            try:
                raw = json.loads(json_str)
                if not isinstance(raw, dict):
                    raise ValueError("expected object")
                data = _unwrap_nested_report_payload(raw)
                report.risk_score = float(data.get("risk_score", 0.0))
                report.threat_level = str(data.get("threat_level", "Unknown"))
                summary = data.get("executive_summary") or ""
                if isinstance(summary, str):
                    summary = _strip_nested_json_fences(summary)
                report.ai_summary = summary
                steps = data.get("remediation_steps", [])
                report.remediation_steps = list(steps) if isinstance(steps, list) else []
                if not report.ai_summary:
                    alt = data.get("detailed_analysis", "")
                    report.ai_summary = (
                        _strip_nested_json_fences(alt) if isinstance(alt, str) else str(alt)
                    ) or text[:500]
                if (
                    report.risk_score == 0.0
                    and report.threat_level in ("Unknown", "")
                    and report.vulnerabilities
                ):
                    report.risk_score = self._estimate_risk(report)
                    report.threat_level = self._risk_to_level(report.risk_score)
                return
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        report.ai_summary = text[:1000]
        report.risk_score = self._estimate_risk(report)
        report.threat_level = self._risk_to_level(report.risk_score)

    @staticmethod
    def _estimate_risk(report: ScanReport) -> float:
        score = 0.0
        for v in report.vulnerabilities:
            if v.severity.value == "critical":
                score += 3.0
            elif v.severity.value == "high":
                score += 2.0
            elif v.severity.value == "medium":
                score += 1.0
            elif v.severity.value == "low":
                score += 0.3
        return min(score, 10.0)

    @staticmethod
    def _risk_to_level(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 2.0:
            return "Low"
        return "Informational"
