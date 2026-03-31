"""Adaptive rate limiter with token-bucket algorithm and backoff."""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import defaultdict

logger = logging.getLogger("vulnhunter.stealth")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


class AdaptiveRateLimiter:
    """Token-bucket rate limiter with per-domain tracking and adaptive backoff.

    - Starts at configured RPS
    - If 429 or WAF block detected, halve the rate and wait
    - If no issues after recovery_window seconds, slowly increase toward max
    - Per-domain isolation so one hostile domain doesn't affect others
    """

    def __init__(
        self,
        max_rps: float = 10.0,
        jitter_range: tuple[float, float] = (0.1, 0.5),
        user_agent_mode: str = "rotate",
    ):
        self.max_rps = max_rps
        self.current_rps: dict[str, float] = defaultdict(lambda: max_rps)
        self.jitter_range = jitter_range
        self.user_agent_mode = user_agent_mode

        self._tokens: dict[str, float] = defaultdict(lambda: max_rps)
        self._last_refill: dict[str, float] = defaultdict(time.monotonic)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._backoff_until: dict[str, float] = defaultdict(float)
        self._consecutive_ok: dict[str, int] = defaultdict(int)
        self._recovery_window = 60.0
        self._ua_index = 0

    async def acquire(self, domain: str = "default") -> None:
        """Wait until a rate-limit token is available for the given domain."""
        async with self._locks[domain]:
            # Check backoff
            now = time.monotonic()
            if self._backoff_until[domain] > now:
                wait = self._backoff_until[domain] - now
                logger.info(f"Rate limiter: backing off {domain} for {wait:.1f}s")
                await asyncio.sleep(wait)

            # Refill tokens
            elapsed = time.monotonic() - self._last_refill[domain]
            rps = self.current_rps[domain]
            self._tokens[domain] = min(rps, self._tokens[domain] + elapsed * rps)
            self._last_refill[domain] = time.monotonic()

            # Wait if no tokens
            if self._tokens[domain] < 1.0:
                wait = (1.0 - self._tokens[domain]) / max(rps, 0.1)
                await asyncio.sleep(wait)
                self._tokens[domain] = 0.0
            else:
                self._tokens[domain] -= 1.0

            # Apply jitter
            jitter = random.uniform(*self.jitter_range)
            await asyncio.sleep(jitter)

    def report_status(self, domain: str, status_code: int) -> None:
        """Report an HTTP response status for adaptive adjustment."""
        if status_code == 429 or status_code == 503:
            self._handle_throttle(domain)
        elif 400 <= status_code < 500:
            pass  # Normal errors, no adjustment
        else:
            self._consecutive_ok[domain] += 1
            if self._consecutive_ok[domain] >= 20:
                self._try_increase(domain)
                self._consecutive_ok[domain] = 0

    def report_waf_block(self, domain: str) -> None:
        """Report a WAF block — aggressive backoff."""
        logger.warning(f"WAF block detected for {domain}, aggressive backoff")
        self.current_rps[domain] = max(self.current_rps[domain] * 0.25, 0.5)
        self._backoff_until[domain] = time.monotonic() + 30.0
        self._consecutive_ok[domain] = 0

    def get_user_agent(self) -> str:
        """Get a User-Agent string based on the configured mode."""
        if self.user_agent_mode == "rotate":
            self._ua_index = (self._ua_index + 1) % len(USER_AGENTS)
            return USER_AGENTS[self._ua_index]
        if self.user_agent_mode == "browser":
            return USER_AGENTS[0]
        return "Mozilla/5.0 (compatible; VulnHunter/2.0)"

    def get_status(self) -> dict[str, dict[str, float]]:
        """Return current rate limiter status for all domains."""
        return {
            domain: {"current_rps": self.current_rps[domain], "max_rps": self.max_rps}
            for domain in self.current_rps
        }

    def _handle_throttle(self, domain: str) -> None:
        old_rps = self.current_rps[domain]
        self.current_rps[domain] = max(old_rps * 0.5, 0.5)
        self._backoff_until[domain] = time.monotonic() + 10.0
        self._consecutive_ok[domain] = 0
        logger.info(f"Rate limit hit for {domain}: {old_rps:.1f} → {self.current_rps[domain]:.1f} RPS")

    def _try_increase(self, domain: str) -> None:
        old_rps = self.current_rps[domain]
        new_rps = min(old_rps * 1.2, self.max_rps)
        if new_rps > old_rps:
            self.current_rps[domain] = new_rps
            logger.debug(f"Rate limit recovery for {domain}: {old_rps:.1f} → {new_rps:.1f} RPS")
