"""Configuration loading for VulnHunter."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml"


def _resolved_default_config_path() -> Path:
    env = os.environ.get("VULNHUNTER_CONFIG_PATH")
    if env:
        return Path(env)
    return DEFAULT_CONFIG_PATH


PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "deepseek":  {"base_url": "https://api.deepseek.com/v1",          "model": "deepseek-chat",            "env_key": "DEEPSEEK_API_KEY"},
    "openai":    {"base_url": "https://api.openai.com/v1",            "model": "gpt-4o-mini",              "env_key": "OPENAI_API_KEY"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1",         "model": "claude-sonnet-4-5-20250514","env_key": "ANTHROPIC_API_KEY"},
    "gemini":    {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai/", "model": "gemini-2.0-flash", "env_key": "GEMINI_API_KEY"},
    "ollama":    {"base_url": "http://localhost:11434/v1",             "model": "llama3.1",                 "env_key": "OLLAMA_API_KEY"},
    "openrouter":{"base_url": "https://openrouter.ai/api/v1",         "model": "openai/gpt-4o-mini",       "env_key": "OPENROUTER_API_KEY"},
    "groq":      {"base_url": "https://api.groq.com/openai/v1",       "model": "llama-3.1-70b-versatile",  "env_key": "GROQ_API_KEY"},
}


@dataclass(frozen=True)
class AIConfig:
    enabled: bool = True
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    max_tokens: int = 8000
    base_url: str = "https://api.deepseek.com/v1"
    max_tool_calls: int = 30

    @property
    def api_key(self) -> str:
        defaults = PROVIDER_DEFAULTS.get(self.provider, {})
        env_key = defaults.get("env_key", "DEEPSEEK_API_KEY")
        return os.environ.get(env_key, os.environ.get("LLM_API_KEY", ""))


@dataclass(frozen=True)
class UIConfig:
    host: str = "127.0.0.1"
    port: int = 8477


@dataclass(frozen=True)
class ReportingConfig:
    output_dir: str = "./reports"
    formats: tuple[str, ...] = ("json", "html")


@dataclass(frozen=True)
class ToolConfig:
    enabled: bool = True
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DatabaseConfig:
    url: str = ""
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def effective_url(self) -> str:
        url = os.environ.get("DATABASE_URL", self.url)
        if not url:
            raise RuntimeError("DATABASE_URL environment variable must be set")
        return url


@dataclass(frozen=True)
class SandboxConfig:
    enabled: bool = False
    image: str = "python:3.12-slim"
    network: str = "vulnhunter-sandbox"
    timeout: int = 300
    net_raw: bool = True
    net_admin: bool = False


@dataclass(frozen=True)
class MemoryConfig:
    enabled: bool = True
    embedding_model: str = "openai/text-embedding-3-small"
    top_k: int = 5


@dataclass(frozen=True)
class AuthConfig:
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    @property
    def effective_secret(self) -> str:
        key = os.environ.get("JWT_SECRET_KEY", self.secret_key)
        if not key:
            raise RuntimeError(
                "JWT_SECRET_KEY must be set. Generate one with: "
                'python -c "import secrets; print(secrets.token_hex(64))"'
            )
        return key


@dataclass(frozen=True)
class AppConfig:
    timeout: int = 60
    max_concurrent: int = 100
    stealth_mode: str = "normal"
    tools: dict[str, ToolConfig] = field(default_factory=dict)
    ai: AIConfig = field(default_factory=AIConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)

    def tool_enabled(self, name: str) -> bool:
        tc = self.tools.get(name)
        return tc.enabled if tc else True

    def tool_settings(self, name: str) -> dict:
        tc = self.tools.get(name)
        return tc.settings if tc else {}


def load_config(config_path: Path | None = None) -> AppConfig:
    path = config_path or _resolved_default_config_path()
    if not path.exists():
        return AppConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    scanner = raw.get("scanner", {})
    tools_raw = raw.get("tools", {})
    ai_raw = raw.get("ai", {})
    reporting_raw = raw.get("reporting", {})
    ui_raw = raw.get("ui", {})

    # Parse tools
    tools: dict[str, ToolConfig] = {}
    for name, settings in tools_raw.items():
        if isinstance(settings, dict):
            enabled = settings.get("enabled", True)
            tool_settings = {k: v for k, v in settings.items() if k != "enabled"}
            tools[name] = ToolConfig(enabled=enabled, settings=tool_settings)
        else:
            tools[name] = ToolConfig(enabled=True)

    provider = os.environ.get("LLM_PROVIDER", ai_raw.get("provider", "")).lower()
    if not provider:
        for pname, pconf in PROVIDER_DEFAULTS.items():
            if os.environ.get(pconf["env_key"]):
                provider = pname
                break
        if not provider:
            provider = "deepseek"

    p_defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["deepseek"])
    model = os.environ.get("LLM_MODEL", os.environ.get("DEEPSEEK_MODEL", ai_raw.get("model", p_defaults["model"])))
    base_url = os.environ.get("LLM_BASE_URL", ai_raw.get("base_url", p_defaults["base_url"]))

    ai = AIConfig(
        enabled=ai_raw.get("enabled", True),
        provider=provider,
        model=model,
        max_tokens=ai_raw.get("max_tokens", 8000),
        base_url=base_url,
        max_tool_calls=ai_raw.get("max_tool_calls", 30),
    )

    reporting = ReportingConfig(
        output_dir=reporting_raw.get("output_dir", "./reports"),
        formats=tuple(reporting_raw.get("formats", ["json", "html"])),
    )

    ui = UIConfig(
        host=ui_raw.get("host", "127.0.0.1"),
        port=ui_raw.get("port", 8477),
    )

    db_raw = raw.get("database", {})
    database = DatabaseConfig(
        url=db_raw.get("url", ""),
        pool_size=db_raw.get("pool_size", 10),
        max_overflow=db_raw.get("max_overflow", 20),
    )

    sandbox_raw = raw.get("sandbox", {})
    if "net_admin" in sandbox_raw:
        net_admin = bool(sandbox_raw["net_admin"])
    else:
        net_admin = os.environ.get("VULNHUNTER_SANDBOX_NET_ADMIN", "").lower() in (
            "1",
            "true",
            "yes",
        )
    sandbox = SandboxConfig(
        enabled=sandbox_raw.get("enabled", False),
        image=sandbox_raw.get("image", "python:3.12-slim"),
        network=sandbox_raw.get("network", "vulnhunter-sandbox"),
        timeout=sandbox_raw.get("timeout", 300),
        net_raw=sandbox_raw.get("net_raw", True),
        net_admin=net_admin,
    )
    if os.environ.get("VULNHUNTER_SANDBOX_ENABLED", "").lower() in ("1", "true", "yes"):
        sandbox = replace(sandbox, enabled=True)

    memory_raw = raw.get("memory", {})
    memory = MemoryConfig(
        enabled=memory_raw.get("enabled", True),
        embedding_model=memory_raw.get("embedding_model", "openai/text-embedding-3-small"),
        top_k=memory_raw.get("top_k", 5),
    )

    auth_raw = raw.get("auth", {})
    auth = AuthConfig(
        secret_key=auth_raw.get("secret_key", ""),
        algorithm=auth_raw.get("algorithm", "HS256"),
        access_token_expire_minutes=auth_raw.get("access_token_expire_minutes", 60),
    )

    return AppConfig(
        timeout=scanner.get("timeout", 60),
        max_concurrent=scanner.get("max_concurrent", 100),
        stealth_mode=scanner.get("stealth_mode", "normal"),
        tools=tools,
        ai=ai,
        reporting=reporting,
        ui=ui,
        database=database,
        sandbox=sandbox,
        memory=memory,
        auth=auth,
    )


def apply_scan_sandbox_cli(
    cfg: AppConfig,
    *,
    lightweight: bool = False,
    sandbox: bool = False,
) -> AppConfig:
    """Apply CLI flags for Docker sandbox. ``--lightweight`` forces sandbox off (wins over ``--sandbox``)."""
    if lightweight:
        return replace(cfg, sandbox=replace(cfg.sandbox, enabled=False))
    if sandbox:
        return replace(cfg, sandbox=replace(cfg.sandbox, enabled=True))
    return cfg
