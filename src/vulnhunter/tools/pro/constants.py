"""Shared strings for pro (sandbox) tools."""

SANDBOX_REQUIRED_MSG = (
    "Docker sandbox required — use `vulnhunter scan <target> --sandbox` "
    "or set sandbox.enabled: true in config YAML (build: docker build -f docker/Dockerfile.sandbox -t vulnhunter-sandbox:latest .). "
    "See README."
)
