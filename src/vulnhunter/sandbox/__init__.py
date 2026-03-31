"""Docker sandbox for isolated tool execution."""

__all__ = ["ContainerManager", "SandboxedExecutor"]


def __getattr__(name: str):
    if name == "ContainerManager":
        from vulnhunter.sandbox.manager import ContainerManager
        return ContainerManager
    if name == "SandboxedExecutor":
        from vulnhunter.sandbox.executor import SandboxedExecutor
        return SandboxedExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
