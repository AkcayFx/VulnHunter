"""Container lifecycle management via aiodocker."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiodocker

from vulnhunter.config import SandboxConfig

logger = logging.getLogger("vulnhunter.sandbox")


class ContainerManager:
    """Creates, executes commands in, and destroys ephemeral Docker containers."""

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._docker: aiodocker.Docker | None = None
        self._container: Any | None = None
        self._container_id: str = ""

    async def start(self) -> str:
        """Spin up an ephemeral container and return its ID."""
        self._docker = aiodocker.Docker()

        try:
            await self._docker.images.inspect(self.config.image)
        except aiodocker.exceptions.DockerError:
            logger.info(f"Pulling image {self.config.image}...")
            await self._docker.images.pull(self.config.image)

        host_config: dict[str, Any] = {
            "NetworkMode": self.config.network,
            "Memory": 512 * 1024 * 1024,
            "CpuPeriod": 100000,
            "CpuQuota": 50000,
        }
        cap_add: list[str] = []
        if self.config.net_raw:
            cap_add.append("NET_RAW")
        if self.config.net_admin:
            cap_add.append("NET_ADMIN")
        if cap_add:
            host_config["CapAdd"] = cap_add

        container_config = {
            "Image": self.config.image,
            "Cmd": ["sleep", str(self.config.timeout)],
            "HostConfig": host_config,
            "NetworkDisabled": False,
            "Tty": False,
        }

        self._container = await self._docker.containers.create_or_replace(
            name=f"vulnhunter-sandbox-{id(self) & 0xFFFF:04x}",
            config=container_config,
        )
        await self._container.start()
        info = await self._container.show()
        self._container_id = info["Id"][:12]
        logger.info(f"Sandbox container started: {self._container_id}")
        return self._container_id

    async def exec_command(self, command: list[str], timeout: int = 60) -> tuple[int, str]:
        """Run a command inside the sandbox. Returns (exit_code, output)."""
        if not self._container:
            raise RuntimeError("Container not started")

        exec_obj = await self._container.exec(
            cmd=command,
            stdout=True,
            stderr=True,
        )
        try:
            stream = exec_obj.start()
            output_parts: list[str] = []
            async with asyncio.timeout(timeout):
                async for chunk in stream:
                    if isinstance(chunk, bytes):
                        output_parts.append(chunk.decode(errors="replace"))
                    else:
                        output_parts.append(str(chunk))

            inspect = await exec_obj.inspect()
            exit_code = inspect.get("ExitCode", -1)
            return exit_code, "".join(output_parts)
        except TimeoutError:
            return -1, "Command timed out"

    async def exec_python(self, script: str, timeout: int = 60) -> tuple[int, str]:
        """Run a Python script inside the container."""
        return await self.exec_command(["python3", "-c", script], timeout=timeout)

    async def destroy(self) -> None:
        """Stop and remove the container."""
        if self._container:
            try:
                await self._container.kill()
            except Exception:
                pass
            try:
                await self._container.delete(force=True)
            except Exception:
                pass
            logger.info(f"Sandbox container destroyed: {self._container_id}")
            self._container = None

        if self._docker:
            await self._docker.close()
            self._docker = None

    async def __aenter__(self) -> ContainerManager:
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.destroy()
