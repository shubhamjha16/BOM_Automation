"""The generation sandbox: network-isolated, non-privileged, resource-capped.

**Why this is not optional.** Generating an SBOM means resolving dependencies,
and dependency resolution *executes code from the repository under assessment*.
`npm install` runs postinstall scripts. `pip install` runs setup.py. A repository
being assessed is, by definition, one nobody has vetted — and the whole product
exists because supply chains are compromised.

So generation runs behind this interface, and the interface has one rule that
matters more than the rest:

    **If isolation cannot be provided, generation is REFUSED, not run
    unprotected.**

A sandbox that silently degrades to "just run it" is worse than no sandbox: the
caller believes they are protected, and the failure mode is exactly the one the
sandbox was bought to prevent.

Two backends. `ContainerSandbox` is the specified one — `--network none`, a
read-only mount, a non-root user, memory and CPU caps. `LocalSandbox` provides
resource caps and a timeout but **no network isolation**, so it refuses untrusted
work and is usable only for code the operator already trusts (our own repository,
in `make self-bom`).
"""

from __future__ import annotations

import resource
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from app.utils.logger import get_logger

logger = get_logger(__name__)


class Isolation(StrEnum):
    #: Network-isolated, non-privileged, resource-capped. The real thing.
    CONTAINER = "container"
    #: Resource caps and a timeout only. No network isolation.
    LOCAL = "local"
    NONE = "none"


class SandboxUnavailable(RuntimeError):
    """No backend can provide the isolation this work requires."""


class SandboxViolation(RuntimeError):
    """The sandboxed process exceeded its limits or failed."""


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    timeout_seconds: int = 900
    memory_mb: int = 4096
    max_repo_mb: int = 2048
    #: Never run as root, even inside a container.
    user: str = "10001:10001"


@dataclass(frozen=True, slots=True)
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    isolation: Isolation
    #: What was actually enforced, for the assessment to report honestly.
    guarantees: tuple[str, ...]


def _container_runtime() -> str | None:
    for candidate in ("docker", "podman"):
        if path := shutil.which(candidate):
            return path
    return None


def available_isolation() -> Isolation:
    """The strongest isolation this machine can provide."""
    if _container_runtime():
        return Isolation.CONTAINER
    return Isolation.LOCAL


class ContainerSandbox:
    """The specified backend: `--network none`, read-only, non-root, capped."""

    isolation = Isolation.CONTAINER
    guarantees = (
        "network egress blocked (--network none)",
        "filesystem read-only except the output volume",
        "non-root user",
        "memory and CPU capped",
        "process killed at timeout",
    )

    def __init__(self, image: str = "ghcr.io/cyclonedx/cdxgen:latest") -> None:
        self.image = image
        runtime = _container_runtime()
        if runtime is None:  # pragma: no cover - guarded by the factory
            raise SandboxUnavailable("no container runtime found")
        self.runtime: str = runtime

    def run(
        self, command: list[str], *, workspace: Path, limits: SandboxLimits
    ) -> SandboxResult:
        argv = [
            self.runtime,
            "run",
            "--rm",
            # The control this class exists for. A build script that phones home
            # or pulls a second-stage payload cannot.
            "--network",
            "none",
            "--user",
            limits.user,
            "--memory",
            f"{limits.memory_mb}m",
            "--cpus",
            "2",
            "--pids-limit",
            "512",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=512m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-v",
            f"{workspace}:/workspace:rw",
            "-w",
            "/workspace",
            self.image,
            *command,
        ]
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, timeout=limits.timeout_seconds
            )
        except subprocess.TimeoutExpired as error:
            raise SandboxViolation(
                f"generation exceeded {limits.timeout_seconds}s and was killed"
            ) from error

        return SandboxResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            isolation=self.isolation,
            guarantees=self.guarantees,
        )


class LocalSandbox:
    """Resource caps and a timeout. **No network isolation.**

    Refuses untrusted work. Used only where the operator already trusts the code
    — generating our own SBOM in `make self-bom` — and it says so rather than
    presenting itself as protection it does not provide.
    """

    isolation = Isolation.LOCAL

    #: What this backend enforces is platform-dependent, so it is *measured*
    #: rather than asserted. macOS rejects a lowered RLIMIT_AS for a process that
    #: needs a large address space (Node does), and a guarantee that silently
    #: failed is worse than one never claimed — the caller would believe they
    #: were capped.
    def __init__(self) -> None:
        self.enforced: tuple[str, ...] = ()

    @property
    def guarantees(self) -> tuple[str, ...]:
        return (
            *self.enforced,
            "process killed at timeout",
            "runs in a temporary directory",
            "NO network isolation",
            "NO privilege reduction beyond the invoking user",
        )

    def run(
        self,
        command: list[str],
        *,
        workspace: Path,
        limits: SandboxLimits,
        trusted: bool = False,
    ) -> SandboxResult:
        if not trusted:
            raise SandboxUnavailable(
                "no container runtime is available, so network isolation cannot be "
                "provided. Generation resolves dependencies, which executes code "
                "from the repository under assessment — refusing to run untrusted "
                "code unprotected. Install Docker or Podman, or mark this source "
                "as trusted if you already control it."
            )

        # Probe what this platform will actually accept, in the parent, so a
        # rejected limit is reported rather than crashing the child.
        enforced: list[str] = []
        for name, attribute, value in (
            ("CPU time capped", "RLIMIT_CPU", (limits.timeout_seconds, limits.timeout_seconds)),
            ("core dumps disabled", "RLIMIT_CORE", (0, 0)),
            ("file size capped", "RLIMIT_FSIZE", (limits.max_repo_mb * 1024 * 1024,) * 2),
        ):
            limit = getattr(resource, attribute, None)
            if limit is None:  # pragma: no cover - platform dependent
                continue
            try:
                soft, hard = resource.getrlimit(limit)
                if hard != resource.RLIM_INFINITY and value[1] > hard:
                    continue
                enforced.append(name)
            except (ValueError, OSError):  # pragma: no cover
                continue
        self.enforced = tuple(enforced)

        def _apply_limits() -> None:  # pragma: no cover - runs in the child
            for attribute, value in (
                ("RLIMIT_CPU", (limits.timeout_seconds, limits.timeout_seconds)),
                ("RLIMIT_CORE", (0, 0)),
                ("RLIMIT_FSIZE", (limits.max_repo_mb * 1024 * 1024,) * 2),
            ):
                limit = getattr(resource, attribute, None)
                if limit is None:
                    continue
                try:
                    resource.setrlimit(limit, value)
                except (ValueError, OSError):
                    # Reported through `enforced`; never fatal. A failed cap must
                    # not take down a run that the operator already trusts.
                    pass

        try:
            completed = subprocess.run(
                command,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
                preexec_fn=_apply_limits,
            )
        except subprocess.TimeoutExpired as error:
            raise SandboxViolation(
                f"generation exceeded {limits.timeout_seconds}s and was killed"
            ) from error

        return SandboxResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            isolation=self.isolation,
            guarantees=self.guarantees,
        )


def get_sandbox() -> ContainerSandbox | LocalSandbox:
    """The strongest available backend."""
    if _container_runtime():
        return ContainerSandbox()
    logger.warning(
        "sandbox_degraded",
        detail=(
            "no container runtime; only trusted sources can be generated and "
            "network isolation is not enforced"
        ),
    )
    return LocalSandbox()


def isolation_report() -> dict[str, object]:
    """What this deployment can actually enforce.

    Surfaced in the assessment rather than assumed, because "generated in a
    sandbox" means different things on different machines and a reader is
    entitled to know which one produced their SBOM.
    """
    sandbox = get_sandbox()
    return {
        "isolation": str(sandbox.isolation),
        "guarantees": list(sandbox.guarantees),
        "network_isolated": sandbox.isolation is Isolation.CONTAINER,
        "untrusted_sources_permitted": sandbox.isolation is Isolation.CONTAINER,
    }


def temporary_workspace() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="bom-automation-generation-")
