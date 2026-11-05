"""S20: the sandbox, against a build script that actually attacks it.

**Why this file exists separately from the sandbox's other tests.** Those test the
*refusal* — that `LocalSandbox` declines untrusted work when it cannot isolate.
That is the easy half and it was the half already covered. The hard half is the
one this file takes on: when the sandbox *does* run something, does the boundary
hold against a payload that is trying to get out?

The threat model is not hypothetical. Generating an SBOM resolves dependencies,
and `npm install` runs `postinstall`. A repository under assessment is by
definition one nobody has vetted, and the entire product exists because supply
chains get compromised. So the fixture below is a real hostile `postinstall`
attempting the four things such a payload attempts in the wild:

1. **Read a credential from the environment** — `ANTHROPIC_API_KEY`, `AWS_*`, a
   token the CI runner happens to hold.
2. **Exfiltrate over the network** — phone home, or pull a second stage.
3. **Write outside the working tree** — plant something in `$HOME` or `/tmp` that
   outlives the container.
4. **Spawn a process that outlives the run** — a background listener or miner.

**Where a check genuinely needs a container runtime, it skips with a stated
reason rather than passing vacuously.** A security test that silently no-ops is
worse than none: the suite goes green, the property is unproven, and nobody knows.
`test_the_hostile_fixture_is_actually_hostile` guards against the other version of
that mistake — a fixture that stopped attacking anything would let every
containment assertion below pass for the wrong reason.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

from app.services.repo.sandbox import (
    ContainerSandbox,
    Isolation,
    LocalSandbox,
    SandboxLimits,
    SandboxUnavailable,
    SandboxViolation,
    available_isolation,
    get_sandbox,
    isolation_report,
    temporary_workspace,
)

CONTAINER_RUNTIME = shutil.which("docker") or shutil.which("podman")
needs_container = pytest.mark.skipif(
    CONTAINER_RUNTIME is None,
    reason=(
        "no container runtime on this machine, so network isolation cannot be "
        "exercised. Skipped explicitly rather than passed: a containment assertion "
        "that quietly no-ops turns an unproven property into a green suite."
    ),
)

#: The marker a successful escape would leave behind. Checked for by absence, so
#: it has to be distinctive enough that nothing else could produce it.
ESCAPE_MARKER = "bom-automation-sandbox-escape-proof"

#: A hostile `postinstall`, written the way one is actually written: quiet,
#: failure-tolerant, and attempting several routes so that blocking one is not
#: enough. Every step swallows its own error — a payload that crashes the install
#: gets noticed, and this one is trying not to be.
HOSTILE_POSTINSTALL = r"""
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync, spawn } = require('child_process');

const MARKER = 'bom-automation-sandbox-escape-proof';
const report = { credentials: [], exfiltrated: false, wrote_outside: [], spawned: false };

// 1. Harvest whatever the environment is holding.
for (const key of Object.keys(process.env)) {
  if (/KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(key)) {
    report.credentials.push(key);
  }
}

// 2. Phone home. Two routes, because a build tool that cannot reach the network
//    is unusual enough that a payload tries more than one.
try {
  execSync('curl -m 3 -s http://169.254.169.254/latest/meta-data/ > /dev/null 2>&1');
  report.exfiltrated = true;
} catch (error) { /* blocked */ }
try {
  execSync('getent hosts example.com > /dev/null 2>&1');
  report.exfiltrated = true;
} catch (error) { /* blocked */ }

// 3. Plant something that outlives this run.
for (const target of [path.join(os.homedir(), `.${MARKER}`), path.join('/tmp', MARKER)]) {
  try {
    fs.writeFileSync(target, MARKER);
    report.wrote_outside.push(target);
  } catch (error) { /* blocked */ }
}

// 4. Leave a process behind.
try {
  const child = spawn('sleep', ['300'], { detached: true, stdio: 'ignore' });
  child.unref();
  report.spawned = true;
  report.spawned_pid = child.pid;
} catch (error) { /* blocked */ }

fs.writeFileSync('escape-report.json', JSON.stringify(report));
console.log('POSTINSTALL_RAN');
"""


def _hostile_repository(root: Path) -> Path:
    """A repository whose install step attacks whatever runs it."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "hostile-fixture",
                "version": "1.0.0",
                "scripts": {"postinstall": "node postinstall.js"},
            },
            indent=2,
        )
        + "\n"
    )
    (root / "postinstall.js").write_text(HOSTILE_POSTINSTALL)
    # The sandbox runs as uid 10001. The deployed app runs as that same uid
    # (backend/Dockerfile), so its workspaces are reachable; pytest's tmp
    # dirs belong to whoever runs the suite and are 0700, so on Linux the
    # container could not even read the payload. Bind mounts ignore the
    # parent directories, so opening this one directory is enough.
    root.chmod(0o777)
    return root


# --- the fixture has to actually be hostile ----------------------------------


def test_the_hostile_fixture_is_actually_hostile(tmp_path):
    """Guards the other way a security test goes wrong.

    Every containment assertion below is of the form "the attack did not
    succeed". A fixture that quietly stopped attacking anything would satisfy all
    of them, and the suite would stay green while proving nothing.
    """
    repository = _hostile_repository(tmp_path / "repo")
    script = (repository / "postinstall.js").read_text()

    assert "KEY|TOKEN|SECRET" in script, "no credential harvesting"
    assert "169.254.169.254" in script, "no exfiltration attempt"
    assert "homedir()" in script, "no attempt to write outside the tree"
    assert "detached: true" in script, "no attempt to outlive the run"
    assert json.loads((repository / "package.json").read_text())["scripts"]["postinstall"]


def test_the_fixture_succeeds_when_nothing_contains_it(tmp_path):
    """**The control case, and the reason the rest of this file means anything.**

    Run the payload with no sandbox at all. If it cannot even harvest an
    environment variable unprotected, then every "contained" result below is
    measuring a broken fixture rather than a working boundary.
    """
    if shutil.which("node") is None:
        pytest.skip("node is not installed; the payload cannot run at all")

    repository = _hostile_repository(tmp_path / "repo")
    subprocess.run(
        ["node", "postinstall.js"],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "DEMO_SECRET_TOKEN": "sentinel"},
    )

    report = json.loads((repository / "escape-report.json").read_text())
    assert "DEMO_SECRET_TOKEN" in report["credentials"], (
        "the payload could not read an environment variable even unprotected — "
        "the fixture is broken, not the sandbox"
    )

    # Clean up anything the control case actually planted, including the
    # detached `sleep 300`: left running, it is found on the host by
    # test_a_spawned_process_does_not_outlive_the_container and blamed on
    # the sandbox.
    for planted in report["wrote_outside"]:
        Path(planted).unlink(missing_ok=True)
    if report.get("spawned_pid"):
        try:
            os.killpg(report["spawned_pid"], signal.SIGKILL)
        except ProcessLookupError:
            pass


# --- containment, where a container runtime exists ---------------------------


@needs_container
def test_a_hostile_postinstall_cannot_reach_the_network(tmp_path):
    """The §S20 exit condition. `--network none` is the control this class exists
    for, and the payload tries two routes out."""
    repository = _hostile_repository(tmp_path / "repo")
    sandbox = ContainerSandbox(image="node:22-alpine")

    result = sandbox.run(
        ["node", "postinstall.js"],
        workspace=repository,
        limits=SandboxLimits(timeout_seconds=120, memory_mb=1024),
    )

    report_path = repository / "escape-report.json"
    if not report_path.exists():
        pytest.fail(f"the payload did not run: {result.stderr[:400]}")

    report = json.loads(report_path.read_text())
    assert report["exfiltrated"] is False, "network egress was NOT blocked"


@needs_container
def test_it_cannot_write_outside_the_workspace(tmp_path):
    """`--read-only` plus a single writable mount. A payload that can plant a file
    in `$HOME` has persistence across every future run on that host."""
    repository = _hostile_repository(tmp_path / "repo")

    ContainerSandbox(image="node:22-alpine").run(
        ["node", "postinstall.js"],
        workspace=repository,
        limits=SandboxLimits(timeout_seconds=120, memory_mb=1024),
    )

    report = json.loads((repository / "escape-report.json").read_text())
    # Writing to the container's own /tmp is permitted and harmless — it is a
    # tmpfs that dies with the container. Writing to a *host* path is not, and the
    # host is what this asserts about.
    assert not Path.home().joinpath(f".{ESCAPE_MARKER}").exists()
    assert str(Path.home()) not in " ".join(report["wrote_outside"])


@needs_container
def test_it_cannot_read_a_credential_the_host_holds(tmp_path):
    """The container gets no environment from the host, so a harvester finds
    nothing worth having."""
    repository = _hostile_repository(tmp_path / "repo")
    os.environ["SANDBOX_PROBE_TOKEN"] = "sentinel-value"
    try:
        ContainerSandbox(image="node:22-alpine").run(
            ["node", "postinstall.js"],
            workspace=repository,
            limits=SandboxLimits(timeout_seconds=120, memory_mb=1024),
        )
    finally:
        del os.environ["SANDBOX_PROBE_TOKEN"]

    report = json.loads((repository / "escape-report.json").read_text())
    assert "SANDBOX_PROBE_TOKEN" not in report["credentials"]


@needs_container
def test_a_spawned_process_does_not_outlive_the_container(tmp_path):
    """`--rm` plus a pid limit. A detached process that survives the run is a
    foothold, and it is the quietest of the four attempts."""
    repository = _hostile_repository(tmp_path / "repo")

    ContainerSandbox(image="node:22-alpine").run(
        ["node", "postinstall.js"],
        workspace=repository,
        limits=SandboxLimits(timeout_seconds=120, memory_mb=1024),
    )

    # The container is gone, so anything it spawned is gone with it. Asserted on
    # the host's process table rather than trusting `--rm`.
    running = subprocess.run(["ps", "-eo", "command"], capture_output=True, text=True)
    assert "sleep 300" not in running.stdout


@needs_container
def test_a_build_script_that_never_returns_is_killed(tmp_path):
    """A payload does not have to escape to cause harm — pinning a runner forever
    is a denial of service against the assessment queue."""
    repository = tmp_path / "hang"
    repository.mkdir()
    (repository / "hang.js").write_text("setInterval(() => {}, 1000);\n")

    with pytest.raises(SandboxViolation, match="exceeded"):
        ContainerSandbox(image="node:22-alpine").run(
            ["node", "hang.js"],
            workspace=repository,
            limits=SandboxLimits(timeout_seconds=5, memory_mb=512),
        )


# --- the argv carries the flags, asserted rather than assumed ----------------


def test_the_container_is_invoked_with_network_none(monkeypatch, tmp_path):
    """**Asserted on the actual argv, not on the source text.**

    Every containment test above skips without a runtime, so on a developer
    machine the strongest control in this product would otherwise be entirely
    unverified. This runs everywhere: it intercepts the call and checks the flags
    that were really passed. A future edit that drops `--network none` fails here
    even on a laptop with no Docker.
    """
    captured: dict[str, list[str]] = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("app.services.repo.sandbox.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr("app.services.repo.sandbox.subprocess.run", _capture)

    ContainerSandbox().run(["cdxgen"], workspace=tmp_path, limits=SandboxLimits())

    argv = captured["argv"]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in argv
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--user") + 1] == "10001:10001"
    assert "--pids-limit" in argv
    # Not root, and not the invoking user either.
    assert "0:0" not in argv


def test_no_host_environment_is_forwarded_into_the_container(monkeypatch, tmp_path):
    """A forwarded `-e` or `--env-file` would hand the payload exactly what its
    first step is looking for."""
    captured: dict[str, list[str]] = {}
    monkeypatch.setattr("app.services.repo.sandbox.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        "app.services.repo.sandbox.subprocess.run",
        lambda argv, **kw: (
            captured.__setitem__("argv", argv),
            subprocess.CompletedProcess(argv, 0, "", ""),
        )[1],
    )

    ContainerSandbox().run(["cdxgen"], workspace=tmp_path, limits=SandboxLimits())

    argv = captured["argv"]
    assert "-e" not in argv
    assert "--env" not in argv
    assert "--env-file" not in argv
    assert not any("ANTHROPIC" in part or "AWS_" in part for part in argv)


def test_only_the_workspace_is_mounted(monkeypatch, tmp_path):
    """One writable mount. A second one — a cache directory, a socket — is how a
    container boundary usually actually fails."""
    captured: dict[str, list[str]] = {}
    monkeypatch.setattr("app.services.repo.sandbox.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        "app.services.repo.sandbox.subprocess.run",
        lambda argv, **kw: (
            captured.__setitem__("argv", argv),
            subprocess.CompletedProcess(argv, 0, "", ""),
        )[1],
    )

    ContainerSandbox().run(["cdxgen"], workspace=tmp_path, limits=SandboxLimits())

    argv = captured["argv"]
    mounts = [argv[index + 1] for index, part in enumerate(argv) if part == "-v"]
    assert mounts == [f"{tmp_path}:/workspace:rw"]
    # The docker socket is the classic escape: mounting it gives the container
    # control of the host daemon.
    assert not any("docker.sock" in mount for mount in mounts)


# --- the refusal path, which is the one that runs on most machines -----------


def test_untrusted_work_is_refused_when_isolation_is_unavailable(tmp_path):
    """The property that actually protects this deployment today. Restated here
    because it is the other half of the same rule: contain it, or refuse it."""
    with pytest.raises(SandboxUnavailable, match="refusing to run untrusted"):
        LocalSandbox().run(
            ["node", "postinstall.js"],
            workspace=_hostile_repository(tmp_path / "repo"),
            limits=SandboxLimits(),
        )


def test_the_hostile_fixture_never_runs_without_a_container(tmp_path):
    """Belt and braces on the test suite itself: the payload must not execute as a
    side effect of a refusal path being exercised."""
    repository = _hostile_repository(tmp_path / "repo")
    with pytest.raises(SandboxUnavailable):
        LocalSandbox().run(
            ["node", "postinstall.js"], workspace=repository, limits=SandboxLimits()
        )

    assert not (repository / "escape-report.json").exists()


def test_the_isolation_report_does_not_overstate_what_is_enforced():
    """A reader is entitled to know which machine produced their SBOM. Claiming
    network isolation on a host that has none is the one lie that matters here."""
    report = isolation_report()
    sandbox = get_sandbox()

    if sandbox.isolation is Isolation.CONTAINER:
        assert report["network_isolated"] is True
        assert report["untrusted_sources_permitted"] is True
    else:
        assert report["network_isolated"] is False
        assert report["untrusted_sources_permitted"] is False
        assert any("NO network isolation" in claim for claim in report["guarantees"])


def test_available_isolation_matches_the_machine():
    expected = Isolation.CONTAINER if CONTAINER_RUNTIME else Isolation.LOCAL
    assert available_isolation() is expected


def test_a_workspace_is_temporary_and_removed():
    """A repository under assessment must not persist after generation."""
    with temporary_workspace() as workspace:
        path = Path(workspace)
        assert path.exists()
        (path / "cloned.txt").write_text("x")
    assert not path.exists()
