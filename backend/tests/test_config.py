"""Configuration fails at import, naming the missing variable.

Run in a subprocess with a scrubbed environment: the point under test is what
happens at interpreter start, and an in-process test would be asserting against a
module that has already imported successfully.

`.env.local` is suppressed via a temporary cwd, since pydantic-settings would
otherwise read the developer's own file and the test would pass for the wrong
reason.
"""

from __future__ import annotations

import subprocess
import sys

BOOT = "import app.main"


def _boot(env: dict[str, str], cwd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", BOOT],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=60,
    )


def _base_env(backend_dir) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONPATH": str(backend_dir),
        "HOME": "/tmp",
    }


def test_boot_without_groq_api_key_exits_non_zero_naming_that_variable(tmp_path, backend_dir):
    env = _base_env(backend_dir) | {
        "ANTHROPIC_API_KEY": "x",
        "JWT_SECRET": "x" * 32,
    }
    result = _boot(env, cwd=str(tmp_path))

    assert result.returncode != 0
    assert "GROQ_API_KEY" in result.stderr
    assert "required" in result.stderr
    assert "MissingConfiguration" in result.stderr


def test_every_missing_variable_is_named_at_once(tmp_path, backend_dir):
    result = _boot(_base_env(backend_dir), cwd=str(tmp_path))

    assert result.returncode != 0
    for name in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "JWT_SECRET"):
        assert name in result.stderr, f"{name} was not reported"


def test_boot_succeeds_with_the_required_variables(tmp_path, backend_dir):
    env = _base_env(backend_dir) | {
        "GROQ_API_KEY": "x",
        "ANTHROPIC_API_KEY": "x",
        "JWT_SECRET": "x" * 32,
    }
    result = _boot(env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr


def test_an_unknown_lane_is_refused_by_name(tmp_path, backend_dir):
    env = _base_env(backend_dir) | {
        "GROQ_API_KEY": "x",
        "ANTHROPIC_API_KEY": "x",
        "JWT_SECRET": "x" * 32,
        "ENABLED_LANES": "sbom,dbom",
    }
    result = _boot(env, cwd=str(tmp_path))

    assert result.returncode != 0
    assert "unknown lane" in result.stderr
    assert "dbom" in result.stderr


def test_enabled_lanes_narrows_the_fan_out(tmp_path, backend_dir):
    env = _base_env(backend_dir) | {
        "GROQ_API_KEY": "x",
        "ANTHROPIC_API_KEY": "x",
        "JWT_SECRET": "x" * 32,
        "ENABLED_LANES": "sbom,aibom",
    }
    script = (
        "from app.configs.laneConfig import resolve_lanes;"
        # An engagement narrows the deployment default; it never widens it.
        "print(resolve_lanes()); print(resolve_lanes(['sbom','cbom']))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=60,
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    assert lines[0] == "('sbom', 'aibom')"
    assert lines[1] == "('sbom',)", "a deployment-disabled lane must not be re-enabled"
