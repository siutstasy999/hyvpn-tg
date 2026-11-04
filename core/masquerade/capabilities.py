"""What the installed Hysteria2 binary can actually do.

Nothing here is guessed from a hardcoded version matrix alone. The version is
parsed from ``hysteria version``; whether a *non-standard* config key is
accepted cannot be answered reliably by a version number, so those questions
are reported as ``unknown`` instead of being silently assumed. A wrong
"supported" answer would be worse than an honest "not verified".

Concretely:

* **Masquerade** — part of Hysteria2 since 2.0.0. Older binaries are refused.
* **Configuration check** — some builds expose a ``check`` subcommand. It is
  detected by reading ``hysteria --help``, never invented. When it is absent,
  :mod:`core.masquerade.deploy` validates the rendered YAML itself and verifies
  the service after a restart.
* **ECH** — Hysteria2 can serve ECH (``ech.keyPath``), but clients must be
  given the ECH config list and not every client implements it. This project
  therefore never enables ECH automatically; the capability is reported so an
  administrator can decide.
* **Obfuscation** — Salamander and Gecko make the server stop being a valid
  HTTP/3 server, which removes the premise of masquerading. Reported, never
  enabled automatically.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

Runner = Callable[..., subprocess.CompletedProcess]

VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)([^\s]*)")
MIN_MASQUERADE_VERSION = (2, 0, 0)


def _run(
    runner: Runner | None,
    args: list[str],
    *,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess | None:
    execute = runner or subprocess.run
    try:
        return execute(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("command %s failed: %s", args, exc)
        return None


def parse_version(text: str) -> tuple[int, int, int, str] | None:
    match = VERSION_RE.search(text or "")
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        match.group(4) or "",
    )


def _version_string(parsed: tuple[int, int, int, str]) -> str:
    major, minor, patch, suffix = parsed
    return f"{major}.{minor}.{patch}{suffix}"


@dataclass
class Capabilities:
    """Facts about the installed binary, plus explicit unknowns."""

    binary: str = ""
    present: bool = False
    version: str = ""
    version_tuple: tuple[int, int, int, str] | None = None
    config_check: list[str] | None = None
    features: dict[str, bool | None] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def supports_masquerade(self) -> bool:
        """True only when the version is known and new enough."""
        if self.version_tuple is None:
            return False
        return self.version_tuple[:3] >= MIN_MASQUERADE_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "present": self.present,
            "version": self.version,
            "supports_masquerade": self.supports_masquerade,
            "config_check": self.config_check,
            "features": self.features,
            "notes": self.notes,
            "error": self.error,
        }


def detect_config_check(
    binary: str, runner: Runner | None = None
) -> list[str] | None:
    """Return the arguments that validate a config file, if the build has them.

    Only a documented ``check`` subcommand listed in ``hysteria --help`` is
    used. If the help text cannot be read, or says nothing about ``check``,
    ``None`` is returned and the caller falls back to structural validation.
    """
    result = _run(runner, [binary, "--help"])
    if result is None or result.returncode != 0:
        return None
    text = f"{result.stdout or ''}\n{result.stderr or ''}"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        token = stripped.split()[0].strip(",")
        if token == "check":
            return ["check", "-c"]
    return None


def detect(binary_path: str, runner: Runner | None = None) -> Capabilities:
    """Inspect the installed binary. Never raises."""
    path = str(binary_path)
    resolved = path
    if not Path(path).exists():
        # Fall back to PATH lookup: the install may live elsewhere.
        import shutil

        found = shutil.which("hysteria")
        if not found:
            return Capabilities(
                binary=path,
                present=False,
                error=f"hysteria binary not found at {path}",
            )
        resolved = found

    result = _run(runner, [resolved, "version"])
    if result is None or result.returncode != 0:
        detail = (result.stderr or "").strip() if result else "could not be executed"
        return Capabilities(
            binary=resolved,
            present=True,
            error=f"hysteria version failed: {detail or 'unknown error'}",
        )

    text = result.stdout or ""
    parsed = parse_version(text)
    config_check = detect_config_check(resolved, runner)

    capabilities = Capabilities(
        binary=resolved,
        present=True,
        version=_version_string(parsed) if parsed else "unknown",
        version_tuple=parsed,
        config_check=config_check,
        features={
            # None means "this build does not tell us, so do not assume".
            "masquerade": (parsed[:3] >= MIN_MASQUERADE_VERSION) if parsed else None,
            "masquerade_proxy": (parsed[:3] >= MIN_MASQUERADE_VERSION) if parsed else None,
            "masquerade_file": (parsed[:3] >= MIN_MASQUERADE_VERSION) if parsed else None,
            "masquerade_string": (parsed[:3] >= MIN_MASQUERADE_VERSION) if parsed else None,
            "ech": None,
            "obfs_salamander": None,
            "obfs_gecko": None,
            "http3_masquerade": None,
        },
    )

    if parsed is None:
        capabilities.notes.append(
            "could not parse the version from `hysteria version`; run "
            "`hyvpn masquerade doctor` on the server to see the raw output"
        )
    elif parsed[:3] < MIN_MASQUERADE_VERSION:
        capabilities.notes.append(
            f"hysteria {capabilities.version} predates masquerade support "
            "(2.0.0); upgrade the binary before managing masquerade"
        )
    if config_check is None:
        capabilities.notes.append(
            "this build exposes no `check` subcommand: configurations are "
            "validated structurally and by verifying the running service"
        )
    capabilities.notes.extend(
        [
            "ECH is not enabled automatically: it needs a key pair generated "
            "for the public name and a client that supports tls.ech",
            "obfuscation (salamander/gecko) is not managed here: it makes the "
            "server stop being a valid HTTP/3 server, so masquerade no longer "
            "applies",
        ]
    )
    return capabilities


def validate_config_with_binary(
    capabilities: Capabilities,
    config_path: Path,
    runner: Runner | None = None,
) -> tuple[bool, str]:
    """Run the build's own config check when it exists.

    Returns (checked, message). ``checked=False`` means the binary has no
    supported way to validate a file, which is not an error: the caller has
    already validated the rendered YAML structurally.
    """
    if capabilities.config_check is None:
        return False, "no config check command in this build"
    args = [capabilities.binary, *capabilities.config_check, str(config_path)]
    result = _run(runner, args)
    if result is None:
        return False, f"`{' '.join(args)}` could not be executed"
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0:
        return True, f"config check failed: {output or 'no output'}"
    return True, output or "config check passed"
