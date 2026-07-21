"""Lab-target safety guard for the offensive tooling.

The attack tool in this package is for exercising **your own** network in a
lab. This guard enforces that: by default a target host must be loopback or
an RFC 1918 / unique-local private address. Aiming at anything public requires
the explicit ``--i-understand-lab`` opt-in, which the CLI surfaces as a flag.
This keeps the offensive material squarely inside the educational scope. Kept
as a self-contained copy (not a cross-project import) so this project remains
an independent deploy unit, same contract as the dns-sinkhole sibling's guard.
"""

from __future__ import annotations

import ipaddress
import socket


class LabGuardError(RuntimeError):
    """Raised when a target is outside the lab and the opt-in was not given."""


def _resolve_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except (OSError, ValueError):
        return None


def is_lab_target(host: str) -> bool:
    """True if ``host`` is loopback or a private/link-local address."""
    ip = _resolve_ip(host)
    if ip is None:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def require_lab_target(host: str, override: bool = False) -> None:
    """Raise :class:`LabGuardError` unless ``host`` is a lab target or overridden."""
    if override or is_lab_target(host):
        return
    raise LabGuardError(
        f"refusing to target non-lab host {host!r}. This tool is for your own "
        f"network only. Pass --i-understand-lab to override for authorized tests."
    )
