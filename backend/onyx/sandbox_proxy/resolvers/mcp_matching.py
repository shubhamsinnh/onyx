"""Shared craft-MCP request attribution.

The credential resolver and the approval evaluator must agree, exactly, on which
craft-enabled `MCPServer` (if any) a sandbox request belongs to — otherwise a
request could be gated as one server but injected with another's credentials, or
gated by one layer and not the other. Both import these pure primitives so the
attribution is defined once.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote
from urllib.parse import urlparse

from pydantic import BaseModel

from onyx.utils.logger import setup_logger

logger = setup_logger()

_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}


class CraftMCPTarget(BaseModel):
    """One craft-enabled server's parsed `server_url`, ready for matching."""

    model_config = {"frozen": True}

    server_id: int
    scheme: str
    host: str
    port: int
    path_prefix: str  # no trailing slash; "" claims the whole host


def parse_target(server_id: int, server_url: str) -> CraftMCPTarget | None:
    parsed = urlparse(server_url)
    scheme = (parsed.scheme or "").lower()
    port = parsed.port or _SCHEME_DEFAULT_PORTS.get(scheme)
    if not scheme or not parsed.hostname or port is None:
        logger.warning(
            "craft MCP server %s has an unusable server_url; "
            "it will not be reachable from Craft",
            server_id,
        )
        return None
    return CraftMCPTarget(
        server_id=server_id,
        scheme=scheme,
        host=parsed.hostname.lower(),
        port=port,
        path_prefix=parsed.path.rstrip("/"),
    )


def normalized_request_path(raw_path: str) -> str:
    """Percent-decode and collapse `.`/`..` so prefix matching can't be escaped
    by traversal (`/mcp/../admin`) the upstream would resolve to another path."""
    path = unquote(raw_path.split("?", 1)[0].split("#", 1)[0])
    return posixpath.normpath(path)


def path_matches(request_path: str, path_prefix: str) -> bool:
    if not path_prefix:
        return True
    return request_path == path_prefix or request_path.startswith(path_prefix + "/")


def host_targets(
    targets: tuple[CraftMCPTarget, ...], scheme: str, host: str, port: int
) -> list[CraftMCPTarget]:
    """Targets on the request's exact scheme + host + port.

    Scheme must match so an HTTPS server's bearer is never injected onto a
    plaintext request to the same host:port.
    """
    scheme = scheme.lower()
    host = host.lower()
    return [
        t for t in targets if t.scheme == scheme and t.host == host and t.port == port
    ]


def match_target(
    targets: tuple[CraftMCPTarget, ...],
    *,
    scheme: str,
    host: str,
    port: int,
    path: str,
) -> CraftMCPTarget | None:
    """The craft-enabled server owning ``path`` on this host, or ``None``.

    Longest configured path prefix wins when servers share a host. ``path`` must
    already be normalized (see ``normalized_request_path``).
    """
    candidates = [
        t
        for t in host_targets(targets, scheme, host, port)
        if path_matches(path, t.path_prefix)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda t: len(t.path_prefix))
