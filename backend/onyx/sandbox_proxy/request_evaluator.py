"""Classify an intercepted HTTPS request into a gated action.

The gate addon treats both a `None` return and any matcher exception as
"not gated" — the real security boundary is the proxy's iptables egress
lockdown, not this heuristic.
"""

import json
import re
from collections.abc import Iterable
from collections.abc import Sequence
from typing import Any
from typing import Protocol
from urllib.parse import parse_qs
from uuid import UUID

from mitmproxy import http

from onyx.db.engine.sql_engine import get_session_with_tenant
from onyx.db.enums import EndpointPolicy
from onyx.db.enums import GatedAppKind
from onyx.db.enums import POLICY_SEVERITY
from onyx.db.external_app import get_external_apps
from onyx.db.mcp import effective_mcp_tool_policy
from onyx.db.mcp import get_craft_enabled_mcp_servers
from onyx.db.mcp import get_mcp_tool_policies
from onyx.db.models import ExternalApp
from onyx.external_apps.credentials import app_is_available
from onyx.external_apps.matching.engine import AllMatchedActions
from onyx.external_apps.matching.engine import apply_credential_gate
from onyx.external_apps.matching.engine import GatedTarget
from onyx.external_apps.matching.engine import MatchedAction
from onyx.external_apps.matching.engine import recognize_actions
from onyx.external_apps.matching.request import ProxiedRequest
from onyx.sandbox_proxy.mcp_jsonrpc import classify_mcp_request
from onyx.sandbox_proxy.mcp_jsonrpc import McpRpcKind
from onyx.sandbox_proxy.resolvers.mcp_matching import match_target
from onyx.sandbox_proxy.resolvers.mcp_matching import normalized_request_path
from onyx.sandbox_proxy.resolvers.mcp_matching import parse_target
from onyx.utils.logger import setup_logger

logger = setup_logger()

# action_type for an unclassifiable request to a matched MCP host (fail closed).
MCP_UNCLASSIFIABLE_ACTION_TYPE = "mcp.unclassifiable"


class RequestEvaluator(Protocol):
    def evaluate(
        self, request: http.Request, tenant_id: str, user_id: UUID
    ) -> AllMatchedActions | None: ...


class CompositeRequestEvaluator(RequestEvaluator):
    """Runs sub-evaluators in order; first non-``None`` verdict wins.

    External apps are tried before MCP: on a host that is both a connected
    external app and a craft MCP server, the external-app attribution governs,
    mirroring the credential resolvers' claim order.
    """

    def __init__(self, evaluators: Sequence[RequestEvaluator]) -> None:
        self._evaluators = list(evaluators)

    def evaluate(
        self, request: http.Request, tenant_id: str, user_id: UUID
    ) -> AllMatchedActions | None:
        for evaluator in self._evaluators:
            matched = evaluator.evaluate(request, tenant_id, user_id)
            if matched is not None:
                return matched
        return None


def resolve_app_for_url(
    url: str,
    apps: Iterable[ExternalApp],
) -> ExternalApp | None:
    """Return the first ``app`` whose any ``upstream_url_patterns`` entry matches
    ``url``, or ``None`` if no connected app claims it.

    ``apps`` is expected id-ordered (as ``get_external_apps`` returns it), so the
    lowest-id app wins when patterns overlap. A malformed built-in regex is
    skipped rather than failing resolution for every other app.
    """
    for app in apps:
        for regex in app.upstream_url_regexes:
            try:
                if re.fullmatch(regex, url):
                    return app
            except re.error:
                logger.warning(
                    "skipping malformed upstream_url_pattern app_id=%s pattern=%r",
                    app.id,
                    regex,
                )
    return None


class ExternalAppRequestEvaluator(RequestEvaluator):
    """Matches a request against the tenant's connected external apps.

    Opens its own short tenant-scoped DB session (mirrors ``IdentityResolver``):
    load the tenant's apps, resolve the one owning the request URL, recognise the
    catalog action(s) via ``recognize_actions``, then apply the credential gate via
    ``apply_credential_gate`` to produce the verdict.
    """

    def evaluate(
        self, request: http.Request, tenant_id: str, user_id: UUID
    ) -> AllMatchedActions | None:
        with get_session_with_tenant(tenant_id=tenant_id) as db:
            apps = get_external_apps(db)
            app = resolve_app_for_url(request.url, apps)
            if app is None:
                return None

            # Catalog path matchers test the URL path only; mitmproxy's
            # `request.path` carries the query string, so drop it.
            proxied = ProxiedRequest(
                method=request.method or "",
                path=(request.path or "").split("?", 1)[0],
                body=request.raw_content,
            )
            matched_actions = apply_credential_gate(
                app,
                proxied,
                recognize_actions(db, app, proxied),
                is_available=app_is_available(db, app, user_id),
            )
            if matched_actions is None:
                return None

        # Engine leaves `payload` empty — we own the raw content + content-type.
        payload = _decode_body(
            request.raw_content or b"",
            (request.headers.get("content-type") or "").lower(),
        )
        return matched_actions.model_copy(update={"payload": payload or {}})


class McpRequestEvaluator(RequestEvaluator):
    """Gates craft-enabled MCP servers: proxy-authoritative per-tool approvals.

    Attributes a request to a craft MCP server by the same host + path-prefix
    rule the credential resolver uses, then parses the JSON-RPC body:

    * protocol plumbing (handshake, discovery, resources) → ``None`` (off-catalog;
      the resolver injects credentials and the request forwards ungated);
    * ``tools/call`` → an ``AllMatchedActions`` over the invoked tool(s), each
      carrying its effective per-tool policy (admin override else default ASK);
    * unclassifiable body on a matched host → a single ``DENY`` action so the
      gate fails closed instead of forwarding with injected credentials.

    A request outside every server's ``server_url`` prefix isn't attributed here
    (returns ``None``); the resolver still fails it closed at injection time.
    """

    def evaluate(
        self,
        request: http.Request,
        tenant_id: str,
        user_id: UUID,  # noqa: ARG002 — org-level gating; per-user creds resolve later
    ) -> AllMatchedActions | None:
        with get_session_with_tenant(tenant_id=tenant_id) as db:
            servers = get_craft_enabled_mcp_servers(db)
            targets = tuple(
                t
                for t in (parse_target(s.id, s.server_url) for s in servers)
                if t is not None
            )
            target = match_target(
                targets,
                scheme=request.scheme,
                host=request.host,
                port=request.port,
                path=normalized_request_path((request.path or "").split("?", 1)[0]),
            )
            if target is None:
                return None
            server = next(s for s in servers if s.id == target.server_id)
            server_name = server.name

            classification = classify_mcp_request(
                request.method or "", request.raw_content
            )
            if classification.kind is McpRpcKind.PLUMBING:
                return None

            gated_target = GatedTarget(
                kind=GatedAppKind.MCP_SERVER, id=server.id, app_name=server_name
            )
            if classification.kind is McpRpcKind.UNCLASSIFIABLE:
                actions: tuple[MatchedAction, ...] = (
                    MatchedAction(
                        action_type=MCP_UNCLASSIFIABLE_ACTION_TYPE,
                        display_name="Unrecognized MCP request",
                        description=(
                            f"{request.method} {request.path} could not be parsed "
                            "as an MCP tool call or protocol message; blocked."
                        ),
                        policy=EndpointPolicy.DENY,
                    ),
                )
            else:
                stored = get_mcp_tool_policies(server.id, db)
                actions = tuple(
                    MatchedAction(
                        action_type=tool_name,
                        display_name=tool_name,
                        description=f"Call the “{tool_name}” tool on {server_name}.",
                        policy=effective_mcp_tool_policy(tool_name, stored),
                    )
                    for tool_name in _dedupe_preserving_order(classification.tool_names)
                )

        sorted_actions = tuple(
            sorted(actions, key=lambda a: POLICY_SEVERITY[a.policy], reverse=True)
        )
        payload = _decode_body(
            request.raw_content or b"",
            (request.headers.get("content-type") or "").lower(),
        )
        return AllMatchedActions(
            actions=sorted_actions, target=gated_target, payload=payload or {}
        )


def _dedupe_preserving_order(names: tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(names))


def _decode_body(body: bytes, content_type: str) -> dict[str, Any] | None:
    if "application/json" in content_type:
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(decoded, dict):
            return decoded
        # A batched GraphQL POST (the canonical multi-action case) is a JSON
        # array at the top level. Wrap so the FE's dict-keyed payload view
        # still surfaces the queries.
        if isinstance(decoded, list):
            return {"batch": decoded}
        return None

    if "application/x-www-form-urlencoded" in content_type:
        try:
            raw = parse_qs(body.decode("utf-8"))
        except UnicodeDecodeError:
            return None
        # Collapse parse_qs's list-per-key to match the JSON shape.
        return {
            key: (values[0] if len(values) == 1 else values)
            for key, values in raw.items()
        }

    return None
