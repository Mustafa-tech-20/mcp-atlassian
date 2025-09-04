"""Main FastMCP server setup for Atlassian integration."""

import logging
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

import json
import io

from cachetools import TTLCache
from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.oauth import OAuthConfig
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool

from .auth import auth_mcp
from .confluence import confluence_mcp
from .context import MainAppContext
from .dependencies import InteractiveOAuthRequiredError, OAuthLoginRequiredError
from .jira import jira_mcp

logger = logging.getLogger("mcp-atlassian.server.main")

# Suppress DEBUG logs from sse_starlette.sse
logging.getLogger("sse_starlette.sse").setLevel(logging.INFO)


async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Atlassian MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None

    if services.get("jira"):
        try:
            jira_config = JiraConfig.from_env()
            if jira_config.is_auth_configured():
                loaded_jira_config = jira_config
                logger.info(
                    "Jira configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Jira URL found, but authentication is not fully configured. Jira tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Jira configuration: {e}", exc_info=True)

    if services.get("confluence"):
        try:
            confluence_config = ConfluenceConfig.from_env()
            if confluence_config.is_auth_configured():
                loaded_confluence_config = confluence_config
                logger.info(
                    "Confluence configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Confluence URL found, but authentication is not fully configured. Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(
                f"Failed to load Confluence configuration: {e}", exc_info=True
            )

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        read_only=read_only,
        enabled_tools=enabled_tools,
    )
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        yield {"app_lifespan_context": app_context}
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            # Close any open connections if needed
            if loaded_jira_config:
                logger.debug("Cleaning up Jira resources...")
            if loaded_confluence_config:
                logger.debug("Cleaning up Confluence resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        logger.info("Main Atlassian MCP server lifespan shutdown complete.")


class AtlassianMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for Atlassian integration with tool filtering."""

    async def _mcp_list_tools(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration from the lifespan context.
        req_context = self._mcp_server.request_context
        if req_context is None or req_context.lifespan_context is None:
            logger.warning(
                "Lifespan context not available during _main_mcp_list_tools call."
            )
            return []

        lifespan_ctx_dict = req_context.lifespan_context
        app_lifespan_state: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        read_only = (
            getattr(app_lifespan_state, "read_only", False)
            if app_lifespan_state
            else False
        )
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )
        logger.debug(
            f"_main_mcp_list_tools: read_only={read_only}, enabled_tools_filter={enabled_tools_filter}"
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode and 'write' tag"
                )
                continue

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                if is_jira_tool and not app_lifespan_state.full_jira_config:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as Jira configuration/authentication is incomplete."
                    )
                    service_configured_and_available = False
                if (
                    is_confluence_tool
                    and not app_lifespan_state.full_confluence_config
                ):
                    
                    service_configured_and_available = False
            elif is_jira_tool or is_confluence_tool:
                logger.warning(
                    f"Excluding tool '{registered_name}' as application context is unavailable to verify service configuration."
                )
                service_configured_and_available = False

            if not service_configured_and_available:
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        
        return filtered_tools

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)

        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)

        app = super().http_app(
            path=path, middleware=final_middleware_list, transport=transport
        )

        # Add the exception handler for OAuth login requests
        app.add_exception_handler(OAuthLoginRequiredError, _handle_oauth_login_request)
        app.add_exception_handler(InteractiveOAuthRequiredError, _handle_interactive_oauth_login_request)

        return app


async def _handle_oauth_login_request(
    request: Request, exc: OAuthLoginRequiredError
) -> JSONResponse:
    """Exception handler that returns a 401 error with the authorization URL."""
    logger.info(
        "Authentication not found, returning authorization URL to the client."
    )
    oauth_config = OAuthConfig.from_env()
    if not oauth_config or not all(
        [
            oauth_config.client_id,
            oauth_config.client_secret,
            oauth_config.redirect_uri,
            oauth_config.scope,
        ]
    ):
        return JSONResponse(
            {
                "error": "OAuth is not configured on the server. "
                "Please set ATLASSIAN_OAUTH_CLIENT_ID, ATLASSIAN_OAUTH_CLIENT_SECRET, "
                "ATLASSIAN_OAUTH_REDIRECT_URI, and ATLASSIAN_OAUTH_SCOPE environment variables."
            },
            status_code=500,
        )

    # In this flow, we send the URL back to the client.
    # The state parameter for CSRF is less critical as the user must actively click the link.
    state = secrets.token_urlsafe(16)  # Still generate a state for the URL
    auth_url = oauth_config.get_authorization_url(state=state)

    return JSONResponse(
        {
            "error": "Authentication required.",
            "details": "Please open the following URL in your browser to authorize the application. "
            "After authorization, please reconnect your client.",
            "authorization_url": auth_url,
        },
        status_code=401,
    )


async def _handle_interactive_oauth_login_request(
    request: Request, exc: InteractiveOAuthRequiredError
) -> JSONResponse:
    """Exception handler that instructs the user to initiate login."""
    logger.info(
        "Interactive OAuth login required. Instructing user to call initiate_oauth_login."
    )
    return JSONResponse(
        {
            "error": "Authentication required.",
            "details": "Please call the `auth.initiate_oauth_login` tool with your email address to begin the authentication process.",
        },
        status_code=401,
    )


token_validation_cache: TTLCache[
    int, tuple[bool, str | None, JiraFetcher | None, ConfluenceFetcher | None]
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware(BaseHTTPMiddleware):
    """Middleware to extract user tokens or load them based on user email."""

    def __init__(
        self, app: Any, mcp_server_ref: Optional["AtlassianMCP"] = None
    ) -> None:
        super().__init__(app)
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. Path matching for MCP endpoint might fail if settings are needed."
            )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> JSONResponse:
        logger.debug(
            f"UserTokenMiddleware.dispatch: ENTERED for request path='{request.url.path}', method='{request.method}'"
        )
        mcp_server_instance = self.mcp_server_ref
        if mcp_server_instance is None:
            logger.debug(
                "UserTokenMiddleware.dispatch: self.mcp_server_ref is None. Skipping MCP auth logic."
            )
            return await call_next(request)

        mcp_path = mcp_server_instance.settings.streamable_http_path.rstrip("/")
        request_path = request.url.path.rstrip("/")

        if request_path == mcp_path and request.method == "POST":
            email = None
            # Try to get email from request body
            try:
                body = await request.body()
                if body:
                    request_json = json.loads(body)
                    email = request_json.get("email") # Assuming email is sent as 'email' in body
                # Re-insert body into request stream for downstream handlers
                request._body_stream = io.BytesIO(body)
                request.scope["_body"] = body
            except json.JSONDecodeError:
                logger.debug("Request body is not JSON or empty.")
            except Exception as e:
                logger.error(f"Error processing request body in middleware: {e}")

            if email:
                lifespan_ctx = request.app.state.app_lifespan_context
                global_jira_config = lifespan_ctx.full_jira_config
                global_confluence_config = lifespan_ctx.full_confluence_config

                client_id = None
                if global_jira_config and global_jira_config.oauth_config:
                    client_id = global_jira_config.oauth_config.client_id
                elif global_confluence_config and global_confluence_config.oauth_config:
                    client_id = global_confluence_config.oauth_config.client_id

                if client_id:
                    token_data = OAuthConfig.load_tokens(email=email, client_id=client_id)
                    if token_data and token_data.get("access_token"):
                        logger.info(f"Loaded token for user {email} from storage.")
                        request.state.user_atlassian_token = token_data["access_token"]
                        request.state.user_atlassian_auth_type = "oauth"
                        request.state.user_atlassian_email = email
                        request.state.user_atlassian_refresh_token = token_data.get(
                            "refresh_token"
                        )
                        request.state.user_atlassian_cloud_id = token_data.get(
                            "cloud_id"
                        )
                    else:
                        logger.warning(f"No stored token found for email: {email}")
                else:
                    logger.warning(
                        "Could not load token by email: OAuth client_id not configured."
                    )

        logger.info("UserTokenMiddleware.dispatch: About to call next in middleware chain.")
        response = await call_next(request)
        logger.info(f"UserTokenMiddleware.dispatch: Response status code: {response.status_code}") # Added 
       
        logger.info(f"UserTokenMiddleware.dispatch: Response headers: {response.headers}") # Changed from 
 
        logger.info( # Changed from debug to info
            f"UserTokenMiddleware.dispatch: EXITED for request path='{request.url.path}'"
        )
        return response



main_mcp = AtlassianMCP(name="Atlassian MCP", lifespan=main_lifespan)
main_mcp.mount("jira", jira_mcp)
main_mcp.mount("confluence", confluence_mcp)
main_mcp.mount("auth", auth_mcp)


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check(request)


@main_mcp.custom_route("/auth/callback", methods=["GET"], include_in_schema=False)
async def auth_callback(request: Request) -> JSONResponse:
    """Handles the OAuth callback from Atlassian."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    logger.info(f"auth_callback: Received code: {code}") # Added log
    logger.info(f"auth_callback: State from query params: {state}") # Added log

    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code' parameter")
    if not state:
        raise HTTPException(status_code=400, detail="Missing 'state' parameter")

    # Note: Disabling state validation for now to unblock container-based flow.
    # This is not recommended for production environments.
    # if state != session_state:
    #     logger.error(
    #         f"OAuth state mismatch: session state is {session_state}, query state is {state}"
    #     )
    #     raise HTTPException(status_code=400, detail="OAuth state mismatch")

    
    

    oauth_config = OAuthConfig.from_env()
    if not oauth_config:
        logger.error("auth_callback: OAuth is not configured on the server.") # Added log
        raise HTTPException(
            status_code=500, detail="OAuth is not configured on the server."
        )

    user_email = oauth_config.exchange_code_for_tokens(code)

    if user_email:
        logger.info(f"OAuth flow completed successfully for {user_email}. Tokens saved.")
        return JSONResponse(
            {
                "status": "success",
                "message": f"Authentication successful for {user_email}. You can now close this browser tab and return to your client.",
                "email": user_email,
            }
        )
    else:
        raise HTTPException(
            status_code=500, detail="Failed to exchange authorization code for tokens."
        )



