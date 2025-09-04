"""Auth FastMCP server instance and tool definitions."""

import logging
import secrets
from typing import Annotated

from cachetools import TTLCache
from fastmcp import Context, FastMCP
from ..context import MainAppContext
from fastmcp.server.dependencies import get_http_request
from pydantic import Field
from starlette.requests import Request

from mcp_atlassian.utils.oauth import OAuthConfig

logger = logging.getLogger(__name__)

auth_mcp = FastMCP(
    name="Auth MCP Service",
    description="Provides tools for handling authentication.",
)


@auth_mcp.tool(tags={"auth"})
async def initiate_oauth_login(
    ctx: Context,
    email: Annotated[str, Field(description="Your email address for Atlassian.")],
    mcptoolset_context: dict | None = None,
) -> str:
    """
    Initiates the OAuth 2.0 login flow for Atlassian.
    """
    request: Request = get_http_request()

    oauth_config = OAuthConfig.from_env()
    if not oauth_config or not all(
        [
            oauth_config.client_id,
            oauth_config.client_secret,
            oauth_config.redirect_uri,
            oauth_config.scope,
        ]
    ):
        return "OAuth is not configured on the server."

    state = secrets.token_urlsafe(16)

    # Store the state and email in the cache
    lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
    oauth_state_cache: TTLCache[str, str] | None = lifespan_ctx_dict.get("oauth_state_cache")
    if oauth_state_cache:
        oauth_state_cache[state] = email
        logger.debug(f"Stored state '{state}' with email '{email}' in cache.")
    else:
        logger.error("oauth_state_cache not found in lifespan context.")

    auth_url = oauth_config.get_authorization_url(state=state)
    logger.info(f"initiate_oauth_login: Generated authorization URL: {auth_url}") # Added log
    return f"Please open the following URL in your browser to authorize the application:\n{auth_url}"


@auth_mcp.tool(tags={"auth"})
async def load_jira_token_for_user(
    ctx: Context,
    email: Annotated[str, Field(description="The email address of the user whose Jira token should be loaded.")],
) -> str:
    """
    Loads the Jira authentication token for a given user email and makes it available for subsequent Jira operations.
    This tool now verifies that the provided email matches the currently authenticated user's email.
    """
    request: Request = get_http_request()

    authenticated_email = request.state.user_atlassian_email if hasattr(request.state, "user_atlassian_email") else None

    if not authenticated_email:
        return "Error: User not authenticated. Please complete the OAuth login flow first."

    if authenticated_email.lower() != email.lower():
        logger.error(f"Unauthorized attempt to load token: Authenticated user '{authenticated_email}' tried to load token for '{email}'.")
        return "Error: Unauthorized. The provided email does not match the authenticated user's email."

    lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
    app_lifespan_ctx: MainAppContext | None = (
        lifespan_ctx_dict.get("app_lifespan_context")
        if isinstance(lifespan_ctx_dict, dict)
        else None
    )

    if not app_lifespan_ctx:
        logger.error("Application lifespan context not available.")
        return "Error: Application context not available. Server might not be initialized correctly."

    global_jira_config = app_lifespan_ctx.full_jira_config
    global_confluence_config = app_lifespan_ctx.full_confluence_config

    client_id = None
    if global_jira_config and global_jira_config.oauth_config:
        client_id = global_jira_config.oauth_config.client_id
    elif global_confluence_config and global_confluence_config.oauth_config:
        client_id = global_confluence_config.oauth_config.client_id

    if not client_id:
        logger.error("OAuth client_id not configured. Cannot load user token.")
        return "Error: OAuth client_id not configured. Please set ATLASSIAN_OAUTH_CLIENT_ID."

    token_data = OAuthConfig.load_tokens(email=email, client_id=client_id)

    if token_data and token_data.get("access_token"):
        request.state.user_atlassian_token = token_data["access_token"]
        request.state.user_atlassian_auth_type = "oauth"
        request.state.user_atlassian_email = email
        request.state.user_atlassian_refresh_token = token_data.get("refresh_token")
        request.state.user_atlassian_cloud_id = token_data.get("cloud_id")
        logger.info(f"Successfully loaded Jira token for user: {email}")
        return f"Jira token loaded successfully for {email}."
    else:
        logger.warning(f"No Jira token found for user: {email}")
        return f"No Jira token found for {email}. Please ensure the user has authenticated."


