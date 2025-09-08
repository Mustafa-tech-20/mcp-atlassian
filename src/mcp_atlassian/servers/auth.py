"""Auth FastMCP server instance and tool definitions."""

import logging
import secrets
from typing import Annotated

from fastmcp import Context, FastMCP
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
    auth_url = oauth_config.get_authorization_url(state=state)
    logger.info(f"initiate_oauth_login: Generated authorization URL: {auth_url}") # Added log
    return f"Please open the following URL in your browser to authorize the application:\n{auth_url}"





