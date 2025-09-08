"""Jira Auth helper functions."""

import logging
from typing import Annotated

from fastmcp import Context
from pydantic import Field
from starlette.requests import Request

from mcp_atlassian.servers.context import MainAppContext
from mcp_atlassian.utils.oauth import OAuthConfig

logger = logging.getLogger(__name__)


async def load_jira_token_for_user(
    request: Request,
    email: Annotated[str, Field(description="The email address of the user whose Jira token should be loaded.")],
    ctx: Context,
) -> str:
    """
    Loads the Jira authentication token for a given user email and makes it available for subsequent Jira operations.
    """
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
