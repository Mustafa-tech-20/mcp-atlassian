"""OAuth 2.0 utilities for Atlassian Cloud authentication.

This module provides utilities for OAuth 2.0 (3LO) authentication with Atlassian Cloud.
It handles:
- OAuth configuration
- Token acquisition, storage, and refresh
- Session configuration for API clients
"""

import json
import logging
import os
import pprint
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests

# Configure logging
logger = logging.getLogger("mcp-atlassian.oauth")

# Constants
TOKEN_URL = "https://auth.atlassian.com/oauth/token"  # noqa: S105 - This is a public API endpoint URL, not a password
AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
CLOUD_ID_URL = "https://api.atlassian.com/oauth/token/accessible-resources"
USER_PROFILE_URL = "https://api.atlassian.com/me"
TOKEN_EXPIRY_MARGIN = 300  # 5 minutes in seconds
KEYRING_SERVICE_NAME = "mcp-atlassian-oauth"

# Determine the project root dynamically and set the credentials directory path
CREDENTIALS_DIR = Path("/tmp/.credentials")


@dataclass
class OAuthConfig:
    """OAuth 2.0 configuration for Atlassian Cloud.

    This class manages the OAuth configuration and tokens. It handles:
    - Authentication configuration (client credentials)
    - Token acquisition and refreshing
    - Token storage and retrieval
    - Cloud ID identification
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    cloud_id: str | None = None
    refresh_token: str | None = None
    access_token: str | None = None
    expires_at: float | None = None

    @property
    def is_token_expired(self) -> bool:
        """Check if the access token is expired or will expire soon.

        Returns:
            True if the token is expired or will expire soon, False otherwise.
        """
        # If we don't have a token or expiry time, consider it expired
        if not self.access_token or not self.expires_at:
            return True

        # Consider the token expired if it will expire within the margin
        return time.time() + TOKEN_EXPIRY_MARGIN >= self.expires_at

    def get_authorization_url(self, state: str) -> str:
        """Get the authorization URL for the OAuth 2.0 flow.

        Args:
            state: Random state string for CSRF protection

        Returns:
            The authorization URL to redirect the user to.
        """
        params = {
            "audience": "api.atlassian.com",
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "prompt": "consent",
            "state": state,
        }
        return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> str | None:
        """Exchange the authorization code for access and refresh tokens.

        Args:
            code: The authorization code from the callback

        Returns:
            The user's email if tokens were successfully acquired, None otherwise.
        """
        try:
            payload = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            }

            logger.info(f"Exchanging authorization code for tokens at {TOKEN_URL}")
            logger.debug(f"Token exchange payload: {pprint.pformat(payload)}")

            response = requests.post(TOKEN_URL, data=payload)

            logger.debug(f"Token exchange response status: {response.status_code}")
            logger.debug(
                f"Token exchange response headers: {pprint.pformat(response.headers)}"
            )
            logger.debug(f"Token exchange response body: {response.text[:500]}...")

            if not response.ok:
                logger.error(
                    f"Token exchange failed with status {response.status_code}. Response: {response.text}"
                )
                return None

            token_data = response.json()

            if "access_token" not in token_data:
                logger.error(
                    f"Access token not found in response. Keys found: {list(token_data.keys())}"
                )
                return None

            if "refresh_token" not in token_data:
                logger.error(
                    "Refresh token not found in response. Ensure 'offline_access' scope is included. "
                    f"Keys found: {list(token_data.keys())}"
                )
                return None

            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.expires_at = time.time() + token_data["expires_in"]

            # Get user email
            user_email = self._get_user_email()
            if not user_email:
                logger.error("Failed to retrieve user email after token exchange.")
                return None

            # Get the cloud ID using the access token
            self._get_cloud_id()

            # Save the tokens, associated with the user's email
            self._save_tokens(email=user_email)

            logger.info(
                f"✅ OAuth token exchange successful for user {user_email}! "
                f"Access token expires in {token_data['expires_in']}s."
            )
            if self.cloud_id:
                logger.info(f"Cloud ID successfully retrieved: {self.cloud_id}")
            else:
                logger.warning(
                    "Cloud ID was not retrieved after token exchange. Check accessible resources."
                )
            return user_email
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during token exchange: {e}", exc_info=True)
            return None
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to decode JSON response from token endpoint: {e}",
                exc_info=True,
            )
            logger.error(
                f"Response text that failed to parse: {response.text if 'response' in locals() else 'Response object not available'}"
            )
            return None
        except Exception as e:
            logger.error(f"Failed to exchange code for tokens: {e}")
            return None

    def refresh_access_token(self, email: str) -> bool:
        """Refresh the access token using the refresh token.

        Args:
            email: The user's email to identify which token to refresh.

        Returns:
            True if the token was successfully refreshed, False otherwise.
        """
        if not self.refresh_token:
            logger.error("No refresh token available")
            return False

        try:
            payload = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }

            logger.debug("Refreshing access token...")
            response = requests.post(TOKEN_URL, data=payload)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data["access_token"]
            if "refresh_token" in token_data:
                self.refresh_token = token_data["refresh_token"]
            self.expires_at = time.time() + token_data["expires_in"]

            # Save the updated tokens
            self._save_tokens(email=email)

            return True
        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            return False

    def ensure_valid_token(self, email: str) -> bool:
        """Ensure the access token is valid, refreshing if necessary.

        Args:
            email: The user's email to identify the token.

        Returns:
            True if the token is valid (or was refreshed successfully), False otherwise.
        """
        if not self.is_token_expired:
            return True
        return self.refresh_access_token(email=email)

    def _get_cloud_id(self) -> None:
        """Get the cloud ID for the Atlassian instance."""
        if not self.access_token:
            logger.debug("No access token available to get cloud ID")
            return

        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = requests.get(CLOUD_ID_URL, headers=headers)
            response.raise_for_status()

            resources = response.json()
            if resources and len(resources) > 0:
                self.cloud_id = resources[0]["id"]
                logger.debug(f"Found cloud ID: {self.cloud_id}")
            else:
                logger.warning("No Atlassian sites found in the response")
        except Exception as e:
            logger.error(f"Failed to get cloud ID: {e}")

    def _get_user_email(self) -> str | None:
        """Get the user's email using the access token."""
        if not self.access_token:
            logger.error("Cannot get user email without an access token.")
            return None
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = requests.get(USER_PROFILE_URL, headers=headers)
            response.raise_for_status()
            profile_data = response.json()
            email = profile_data.get("email")
            if email:
                logger.info(f"Retrieved user email: {email}")
                return email
            else:
                logger.error(f"Could not find 'email' in user profile response: {profile_data}")
                return None
        except Exception as e:
            logger.error(f"Failed to get user profile: {e}", exc_info=True)
            return None

    def _get_keyring_username(self, email: str) -> str:
        """Get the keyring username for storing tokens, scoped by email."""
        return f"oauth-{self.client_id}-{email}"

    def _save_tokens(self, email: str) -> None:
        """Save the tokens securely, associated with a user's email."""
        self._save_tokens_to_file(email)

    def _save_tokens_to_file(self, email: str, token_data: dict = None) -> None:
        """Save the tokens to a file as fallback, named by email."""
        try:
            # Use a project-local directory for credentials
            token_dir = CREDENTIALS_DIR
            token_dir.mkdir(exist_ok=True)
            # Sanitize email for filename
            safe_email = urllib.parse.quote_plus(email)
            token_path = token_dir / f"oauth-credentials-{self.client_id}-{safe_email}.json"

            if token_data is None:
                token_data = {
                    "refresh_token": self.refresh_token,
                    "access_token": self.access_token,
                    "expires_at": self.expires_at,
                    "cloud_id": self.cloud_id,
                }
            with open(token_path, "w") as f:
                json.dump(token_data, f)
            logger.info(f"Saved OAuth tokens to file {token_path}")
        except Exception as e:
            logger.error(f"Failed to save tokens to file: {e}")

    @staticmethod
    def load_tokens(email: str, client_id: str) -> dict[str, Any]:
        """Load tokens for a specific user from keyring or file."""
        return OAuthConfig._load_tokens_from_file(email, client_id)

    @staticmethod
    def _load_tokens_from_file(email: str, client_id: str) -> dict[str, Any]:
        """Load tokens from a file for a specific user."""
        safe_email = urllib.parse.quote_plus(email)
        # Use a project-local directory for credentials
        token_path = CREDENTIALS_DIR / f"oauth-credentials-{client_id}-{safe_email}.json"

        logger.debug(f"Attempting to load token from {token_path}")
        if not token_path.exists():
            logger.warning(f"Token file not found at {token_path}")
            return {}
        try:
            with open(token_path) as f:
                token_data = json.load(f)
                logger.debug(f"Loaded OAuth tokens from file {token_path}")
                return token_data
        except Exception as e:
            logger.error(f"Failed to load tokens from file: {e}")
            return {}

    @classmethod
    def from_env(cls) -> Optional["OAuthConfig"]:
        """Create an OAuth configuration from environment variables."""
        oauth_enabled = os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in ("true", "1", "yes")
        client_id = os.getenv("ATLASSIAN_OAUTH_CLIENT_ID")
        client_secret = os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET")
        redirect_uri = os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI")
        scope = os.getenv("ATLASSIAN_OAUTH_SCOPE")

        if scope:
            # Ensure 'read:me' scope is always present for user email retrieval
            if "read:me" not in scope:
                logger.warning("'read:me' scope is missing from ATLASSIAN_OAUTH_SCOPE. Adding it automatically for user email retrieval.")
                scope += " read:me"
        else:
            # Provide a default scope if not set, including 'read:me'
            logger.info("ATLASSIAN_OAUTH_SCOPE not set. Using default scopes including 'read:me'.")
            scope = "offline_access read:jira-work write:jira-work read:jira-user manage:jira-project read:confluence-content.all write:confluence-content read:confluence-space.summary read:confluence-user write:confluence-file search:confluence read:me"

        if all([client_id, client_secret, redirect_uri, scope]):
            # Create the config but DO NOT load tokens yet.
            # Token loading is now handled by the middleware which has the user's email.
            return cls(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scope=scope,
                cloud_id=os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            )
        elif oauth_enabled:
            logger.info(
                "Creating minimal OAuth config for user-provided tokens (ATLASSIAN_OAUTH_ENABLE=true)"
            )
            return cls(
                client_id="",
                client_secret="",
                redirect_uri="",
                scope="",
                cloud_id=os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            )
        return None


@dataclass
class BYOAccessTokenOAuthConfig:
    """OAuth configuration when providing a pre-existing access token.

    This class is used when the user provides their own Atlassian Cloud ID
    and access token directly, bypassing the full OAuth 2.0 (3LO) flow.
    It's suitable for scenarios like service accounts or CI/CD pipelines
    where an access token is already available.

    This configuration does not support token refreshing.
    """

    cloud_id: str
    access_token: str
    refresh_token: None = None
    expires_at: None = None

    @classmethod
    def from_env(cls) -> Optional["BYOAccessTokenOAuthConfig"]:
        """Create a BYOAccessTokenOAuthConfig from environment variables.

        Reads `ATLASSIAN_OAUTH_CLOUD_ID` and `ATLASSIAN_OAUTH_ACCESS_TOKEN`.

        Returns:
            BYOAccessTokenOAuthConfig instance or None if required
            environment variables are missing.
        """
        cloud_id = os.getenv("ATLASSIAN_OAUTH_CLOUD_ID")
        access_token = os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN")

        if not all([cloud_id, access_token]):
            return None

        return cls(cloud_id=cloud_id, access_token=access_token)


def get_oauth_config_from_env() -> OAuthConfig | BYOAccessTokenOAuthConfig | None:
    """Get the appropriate OAuth configuration from environment variables.

    This function attempts to load standard OAuth configuration first (OAuthConfig).
    If that's not available, it tries to load a "Bring Your Own Access Token"
    configuration (BYOAccessTokenOAuthConfig).

    Returns:
        An instance of OAuthConfig or BYOAccessTokenOAuthConfig if environment
        variables are set for either, otherwise None.
    """
    return BYOAccessTokenOAuthConfig.from_env() or OAuthConfig.from_env()


def configure_oauth_session(
    session: requests.Session, oauth_config: OAuthConfig | BYOAccessTokenOAuthConfig
) -> bool:
    """Configure a requests session with OAuth 2.0 authentication.

    This function ensures the access token is valid and adds it to the session headers.

    Args:
        session: The requests session to configure
        oauth_config: The OAuth configuration to use

    Returns:
        True if the session was successfully configured, False otherwise
    """
    logger.debug(
        f"configure_oauth_session: Received OAuthConfig with "
        f"access_token_present={bool(oauth_config.access_token)}, "
        f"refresh_token_present={bool(oauth_config.refresh_token)}, "
        f"cloud_id='{oauth_config.cloud_id}'"
    )
    # If user provided only an access token (no refresh_token), use it directly
    if oauth_config.access_token and not oauth_config.refresh_token:
        logger.info(
            "configure_oauth_session: Using provided OAuth access token directly (no refresh_token)."
        )
        session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
        return True
    logger.debug("configure_oauth_session: Proceeding to ensure_valid_token.")
    # Otherwise, ensure we have a valid token (refresh if needed)
    if isinstance(oauth_config, BYOAccessTokenOAuthConfig):
        logger.error(
            "configure_oauth_session: oauth access token configuration provided as empty string."
        )
        return False
    if not oauth_config.ensure_valid_token():
        logger.error(
            f"configure_oauth_session: ensure_valid_token returned False. "
            f"Token was expired: {oauth_config.is_token_expired}, "
            f"Refresh token present for attempt: {bool(oauth_config.refresh_token)}"
        )
        return False
    session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
    logger.info("Successfully configured OAuth session for Atlassian Cloud API")
    return True