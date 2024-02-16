#!/usr/bin/env python3
"""Auth module for handling authentication and authorization."""

from flask import request
from typing import List, TypeVar
from fnmatch import fnmatch
from os import getenv


class Auth:
    """
    Auth class for handling authentication and authorization.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of paths that are
            excluded from authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if not path or not excluded_paths:
            return True
        if path[-1] != "/":
            path += "/"
        return not [n for n in excluded_paths if fnmatch(path, n)]

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.

        Args:
            request (Request): The request object.

        Returns:
            str: The authorization header value.
        """
        if not request:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the current user based on the request.

        Args:
            request (Request): The request object.

        Returns:
            User: The current user object.
        """
        return None

    def session_cookie(self, request=None):
        """
        Retrieves the session cookie from the request.

        Args:
            request (Request): The request object.

        Returns:
            str: The session cookie value.
        """
        if not request:
            return None
        return request.cookies.get(getenv("SESSION_NAME"), None)
