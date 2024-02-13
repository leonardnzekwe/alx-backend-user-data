#!/usr/bin/env python3
"""
Auth module
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """
    Auth class to manage API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Public method that returns True if the path is
        not in the list of strings excluded_paths.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        # for excluded_path in excluded_paths:
        #     if excluded_path.endswith("/"):
        #         # Remove trailing slash for tolerance
        #         excluded_path = excluded_path[:-1]
        #     if path.endswith("/"):
        #         path = path[:-1]  # Remove trailing slash for tolerance
        #     if path == excluded_path:
        #         return False

        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                excluded_prefix = excluded_path[:-1]  # Remove the *
                if path.startswith(excluded_prefix):
                    return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Public method that returns the value of
        the header request Authorization.
        """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """
        Public method that returns None.
        """
        return None
