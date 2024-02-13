#!/usr/bin/env python3
"""
BasicAuth module
"""
from api.v1.auth.auth import Auth
import base64
from typing import Union, Tuple, TypeVar
from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth class to manage API authentication
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Returns the Base64 part of the
        Authorization header for Basic Authentication.
        """
        if authorization_header is None or not isinstance(
          authorization_header, str
        ):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Returns the decoded value of a Base64 string.
        """
        if base64_authorization_header is None or not isinstance(
            base64_authorization_header, str
        ):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode("utf-8")
            return decoded_string
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
      ) -> (str, str):  # type: ignore
        """
        Returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None or not isinstance(
            decoded_base64_authorization_header, str
        ):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        user_email, user_password = (
            decoded_base64_authorization_header.split(":", 1)
        )
        return user_email, user_password

    def user_object_from_credentials(
          self, user_email: str, user_pwd: str
      ) -> TypeVar("User"):  # type: ignore
        """
        Returns the User instance based on his email and password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        users = User.search({"email": user_email})
        if not users:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the User instance for a request.
        """
        if request is None:
            return None

        authorization_header = request.headers.get("Authorization")

        if authorization_header is None:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
            authorization_header
        )

        if base64_auth_header is None:
            return None

        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header
        )

        if decoded_auth_header is None:
            return None

        user_email, user_password = self.extract_user_credentials(
            decoded_auth_header
        )

        if user_email is None or user_password is None:
            return None

        return self.user_object_from_credentials(user_email, user_password)
