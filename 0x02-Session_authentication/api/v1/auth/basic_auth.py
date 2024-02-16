#!/usr/bin/env python3
"""BasicAuth module for handling basic authentication."""

from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User
import base64


class BasicAuth(Auth):
    """Class representing basic authentication."""

    def extract_base64_authorization_header(
            self, authorization_header: str
    ) -> str:
        """Extracts the base64 authorization header from the given header.

        Args:
            authorization_header (str): The authorization header.

        Returns:
            str: The base64 authorization header.
        """
        if (
            not authorization_header
            or type(authorization_header) != str  # noqa
            or not authorization_header.startswith("Basic ")
        ):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decodes the base64 authorization header.

        Args:
            base64_authorization_header (str): The base64 authorization header.

        Returns:
            str: The decoded authorization header.
        """
        if (
            not base64_authorization_header or
            type(base64_authorization_header) != str  # noqa
        ):
            return None
        try:
            return base64.b64decode(
                base64_authorization_header.encode()
            ).decode("utf-8")
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):  # type: ignore
        """Extracts the user credentials from the decoded
        authorization header.

        Args:
            decoded_base64_authorization_header (str): The decoded
            authorization header.

        Returns:
            Tuple[str, str]: The user email and password.
        """
        if (
            not decoded_base64_authorization_header
            or type(decoded_base64_authorization_header) != str  # noqa
            or ":" not in decoded_base64_authorization_header
        ):
            return None, None
        line = decoded_base64_authorization_header.split(":")
        email = line[0]
        password = ":".join(line[1:])
        return email, password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):  # type: ignore
        """Creates a user object from the given email and password.

        Args:
            user_email (str): The user email.
            user_pwd (str): The user password.

        Returns:
            TypeVar('User'): The user object.
        """
        if (
            not user_email
            or not user_pwd
            or type(user_email) != str  # noqa
            or type(user_pwd) != str
        ):
            return None
        try:
            user = User.search({"email": user_email})
        except KeyError:
            return None
        if not user or not user[0].is_valid_password(user_pwd):
            return None
        return user[0]

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """Gets the current user based on the request.

        Args:
            request (Optional): The request object.

        Returns:
            TypeVar('User'): The current user object.
        """
        auth = self.authorization_header(request)
        extracted = self.extract_base64_authorization_header(auth)
        decoded = self.decode_base64_authorization_header(extracted)
        email, password = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(email, password)
