#!/usr/bin/env python3
"""SessionAuth module for handling session-based authentication."""
from api.v1.auth.auth import Auth
import uuid


class SessionAuth(Auth):
    """
    SessionAuth class provides methods for session-based authentication.

    Attributes:
        user_id_by_session_id (dict): A dictionary that
        maps session IDs to user IDs.
    """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a new session for the given user ID.

        Args:
            user_id (str): The ID of the user.

        Returns:
            str: The session ID.

        """
        if not user_id or type(user_id) != str:  # noqa
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieve the user ID associated with the given session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            str: The user ID.

        """
        if not session_id or type(session_id) != str:  # noqa
            return None
        return self.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None):
        """
        Retrieve the current user based on the session ID in the request.

        Args:
            request (object): The request object.

        Returns:
            object: The User object representing the current user.

        """
        from models.user import User

        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Destroy the session associated with the session ID in the request.

        Args:
            request (object): The request object.

        Returns:
            bool: True if the session was successfully destroyed,
            False otherwise.

        """
        if not request:
            return False
        session_id = self.session_cookie(request)
        if not session_id or not self.user_id_for_session_id(session_id):
            return False
        del self.user_id_by_session_id[session_id]
        return True
