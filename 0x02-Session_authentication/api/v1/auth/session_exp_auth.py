#!/usr/bin/env python3
"""
SessionExpAuth module for handling session-based
authentication with session expiration.
"""
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """
    Represents a session-based authentication mechanism
    with session expiration.

    Inherits from the SessionAuth class.

    Attributes:
        session_duration (int): The duration of a
        session in seconds.

    Methods:
        create_session(user_id=None): Creates a new
        session for the given user ID.
        user_id_for_session_id(session_id=None): Retrieves the user
        ID associated with the given session ID.
    """

    def __init__(self):
        try:
            self.session_duration = int(getenv("SESSION_DURATION", 0))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """
        Creates a new session for the given user ID.

        Args:
            user_id (str): The ID of the user.

        Returns:
            str: The session ID if the session was
            created successfully, None otherwise.
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        self.user_id_by_session_id[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieves the user ID associated with the given session ID.

        Args:
            session_id (str): The ID of the session.

        Returns:
            str: The user ID if the session is valid and
            not expired, None otherwise.
        """
        if not session_id:
            return None
        session_dict = super().user_id_for_session_id(session_id)
        if not session_dict:
            return None
        if self.session_duration <= 0:
            return session_dict.get("user_id", None)
        created_at = session_dict.get("created_at", None)
        if not created_at:
            return None
        exp = created_at + timedelta(seconds=self.session_duration)
        if exp < datetime.now():
            return None
        return session_dict.get("user_id", None)
