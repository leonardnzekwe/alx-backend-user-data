#!/usr/bin/env python3
"""UserSession module for representing a user session."""
from models.base import Base


class UserSession(Base):
    """
    Represents a user session.

    Attributes:
        user_id (int): The ID of the user associated with the session.
        session_id (str): The ID of the session.
    """

    def __init__(self, *args: list, **kwargs: dict):
        """Initialize a UserSession instance."""
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get("user_id")
        self.session_id = kwargs.get("session_id")
