#!/usr/bin/env python3
"""Main module"""
import requests

URL = "http://localhost:5000"


def register_user(email: str, password: str) -> None:
    """Register a new user"""
    response = requests.post(
        f"{URL}/users", data={"email": email, "password": password}
    )
    assert response.status_code == 200
    assert response.json()["email"] == email


def log_in_wrong_password(email: str, password: str) -> None:
    """Check if the provided email and password are valid"""
    response = requests.post(
        f"{URL}/sessions", data={"email": email, "password": password}
    )
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Create a new session for the user"""
    response = requests.post(
        f"{URL}/sessions", data={"email": email, "password": password}
    )
    assert response.status_code == 200
    return response.json()["email"]


def profile_unlogged() -> None:
    """Check if the user is logged in"""
    response = requests.get(f"{URL}/profile")
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Check if the user is logged in"""
    response = requests.get(
        f"{URL}/profile", cookies={"session_id": session_id}
    )
    assert response.status_code == 200
    assert response.json()["email"] == "guillaume@holberton.io"


def log_out(session_id: str) -> None:
    """Destroy the session"""
    response = requests.delete(
        f"{URL}/sessions", cookies={"session_id": session_id}
    )
    assert response.status_code == 302  # Redirect status code


def reset_password_token(email: str) -> str:
    """Generate a reset password token for the user."""
    response = requests.post(f"{URL}/reset_password", data={"email": email})
    assert response.status_code == 200
    return response.json()["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update the password of the user."""
    response = requests.put(
        f"{URL}/reset_password",
        data={
            "email": email,
            "reset_token": reset_token,
            "new_password": new_password
        },
    )
    assert response.status_code == 200


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
