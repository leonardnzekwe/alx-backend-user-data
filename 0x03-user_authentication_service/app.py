#!/usr/bin/env python3
"""Flask app module
"""
from flask import Flask, jsonify, request, make_response, redirect
from auth import Auth


app = Flask(__name__)


AUTH = Auth()


@app.route("/")
def welcome():
    """Welcome route"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """Users route"""
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError as err:
        return jsonify({"message": str(err)}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """Login route"""
    email = request.form.get("email")
    password = request.form.get("password")

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response, 200
    else:
        return make_response("Unauthorized", 401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """Logout route"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        return make_response("Forbidden", 403)


@app.route("/profile", methods=["GET"])
def profile():
    """Profile route"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": user.email}), 200
    else:
        return make_response("Forbidden", 403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """Get reset password token route"""
    email = request.form.get("email")

    try:
        reset_token = Auth.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        return "", 403


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """Update password route"""
    try:
        email = request.form["email"]
        reset_token = request.form["reset_token"]
        new_password = request.form["new_password"]

        AUTH.update_password(reset_token, new_password)

        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        return "", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
