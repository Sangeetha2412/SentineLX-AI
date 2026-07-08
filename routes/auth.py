"""
SentinelX - Authentication Routes
"""

from datetime import datetime
import os
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user

from database.models import db, User, Settings, ActivityLog
from utils.validators import is_valid_email, is_valid_username, is_strong_enough_for_signup

auth_bp = Blueprint("auth", __name__)


def _log_activity(user_id, action):
    log = ActivityLog(user_id=user_id, action=action, ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not is_valid_username(username):
            flash("Username must be 3-30 characters (letters, numbers, underscore only).", "error")
            return render_template("register.html")

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        if not is_strong_enough_for_signup(password):
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already registered.", "error")
            return render_template("register.html")

        admin_email = os.getenv("ADMIN_EMAIL", "").lower()

        role = "admin" if email == admin_email else "user"

        user = User(
            username=username,
            email=email,
            role=role
        )

        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        settings = Settings(user_id=user.id)
        db.session.add(settings)
        db.session.commit()

        _log_activity(user.id, "User registered")
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            _log_activity(user.id, "User logged in")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard.home"))

        flash("Invalid username/email or password.", "error")
        return render_template("login.html")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    _log_activity(current_user.id, "User logged out")
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
