"""
SentinelX - Profile, Settings & Admin Routes
"""

from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from database.models import db, User, Settings, ScanHistory, ActivityLog, Report

profile_bp = Blueprint("profile", __name__)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@profile_bp.route("/profile")
@login_required
def profile():
    scan_count = ScanHistory.query.filter_by(user_id=current_user.id).count()
    report_count = Report.query.filter_by(user_id=current_user.id).count()
    return render_template("profile.html", scan_count=scan_count, report_count=report_count)


@profile_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_settings = Settings.query.filter_by(user_id=current_user.id).first()
    if not user_settings:
        user_settings = Settings(user_id=current_user.id)
        db.session.add(user_settings)
        db.session.commit()

    if request.method == "POST":
        user_settings.theme = request.form.get("theme", "dark")
        user_settings.email_notifications = request.form.get("email_notifications") == "on"
        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("profile.settings"))

    return render_template("settings.html", settings=user_settings)


@profile_bp.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    total_scans = ScanHistory.query.count()
    total_reports = Report.query.count()
    recent_logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(30).all()
    return render_template(
        "admin.html",
        users=users,
        total_scans=total_scans,
        total_reports=total_reports,
        recent_logs=recent_logs,
    )


@profile_bp.route("/admin/toggle-role/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_role(user_id):
    user = User.query.get_or_404(user_id)
    user.role = "user" if user.role == "admin" else "admin"
    db.session.commit()
    flash(f"{user.username} is now {user.role}.", "success")
    return redirect(url_for("profile.admin_dashboard"))
