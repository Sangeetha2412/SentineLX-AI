"""
SentinelX - Dashboard Routes
"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from database.models import db, ScanHistory, Report, ChatHistory

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def home():
    recent_scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(8)
        .all()
    )
    recent_reports = (
        Report.query.filter_by(user_id=current_user.id)
        .order_by(Report.created_at.desc())
        .limit(5)
        .all()
    )
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    total_reports = Report.query.filter_by(user_id=current_user.id).count()
    total_chats = ChatHistory.query.filter_by(user_id=current_user.id).count()

    avg_risk = 0
    scored = [s.risk_score for s in ScanHistory.query.filter_by(user_id=current_user.id).all() if s.risk_score]
    if scored:
        avg_risk = round(sum(scored) / len(scored), 1)

    return render_template(
        "dashboard.html",
        recent_scans=recent_scans,
        recent_reports=recent_reports,
        total_scans=total_scans,
        total_reports=total_reports,
        total_chats=total_chats,
        avg_risk=avg_risk,
    )


@dashboard_bp.route("/")
def landing():
    return render_template("landing.html")
