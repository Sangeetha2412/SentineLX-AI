"""
SentinelX - Reports Routes
"""

import os
import uuid

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user

from database.models import db, Report, ScanHistory
from reports.report_generator import generate_pdf_report

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def reports_list():
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    return render_template("reports.html", reports=reports)


@reports_bp.route("/reports/generate", methods=["POST"])
@login_required
def generate_report():
    title = request.form.get("title", "Security Summary Report").strip() or "Security Summary Report"

    scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )

    if not scans:
        flash("Run at least one security tool before generating a report.", "error")
        return redirect(url_for("reports.reports_list"))

    avg_risk = sum(s.risk_score for s in scans) / len(scans)

    filename = f"sentinelx_report_{uuid.uuid4().hex[:10]}.pdf"
    output_path = os.path.join(current_app.config["REPORT_FOLDER"], filename)

    generate_pdf_report(
        output_path=output_path,
        title=title,
        user=current_user,
        scans=scans,
        risk_score=avg_risk,
        summary_text=f"This report summarizes the {len(scans)} most recent scans performed on SentinelX.",
    )

    report = Report(
        user_id=current_user.id,
        title=title,
        report_type="summary",
        risk_score=avg_risk,
        file_path=filename,
        summary=f"{len(scans)} scans included.",
    )
    db.session.add(report)
    db.session.commit()

    flash("Report generated successfully.", "success")
    return redirect(url_for("reports.reports_list"))


@reports_bp.route("/reports/download/<int:report_id>")
@login_required
def download_report(report_id):
    report = Report.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    path = os.path.join(current_app.config["REPORT_FOLDER"], report.file_path)
    return send_file(path, as_attachment=True, download_name=f"{report.title}.pdf")
