"""
SentinelX - AI Security Assistant Routes
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from database.models import db, ChatHistory
from ai.groq_client import ask_security_assistant
from utils.validators import global_rate_limiter

ai_bp = Blueprint("ai", __name__)


@ai_bp.route("/ai-assistant")
@login_required
def ai_assistant():
    history = (
        ChatHistory.query.filter_by(user_id=current_user.id)
        .order_by(ChatHistory.created_at.asc())
        .limit(50)
        .all()
    )
    return render_template("ai_assistant.html", history=history)


@ai_bp.route("/api/chat", methods=["POST"])
@login_required
def chat_api():
    if not global_rate_limiter.allow(f"chat:{current_user.id}"):
        return jsonify({"success": False, "reply": "You're sending messages too quickly. Please wait a moment."}), 429

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"success": False, "reply": "Message cannot be empty."}), 400

    recent = (
        ChatHistory.query.filter_by(user_id=current_user.id)
        .order_by(ChatHistory.created_at.desc())
        .limit(10)
        .all()
    )
    history_payload = [{"role": c.role, "content": c.message} for c in reversed(recent)]

    result = ask_security_assistant(
        api_key=current_app.config["GROQ_API_KEY"],
        model=current_app.config["GROQ_MODEL"],
        user_message=message,
        history=history_payload,
    )

    db.session.add(ChatHistory(user_id=current_user.id, role="user", message=message))
    db.session.add(ChatHistory(user_id=current_user.id, role="assistant", message=result["reply"]))
    db.session.commit()

    return jsonify(result)
