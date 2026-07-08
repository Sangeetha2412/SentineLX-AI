"""
SentinelX - Security Tools Routes
Each tool records a ScanHistory row so it shows up on the dashboard.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from database.models import db, ScanHistory
from utils import security_tools as sec
from utils.validators import sanitize_target, global_rate_limiter
from ml.predict import predict_password_strength_ml, predict_url_phishing_ml

tools_bp = Blueprint("tools", __name__)


def _record_scan(tool_name, target, summary, risk_score=0.0):
    scan = ScanHistory(
        user_id=current_user.id,
        tool_name=tool_name,
        target=target,
        result_summary=summary,
        risk_score=risk_score,
    )
    db.session.add(scan)
    db.session.commit()


def _rate_limited():
    return not global_rate_limiter.allow(f"user:{current_user.id}")


# ----------------------------------------------------------------------------
# Password Strength Analyzer
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/password-strength", methods=["GET", "POST"])
@login_required
def password_strength():
    result = None
    ml_result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        result = sec.analyze_password_strength(password)
        ml_result = predict_password_strength_ml(password)
        _record_scan("Password Strength Analyzer", "•" * min(len(password), 20),
                     f"Verdict: {result['verdict']} (score {result['score']}/100)",
                     risk_score=100 - result["score"])
    return render_template("tools/password_strength.html", result=result, ml_result=ml_result)


# ----------------------------------------------------------------------------
# Password Generator
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/password-generator", methods=["GET", "POST"])
@login_required
def password_generator():
    generated = None
    if request.method == "POST":
        length = int(request.form.get("length", 16))
        use_upper = request.form.get("use_upper") == "on"
        use_digits = request.form.get("use_digits") == "on"
        use_symbols = request.form.get("use_symbols") == "on"
        generated = sec.generate_password(length, use_upper, use_digits, use_symbols)
        _record_scan("Password Generator", "-", f"Generated a {length}-char password", risk_score=0)
    return render_template("tools/password_generator.html", generated=generated)


# ----------------------------------------------------------------------------
# Hash Generator / Checker / File Hash
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/hash-generator", methods=["GET", "POST"])
@login_required
def hash_generator():
    hashes = None
    if request.method == "POST":
        text = request.form.get("text", "")
        hashes = sec.generate_hashes(text)
        _record_scan("Hash Generator", text[:40], "Generated MD5/SHA1/SHA256/SHA512")
    return render_template("tools/hash_generator.html", hashes=hashes)


@tools_bp.route("/tools/hash-checker", methods=["GET", "POST"])
@login_required
def hash_checker():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        provided_hash = request.form.get("provided_hash", "")
        result = sec.check_hash_match(text, provided_hash)
        _record_scan("Hash Checker", provided_hash[:40],
                     f"Match: {result['is_match']} ({', '.join(result['matches']) or 'none'})")
    return render_template("tools/hash_checker.html", result=result)


@tools_bp.route("/tools/file-hash", methods=["GET", "POST"])
@login_required
def file_hash():
    result = None
    if request.method == "POST":
        uploaded = request.files.get("file")
        algorithm = request.form.get("algorithm", "sha256")
        if uploaded and uploaded.filename:
            digest = sec.hash_file(uploaded.stream, algorithm)
            result = {"filename": uploaded.filename, "algorithm": algorithm, "hash": digest}
            _record_scan("File Hash Calculator", uploaded.filename, f"{algorithm.upper()}: {digest}")
    return render_template("tools/file_hash.html", result=result)


# ----------------------------------------------------------------------------
# Base64
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/base64", methods=["GET", "POST"])
@login_required
def base64_tool():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        mode = request.form.get("mode", "encode")
        if mode == "encode":
            result = {"mode": "encode", "output": sec.base64_encode(text)}
        else:
            decoded = sec.base64_decode(text)
            result = {"mode": "decode", "output": decoded.get("result"), "error": decoded.get("error")}
    return render_template("tools/base64_tool.html", result=result)


# ----------------------------------------------------------------------------
# WHOIS / DNS / IP Lookup
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/whois", methods=["GET", "POST"])
@login_required
def whois_tool():
    result = None
    if request.method == "POST":
        if _rate_limited():
            return render_template("tools/whois.html", result={"success": False, "error": "Rate limit exceeded, try again shortly."})
        domain = sanitize_target(request.form.get("domain", ""))
        result = sec.whois_lookup(domain)
        _record_scan("WHOIS Lookup", domain, "Success" if result.get("success") else result.get("error", ""))
    return render_template("tools/whois.html", result=result)


@tools_bp.route("/tools/dns", methods=["GET", "POST"])
@login_required
def dns_tool():
    result = None
    if request.method == "POST":
        domain = sanitize_target(request.form.get("domain", ""))
        result = sec.dns_lookup(domain)
        _record_scan("DNS Lookup", domain, f"Resolved {sum(len(v) for v in result['records'].values())} records")
    return render_template("tools/dns.html", result=result)


@tools_bp.route("/tools/ip-lookup", methods=["GET", "POST"])
@login_required
def ip_lookup_tool():
    result = None
    if request.method == "POST":
        target = sanitize_target(request.form.get("target", ""))
        result = sec.ip_lookup(target)
        _record_scan("IP Lookup", target, "Success" if result.get("success") else result.get("error", ""))
    return render_template("tools/ip_lookup.html", result=result)


# ----------------------------------------------------------------------------
# SSL Certificate Checker
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/ssl-checker", methods=["GET", "POST"])
@login_required
def ssl_checker():
    result = None
    if request.method == "POST":
        hostname = sanitize_target(request.form.get("hostname", ""))
        result = sec.check_ssl_certificate(hostname)
        risk = 0
        if result.get("success"):
            risk = 80 if result["is_expired"] else (40 if result["is_expiring_soon"] else 5)
        _record_scan("SSL Certificate Checker", hostname,
                     "Success" if result.get("success") else result.get("error", ""), risk_score=risk)
    return render_template("tools/ssl_checker.html", result=result)


# ----------------------------------------------------------------------------
# Security Headers Checker
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/security-headers", methods=["GET", "POST"])
@login_required
def security_headers():
    result = None
    if request.method == "POST":
        url = sanitize_target(request.form.get("url", ""))
        result = sec.check_security_headers(url)
        risk = 100 - result.get("score", 0) if result.get("success") else 0
        _record_scan("Security Headers Checker", url,
                     f"Score {result.get('score')}/100" if result.get("success") else result.get("error", ""),
                     risk_score=risk)
    return render_template("tools/security_headers.html", result=result)


# ----------------------------------------------------------------------------
# URL Reputation Checker (ML-based, lexical only)
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/url-reputation", methods=["GET", "POST"])
@login_required
def url_reputation():
    result = None
    if request.method == "POST":
        url = sanitize_target(request.form.get("url", ""))
        result = predict_url_phishing_ml(url)
        result["url"] = url
        risk = result.get("confidence", 0) if result.get("prediction") == "phishing" else (100 - result.get("confidence", 100))
        _record_scan("URL Reputation Checker", url,
                     result.get("prediction", result.get("message", "")), risk_score=risk)
    return render_template("tools/url_reputation.html", result=result)


# ----------------------------------------------------------------------------
# HTTP Header Viewer / Robots.txt Viewer
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/http-headers", methods=["GET", "POST"])
@login_required
def http_headers():
    result = None
    if request.method == "POST":
        url = sanitize_target(request.form.get("url", ""))
        result = sec.get_http_headers(url)
        _record_scan("HTTP Header Viewer", url, "Success" if result.get("success") else result.get("error", ""))
    return render_template("tools/http_headers.html", result=result)


@tools_bp.route("/tools/robots-txt", methods=["GET", "POST"])
@login_required
def robots_txt():
    result = None
    if request.method == "POST":
        domain = sanitize_target(request.form.get("domain", ""))
        result = sec.get_robots_txt(domain)
        _record_scan("Robots.txt Viewer", domain, "Found" if result.get("success") else result.get("error", ""))
    return render_template("tools/robots_txt.html", result=result)


# ----------------------------------------------------------------------------
# Port Scanner (authorized targets only - explicit checkbox required)
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/port-scanner", methods=["GET", "POST"])
@login_required
def port_scanner():
    result = None
    error = None
    if request.method == "POST":
        authorized = request.form.get("authorized") == "on"
        host = sanitize_target(request.form.get("host", ""))
        if not authorized:
            error = "You must confirm you own this system or have explicit written authorization to scan it."
        elif _rate_limited():
            error = "Rate limit exceeded, try again shortly."
        else:
            result = sec.scan_ports(host)
            risk = min(100, len(result.get("open_ports", [])) * 15) if result.get("success") else 0
            _record_scan("Port Scanner", host,
                         f"{len(result.get('open_ports', []))} open ports" if result.get("success") else result.get("error", ""),
                         risk_score=risk)
    return render_template("tools/port_scanner.html", result=result, error=error)


# ----------------------------------------------------------------------------
# Coming soon: Email Header Analyzer, Subdomain Discovery
# (Kept as honest "planned" pages rather than fake output - see README roadmap)
# ----------------------------------------------------------------------------

@tools_bp.route("/tools/email-header-analyzer")
@login_required
def email_header_analyzer():
    return render_template("tools/coming_soon.html", tool_name="Email Header Analyzer")


@tools_bp.route("/tools/subdomain-discovery")
@login_required
def subdomain_discovery():
    return render_template("tools/coming_soon.html", tool_name="Subdomain Discovery")
