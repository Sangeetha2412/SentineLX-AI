"""
SentinelX - Security Utility Functions
Real, working implementations for the core defensive-security tools.
No placeholders: every function here executes genuine logic.
"""

import re
import math
import base64
import hashlib
import secrets
import socket
import ssl
import string
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests
import validators
import whois as whois_lib


# ----------------------------------------------------------------------------
# Password Strength Analyzer
# ----------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "login", "iloveyou", "starwars", "dragon", "sunshine",
    "princess", "football", "passw0rd", "password1", "trustno1",
}


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def analyze_password_strength(password: str) -> dict:
    """
    Rule-based + entropy-based password strength analysis.
    Returns a dict with score (0-100), verdict, entropy, and specific feedback.
    """
    if not password:
        return {"score": 0, "verdict": "Empty", "entropy": 0, "feedback": ["Password is empty."]}

    feedback = []
    score = 0

    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
    else:
        feedback.append("Use at least 12 characters (16+ is ideal).")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    if not has_upper:
        feedback.append("Add uppercase letters.")
    if not has_lower:
        feedback.append("Add lowercase letters.")
    if not has_digit:
        feedback.append("Add numbers.")
    if not has_symbol:
        feedback.append("Add special characters (e.g. ! @ # $ %).")

    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)
        feedback.append("This is one of the most commonly leaked passwords in the world.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()):
        score -= 10
        feedback.append("Avoid sequential characters like '1234' or 'abcd'.")

    entropy = calculate_entropy(password)
    score = max(0, min(100, score))

    if score >= 80:
        verdict = "Very Strong"
    elif score >= 60:
        verdict = "Strong"
    elif score >= 40:
        verdict = "Moderate"
    elif score >= 20:
        verdict = "Weak"
    else:
        verdict = "Very Weak"

    if not feedback:
        feedback.append("No major weaknesses detected.")

    return {
        "score": score,
        "verdict": verdict,
        "entropy": entropy,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "feedback": feedback,
    }


def generate_password(length: int = 16, use_upper=True, use_digits=True, use_symbols=True) -> str:
    """Cryptographically secure password generator."""
    length = max(6, min(128, length))
    pool = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        pool += "!@#$%^&*()-_=+[]{}?"
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}?"))

    remaining = [secrets.choice(pool) for _ in range(length - len(required))]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ----------------------------------------------------------------------------
# Hashing tools
# ----------------------------------------------------------------------------

def generate_hashes(text: str) -> dict:
    """Generate MD5, SHA1, SHA256, SHA512 for a given text (utf-8)."""
    data = text.encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def hash_file(file_stream, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Compute a hash for a file-like stream without loading it all into memory."""
    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    hasher = algo_map.get(algorithm, hashlib.sha256)()
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def check_hash_match(text: str, provided_hash: str) -> dict:
    """Check which algorithm (if any) a provided hash matches for given text."""
    computed = generate_hashes(text)
    provided_hash = provided_hash.strip().lower()
    matches = [algo for algo, value in computed.items() if value == provided_hash]
    return {"computed": computed, "provided": provided_hash, "matches": matches, "is_match": bool(matches)}


# ----------------------------------------------------------------------------
# Base64
# ----------------------------------------------------------------------------

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def base64_decode(text: str) -> dict:
    try:
        decoded = base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace")
        return {"success": True, "result": decoded}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ----------------------------------------------------------------------------
# WHOIS / DNS / IP lookups
# ----------------------------------------------------------------------------

def whois_lookup(domain: str) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        w = whois_lib.whois(domain)
        return {
            "success": True,
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
        }
    except Exception as exc:
        return {"success": False, "domain": domain, "error": str(exc)}


def dns_lookup(domain: str) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 4

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            results[rtype] = []

    return {"domain": domain, "records": results}


def ip_lookup(ip_or_domain: str) -> dict:
    """Resolve a hostname to IP and fetch basic geo/ASN info via ip-api.com (public, no key)."""
    target = ip_or_domain.strip()
    try:
        # Resolve to IP if a hostname was given
        try:
            socket.inet_aton(target)
            ip = target
        except OSError:
            ip = socket.gethostbyname(target)

        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "success": True,
                "ip": ip,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
            }
        return {"success": False, "ip": ip, "error": data.get("message", "Lookup failed")}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ----------------------------------------------------------------------------
# SSL Certificate Checker
# ----------------------------------------------------------------------------

def check_ssl_certificate(hostname: str, port: int = 443) -> dict:
    hostname = hostname.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "success": True,
            "hostname": hostname,
            "issuer": issuer.get("organizationName", str(issuer)),
            "subject": subject.get("commonName", str(subject)),
            "valid_from": str(not_before),
            "valid_until": str(not_after),
            "days_remaining": days_remaining,
            "is_expired": days_remaining < 0,
            "is_expiring_soon": 0 <= days_remaining <= 30,
        }
    except Exception as exc:
        return {"success": False, "hostname": hostname, "error": str(exc)}


# ----------------------------------------------------------------------------
# Security Headers Checker
# ----------------------------------------------------------------------------

IMPORTANT_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def check_security_headers(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = requests.get(url, timeout=6, allow_redirects=True)
        headers = resp.headers
        present, missing = {}, []
        for h in IMPORTANT_HEADERS:
            if h in headers:
                present[h] = headers[h]
            else:
                missing.append(h)

        score = round((len(present) / len(IMPORTANT_HEADERS)) * 100)
        return {
            "success": True,
            "url": url,
            "status_code": resp.status_code,
            "present_headers": present,
            "missing_headers": missing,
            "score": score,
            "server": headers.get("Server", "Unknown"),
        }
    except Exception as exc:
        return {"success": False, "url": url, "error": str(exc)}


# ----------------------------------------------------------------------------
# Port Scanner (AUTHORIZED TARGETS ONLY - user must confirm ownership/authorization)
# ----------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
}


def scan_ports(host: str, ports: list = None, timeout: float = 0.6) -> dict:
    """
    Simple TCP-connect scan of common ports. Intended ONLY for hosts the user
    owns or is explicitly authorized to test. The route calling this enforces
    an explicit authorization checkbox before invoking this function.
    """
    host = host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    ports = ports or list(COMMON_PORTS.keys())
    open_ports = []

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"success": False, "error": f"Could not resolve host: {exc}"}

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "Unknown")})
        sock.close()

    return {"success": True, "host": host, "ip": ip, "open_ports": open_ports, "scanned_count": len(ports)}


# ----------------------------------------------------------------------------
# URL / Robots.txt helpers
# ----------------------------------------------------------------------------

def get_http_headers(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = requests.get(url, timeout=6)
        return {"success": True, "url": url, "status_code": resp.status_code, "headers": dict(resp.headers)}
    except Exception as exc:
        return {"success": False, "url": url, "error": str(exc)}


def get_robots_txt(domain: str) -> dict:
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    url = f"https://{domain}/robots.txt"
    try:
        resp = requests.get(url, timeout=6)
        if resp.status_code == 200:
            return {"success": True, "url": url, "content": resp.text[:5000]}
        return {"success": False, "url": url, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"success": False, "url": url, "error": str(exc)}


def is_valid_url(url: str) -> bool:
    return bool(validators.url(url)) or bool(validators.domain(url))
