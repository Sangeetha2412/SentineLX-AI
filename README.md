# 🛡️ SentinelX — AI-Powered Cybersecurity Intelligence Platform

A defensive-security education and dashboard platform built with Flask, scikit-learn, and the Groq API. Dark cyberpunk UI, real working security tools, two trained ML models, and an AI assistant that explains results in plain language.

**Strictly for defensive cybersecurity and educational use.** No feature in this codebase enables unauthorized access, malware creation, or attacks on third-party systems — the port scanner requires an explicit authorization confirmation before it will run.

---

## ✅ What's fully built and working right now

| Category | Modules |
|---|---|
| Auth | Register, Login, Logout, Sessions (Flask-Login, hashed passwords) |
| Dashboard | Stats, recent scans, recent reports |
| Password Tools | Strength Analyzer (rule + ML), Password Generator |
| Hashing | Hash Generator, Hash Checker, File Hash Calculator (MD5/SHA1/SHA256/SHA512) |
| Encoding | Base64 Encoder/Decoder |
| Recon | WHOIS Lookup, DNS Lookup, IP Lookup (geo/ASN) |
| Web Security | SSL Certificate Checker, Security Headers Checker, HTTP Header Viewer, Robots.txt Viewer |
| AI/ML | URL Reputation Checker (Gradient Boosting), Password Strength ML model (Random Forest), AI Security Assistant (Groq) |
| Offensive-adjacent (defensive-use only) | Port Scanner — gated behind an explicit "I'm authorized" checkbox |
| Reporting | PDF report generation (ReportLab), report history & download |
| Account | Profile, Settings, Admin Dashboard (user management, activity log, role toggling) |

Every one of these executes real logic — nothing above is a placeholder or mocked response.

## 🚧 Not yet built (honest roadmap, see "Coming Soon" pages in the app)

- Email Header Analyzer
- Subdomain Discovery
- Log Analyzer / uploaded-file AI analysis
- 2FA (schema field exists, flow not implemented)
- Chart.js/Plotly dashboards (data is there; visual charts are the next layer to add)

These are stubbed with an honest "on the roadmap" page rather than fake output, so you always know what's real.

---

## 📁 Folder Structure

```
sentinelx/
├── app.py                       # Flask app factory & entrypoint
├── config.py                    # Env-based configuration
├── requirements.txt
├── .env.example                 # Copy to .env and fill in
├── .gitignore
│
├── database/
│   ├── __init__.py
│   └── models.py                 # User, Report, ChatHistory, ScanHistory, Settings, ActivityLog
│
├── routes/                       # Flask Blueprints (MVC "controllers")
│   ├── auth.py                   # register/login/logout
│   ├── dashboard.py              # dashboard + landing page
│   ├── tools.py                  # all security tool endpoints
│   ├── ai_routes.py              # AI chat page + /api/chat
│   ├── reports_routes.py         # PDF report generate/list/download
│   └── profile_routes.py         # profile, settings, admin
│
├── utils/
│   ├── security_tools.py         # core tool logic (password, hash, whois, dns, ssl, headers, ports…)
│   └── validators.py             # input validation + in-memory rate limiter
│
├── ai/
│   └── groq_client.py            # Groq API wrapper with a defensive-security system prompt
│
├── ml/
│   ├── train_password_model.py   # trains RandomForest password-strength classifier
│   ├── train_phishing_model.py   # trains GradientBoosting URL/phishing classifier
│   ├── predict.py                # inference helpers used by routes
│   └── models/                   # saved .pkl models (pre-trained and included)
│
├── reports/
│   └── report_generator.py       # ReportLab PDF builder
│
├── templates/                    # Jinja2 templates (dark cyberpunk theme)
│   ├── base.html                 # sidebar shell, nav, flash messages
│   ├── landing.html, login.html, register.html
│   ├── dashboard.html, ai_assistant.html, reports.html
│   ├── profile.html, settings.html, admin.html
│   ├── errors/403.html, 404.html, 500.html
│   └── tools/                    # one template per tool
│
├── static/
│   ├── css/style.css              # full design system (CSS variables, glassmorphism, etc.)
│   ├── js/particles.js            # canvas particle network + cursor glow background
│   └── js/main.js                 # GSAP animations, chat, copy buttons, progress bars
│
└── instance/                      # created at runtime: sentinelx.db, uploads/, reports/
```

---

## 🚀 Setup — Step by Step

### 1. Extract the zip and open a terminal in the `sentinelx/` folder

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
cp .env.example .env
```
Open `.env` and:
- Set `SECRET_KEY` to any long random string.
- Get a **free** Groq API key at https://console.groq.com/keys and set `GROQ_API_KEY` (the AI Assistant won't respond without this — every other tool works fine without it).

### 5. Train the ML models (takes under a minute, models are also already included pre-trained in the zip)
```bash
python ml/train_password_model.py
python ml/train_phishing_model.py
```

### 6. Run the app
```bash
python app.py
```
Visit **http://localhost:5000** — the database and folders are created automatically on first run.

### 7. Create your account
Register a normal account at `/register`. To make yourself an admin, open a Python shell:
```bash
python -c "
from app import create_app
from database.models import db, User
app = create_app()
with app.app_context():
    u = User.query.filter_by(username='YOUR_USERNAME').first()
    u.role = 'admin'
    db.session.commit()
    print('done')
"
```

---

## 🌐 Deploying to Render (free tier)

1. Push this project to a GitHub repo (`.env` is gitignored — never commit real secrets).
2. On Render: **New → Web Service** → connect your repo.
3. Build command: `pip install -r requirements.txt && python ml/train_password_model.py && python ml/train_phishing_model.py`
4. Start command: `gunicorn app:create_app()` — add `gunicorn` to requirements.txt first (`pip install gunicorn` then add to the file), or simply `python app.py` for a quick test deploy.
5. Add environment variables in Render's dashboard: `SECRET_KEY`, `GROQ_API_KEY`, `GROQ_MODEL`, `FLASK_ENV=production`.
6. SQLite works for a demo/portfolio deploy, but Render's free disk is ephemeral — for anything persistent, swap `DATABASE_URL` to a Render PostgreSQL instance (SQLAlchemy makes this a one-line change).

---

## 🧠 How the ML models work

- **Password Strength Model** (`ml/train_password_model.py`): generates thousands of synthetic passwords across weak/medium/strong/common tiers, labels them using the rule-based analyzer as ground truth, extracts 8 numeric features (length, character-class flags, unique-char ratio, common-password flag, max repeat run), and trains a Random Forest.
- **Phishing URL Model** (`ml/train_phishing_model.py`): generates synthetic legitimate vs. phishing-style URLs (IP-based hosts, suspicious keywords, hyphenated brand-impersonation domains, etc.), extracts 10 lexical/structural features, and trains a Gradient Boosting classifier. **It never fetches the URL's actual content** — purely structural, so it's safe to run against arbitrary input.

Both are trained on synthetic data for a self-contained, no-external-dataset build. For production-grade accuracy, retrain on a real labelled dataset (e.g. PhishTank exports, HaveIBeenPwned password lists) by swapping out `build_dataset()` in each script.

---

## 🔒 Security measures already in place

- Passwords hashed with Werkzeug's `generate_password_hash` (never stored in plaintext)
- Flask-Login session management, `HttpOnly` + `SameSite=Lax` cookies
- Input sanitization on all recon-tool targets (`utils/validators.sanitize_target`)
- In-memory sliding-window rate limiter on WHOIS/port-scan/AI-chat endpoints
- Port Scanner requires an explicit authorization checkbox before it will run
- AI Assistant has a scoped system prompt + keyword-based refusal for attack-enabling requests
- SQLAlchemy ORM (parameterized queries — no raw SQL string interpolation, so no SQL injection surface)
- File upload size capped at 10MB
- `.env` gitignored by default

For a production deployment, also add: Flask-WTF CSRF tokens on all forms, HTTPS-only cookies (`SESSION_COOKIE_SECURE=True`), and a persistent rate limiter (Flask-Limiter + Redis) instead of the in-memory one.

---

## 🗺️ Suggested build order if you want to keep extending it

1. Wire up Chart.js on the dashboard for real charts (risk-over-time, tool-usage breakdown) — the data already exists in `ScanHistory`.
2. Build the Email Header Analyzer (parse `Received:`/`SPF`/`DKIM`/`DMARC` headers from pasted raw email source).
3. Build Subdomain Discovery (wordlist + DNS resolution against a target domain — reuse `utils/security_tools.dns_lookup`).
4. Add CSRF protection via Flask-WTF to every POST form.
5. Add 2FA (TOTP via `pyotp`) — the `Settings.two_factor_enabled` field is already in the schema.
6. Swap SQLite → PostgreSQL for the Render production deploy.

---

## 📜 License / Ethical Use

This project is for educational and authorized-defensive-security purposes only. Do not point the Port Scanner, Subdomain Discovery, or any recon tool at a system you do not own or have explicit written authorization to test.
