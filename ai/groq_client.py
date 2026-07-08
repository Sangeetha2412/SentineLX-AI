"""
SentinelX - AI Security Assistant (Groq API wrapper)
Keeps the assistant scoped to defensive cybersecurity education and refuses
to help with attacks, malware, or unauthorized access - enforced both by
system prompt and a lightweight keyword safety check.
"""

import os
from groq import Groq

SYSTEM_PROMPT = """You are the SentinelX AI Security Assistant, built into a defensive
cybersecurity education platform. Your job:
- Explain vulnerabilities, CVEs, and security concepts clearly and accurately.
- Help users interpret their OWN scan results, hashes, headers, and logs from this platform.
- Teach best practices: password hygiene, patching, network hardening, secure coding.
- Never provide step-by-step instructions for attacking, exploiting, or gaining unauthorized
  access to systems the user does not own or have explicit written authorization to test.
- Never write malware, exploit code, phishing content, or credential-harvesting tools.
- If a request is ambiguous, assume good faith but keep the answer at a conceptual/defensive
  level rather than an operational attack level.
- Be precise and avoid making up facts (no hallucinated CVE numbers, no invented statistics).
- Keep answers concise, structured, and practical for a student/practitioner audience.
"""

BLOCKED_KEYWORDS = [
    "write malware", "ransomware code", "keylogger code", "ddos script",
    "how to hack into", "bypass login without permission", "crack this password for me",
    "exploit for cve", "reverse shell payload for", "steal credentials from",
]


def _looks_malicious(message: str) -> bool:
    lowered = message.lower()
    return any(kw in lowered for kw in BLOCKED_KEYWORDS)


def get_client(api_key: str) -> Groq:
    return Groq(api_key=api_key)


def ask_security_assistant(api_key: str, model: str, user_message: str, history: list = None) -> dict:
    """
    Sends a message to Groq's chat completion API with a defensive-security
    system prompt. `history` is a list of {"role": "user"/"assistant", "content": str}.
    """
    if not api_key:
        return {
            "success": False,
            "reply": "AI Assistant is not configured. Add GROQ_API_KEY to your .env file "
                     "(get a free key at https://console.groq.com/keys).",
        }

    if _looks_malicious(user_message):
        return {
            "success": True,
            "reply": "I can't help with that request because it describes attacking or "
                     "accessing a system without authorization. I'm happy to explain the "
                     "underlying vulnerability class conceptually, or help you understand "
                     "how to defend against it instead.",
        }

    try:
        client = get_client(api_key)
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if history:
            messages.extend(history[-10:])  # keep last 10 turns for context
        messages.append({"role": "user", "content": user_message})

        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.3,
            max_tokens=800,
        )
        reply = completion.choices[0].message.content
        return {"success": True, "reply": reply}
    except Exception as exc:
        return {"success": False, "reply": f"AI request failed: {exc}"}
