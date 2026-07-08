"""
SentinelX - ML Model Training: Phishing / Suspicious URL Classifier
Trains a Gradient Boosting classifier on lexical URL features using a
programmatically generated dataset built from heuristic rules (URL length,
presence of IP address, suspicious keywords, hyphens, subdomain count, etc).

This is intentionally a lexical/structural classifier only -- it never fetches
or executes remote content, so it is safe to run and safe to use for
education. Run once during setup:

    python ml/train_phishing_model.py
"""

import os
import random
import re
import sys

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "bank", "confirm", "signin", "free", "bonus"]
LEGIT_DOMAINS = ["google.com", "github.com", "wikipedia.org", "microsoft.com", "amazon.com", "apple.com"]


def extract_url_features(url: str) -> list:
    length = len(url)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_digits = sum(c.isdigit() for c in url)
    has_ip = int(bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url)))
    has_at = int("@" in url)
    has_https = int(url.startswith("https://"))
    num_subdomains = max(0, url.split("//")[-1].split("/")[0].count(".") - 1)
    suspicious_word_count = sum(1 for w in SUSPICIOUS_WORDS if w in url.lower())
    url_len_ratio = length / 100.0
    return [length, num_dots, num_hyphens, num_digits, has_ip, has_at, has_https,
            num_subdomains, suspicious_word_count, url_len_ratio]


def generate_legit_url() -> str:
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(["", "/search", "/user/profile", "/docs", "/en/article", "/products/123"])
    return f"https://{domain}{path}"


def generate_phishing_url() -> str:
    base = random.choice(["paypa1", "secure-login", "verify-account", "bankofamerica-alert", "192.168.1.1",
                           "appleid-verify", "amaz0n-update", "signin-security"])
    tld = random.choice([".com", ".net", ".info", ".xyz", ".ru", ".top"])
    word = random.choice(SUSPICIOUS_WORDS)
    scheme = random.choice(["http://", "https://"])
    extra = random.choice(["", "-" + str(random.randint(1, 999))])
    return f"{scheme}{base}{extra}{tld}/{word}"


def build_dataset(n_samples: int = 4000):
    X, y = [], []
    for _ in range(n_samples):
        if random.random() < 0.5:
            url = generate_legit_url()
            label = "legitimate"
        else:
            url = generate_phishing_url()
            label = "phishing"
        X.append(extract_url_features(url))
        y.append(label)
    return np.array(X), np.array(y)


def main():
    print("Generating synthetic phishing-URL dataset...")
    X, y = build_dataset()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training GradientBoostingClassifier...")
    clf = GradientBoostingClassifier(n_estimators=150, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Test accuracy: {acc:.4f}")
    print(classification_report(y_test, preds))

    model_path = os.path.join(MODEL_DIR, "phishing_url_model.pkl")
    joblib.dump(clf, model_path)
    print(f"Saved model to {model_path}")


if __name__ == "__main__":
    main()
