"""
SentinelX - ML Model Training: Password Strength Classifier
Trains a RandomForest on programmatically generated password samples
(labelled by a rule-based ground truth), then saves the model + vectorizer
to ml/models/. Run this once during setup:

    python ml/train_password_model.py
"""

import os
import random
import string
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.security_tools import analyze_password_strength, COMMON_PASSWORDS  # noqa: E402

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def extract_features(password: str) -> list:
    length = len(password)
    has_upper = int(any(c.isupper() for c in password))
    has_lower = int(any(c.islower() for c in password))
    has_digit = int(any(c.isdigit() for c in password))
    has_symbol = int(any(c in string.punctuation for c in password))
    unique_ratio = len(set(password)) / max(1, length)
    is_common = int(password.lower() in COMMON_PASSWORDS)
    max_repeat = max((len(list(g)) for _, g in _group(password)), default=0)
    return [length, has_upper, has_lower, has_digit, has_symbol, unique_ratio, is_common, max_repeat]


def _group(s):
    import itertools
    return itertools.groupby(s)


def generate_password_sample() -> str:
    """Generate a random password-like string across a range of qualities."""
    style = random.choice(["weak", "medium", "strong", "common"])
    if style == "common":
        return random.choice(list(COMMON_PASSWORDS))
    if style == "weak":
        length = random.randint(4, 7)
        return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))
    if style == "medium":
        length = random.randint(8, 11)
        pool = string.ascii_letters + string.digits
        return "".join(random.choice(pool) for _ in range(length))
    length = random.randint(12, 20)
    pool = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(pool) for _ in range(length))


def build_dataset(n_samples: int = 6000):
    X, y = [], []
    for _ in range(n_samples):
        pwd = generate_password_sample()
        label = analyze_password_strength(pwd)["verdict"]
        X.append(extract_features(pwd))
        y.append(label)
    return np.array(X), np.array(y)


def main():
    print("Generating synthetic password dataset...")
    X, y = build_dataset()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Test accuracy: {acc:.4f}")
    print(classification_report(y_test, preds))

    model_path = os.path.join(MODEL_DIR, "password_strength_model.pkl")
    joblib.dump(clf, model_path)
    print(f"Saved model to {model_path}")


if __name__ == "__main__":
    main()
