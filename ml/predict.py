"""
SentinelX - ML Inference Helpers
Loads trained models (if present) and exposes simple predict functions used
by the Flask routes. Falls back gracefully with a clear message if a model
hasn't been trained yet (see README: "Training the ML models").
"""

import os
import joblib

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

_password_model = None
_phishing_model = None


def _load(name):
    path = os.path.join(MODEL_DIR, name)
    if os.path.exists(path):
        return joblib.load(path)
    return None


def get_password_model():
    global _password_model
    if _password_model is None:
        _password_model = _load("password_strength_model.pkl")
    return _password_model


def get_phishing_model():
    global _phishing_model
    if _phishing_model is None:
        _phishing_model = _load("phishing_url_model.pkl")
    return _phishing_model


def predict_password_strength_ml(password: str):
    from ml.train_password_model import extract_features

    model = get_password_model()
    if model is None:
        return {"available": False, "message": "Model not trained yet. Run: python ml/train_password_model.py"}
    features = [extract_features(password)]
    prediction = model.predict(features)[0]
    proba = model.predict_proba(features)[0]
    confidence = round(float(max(proba)) * 100, 1)
    return {"available": True, "prediction": prediction, "confidence": confidence}


def predict_url_phishing_ml(url: str):
    from ml.train_phishing_model import extract_url_features

    model = get_phishing_model()
    if model is None:
        return {"available": False, "message": "Model not trained yet. Run: python ml/train_phishing_model.py"}
    features = [extract_url_features(url)]
    prediction = model.predict(features)[0]
    proba = model.predict_proba(features)[0]
    confidence = round(float(max(proba)) * 100, 1)
    return {"available": True, "prediction": prediction, "confidence": confidence}
