# app/utils/qr_utils.py
import io
import cv2
import joblib
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import urlparse
import math
import re
import tldextract

# ---------------- Load model and scaler ----------------
MODEL_PATH = "app/models/qr_model.pkl"
SCALER_PATH = "app/models/scaler.pkl"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# ---------------- Feature extraction helpers ----------------
def has_ip(url):
    try:
        netloc = urlparse(url).netloc
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc))
    except:
        return False

def count_dots(url):
    return url.count('.')

def url_length(url):
    return len(url)

def count_at(url):
    return url.count('@')

def count_hyphen(url):
    return url.count('-')

def has_https(url):
    return 1 if url.lower().startswith("https://") else 0

def suspicious_tld(url):
    ext = tldextract.extract(url)
    tld = ext.suffix
    suspicious = ['xyz','top','club','gdn','loan','info','biz','ru']
    return 1 if tld in suspicious else 0

def num_subdirs(url):
    path = urlparse(url).path
    return len([p for p in path.split('/') if p])

def char_entropy(url):
    if not url:
        return 0.0
    probs = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum([p * math.log2(p) for p in probs])

def is_valid_url(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        return 1 if '.' in parsed.netloc else 0
    except:
        return 0

def extract_features(url):
    feats = {}
    feats['url_length'] = url_length(url)
    feats['count_dots'] = count_dots(url)
    feats['has_ip'] = int(has_ip(url))
    feats['count_at'] = count_at(url)
    feats['count_hyphen'] = count_hyphen(url)
    feats['has_https'] = has_https(url)
    feats['suspicious_tld'] = suspicious_tld(url)
    feats['num_subdirs'] = num_subdirs(url)
    feats['entropy'] = char_entropy(url)
    feats['is_valid'] = is_valid_url(url)
    return np.array([feats[k] for k in sorted(feats.keys())], dtype=float)

# ---------------- QR decoding & prediction ----------------
def decode_qr(image_bytes: bytes):
    """Extracts QR code content (e.g., URL) from uploaded image bytes"""
    try:
        # Ensure image is in RGB format
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        image_cv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        decoded_objects = decode(image_cv)
        if not decoded_objects:
            return None
        qr_data = decoded_objects[0].data.decode("utf-8")
        return qr_data
    except Exception as e:
        raise ValueError(f"Failed to decode QR: {e}")

def predict_qr(image_bytes: bytes):
    """Predicts whether QR code is phishing or legit"""
    qr_content = decode_qr(image_bytes)
    if not qr_content:
        return {"error": "No QR code detected"}

    features = extract_features(qr_content).reshape(1, -1)
    scaled = scaler.transform(features)
    prediction = model.predict(scaled)[0]
    probability = model.predict_proba(scaled)[0][prediction]

    result = {
        "qr_content": qr_content,
        "prediction": "Legit" if prediction == 1 else "Phishing",
        "confidence": round(float(probability), 3)
    }
    return result
