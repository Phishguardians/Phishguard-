# train/train_qr_model.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse
import math
import re
import tldextract

# ---------------- Feature extraction ----------------
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
    # basic validation: must have a dot in netloc
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        return 1 if '.' in parsed.netloc else 0
    except:
        return 0

def extract_features(url):
    if not url:
        return np.zeros(10)
    if not url.lower().startswith('http'):
        url_norm = 'http://' + url
    else:
        url_norm = url
    feats = {}
    feats['url_length'] = url_length(url_norm)
    feats['count_dots'] = count_dots(url_norm)
    feats['has_ip'] = int(has_ip(url_norm))
    feats['count_at'] = count_at(url_norm)
    feats['count_hyphen'] = count_hyphen(url_norm)
    feats['has_https'] = has_https(url_norm)
    feats['suspicious_tld'] = suspicious_tld(url_norm)
    feats['num_subdirs'] = num_subdirs(url_norm)
    feats['entropy'] = char_entropy(url_norm)
    feats['is_valid'] = is_valid_url(url_norm)
    # Keep consistent feature order
    return np.array([feats[k] for k in sorted(feats.keys())], dtype=float)

# ---------------- Training script ----------------
def train(csv_path, model_out, scaler_out):
    df = pd.read_csv(csv_path)
    X = []
    for url in df['qr_content'].astype(str).tolist():
        X.append(extract_features(url))
    X = np.vstack(X)
    y = df['label'].values

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(Xs, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    acc = clf.score(X_test, y_test)
    print("Test accuracy:", acc)

    os.makedirs(os.path.dirname(model_out), exist_ok=True)
    joblib.dump(clf, model_out)
    joblib.dump(scaler, scaler_out)
    print(f"Saved model to {model_out} and scaler to {scaler_out}")

if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(__file__))
    csv_path = os.path.join(root, "datasets", "qr_codes.csv")
    model_out = os.path.join(root, "app", "models", "qr_model.pkl")
    scaler_out = os.path.join(root, "app", "models", "scaler.pkl")
    train(csv_path, model_out, scaler_out)
