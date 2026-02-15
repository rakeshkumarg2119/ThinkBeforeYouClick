import whois
import tldextract
import requests
import joblib
import os
import re
import threading
import ipaddress
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from database import (
    initialize_database, get_cached_result, store_analysis,
    get_training_data, get_record_count, get_class_distribution, update_labels
)

# Model paths
RISK_MODEL_PATH = "risk_model.pkl"
RISK_TYPE_MODEL_PATH = "risk_type_model.pkl"
ANOMALY_MODEL_PATH = "anomaly_model.pkl"

# Training thresholds
FIRST_TRAINING = 50
RETRAIN_INTERVAL = 100

model_lock = threading.Lock()

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def calculate_domain_score(domain):
    """Domain age from WHOIS"""
    score = 0
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                if age_days < 7:
                    score = 40
                elif age_days < 30:
                    score = 30
                elif age_days < 180:
                    score = 15
                elif age_days < 365:
                    score = 5
            else:
                score = 10
        else:
            score = 20
    except:
        score = 15
    return score

def calculate_url_score(url):
    """URL structure patterns"""
    score = 0
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        
        try:
            ipaddress.ip_address(netloc)
            score += 30
        except:
            pass
        
        if netloc.count("-") > 3:
            score += 10
        
        if len(url) > 75:
            score += 10
        
        if "@" in url:
            score += 20
        
        special_count = len(re.findall(r"[!#$%^&*(),?\":{}|<>]", url))
        if special_count > 3:
            score += 10
        
        digit_count = sum(c.isdigit() for c in url)
        if digit_count > 8:
            score += 15
        elif digit_count > 5:
            score += 10
        
        if "//" in parsed.path:
            score += 15
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            score += 15
    except:
        pass
    
    return score

def calculate_keyword_score(url):
    """Numeric keyword count (NOT rule-based classification)"""
    url_lower = url.lower()
    
    keywords = [
        'login', 'verify', 'bank', 'otp', 'account', 'update',
        'secure', 'signin', 'password', 'credential', 'suspend', 'confirm',
        'reward', 'bonus', 'urgent', 'free', 'prize', 'winner',
        'claim', 'limited', 'offer', 'click', 'betting', 'casino',
        'lottery', 'paypal', 'amazon', 'wallet', 'payment'
    ]
    
    count = sum(1 for word in keywords if word in url_lower)
    return min(count * 5, 50)

def calculate_security_score(url):
    """HTTPS check"""
    return 25 if not url.startswith("https") else 0

def calculate_redirect_score(url):
    """Redirect chain analysis"""
    try:
        response = requests.get(
            url, timeout=5, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'},
            verify=True
        )
        redirect_count = len(response.history)
        
        if redirect_count > 5:
            return 30
        elif redirect_count > 3:
            return 20
        elif redirect_count > 1:
            return 10
        return 0
    except requests.exceptions.SSLError:
        return 25
    except requests.exceptions.Timeout:
        return 15
    except:
        return 10

def extract_features(url):
    """Extract all features"""
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        
        features = {
            'domain': domain,
            'domain_score': calculate_domain_score(domain),
            'url_score': calculate_url_score(url),
            'keyword_score': calculate_keyword_score(url),
            'security_score': calculate_security_score(url),
            'redirect_score': calculate_redirect_score(url)
        }
        
        features['total_score'] = sum([
            features['domain_score'],
            features['url_score'],
            features['keyword_score'],
            features['security_score'],
            features['redirect_score']
        ])
        
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None

# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_models():
    """Train all three ML models"""
    print("\n" + "="*60)
    print("MODEL TRAINING INITIATED")
    print("="*60)
    
    X, y_risk, y_type = get_training_data()
    
    if X is None or len(X) < FIRST_TRAINING:
        print(f"❌ Insufficient data: {len(X) if X else 0}/{FIRST_TRAINING}")
        return False
    
    print(f"✓ Training samples: {len(X)}")
    
    X = np.array(X)
    y_risk = np.array(y_risk)
    
    # Train Risk Level Model
    print("\n[1/3] Training Risk Level Classifier...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_risk, test_size=0.2, random_state=42, stratify=y_risk
    )
    
    risk_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        random_state=42,
        class_weight='balanced'
    )
    risk_model.fit(X_train, y_train)
    
    y_pred = risk_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✓ Risk Level Accuracy: {accuracy:.2%}")
    
    # Train Risk Type Model
    print("\n[2/3] Training Risk Type Classifier...")
    
    # Filter out entries with valid type labels
    valid_indices = [i for i, t in enumerate(y_type) if t and t != 'Unknown']
    
    if len(valid_indices) >= 10:
        X_type = X[valid_indices]
        y_type_filtered = np.array([y_type[i] for i in valid_indices])
        
        # Check if we have at least 2 classes
        unique_types = np.unique(y_type_filtered)
        if len(unique_types) >= 2:
            X_train_t, X_test_t, y_train_t, y_test_t = train_test_split(
                X_type, y_type_filtered, test_size=0.2, random_state=42
            )
            
            risk_type_model = RandomForestClassifier(
                n_estimators=150,
                max_depth=8,
                min_samples_split=4,
                random_state=42
            )
            risk_type_model.fit(X_train_t, y_train_t)
            
            y_pred_t = risk_type_model.predict(X_test_t)
            accuracy_t = accuracy_score(y_test_t, y_pred_t)
            print(f"✓ Risk Type Accuracy: {accuracy_t:.2%}")
            print(f"✓ Risk Types: {list(unique_types)}")
        else:
            print("⚠ Only 1 risk type, skipping type model")
            risk_type_model = None
    else:
        print(f"⚠ Insufficient type labels ({len(valid_indices)}), skipping type model")
        risk_type_model = None
    
    # Train Anomaly Detector
    print("\n[3/3] Training Anomaly Detector...")
    anomaly_model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    anomaly_model.fit(X)
    print("✓ Anomaly model trained")
    
    # Save models
    with model_lock:
        joblib.dump(risk_model, RISK_MODEL_PATH)
        if risk_type_model:
            joblib.dump(risk_type_model, RISK_TYPE_MODEL_PATH)
        joblib.dump(anomaly_model, ANOMALY_MODEL_PATH)
    
    print(f"\n✓ Models saved")
    print("="*60 + "\n")
    
    return True

def load_models():
    """Load trained models"""
    with model_lock:
        risk_model = None
        risk_type_model = None
        anomaly_model = None
        
        if os.path.exists(RISK_MODEL_PATH):
            try:
                risk_model = joblib.load(RISK_MODEL_PATH)
            except:
                pass
        
        if os.path.exists(RISK_TYPE_MODEL_PATH):
            try:
                risk_type_model = joblib.load(RISK_TYPE_MODEL_PATH)
            except:
                pass
        
        if os.path.exists(ANOMALY_MODEL_PATH):
            try:
                anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
            except:
                pass
        
        return risk_model, risk_type_model, anomaly_model

def check_and_retrain():
    """Auto retrain logic"""
    count = get_record_count()
    
    if count >= FIRST_TRAINING and not os.path.exists(RISK_MODEL_PATH):
        print(f"\n⚡ AUTO-TRAIN: {count} samples available")
        return train_models()
    
    if count > 0 and count % RETRAIN_INTERVAL == 0:
        print(f"\n⚡ AUTO-RETRAIN: Reached {count} samples")
        return train_models()
    
    return False

def get_feature_importance_reason(features, risk_model):
    """Get top contributing feature for 'Why Risk' explanation"""
    if risk_model is None:
        scores = [
            ('domain_score', features['domain_score']),
            ('url_score', features['url_score']),
            ('keyword_score', features['keyword_score']),
            ('security_score', features['security_score']),
            ('redirect_score', features['redirect_score'])
        ]
        top_feature = max(scores, key=lambda x: x[1])
        
        reasons = {
            'domain_score': 'New or suspicious domain age',
            'url_score': 'Suspicious URL structure patterns',
            'keyword_score': 'High-risk keywords detected',
            'security_score': 'Missing HTTPS security',
            'redirect_score': 'Excessive redirect chains'
        }
        return reasons.get(top_feature[0], 'Multiple risk factors')
    else:
        feature_array = np.array([[
            features['domain_score'],
            features['url_score'],
            features['keyword_score'],
            features['security_score'],
            features['redirect_score']
        ]])
        
        importances = risk_model.feature_importances_
        feature_names = ['domain_score', 'url_score', 'keyword_score', 'security_score', 'redirect_score']
        feature_values = feature_array[0]
        
        weighted_scores = importances * feature_values
        top_idx = np.argmax(weighted_scores)
        
        reasons = {
            0: 'Domain age indicates risk',
            1: 'URL structure is suspicious',
            2: 'Risky keywords present',
            3: 'Security configuration weak',
            4: 'Redirect behavior suspicious'
        }
        return reasons.get(top_idx, 'Combined risk factors')

# ============================================================================
# MAIN ANALYZER WITH CACHE-FIRST LOGIC
# ============================================================================

def analyze_url(url):
    """
    CACHE-FIRST URL Analysis
    
    1. Check cache first
    2. If not found, extract features and predict
    3. Store result
    """
    
    print(f"\n{'='*60}")
    print(f"ANALYZING: {url}")
    print(f"{'='*60}")
    
    # STEP 1: Check cache
    cached = get_cached_result(url)
    if cached:
        print("✓ CACHE HIT - Returning stored result")
        cached['why_risk'] = 'Cached result'
        return cached
    
    print("✗ CACHE MISS - Performing fresh analysis")
    
    # STEP 2: Extract features
    print("⚙ Extracting features...")
    features = extract_features(url)
    if features is None:
        return {"error": "Feature extraction failed"}
    
    print(f"  Domain: {features['domain']}")
    print(f"  Domain Score: {features['domain_score']}")
    print(f"  URL Score: {features['url_score']}")
    print(f"  Keyword Score: {features['keyword_score']}")
    print(f"  Security Score: {features['security_score']}")
    print(f"  Redirect Score: {features['redirect_score']}")
    print(f"  Total Score: {features['total_score']}")
    
    # STEP 3: Load models
    risk_model, risk_type_model, anomaly_model = load_models()
    
    feature_array = np.array([[
        features['domain_score'],
        features['url_score'],
        features['keyword_score'],
        features['security_score'],
        features['redirect_score']
    ]])
    
    # Predict Risk Level
    if risk_model is None:
        print("⚠ No risk model - using fallback")
        if features['total_score'] > 80:
            risk_label = 1
            confidence = 70.0
        elif features['total_score'] > 50:
            risk_label = 1
            confidence = 55.0
        else:
            risk_label = 0
            confidence = 65.0
    else:
        print("✓ Using Risk Level ML model")
        risk_label = int(risk_model.predict(feature_array)[0])
        probabilities = risk_model.predict_proba(feature_array)[0]
        confidence = round(max(probabilities) * 100, 2)
    
    risk_level = 'High' if risk_label == 1 else 'Low'
    
    # Predict Risk Type
    if risk_type_model is None:
        print("⚠ No type model - returning Unknown")
        risk_type = 'Unknown'
    else:
        print("✓ Using Risk Type ML model")
        risk_type = risk_type_model.predict(feature_array)[0]
    
    # Anomaly Detection
    is_anomaly = False
    if anomaly_model is not None:
        anomaly_pred = anomaly_model.predict(feature_array)[0]
        is_anomaly = (anomaly_pred == -1)
        print(f"✓ Anomaly: {'YES' if is_anomaly else 'NO'}")
    
    # Risk Severity Index
    severity = (features['total_score'] * 0.6) + (confidence * 0.3) + (20 if is_anomaly else 0)
    severity = min(int(severity), 100)
    
    # Why Risk
    why_risk = get_feature_importance_reason(features, risk_model)
    
    # STEP 4: Store in database
    store_analysis(
        url, features['domain'], features,
        risk_label, risk_type, confidence, is_anomaly, severity
    )
    print("✓ Result stored in database")
    
    # STEP 5: Check retrain
    check_and_retrain()
    
    # Return result
    result = {
        'url': url,
        'domain': features['domain'],
        'domain_score': features['domain_score'],
        'url_score': features['url_score'],
        'keyword_score': features['keyword_score'],
        'security_score': features['security_score'],
        'redirect_score': features['redirect_score'],
        'total_score': features['total_score'],
        'risk_level': risk_level,
        'confidence_percent': confidence,
        'anomaly_detected': is_anomaly,
        'risk_severity_index': severity,
        'why_risk': why_risk,
        'risk_type': risk_type,
        'cached': False
    }
    
    return result

def display_result(result):
    """Display formatted result"""
    print("\n" + "="*60)
    print("ANALYSIS RESULT")
    print("="*60)
    
    if 'error' in result:
        print(f"ERROR: {result['error']}")
        return
    
    print(f"URL: {result['url']}")
    print(f"Domain: {result['domain']}")
    
    if result.get('cached'):
        print("\n⚡ SOURCE: CACHED (No WHOIS/HTTP checks performed)")
    
    print(f"\nFEATURE SCORES:")
    print(f"  Domain Score:    {result['domain_score']:3d}")
    print(f"  URL Score:       {result['url_score']:3d}")
    print(f"  Keyword Score:   {result['keyword_score']:3d}")
    print(f"  Security Score:  {result['security_score']:3d}")
    print(f"  Redirect Score:  {result['redirect_score']:3d}")
    print(f"  Total Score:     {result['total_score']:3d}")
    
    print(f"\nRISK ASSESSMENT:")
    print(f"  Risk Level:           {result['risk_level']}")
    print(f"  Confidence:           {result['confidence_percent']:.1f}%")
    print(f"  Anomaly Detected:     {result['anomaly_detected']}")
    print(f"  Risk Severity Index:  {result['risk_severity_index']}/100")
    print(f"  Why Risk:             {result['why_risk']}")
    print(f"  What Type of Risk:    {result['risk_type']}")
    
    print("="*60 + "\n")

def show_stats():
    """Display system statistics"""
    print("\n" + "="*60)
    print("SYSTEM STATISTICS")
    print("="*60)
    
    count = get_record_count()
    risk_dist, type_dist = get_class_distribution()
    
    print(f"\nDatabase:")
    print(f"  Total Records: {count}")
    print(f"  Low Risk:      {risk_dist.get(0, 0)}")
    print(f"  High Risk:     {risk_dist.get(1, 0)}")
    
    if type_dist:
        print(f"\nRisk Types:")
        for rtype, cnt in sorted(type_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rtype:20s}: {cnt}")
    
    risk_model, risk_type_model, anomaly_model = load_models()
    print(f"\nModels:")
    print(f"  Risk Level:    {'✓ Trained' if risk_model else '✗ Not trained'}")
    print(f"  Risk Type:     {'✓ Trained' if risk_type_model else '✗ Not trained'}")
    print(f"  Anomaly:       {'✓ Trained' if anomaly_model else '✗ Not trained'}")
    
    print(f"\nTraining Schedule:")
    print(f"  First training:    {FIRST_TRAINING} samples")
    print(f"  Retrain interval:  {RETRAIN_INTERVAL} samples")
    if not risk_model:
        print(f"  Next training in:  {max(0, FIRST_TRAINING - count)} samples")
    else:
        print(f"  Next retrain in:   {RETRAIN_INTERVAL - (count % RETRAIN_INTERVAL)} samples")
    
    print("="*60 + "\n")

# Initialize database
initialize_database()