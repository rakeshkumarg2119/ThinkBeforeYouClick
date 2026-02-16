"""
Core URL Risk Analysis Engine v3.0
- Piracy detection
- Safe site recognition
- Gambling/Betting detection with financial risk warnings
- Dynamic TLD reputation checking
"""
import os
import re
import joblib
import numpy as np
import requests
import warnings
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from urllib.parse import urlparse
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split

warnings.filterwarnings('ignore')

# Import database
from database import (
    initialize_database, get_cached_result, store_analysis,
    get_training_data, get_record_count, get_class_distribution
)

# Configuration
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

RISK_MODEL_PATH = MODEL_DIR / "risk_model.pkl"
RISK_TYPE_MODEL_PATH = MODEL_DIR / "risk_type_model.pkl"
ANOMALY_MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"

MIN_SAMPLES_FOR_TRAINING = 30
RETRAIN_INTERVAL = 50

# ============================================================================
# TRUSTED SITES & KNOWN PLATFORMS
# ============================================================================

TRUSTED_DOMAINS = {
    # Major tech companies
    'google.com', 'youtube.com', 'gmail.com', 'google.co.in', 'google.co.uk',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
    'microsoft.com', 'office.com', 'outlook.com', 'live.com', 'xbox.com',
    'apple.com', 'icloud.com', 'itunes.com',
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com',
    
    # Social media & communication
    'twitter.com', 'x.com', 'linkedin.com', 'reddit.com', 'discord.com',
    'telegram.org', 'signal.org', 'snapchat.com', 'tiktok.com',
    
    # Development & tech
    'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
    'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io',
    
    # Education & reference
    'wikipedia.org', 'wikimedia.org', 'scholar.google.com',
    'coursera.org', 'udemy.com', 'khanacademy.org', 'edx.org',
    
    # News & media
    'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com', 'theguardian.com',
    
    # Finance & payment (legitimate)
    'paypal.com', 'stripe.com', 'visa.com', 'mastercard.com',
    
    # Entertainment (legitimate)
    'netflix.com', 'spotify.com', 'hulu.com', 'primevideo.com',
    'twitch.tv', 'soundcloud.com',
    
    # Government & official
    'gov.in', 'nic.in', 'gov.uk', 'usa.gov', 'irs.gov',
    
    # Others
    'cloudflare.com', 'wordpress.com', 'medium.com', 'zoom.us'
}

# Known gambling/betting platforms (skill-based and chance-based)
GAMBLING_PLATFORMS = {
    # Indian platforms
    'rummycircle.com', 'ace2three.com', 'junglee.com', 'classicrummy.com',
    'dream11.com', 'my11circle.com', 'mpl.live', 'paytmfirstgames.com',
    'winzo.com', 'ballebaazi.com', 'howzat.com', 'gamezy.com',
    '1xbet.com', 'betway.com', 'bet365.com', '10cric.com', 'dafabet.com',
    'fairbet.com', 'pure.win', 'parimatch.in', 'betfair.com',
    
    # International platforms
    'poker.com', 'pokerstars.com', 'zynga.com', 'worldseries.com',
    'draftkings.com', 'fanduel.com', 'caesars.com', 'mgm.com',
    'bovada.lv', 'betonline.ag', 'ignition.casino'
}

# TLD Reputation Scoring
TLD_REPUTATION = {
    # High-risk TLDs (free/abused)
    '.tk': 25, '.ml': 25, '.ga': 25, '.cf': 25, '.gq': 25,
    '.top': 20, '.xyz': 18, '.club': 18, '.win': 20, '.bid': 20,
    '.loan': 22, '.work': 18, '.click': 18, '.download': 20,
    '.stream': 18, '.science': 18, '.racing': 18, '.review': 18,
    '.trade': 18, '.date': 18, '.party': 18, '.faith': 18,
    
    # Medium-risk TLDs
    '.site': 12, '.online': 12, '.store': 10, '.tech': 10,
    '.space': 12, '.fun': 12, '.host': 12, '.website': 10,
    '.press': 10, '.news': 10, '.live': 10, '.world': 10,
    
    # Low-risk TLDs
    '.com': 0, '.org': 0, '.net': 0, '.edu': 0, '.gov': 0,
    '.co.uk': 0, '.co.in': 0, '.de': 0, '.fr': 0, '.jp': 0,
    '.au': 0, '.ca': 0, '.us': 0, '.info': 2, '.biz': 3
}


def get_tld_score(domain):
    """Get reputation score based on TLD"""
    for tld, score in sorted(TLD_REPUTATION.items(), key=lambda x: len(x[0]), reverse=True):
        if domain.endswith(tld):
            return score
    return 5


def is_trusted_domain(domain):
    """Check if domain is in trusted list"""
    if domain in TRUSTED_DOMAINS:
        return True
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith('.' + trusted):
            return True
    return False


def is_gambling_platform(domain):
    """Check if domain is a known gambling/betting platform"""
    if domain in GAMBLING_PLATFORMS:
        return True
    for gambling in GAMBLING_PLATFORMS:
        if domain.endswith('.' + gambling) or gambling in domain:
            return True
    return False


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def calculate_domain_score(domain):
    """Domain score (0-25 points)"""
    
    # Trusted domains get 0 score
    if is_trusted_domain(domain):
        return 0
    
    # Known gambling platforms get moderate score (not zero, but not high)
    if is_gambling_platform(domain):
        return 8  # Moderate concern due to financial risk
    
    score = 0
    
    try:
        # IP address check
        parts = domain.split('.')
        if all(part.isdigit() for part in parts if part):
            return 25
        
        # TLD reputation (dynamic)
        tld_score = get_tld_score(domain)
        score += tld_score
        
        # Get domain name (without TLD)
        domain_name = domain.split('.')[0]
        
        # Length analysis
        if len(domain_name) > 25:
            score += 8
        elif len(domain_name) > 15:
            score += 5
        elif len(domain_name) < 3:
            score += 8
        
        # Excessive hyphens
        hyphen_count = domain_name.count('-')
        if hyphen_count > 3:
            score += 10
        elif hyphen_count > 2:
            score += 5
        
        # Digit count
        digit_count = sum(c.isdigit() for c in domain_name)
        if digit_count > 5:
            score += 8
        elif digit_count > 3:
            score += 4
        
        # Suspicious patterns
        if re.search(r'\d{4}', domain_name):
            score += 5
            
    except:
        score = 15
    
    return min(score, 25)


def calculate_url_score(url):
    """URL structure score (0-25 points)"""
    score = 0
    
    try:
        parsed = urlparse(url)
        
        # IP in URL
        netloc = parsed.netloc.split(':')[0]
        try:
            import ipaddress
            ipaddress.ip_address(netloc)
            score += 20
        except:
            pass
        
        # URL length
        if len(url) > 120:
            score += 10
        elif len(url) > 80:
            score += 5
        
        # @ symbol
        if '@' in url:
            score += 15
        
        # Multiple subdomains
        subdomain_count = parsed.netloc.count('.')
        if subdomain_count > 3:
            score += 8
        elif subdomain_count > 2:
            score += 4
        
        # Excessive special characters
        special_chars = len(re.findall(r'[!#$%^&*(),?":{}|<>]', url))
        if special_chars > 5:
            score += 8
        
        # Double slashes in path
        if '//' in parsed.path:
            score += 10
        
        # Query string complexity
        if len(parsed.query) > 100:
            score += 8
            
    except:
        score = 10
    
    return min(score, 25)


def calculate_keyword_score_and_type(url, domain):
    """
    Enhanced keyword analysis with gambling/betting detection
    Returns: (score, risk_type)
    """
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # Check if it's a known gambling platform first
    is_known_gambling = is_gambling_platform(domain)
    
    # Phishing keywords
    phishing_keywords = [
        'login', 'signin', 'verify', 'account', 'update', 'suspend',
        'confirm', 'secure', 'validate', 'authenticate', 'credential',
        'password', 'security', 'alert', 'warning', 'blocked'
    ]
    
    # Financial fraud keywords
    financial_keywords = [
        'bank', 'paypal', 'wallet', 'payment', 'credit', 'debit',
        'transaction', 'transfer', 'wire', 'swift', 'iban',
        'crypto', 'bitcoin', 'ethereum', 'blockchain', 'invest', 'trading',
        'forex', 'stock', 'profit', 'money'
    ]
    
    # Scam keywords
    scam_keywords = [
        'reward', 'prize', 'winner', 'congratulations', 'claim',
        'free', 'bonus', 'gift', 'lottery', 'sweepstakes',
        'offer', 'limited', 'expires', 'urgent', 'act-now',
        'guaranteed', 'risk-free', 'no-cost'
    ]
    
    # Gambling/Betting keywords (both skill-based and chance-based)
    gambling_keywords = [
        # General gambling
        'bet', 'betting', 'wager', 'gamble', 'casino', 'poker',
        'slots', 'jackpot', 'roulette', 'blackjack', 'odds',
        
        # Indian skill-based gaming
        'rummy', 'fantasy', 'dream11', 'my11', 'contest', 'league',
        'tournament', 'winning', 'cash-prize', 'real-money', 'earn-money',
        'play-win', 'prize-pool', 'join-contest', 'prediction',
        
        # Sports betting
        'sportsbook', 'cricket-bet', 'football-bet', 'live-bet',
        'in-play', 'odds', 'accumulator', 'parlay',
        
        # Online gaming platforms
        'mpl', 'winzo', 'paytm-games', 'ludo', 'carrom', 'chess-money',
        'skill-game', 'earn-playing', 'game-money', 'withdraw',
        
        # Betting identifiers
        '1xbet', 'betway', 'bet365', '10cric', 'fairbet', 'pure-win',
        'dafabet', 'parimatch', 'melbet'
    ]
    
    # Malware keywords
    malware_keywords = [
        'download', 'exe', 'install', 'plugin', 'codec',
        'update-now', 'flash', 'java', 'activex', 'setup'
    ]
    
    # Piracy keywords
    piracy_keywords = [
        'crack', 'cracked', 'keygen', 'serial', 'patch', 'nulled',
        'repack', 'repacks', 'fitgirl', 'dodi', 'codex', 'skidrow',
        'torrent', 'pirate', 'warez', 'free-download', 'full-version',
        'activated', 'unlocked', 'premium-free', 'mod-apk', 'hacked'
    ]
    
    # Count matches per category
    phishing_count = sum(1 for kw in phishing_keywords if kw in url_lower)
    financial_count = sum(1 for kw in financial_keywords if kw in url_lower)
    scam_count = sum(1 for kw in scam_keywords if kw in url_lower)
    gambling_count = sum(1 for kw in gambling_keywords if kw in url_lower or kw in domain_lower)
    malware_count = sum(1 for kw in malware_keywords if kw in url_lower)
    piracy_count = sum(1 for kw in piracy_keywords if kw in url_lower)
    
    # Boost gambling count if it's a known platform
    if is_known_gambling:
        gambling_count += 3
    
    # Category scores
    category_scores = {
        'Phishing': phishing_count,
        'Financial Fraud': financial_count,
        'Scam': scam_count,
        'Gambling/Betting': gambling_count,
        'Malware': malware_count,
        'Piracy': piracy_count
    }
    
    # Determine dominant category
    max_count = max(category_scores.values())
    
    if max_count == 0:
        risk_type = 'Unknown'
        score = 0
    else:
        risk_type = max(category_scores, key=category_scores.get)
        
        # Moderate scoring for gambling (not too high, not too low)
        if risk_type == 'Gambling/Betting':
            score = min(gambling_count * 4, 18)  # Max 18/25 (moderate risk)
        elif risk_type == 'Piracy':
            score = piracy_count * 6
        else:
            score = max_count * 5
    
    return min(score, 25), risk_type


def calculate_security_score(url):
    """Security score (0-15 points)"""
    if not url.startswith('https://'):
        return 15
    return 0


def calculate_redirect_score(url):
    """Redirect score (0-10 points)"""
    try:
        response = requests.get(
            url, timeout=2, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'}, 
            verify=False
        )
        
        redirect_count = len(response.history)
        
        if redirect_count > 5:
            return 10
        elif redirect_count > 3:
            return 7
        elif redirect_count > 1:
            return 4
        
        # Check domain change
        try:
            original_domain = urlparse(url).netloc
            final_domain = urlparse(response.url).netloc
            if original_domain != final_domain:
                return 6
        except:
            pass
        
        return 0
        
    except:
        return 5


def extract_features(url):
    """Extract all features (Total: 0-100 points)"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        
        if not domain:
            return None
        
        # Calculate scores
        domain_score = calculate_domain_score(domain)
        url_score = calculate_url_score(url)
        keyword_score, inferred_risk_type = calculate_keyword_score_and_type(url, domain)
        security_score = calculate_security_score(url)
        redirect_score = calculate_redirect_score(url)
        
        total_score = domain_score + url_score + keyword_score + security_score + redirect_score
        
        # Check platform types
        is_trusted = is_trusted_domain(domain)
        is_gambling = is_gambling_platform(domain) or inferred_risk_type == 'Gambling/Betting'
        
        return {
            'domain': domain,
            'domain_score': domain_score,
            'url_score': url_score,
            'keyword_score': keyword_score,
            'security_score': security_score,
            'redirect_score': redirect_score,
            'total_score': total_score,
            'inferred_risk_type': inferred_risk_type,
            'is_trusted': is_trusted,
            'is_gambling': is_gambling
        }
        
    except Exception as e:
        print(f"⚠ Feature extraction error: {e}")
        return None


# ============================================================================
# MODEL MANAGEMENT
# ============================================================================

def load_models():
    """Load models if they exist"""
    models = [None, None, None]
    
    try:
        if RISK_MODEL_PATH.exists():
            models[0] = joblib.load(RISK_MODEL_PATH)
    except:
        pass
    
    try:
        if RISK_TYPE_MODEL_PATH.exists():
            models[1] = joblib.load(RISK_TYPE_MODEL_PATH)
    except:
        pass
    
    try:
        if ANOMALY_MODEL_PATH.exists():
            models[2] = joblib.load(ANOMALY_MODEL_PATH)
    except:
        pass
    
    return models


def train_models():
    """Train all models"""
    print("\n" + "="*60)
    print("🔧 TRAINING MODELS")
    print("="*60)
    
    X, y_risk, y_type = get_training_data()
    
    if X is None or len(X) < MIN_SAMPLES_FOR_TRAINING:
        print(f"❌ Need {MIN_SAMPLES_FOR_TRAINING} samples (have: {len(X) if X else 0})")
        print("="*60 + "\n")
        return False
    
    print(f"✓ Samples: {len(X)}")
    
    X = np.array(X)
    y_risk = np.array(y_risk)
    
    # Train risk classifier
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y_risk, test_size=0.2, random_state=42)
        
        risk_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
        risk_model.fit(X_train, y_train)
        
        accuracy = risk_model.score(X_test, y_test)
        print(f"✓ Risk Model: {accuracy:.0%} accurate")
        
        joblib.dump(risk_model, RISK_MODEL_PATH)
    except Exception as e:
        print(f"❌ Risk model failed: {e}")
    
    # Train type classifier
    try:
        valid_indices = [i for i, t in enumerate(y_type) if t and t not in ['Unknown', 'Safe']]
        
        if len(valid_indices) >= 10:
            X_type = X[valid_indices]
            y_type_filtered = np.array([y_type[i] for i in valid_indices])
            
            if len(np.unique(y_type_filtered)) >= 2:
                X_train_t, X_test_t, y_train_t, y_test_t = train_test_split(
                    X_type, y_type_filtered, test_size=0.2, random_state=42
                )
                
                risk_type_model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
                risk_type_model.fit(X_train_t, y_train_t)
                
                accuracy_t = risk_type_model.score(X_test_t, y_test_t)
                print(f"✓ Type Model: {accuracy_t:.0%} accurate")
                
                joblib.dump(risk_type_model, RISK_TYPE_MODEL_PATH)
    except:
        pass
    
    # Train anomaly detector
    try:
        anomaly_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        anomaly_model.fit(X)
        print("✓ Anomaly Model: Trained")
        
        joblib.dump(anomaly_model, ANOMALY_MODEL_PATH)
    except:
        pass
    
    print("="*60 + "\n")
    return True


def check_and_retrain():
    """Auto-retrain"""
    count = get_record_count()
    
    if count >= MIN_SAMPLES_FOR_TRAINING and not RISK_MODEL_PATH.exists():
        print(f"\n⚡ AUTO-TRAIN: {count} samples")
        return train_models()
    
    if count > 0 and count % RETRAIN_INTERVAL == 0:
        print(f"\n⚡ RETRAIN: {count} samples")
        return train_models()
    
    return False


# ============================================================================
# ANALYSIS WITH GAMBLING WARNINGS
# ============================================================================

def generate_risk_explanation(features, risk_type):
    """Generate explanation with specific gambling warnings"""
    
    # Trusted sites
    if features.get('is_trusted'):
        return "Verified trusted domain"
    
    # Gambling/Betting specific warnings
    if risk_type == 'Gambling/Betting' or features.get('is_gambling'):
        warnings = []
        
        # Build nuanced warning based on score
        if features['total_score'] > 40:
            warnings.append("⚠️ Financial risk involved")
        else:
            warnings.append("Financial risk present")
        
        warnings.append("outcomes depend on probability")
        
        if features['keyword_score'] > 10:
            warnings.append("real money transactions involved")
        
        return ", ".join(warnings).capitalize()
    
    # Other risk types
    reasons = []
    
    if features['domain_score'] > 10:
        reasons.append("suspicious domain")
    if features['keyword_score'] > 10:
        reasons.append(f"{risk_type.lower()} indicators")
    if features['security_score'] > 10:
        reasons.append("no HTTPS")
    if features['redirect_score'] > 5:
        reasons.append("redirects")
    if features['url_score'] > 10:
        reasons.append("suspicious URL structure")
    
    return ", ".join(reasons).capitalize() if reasons else "Low-level risk indicators"


def get_gambling_warning(features):
    """Get additional gambling-specific warning message"""
    if not (features.get('is_gambling') or features.get('inferred_risk_type') == 'Gambling/Betting'):
        return None
    
    score = features['total_score']
    
    # Nuanced warnings based on risk level
    if score > 50:
        return """
⚠️  FINANCIAL RISK WARNING:
• Money loss is highly probable
• Outcomes are uncertain and depend on chance/skill
• Only use money you can afford to lose
• Gambling can be addictive - seek help if needed"""
    
    elif score > 30:
        return """
⚠️  FINANCIAL CAUTION:
• Real money transactions involved
• Risk of financial loss exists
• Probability of winning varies - no guarantees
• Set limits and gamble responsibly"""
    
    else:
        return """
ℹ️  ADVISORY:
• Platform involves real money gaming
• Financial risk is present
• Understand the odds before participating
• Play responsibly within your means"""


def analyze_url(url):
    """Main analysis with gambling warnings"""
    
    print(f"\n{'='*60}")
    print(f"🔍 {url}")
    print(f"{'='*60}")
    
    # Check cache
    cached = get_cached_result(url)
    if cached:
        print("✓ CACHED")
        print("="*60 + "\n")
        return cached
    
    print("✗ Analyzing...")
    
    # Extract features
    features = extract_features(url)
    if features is None:
        return {"error": "Invalid URL", "url": url}
    
    print(f"  Domain: {features['domain']}")
    print(f"  Total Score: {features['total_score']}/100")
    
    # Load models
    risk_model, risk_type_model, anomaly_model = load_models()
    
    feature_array = np.array([[
        features['domain_score'], features['url_score'], features['keyword_score'],
        features['security_score'], features['redirect_score']
    ]])
    
    # Determine risk level and type
    if features.get('is_trusted'):
        risk_label = 0
        risk_level = 'Low'
        risk_type = 'Safe'
        confidence = 95.0
    else:
        # Predict risk level
        if risk_model is None:
            # Adjusted thresholds for gambling sites (moderate risk)
            if features.get('is_gambling'):
                if features['total_score'] > 50:
                    risk_label = 2  # High
                elif features['total_score'] > 25:
                    risk_label = 1  # Medium
                else:
                    risk_label = 1  # Medium (always at least medium for gambling)
                confidence = 70.0
            else:
                if features['total_score'] > 60:
                    risk_label = 2
                    confidence = 70.0
                elif features['total_score'] > 35:
                    risk_label = 1
                    confidence = 65.0
                else:
                    risk_label = 0
                    confidence = 60.0
        else:
            risk_label = int(risk_model.predict(feature_array)[0])
            probabilities = risk_model.predict_proba(feature_array)[0]
            confidence = round(max(probabilities) * 100, 2)
        
        risk_map = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
        risk_level = risk_map.get(risk_label, 'Low')
        
        # Predict risk type
        if risk_type_model is not None:
            try:
                risk_type = risk_type_model.predict(feature_array)[0]
            except:
                risk_type = features['inferred_risk_type']
        else:
            risk_type = features['inferred_risk_type']
    
    # Anomaly detection (skip for known gambling platforms)
    is_anomaly = False
    if anomaly_model is not None and not features.get('is_trusted') and not features.get('is_gambling'):
        try:
            anomaly_pred = anomaly_model.predict(feature_array)[0]
            is_anomaly = (anomaly_pred == -1)
        except:
            pass
    
    # Severity (adjusted for gambling)
    if features.get('is_gambling'):
        # Moderate severity for gambling (40-65 range typically)
        severity = int(35 + (features['total_score'] * 0.4) + (confidence * 0.2))
    else:
        severity = int((features['total_score'] * 0.7) + (confidence * 0.3))
    severity = min(severity, 100)
    
    # Explanation
    why_risk = generate_risk_explanation(features, risk_type)
    
    # Get gambling warning if applicable
    gambling_warning = get_gambling_warning(features)
    
    # Store
    store_analysis(url, features['domain'], features, risk_label, risk_type, confidence, is_anomaly, severity, why_risk)
    print(f"✓ Stored")
    
    # Retrain check
    check_and_retrain()
    
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
        'risk_level_numeric': risk_label,
        'confidence_percent': confidence,
        'anomaly_detected': is_anomaly,
        'risk_severity_index': severity,
        'why_risk': why_risk,
        'risk_type': risk_type,
        'gambling_warning': gambling_warning,
        'cached': False
    }
    
    print("="*60 + "\n")
    return result


def display_result(result):
    """Display result with gambling warnings"""
    print("\n" + "="*60)
    print("📊 RESULT")
    print("="*60)
    
    if 'error' in result:
        print(f"❌ {result['error']}")
        return
    
    print(f"\n🌐 {result['url']}")
    print(f"🏠 {result['domain']}")
    
    print(f"\n📈 SCORES:")
    print(f"  Domain:      {result['domain_score']}/25")
    print(f"  URL:         {result['url_score']}/25")
    print(f"  Keywords:    {result['keyword_score']}/25")
    print(f"  Security:    {result['security_score']}/15")
    print(f"  Redirects:   {result['redirect_score']}/10")
    print(f"  ──────────────────")
    print(f"  TOTAL:       {result['total_score']}/100")
    
    print(f"\n🎯 ASSESSMENT:")
    print(f"  Risk:        {result['risk_level']}")
    print(f"  Type:        {result['risk_type']}")
    print(f"  Confidence:  {result['confidence_percent']:.0f}%")
    print(f"  Severity:    {result['risk_severity_index']}/100")
    print(f"\n💡 {result['why_risk']}")
    
    # Display gambling warning if present
    if result.get('gambling_warning'):
        print(result['gambling_warning'])
    
    print("="*60 + "\n")


def show_stats():
    """Show stats"""
    print("\n" + "="*60)
    print("📊 STATS")
    print("="*60)
    
    count = get_record_count()
    risk_dist, type_dist = get_class_distribution()
    
    print(f"\n📂 Database: {count} URLs")
    print(f"  Low:      {risk_dist.get(0, 0)}")
    print(f"  Medium:   {risk_dist.get(1, 0)}")
    print(f"  High:     {risk_dist.get(2, 0)}")
    
    if type_dist:
        print(f"\n🏷️  Types:")
        for rtype, cnt in sorted(type_dist.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {rtype:18s}: {cnt}")
    
    risk_model, risk_type_model, anomaly_model = load_models()
    
    print(f"\n🤖 Models:")
    print(f"  Risk:     {'✓' if risk_model else '✗'}")
    print(f"  Type:     {'✓' if risk_type_model else '✗'}")
    print(f"  Anomaly:  {'✓' if anomaly_model else '✗'}")
    
    if not risk_model:
        print(f"\n⚙️  Train in: {max(0, MIN_SAMPLES_FOR_TRAINING - count)} URLs")
    
    print("="*60 + "\n")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    initialize_database()
    
    print("\n" + "="*60)
    print("🛡️  URL RISK ANALYZER v3.0")
    print("="*60)
    print("\nUsage:")
    print("  <url>   - Analyze URL")
    print("  stats   - Show stats")
    print("  train   - Train models")
    print("  exit    - Quit")
    print("="*60)
    
    while True:
        try:
            user_input = input("\n>>> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == 'exit':
                print("Bye!")
                break
            
            if user_input.lower() == 'stats':
                show_stats()
                continue
            
            if user_input.lower() == 'train':
                train_models()
                continue
            
            # Analyze URL
            result = analyze_url(user_input)
            display_result(result)
            
        except KeyboardInterrupt:
            print("\n\nStopped")
            break
        except Exception as e:
            print(f"❌ Error: {e}")