import sqlite3
import threading
from datetime import datetime

DB_NAME = "url_risk.db"
db_lock = threading.Lock()

def get_connection():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Initialize database schema"""
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain TEXT,
            domain_score INTEGER,
            url_score INTEGER,
            keyword_score INTEGER,
            security_score INTEGER,
            redirect_score INTEGER,
            total_score INTEGER,
            risk_label INTEGER,
            risk_type_label TEXT,
            confidence REAL,
            anomaly_flag INTEGER,
            severity INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_url ON analysis_log(url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON analysis_log(timestamp)")
        
        conn.commit()
        conn.close()

def get_cached_result(url):
    """Check if URL is already analyzed (CACHE HIT)"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_log WHERE url = ?", (url,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'url': result['url'],
                    'domain': result['domain'],
                    'domain_score': result['domain_score'],
                    'url_score': result['url_score'],
                    'keyword_score': result['keyword_score'],
                    'security_score': result['security_score'],
                    'redirect_score': result['redirect_score'],
                    'total_score': result['total_score'],
                    'risk_level': 'High' if result['risk_label'] == 1 else 'Low',
                    'risk_type': result['risk_type_label'],
                    'confidence_percent': result['confidence'],
                    'anomaly_detected': bool(result['anomaly_flag']),
                    'risk_severity_index': result['severity'],
                    'cached': True
                }
            return None
        except:
            return None

def store_analysis(url, domain, features, risk_label, risk_type, confidence, anomaly_flag, severity):
    """Store new analysis result"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            INSERT OR REPLACE INTO analysis_log
            (url, domain, domain_score, url_score, keyword_score, 
             security_score, redirect_score, total_score, 
             risk_label, risk_type_label, confidence, anomaly_flag, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url, domain,
                features['domain_score'],
                features['url_score'],
                features['keyword_score'],
                features['security_score'],
                features['redirect_score'],
                features['total_score'],
                risk_label,
                risk_type,
                confidence,
                1 if anomaly_flag else 0,
                severity
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Storage error: {e}")
            return False

def update_labels(url, risk_label, risk_type):
    """Update labels for manual corrections"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE analysis_log 
            SET risk_label = ?, risk_type_label = ?
            WHERE url = ?
            """, (risk_label, risk_type, url))
            conn.commit()
            conn.close()
            return True
        except:
            return False

def get_training_data():
    """Fetch training data for ML models"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            SELECT domain_score, url_score, keyword_score, 
                   security_score, redirect_score,
                   risk_label, risk_type_label
            FROM analysis_log
            ORDER BY timestamp DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                return None, None, None
            
            X = [[r['domain_score'], r['url_score'], r['keyword_score'],
                  r['security_score'], r['redirect_score']] for r in rows]
            y_risk = [r['risk_label'] for r in rows]
            y_type = [r['risk_type_label'] for r in rows]
            
            return X, y_risk, y_type
        except Exception as e:
            print(f"Training data error: {e}")
            return None, None, None

def get_record_count():
    """Get total records in database"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM analysis_log")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except:
            return 0

def get_class_distribution():
    """Get distribution of risk labels and types"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT risk_label, COUNT(*) as count FROM analysis_log GROUP BY risk_label")
            risk_dist = {row['risk_label']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute("SELECT risk_type_label, COUNT(*) as count FROM analysis_log GROUP BY risk_type_label")
            type_dist = {row['risk_type_label']: row['count'] for row in cursor.fetchall()}
            
            conn.close()
            return risk_dist, type_dist
        except:
            return {}, {}