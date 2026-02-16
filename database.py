"""
SQLite Database Module - Cache Layer for URL Analysis
Handles all database operations with thread-safe access
"""
import sqlite3
import threading
import os
from datetime import datetime
from pathlib import Path

# Database configuration
DB_DIR = Path(__file__).parent / "db"
DB_PATH = DB_DIR / "url_risk.db"

db_lock = threading.Lock()


def get_connection():
    """Get thread-safe database connection"""
    DB_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Initialize database schema with proper indexes"""
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            domain_score INTEGER,
            url_score INTEGER,
            keyword_score INTEGER,
            security_score INTEGER,
            redirect_score INTEGER,
            total_score INTEGER,
            predicted_risk_level INTEGER,
            predicted_risk_type TEXT,
            confidence_percent REAL,
            anomaly_detected INTEGER,
            risk_severity_index INTEGER,
            why_risk TEXT,
            actual_risk_level INTEGER,
            actual_risk_type TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_url ON url_analysis(url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON url_analysis(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyzed_at ON url_analysis(analyzed_at)")
        
        conn.commit()
        conn.close()
        print(f"✓ Database initialized: {DB_PATH}")


def get_cached_result(url):
    """
    Retrieve cached analysis result
    Returns None if not found, otherwise returns dict with all analysis data
    """
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM url_analysis WHERE url = ?', (url,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            # Use actual values if available, otherwise predicted
            risk_level = row['actual_risk_level'] if row['actual_risk_level'] is not None else row['predicted_risk_level']
            risk_type = row['actual_risk_type'] if row['actual_risk_type'] else row['predicted_risk_type']
            
            risk_map = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
            
            return {
                'url': row['url'],
                'domain': row['domain'],
                'domain_score': row['domain_score'],
                'url_score': row['url_score'],
                'keyword_score': row['keyword_score'],
                'security_score': row['security_score'],
                'redirect_score': row['redirect_score'],
                'total_score': row['total_score'],
                'risk_level': risk_map.get(risk_level, 'Low'),
                'risk_level_numeric': risk_level,
                'confidence_percent': row['confidence_percent'],
                'anomaly_detected': bool(row['anomaly_detected']),
                'risk_severity_index': row['risk_severity_index'],
                'why_risk': row['why_risk'] or 'Multiple risk factors',
                'risk_type': risk_type or 'Unknown',
                'cached': True,
                'analyzed_at': row['analyzed_at']
            }
        except Exception as e:
            print(f"Cache read error: {e}")
            return None


def store_analysis(url, domain, features, risk_label, risk_type, confidence, is_anomaly, severity, why_risk):
    """Store or update analysis result in database"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Check if URL exists
            cursor.execute('SELECT id FROM url_analysis WHERE url = ?', (url,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                cursor.execute("""
                    UPDATE url_analysis SET
                        domain = ?, domain_score = ?, url_score = ?, keyword_score = ?,
                        security_score = ?, redirect_score = ?, total_score = ?,
                        predicted_risk_level = ?, predicted_risk_type = ?,
                        confidence_percent = ?, anomaly_detected = ?, 
                        risk_severity_index = ?, why_risk = ?, updated_at = ?
                    WHERE url = ?
                """, (
                    domain, features['domain_score'], features['url_score'], 
                    features['keyword_score'], features['security_score'], 
                    features['redirect_score'], features['total_score'],
                    risk_label, risk_type, confidence, int(is_anomaly), 
                    severity, why_risk, datetime.now(), url
                ))
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO url_analysis (
                        url, domain, domain_score, url_score, keyword_score,
                        security_score, redirect_score, total_score,
                        predicted_risk_level, predicted_risk_type, confidence_percent,
                        anomaly_detected, risk_severity_index, why_risk
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    url, domain, features['domain_score'], features['url_score'],
                    features['keyword_score'], features['security_score'],
                    features['redirect_score'], features['total_score'],
                    risk_label, risk_type, confidence, int(is_anomaly), severity, why_risk
                ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Storage error: {e}")
            return False


def get_training_data():
    """
    Fetch all analysis records for model training
    Returns: X (features), y_risk (labels), y_type (risk types)
    """
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT domain_score, url_score, keyword_score, 
                       security_score, redirect_score,
                       predicted_risk_level, predicted_risk_type
                FROM url_analysis
                ORDER BY analyzed_at DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                return None, None, None
            
            X = [[r['domain_score'], r['url_score'], r['keyword_score'],
                  r['security_score'], r['redirect_score']] for r in rows]
            y_risk = [r['predicted_risk_level'] for r in rows]
            y_type = [r['predicted_risk_type'] for r in rows]
            
            return X, y_risk, y_type
        except Exception as e:
            print(f"Training data fetch error: {e}")
            return None, None, None


def get_record_count():
    """Get total number of analyzed URLs"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM url_analysis")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except:
            return 0


def get_class_distribution():
    """Get distribution of risk levels and types"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT predicted_risk_level, COUNT(*) as count 
                FROM url_analysis 
                GROUP BY predicted_risk_level
            """)
            risk_dist = {row['predicted_risk_level']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute("""
                SELECT predicted_risk_type, COUNT(*) as count 
                FROM url_analysis 
                GROUP BY predicted_risk_type
            """)
            type_dist = {row['predicted_risk_type']: row['count'] for row in cursor.fetchall()}
            
            conn.close()
            return risk_dist, type_dist
        except:
            return {}, {}


def update_labels(url, risk_level, risk_type):
    """Update actual labels for manual corrections (for active learning)"""
    with db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE url_analysis 
                SET actual_risk_level = ?, actual_risk_type = ?, updated_at = ?
                WHERE url = ?
            """, (risk_level, risk_type, datetime.now(), url))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Label update error: {e}")
            return False