import sqlite3
import os
import hashlib
import uuid
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "security.db")

def init_db():
    """Initialize SQLite database schema for users, sessions, analyses, and saved reports."""
    os.makedirs(DB_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # 1. Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # 2. User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # 3. Analysis history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                summary TEXT,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # 4. Saved reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_reports (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                analysis_id TEXT,
                report_name TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                content_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # 5. Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        ''')

        # Check and migrate onboarding_completed in users table if needed
        cursor.execute("PRAGMA table_info(users)")
        cols = [col[1] for col in cursor.fetchall()]
        if "onboarding_completed" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN onboarding_completed INTEGER DEFAULT 0")

        conn.commit()

def hash_password(password: str) -> str:
    """Secure SHA-256 password hashing with application salt."""
    salt = "security_intelligence_salt_v1"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def get_connection():
    return sqlite3.connect(DB_PATH)

init_db()
