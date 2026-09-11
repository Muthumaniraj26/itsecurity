import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

from src.services.user_store.db import get_connection, hash_password

router = APIRouter(prefix="/api/user", tags=["User & Persistence Service"])

class RegisterSchema(BaseModel):
    name: str
    email: str
    password: str

class LoginSchema(BaseModel):
    email: str
    password: str

class ChangePasswordSchema(BaseModel):
    currentPassword: str
    newPassword: str

class AnalysisRecordSchema(BaseModel):
    tool: str
    target: str
    riskLevel: str
    confidence: int = 85
    summary: str = ""
    resultJson: Dict[str, Any]

class SaveReportSchema(BaseModel):
    analysisId: Optional[str] = None
    reportName: str
    target: str
    riskLevel: str
    contentJson: Dict[str, Any]

def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.name, u.email, u.created_at, COALESCE(u.onboarding_completed, 0)
            FROM users u 
            JOIN sessions s ON u.id = s.user_id 
            WHERE s.token = ?
        ''', (token,))
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0],
                "name": row[1],
                "email": row[2],
                "createdAt": row[3],
                "onboardingCompleted": bool(row[4])
            }
    return None

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================

@router.post("/register")
async def register_user(data: RegisterSchema):
    email = data.email.strip().lower()
    name = data.name.strip()
    if not email or not name or len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Invalid registration data. Password must be at least 8 characters.")

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="An account with this email address already exists.")

        user_id = str(uuid.uuid4())
        pwd_hash = hash_password(data.password)
        created_at = datetime.utcnow().isoformat() + "Z"

        cursor.execute('''
            INSERT INTO users (id, name, email, password_hash, created_at, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (user_id, name, email, pwd_hash, created_at))

        # Create session token
        token = str(uuid.uuid4())
        cursor.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, created_at))
        
        # Add welcome notification
        notif_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (notif_id, user_id, "Welcome to Security Intelligence", "Your account has been successfully initialized. Explore security tools to run your first analysis.", "info", 0, created_at))
        
        conn.commit()

        return {
            "token": token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "createdAt": created_at,
                "onboardingCompleted": False
            }
        }

@router.post("/login")
async def login_user(data: LoginSchema):
    email = data.email.strip().lower()
    pwd_hash = hash_password(data.password)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, created_at, COALESCE(onboarding_completed, 0) FROM users WHERE email = ? AND password_hash = ?", (email, pwd_hash))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        user_id, name, email_val, created_at, onboarding_comp = row
        token = str(uuid.uuid4())
        session_created = datetime.utcnow().isoformat() + "Z"
        cursor.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, session_created))
        conn.commit()

        return {
            "token": token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email_val,
                "createdAt": created_at,
                "onboardingCompleted": bool(onboarding_comp)
            }
        }

@router.get("/me")
async def get_profile(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"user": user}

@router.post("/onboarding/complete")
async def complete_onboarding(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET onboarding_completed = 1 WHERE id = ?", (user["id"],))
        conn.commit()
    return {"status": "success", "onboardingCompleted": True}

@router.post("/logout")
async def logout_user(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    return {"status": "logged_out"}

@router.post("/change-password")
async def change_password(data: ChangePasswordSchema, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if len(data.newPassword) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters.")

    curr_hash = hash_password(data.currentPassword)
    new_hash = hash_password(data.newPassword)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ? AND password_hash = ?", (user["id"], curr_hash))
        if not cursor.fetchone():
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
        conn.commit()

    return {"message": "Password updated successfully."}

# ==========================================
# HISTORY & SAVED REPORTS ENDPOINTS
# ==========================================

@router.get("/history")
async def get_history(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, tool, target, risk_level, confidence, summary, result_json, created_at 
            FROM analyses 
            WHERE user_id = ? OR user_id = 'guest'
            ORDER BY created_at DESC 
            LIMIT 50
        ''', (user_id,))
        rows = cursor.fetchall()
        history = []
        for r in rows:
            try:
                res_obj = json.loads(r[6])
            except Exception:
                res_obj = {}
            history.append({
                "id": r[0],
                "tool": r[1],
                "target": r[2],
                "riskLevel": r[3],
                "confidence": r[4],
                "summary": r[5],
                "resultJson": res_obj,
                "createdAt": r[7]
            })
        return history

@router.post("/history")
async def record_analysis(data: AnalysisRecordSchema, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"
    analysis_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + "Z"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analyses (id, user_id, tool, target, risk_level, confidence, summary, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            user_id,
            data.tool,
            data.target,
            data.riskLevel,
            data.confidence,
            data.summary,
            json.dumps(data.resultJson),
            created_at
        ))
        
        # Generate alert if high or critical risk
        if data.riskLevel.upper() in ["CRITICAL", "HIGH"]:
            notif_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                notif_id,
                user_id,
                f"Elevated Risk Detected: {data.target}",
                f"{data.tool} flagged target as {data.riskLevel.upper()} priority ({data.confidence}% confidence).",
                "warning",
                0,
                created_at
            ))
        
        conn.commit()

    return {"id": analysis_id, "createdAt": created_at}

@router.get("/reports")
async def get_saved_reports(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, analysis_id, report_name, target, risk_level, content_json, created_at 
            FROM saved_reports 
            WHERE user_id = ? OR user_id = 'guest'
            ORDER BY created_at DESC
        ''', (user_id,))
        rows = cursor.fetchall()
        reports = []
        for r in rows:
            try:
                content = json.loads(r[5])
            except Exception:
                content = {}
            reports.append({
                "id": r[0],
                "analysisId": r[1],
                "reportName": r[2],
                "target": r[3],
                "riskLevel": r[4],
                "content": content,
                "createdAt": r[6]
            })
        return reports

@router.post("/reports")
async def save_report(data: SaveReportSchema, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"
    report_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + "Z"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO saved_reports (id, user_id, analysis_id, report_name, target, risk_level, content_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_id,
            user_id,
            data.analysisId,
            data.reportName,
            data.target,
            data.riskLevel,
            json.dumps(data.contentJson),
            created_at
        ))
        
        notif_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            notif_id,
            user_id,
            f"Report Saved: {data.reportName}",
            f"Security analysis report for '{data.target}' was successfully saved to your repository.",
            "success",
            0,
            created_at
        ))
        conn.commit()

    return {"id": report_id, "message": "Report saved successfully."}

@router.delete("/reports/{report_id}")
async def delete_saved_report(report_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM saved_reports WHERE id = ? AND (user_id = ? OR user_id = 'guest')", (report_id, user_id))
        conn.commit()
    return {"message": "Report deleted successfully."}

@router.get("/notifications")
async def get_notifications(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, title, message, type, is_read, created_at 
            FROM notifications 
            WHERE user_id = ? OR user_id = 'guest'
            ORDER BY created_at DESC 
            LIMIT 20
        ''', (user_id,))
        rows = cursor.fetchall()
        return [{
            "id": r[0],
            "title": r[1],
            "message": r[2],
            "type": r[3],
            "isRead": bool(r[4]),
            "createdAt": r[5]
        } for r in rows]

@router.post("/notifications/read")
async def mark_notifications_read(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["id"] if user else "guest"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ? OR user_id = 'guest'", (user_id,))
        conn.commit()
    return {"status": "ok"}
