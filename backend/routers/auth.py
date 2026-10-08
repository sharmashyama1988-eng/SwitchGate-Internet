"""
SwitchGate - Firebase Authentication & Identity Router
Handles Google and Apple OAuth user profile synchronization, session state, and Firebase credentials.
"""
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.database import db

router = APIRouter(prefix="/api/auth", tags=["auth"])


class UserSyncPayload(BaseModel):
    uid: str
    email: Optional[str] = ""
    display_name: Optional[str] = ""
    photo_url: Optional[str] = ""
    provider: Optional[str] = "google.com"


class FirebaseConfigPayload(BaseModel):
    apiKey: str
    authDomain: str
    projectId: str
    appId: Optional[str] = ""


@router.get("/user")
def get_current_auth_user() -> Dict[str, Any]:
    """Returns the current active authenticated user or unauthenticated state."""
    user = db.get_current_user()
    if user:
        return {"authenticated": True, "user": user}
    return {"authenticated": False, "user": None}


@router.post("/sync")
def sync_auth_user(payload: UserSyncPayload) -> Dict[str, Any]:
    """Syncs a Firebase-authenticated user (Google / Apple) into local SQLite storage."""
    if not payload.uid:
        raise HTTPException(status_code=400, detail="Missing user UID")

    user = db.sync_user(
        uid=payload.uid,
        email=payload.email or "",
        display_name=payload.display_name or "",
        photo_url=payload.photo_url or "",
        provider=payload.provider or "google.com"
    )
    return {"authenticated": True, "user": user}


@router.post("/signout")
def signout_user() -> Dict[str, Any]:
    """Signs out the active user session."""
    db.signout_user()
    return {"authenticated": False, "message": "Signed out successfully"}


@router.get("/config")
def get_firebase_config() -> Dict[str, Any]:
    """Returns public Firebase web configuration."""
    api_key = db.get_setting("firebase_api_key", "")
    auth_domain = db.get_setting("firebase_auth_domain", "")
    project_id = db.get_setting("firebase_project_id", "")
    app_id = db.get_setting("firebase_app_id", "")

    # Default fallback demo config for immediate out-of-the-box UI readiness
    if not api_key:
        api_key = "AIzaSyDemoSwitchGateDefaultKey2026"
    if not auth_domain:
        auth_domain = "switchgate-security.firebaseapp.com"
    if not project_id:
        project_id = "switchgate-security"

    return {
        "apiKey": api_key,
        "authDomain": auth_domain,
        "projectId": project_id,
        "appId": app_id,
        "is_custom": bool(db.get_setting("firebase_api_key", ""))
    }


@router.post("/config")
def save_firebase_config(payload: FirebaseConfigPayload) -> Dict[str, Any]:
    """Saves customized Firebase web configuration."""
    db.set_setting("firebase_api_key", payload.apiKey.strip())
    db.set_setting("firebase_auth_domain", payload.authDomain.strip())
    db.set_setting("firebase_project_id", payload.projectId.strip())
    if payload.appId:
        db.set_setting("firebase_app_id", payload.appId.strip())

    return {"status": "success", "message": "Firebase configuration updated"}
