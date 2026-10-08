"""
SwitchGate - Google Workspace Integration Router v2.0
Endpoints for Google Sheets telemetry export, Docs executive reports,
Google Chat security alerts, Calendar curfew sync, and Drive backups.
"""
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import Dict, Any, Optional

from backend.core.google_workspace_bridge import workspace_bridge

router = APIRouter(prefix="/api/workspace", tags=["Google Workspace"])


class WorkspaceConfigRequest(BaseModel):
    webhook_url: Optional[str] = None
    calendar_feed_url: Optional[str] = None
    auto_export_sheets: Optional[bool] = None
    auto_alert_intruders: Optional[bool] = None
    auto_calendar_sync: Optional[bool] = None


class CalendarSyncRequest(BaseModel):
    target_mac: Optional[str] = None


class TestAlertRequest(BaseModel):
    title: Optional[str] = "SwitchGate Security Test Alert"
    message: Optional[str] = "Google Workspace integration is online and active! Telemetry and threat monitors connected."
    alert_type: Optional[str] = "INFO"


@router.get("/config", response_model=Dict[str, Any])
async def get_workspace_config():
    """Returns current Google Workspace bridge settings and status."""
    return workspace_bridge.get_config()


@router.post("/config", response_model=Dict[str, Any])
async def save_workspace_config(req: WorkspaceConfigRequest):
    """Updates Google Workspace bridge settings."""
    return workspace_bridge.save_config(
        webhook_url=req.webhook_url,
        calendar_feed_url=req.calendar_feed_url,
        auto_export_sheets=req.auto_export_sheets,
        auto_alert_intruders=req.auto_alert_intruders,
        auto_calendar_sync=req.auto_calendar_sync
    )


@router.get("/export/sheets")
async def export_sheets_csv():
    """Downloads a live Google Sheets-ready CSV of all network devices and bandwidth."""
    csv_data = workspace_bridge.generate_sheets_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=SwitchGate_GoogleSheets_Devices.csv"}
    )


@router.get("/export/audit")
async def export_audit_csv():
    """Downloads a Google Sheets-ready CSV of all system security logs."""
    csv_data = workspace_bridge.generate_sheets_audit_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=SwitchGate_GoogleSheets_AuditLogs.csv"}
    )


@router.get("/export/docs-report")
async def export_docs_report():
    """Returns the executive security diagnostic report formatted for Google Docs."""
    report_md = workspace_bridge.generate_docs_report_markdown()
    return {
        "status": "success",
        "format": "markdown",
        "content": report_md,
        "title": "SwitchGate Internet — Executive Security Audit"
    }


@router.post("/test-webhook")
async def send_test_webhook(req: TestAlertRequest):
    """Dispatches a test card notification to Google Chat / Workspace Webhook."""
    success = workspace_bridge.dispatch_workspace_alert(
        title=req.title or "Test Alert",
        message=req.message or "Google Workspace connected.",
        alert_type=req.alert_type or "INFO"
    )
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to send webhook. Please verify that your Google Chat / Workspace Webhook URL is valid."
        )
    return {"status": "success", "message": "Test card delivered to Google Workspace channel successfully!"}


@router.post("/sync/calendar")
async def sync_calendar(req: Optional[CalendarSyncRequest] = None):
    """Syncs Google Calendar event windows into SwitchGate smart schedules."""
    target_mac = req.target_mac if req else None
    result = workspace_bridge.sync_calendar_schedules(default_target_mac=target_mac)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result


@router.post("/backup/drive")
async def backup_to_drive():
    """Generates an encrypted Google Drive backup snapshot package."""
    return workspace_bridge.generate_drive_backup_payload()
