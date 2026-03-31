"""REST API endpoints for VulnHunter."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from vulnhunter.auth.dependencies import get_current_user
from vulnhunter.auth.jwt import (
    create_access_token, generate_api_token, hash_password, verify_password,
)
from vulnhunter.config import load_config
from vulnhunter.db import get_session
from vulnhunter.db.repository import Repository

router = APIRouter(prefix="/api", tags=["api"])


# ── Schemas ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str = ""

    @property
    def validated_password(self) -> str:
        if len(self.password) < 8:
            raise ValueError("Password must be at least 8 characters")
        return self.password

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class CreateAPITokenRequest(BaseModel):
    name: str = ""
    expires_days: int = 90

class APITokenResponse(BaseModel):
    id: str
    name: str
    raw_token: str
    expires_at: str

class FlowSummary(BaseModel):
    id: str
    target_host: str
    status: str
    risk_score: float
    threat_level: str
    duration_seconds: float
    created_at: str

class VulnSummary(BaseModel):
    id: str
    title: str
    severity: str
    tool: str
    description: str
    cwe_id: str
    cvss_score: float

class ScanRequest(BaseModel):
    target: str
    ports: str = ""
    custom_task: str = ""


# ── Auth ────────────────────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse)
async def register(body: RegisterRequest):
    if len(body.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters")
    async with get_session() as session:
        repo = Repository(session)
        existing = await repo.get_user_by_email(body.email)
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
        user = await repo.create_user(
            email=body.email,
            password_hash=hash_password(body.password),
            display_name=body.display_name,
        )
        config = load_config()
        token = create_access_token(user.id, config.auth)
        return TokenResponse(access_token=token)


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    async with get_session() as session:
        repo = Repository(session)
        user = await repo.get_user_by_email(body.email)
        if not user or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        config = load_config()
        token = create_access_token(user.id, config.auth)
        return TokenResponse(access_token=token)


# ── API Tokens ──────────────────────────────────────────────────────────

@router.post("/tokens", response_model=APITokenResponse)
async def create_token(body: CreateAPITokenRequest, user_id: uuid.UUID = Depends(get_current_user)):
    raw_token, token_hash = generate_api_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)
    async with get_session() as session:
        repo = Repository(session)
        row = await repo.create_api_token(
            user_id=user_id, token_hash=token_hash, name=body.name, expires_at=expires_at,
        )
        return APITokenResponse(
            id=str(row.id), name=row.name,
            raw_token=raw_token, expires_at=expires_at.isoformat(),
        )


@router.get("/tokens")
async def list_tokens(user_id: uuid.UUID = Depends(get_current_user)):
    async with get_session() as session:
        repo = Repository(session)
        tokens = await repo.list_api_tokens(user_id)
        return [
            {"id": str(t.id), "name": t.name, "revoked": t.revoked,
             "expires_at": t.expires_at.isoformat(), "created_at": t.created_at.isoformat()}
            for t in tokens
        ]


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: uuid.UUID, user_id: uuid.UUID = Depends(get_current_user)):
    async with get_session() as session:
        repo = Repository(session)
        ok = await repo.revoke_api_token(token_id, user_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Token not found")
        return {"status": "revoked"}


# ── Scans / Flows ──────────────────────────────────────────────────────

@router.get("/scans", response_model=list[FlowSummary])
async def list_scans(
    limit: int = 50, offset: int = 0,
    user_id: uuid.UUID = Depends(get_current_user),
):
    async with get_session() as session:
        repo = Repository(session)
        flows = await repo.list_flows(user_id=user_id, limit=limit, offset=offset)
        return [
            FlowSummary(
                id=str(f.id), target_host=f.target_host, status=f.status,
                risk_score=f.risk_score, threat_level=f.threat_level,
                duration_seconds=f.duration_seconds, created_at=f.created_at.isoformat(),
            )
            for f in flows
        ]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: uuid.UUID, user_id: uuid.UUID = Depends(get_current_user)):
    async with get_session() as session:
        repo = Repository(session)
        flow = await repo.get_flow(scan_id)
        if not flow:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "id": str(flow.id),
            "target_host": flow.target_host,
            "status": flow.status,
            "risk_score": flow.risk_score,
            "threat_level": flow.threat_level,
            "ai_summary": flow.ai_summary,
            "remediation_steps": flow.remediation_steps,
            "duration_seconds": flow.duration_seconds,
            "created_at": flow.created_at.isoformat(),
            "tool_results": [
                {"tool": tr.tool_name, "success": tr.success, "duration": tr.duration_seconds, "error": tr.error}
                for tr in flow.tool_results
            ],
            "vulnerabilities": [
                {"id": str(v.id), "title": v.title, "severity": v.severity, "tool": v.tool,
                 "description": v.description, "cwe_id": v.cwe_id, "cvss_score": v.cvss_score}
                for v in flow.vulnerabilities
            ],
        }


@router.get("/scans/{scan_id}/vulnerabilities", response_model=list[VulnSummary])
async def get_scan_vulns(scan_id: uuid.UUID, user_id: uuid.UUID = Depends(get_current_user)):
    async with get_session() as session:
        repo = Repository(session)
        vulns = await repo.list_vulnerabilities(scan_id)
        return [
            VulnSummary(
                id=str(v.id), title=v.title, severity=v.severity, tool=v.tool,
                description=v.description, cwe_id=v.cwe_id, cvss_score=v.cvss_score,
            )
            for v in vulns
        ]


@router.get("/scans/{scan_id}/bounty-report/{vuln_id}")
async def get_bounty_report(
    scan_id: uuid.UUID,
    vuln_id: uuid.UUID,
    format: str = "hackerone",
    user_id: uuid.UUID = Depends(get_current_user),
):
    """Generate a bug bounty submission report for a specific vulnerability."""
    from vulnhunter.models import Severity, Vulnerability
    from vulnhunter.reporting.bounty_report import BountyReportGenerator

    async with get_session() as session:
        repo = Repository(session)
        db_vuln = await repo.get_vulnerability(vuln_id)
        if not db_vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        vuln = Vulnerability(
            title=db_vuln.title,
            severity=Severity(db_vuln.severity),
            tool=db_vuln.tool,
            description=db_vuln.description,
            evidence=db_vuln.evidence,
            cwe_id=db_vuln.cwe_id,
            cvss_score=db_vuln.cvss_score,
            remediation=db_vuln.remediation,
        )

        gen = BountyReportGenerator()
        if format == "bugcrowd":
            report_md = gen.generate_bugcrowd(vuln)
        else:
            report_md = gen.generate_hackerone(vuln)

        return {"format": format, "markdown": report_md}
