import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

from prompts import (
    build_report_prompt,
    build_attack_suggestion_prompt,
    build_final_report_prompt,
    build_final_report_markdown,
    build_exploitability_assessment,
    build_privilege_path_assessment
)
from database import (
    get_full_reports_by_project,
    init_db,
    save_report,
    get_reports,
    get_report_by_id,
    create_user,
    get_user_by_username,
    create_project,
    get_projects,
    get_project_by_id,
    delete_project,
    create_finding,
    get_findings_by_project,
    get_finding_by_id,
    delete_finding,
    update_user_password,
    create_password_reset_token,
    get_password_reset_token,
    mark_password_reset_token_used,
    save_scan,
    get_scans_by_project,
    get_scan_by_id
)
from auth import hash_password, verify_password, create_access_token, get_current_user
from config import OPENAI_API_KEY, OPENAI_MODEL
from scanner import ScannerError, run_web_scan


app = FastAPI(title="VulnPilot ReportGen", version="0.4.0")

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=OPENAI_API_KEY)


class FindingInput(BaseModel):
    project_id: int
    vulnerability_type: str
    affected_endpoint: str
    severity: str
    report_style: str
    output_format: str
    test_performed: str
    observed_result: str
    impact: str


class FindingCreate(BaseModel):
    vulnerability_type: str
    affected_endpoint: str
    severity: str
    test_performed: str
    observed_result: str
    impact: str


class UserInput(BaseModel):
    username: str
    password: str


class ForgotPasswordInput(BaseModel):
    username: str


class ResetPasswordInput(BaseModel):
    token: str
    new_password: str


class ScanInput(BaseModel):
    profile: str = "web-baseline"
    scan_depth: int = 1
    max_pages: int = 25
    include_ports: bool = False
    include_common_paths: bool = True
    include_recon: bool = True
    allow_private: bool = False
    path_profile: str = "standard"
    concurrency: int = 12
    ports: list[int] = []


class ProjectInput(BaseModel):
    name: str
    target_url: str
    app_type: str
    auth_type: str
    description: str = ""


@app.get("/")
def home():
    return {
        "app": "VulnPilot ReportGen",
        "status": "running",
        "version": "0.4.0"
    }


@app.post("/register")
def register_user(data: UserInput):
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    password_hash = hash_password(data.password)
    user_id = create_user(data.username, password_hash)

    if not user_id:
        raise HTTPException(status_code=400, detail="Username already exists")

    return {
        "status": "success",
        "message": "User registered successfully",
        "user_id": user_id
    }


@app.post("/login")
def login_user(data: UserInput):
    user = get_user_by_username(data.username)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({
        "sub": user["username"],
        "user_id": user["id"]
    })

    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer"
    }


@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordInput):
    username = data.username.strip()

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    user = get_user_by_username(username)
    response = {
        "status": "success",
        "message": "If the account exists, a reset token has been generated."
    }

    if not user:
        return response

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    create_password_reset_token(
        user["id"],
        token,
        expires_at.isoformat(timespec="seconds")
    )

    response.update({
        "reset_token": token,
        "expires_minutes": 30
    })

    return response


@app.post("/reset-password")
def reset_password(data: ResetPasswordInput):
    token = data.token.strip()

    if not token:
        raise HTTPException(status_code=400, detail="Reset token is required")

    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    reset = get_password_reset_token(token)

    if not reset or reset["used_at"]:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    expires_at = datetime.fromisoformat(reset["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    password_hash = hash_password(data.new_password)

    if not update_user_password(reset["user_id"], password_hash):
        raise HTTPException(status_code=400, detail="Could not reset password")

    mark_password_reset_token_used(reset["id"])

    return {
        "status": "success",
        "message": "Password reset successfully"
    }


@app.post("/projects")
def create_new_project(
    data: ProjectInput,
    current_user: dict = Depends(get_current_user)
):
    project_id = create_project(current_user["user_id"], data)

    return {
        "status": "success",
        "project_id": project_id,
        "message": "Project created successfully"
    }


@app.get("/projects")
def list_projects(current_user: dict = Depends(get_current_user)):
    return {
        "status": "success",
        "projects": get_projects(current_user["user_id"])
    }


@app.get("/projects/{project_id}")
def read_project(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "success",
        "project": project
    }


@app.delete("/projects/{project_id}")
def remove_project(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    deleted = delete_project(current_user["user_id"], project_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "success",
        "message": "Project deleted"
    }


@app.post("/projects/{project_id}/findings")
def add_finding(
    project_id: int,
    data: FindingCreate,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    finding_id = create_finding(
        current_user["user_id"],
        project_id,
        data
    )

    return {
        "status": "success",
        "project_id": project_id,
        "finding_id": finding_id
    }


@app.get("/projects/{project_id}/findings")
def list_findings(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "success",
        "project_id": project_id,
        "findings": get_findings_by_project(
            current_user["user_id"],
            project_id
        )
    }


@app.get("/findings/{finding_id}")
def read_finding(
    finding_id: int,
    current_user: dict = Depends(get_current_user)
):
    finding = get_finding_by_id(current_user["user_id"], finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "status": "success",
        "finding": finding
    }


@app.delete("/findings/{finding_id}")
def remove_finding(
    finding_id: int,
    current_user: dict = Depends(get_current_user)
):
    deleted = delete_finding(current_user["user_id"], finding_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "status": "success",
        "message": "Finding deleted"
    }


@app.post("/projects/{project_id}/scan")
def run_project_scan(
    project_id: int,
    data: ScanInput,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    options = {
        "profile": data.profile,
        "scan_depth": data.scan_depth,
        "max_pages": data.max_pages,
        "include_ports": data.include_ports,
        "include_common_paths": data.include_common_paths,
        "include_recon": data.include_recon,
        "allow_private": data.allow_private,
        "path_profile": data.path_profile,
        "concurrency": data.concurrency,
        "ports": data.ports,
    }

    try:
        result = run_web_scan(project["target_url"], options)
    except ScannerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    scan_id = save_scan(
        current_user["user_id"],
        project_id,
        project["target_url"],
        data.profile,
        result
    )

    return {
        "status": "success",
        "scan": {
            "id": scan_id,
            "project_id": project_id,
            "target_url": project["target_url"],
            "status": "completed",
            "profile": data.profile,
            "summary": result["summary"],
            "result": result
        }
    }


@app.get("/projects/{project_id}/scans")
def list_project_scans(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "success",
        "project_id": project_id,
        "scans": get_scans_by_project(current_user["user_id"], project_id)
    }


@app.get("/scans/{scan_id}")
def read_scan(
    scan_id: int,
    current_user: dict = Depends(get_current_user)
):
    scan = get_scan_by_id(current_user["user_id"], scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "status": "success",
        "scan": scan
    }


@app.post("/generate-report")
def generate_report(
    data: FindingInput,
    current_user: dict = Depends(get_current_user)
):
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is missing")

    project = get_project_by_id(current_user["user_id"], data.project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    prompt = build_report_prompt(data)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity consultant writing professional penetration testing reports."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3
        )

        report = response.choices[0].message.content

        report_id = save_report(
            current_user["user_id"],
            data.project_id,
            data,
            report
        )

        return {
            "status": "success",
            "project_id": data.project_id,
            "report_id": report_id,
            "report": report
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(e)}"
        )


@app.post("/suggest-attacks")
def suggest_attacks(
    data: FindingInput,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], data.project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    prompt = build_attack_suggestion_prompt(data)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity consultant helping with safe testing planning."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.4
        )

        return {
            "status": "success",
            "project_id": data.project_id,
            "suggestions": response.choices[0].message.content
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Attack suggestion failed: {str(e)}"
        )


@app.get("/reports")
def list_reports(
    project_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    return {
        "status": "success",
        "reports": get_reports(current_user["user_id"], project_id)
    }


@app.get("/reports/{report_id}")
def read_report(
    report_id: int,
    current_user: dict = Depends(get_current_user)
):
    report = get_report_by_id(current_user["user_id"], report_id)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "status": "success",
        "report": report
    }


@app.get("/projects/{project_id}/final-report")
def generate_final_report(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    reports = get_full_reports_by_project(current_user["user_id"], project_id)
    findings = get_findings_by_project(current_user["user_id"], project_id)
    scans = get_scans_by_project(current_user["user_id"], project_id)

    if not reports and not findings and not scans:
        raise HTTPException(
            status_code=400,
            detail="No reports, findings, or scans found for this project"
        )

    if not OPENAI_API_KEY:
        return {
            "status": "success",
            "project_id": project_id,
            "generator": "local",
            "source_counts": {
                "reports": len(reports),
                "findings": len(findings),
                "scans": len(scans)
            },
            "final_report": build_final_report_markdown(project, reports, findings, scans)
        }

    prompt = build_final_report_prompt(project, reports, findings, scans)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity consultant preparing full penetration testing reports."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3
        )

        return {
            "status": "success",
            "project_id": project_id,
            "generator": "openai",
            "source_counts": {
                "reports": len(reports),
                "findings": len(findings),
                "scans": len(scans)
            },
            "final_report": response.choices[0].message.content
        }

    except Exception as e:
        return {
            "status": "success",
            "project_id": project_id,
            "generator": "local-fallback",
            "warning": f"OpenAI final report generation failed: {str(e)}",
            "source_counts": {
                "reports": len(reports),
                "findings": len(findings),
                "scans": len(scans)
            },
            "final_report": build_final_report_markdown(project, reports, findings, scans)
        }


@app.get("/projects/{project_id}/exploitability-review")
def generate_exploitability_review(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = get_findings_by_project(current_user["user_id"], project_id)
    scans = get_scans_by_project(current_user["user_id"], project_id)

    return {
        "status": "success",
        "project_id": project_id,
        "review": build_exploitability_assessment(project, findings, scans)
    }


@app.get("/projects/{project_id}/privilege-path-review")
def generate_privilege_path_review(
    project_id: int,
    current_user: dict = Depends(get_current_user)
):
    project = get_project_by_id(current_user["user_id"], project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = get_findings_by_project(current_user["user_id"], project_id)
    scans = get_scans_by_project(current_user["user_id"], project_id)

    return {
        "status": "success",
        "project_id": project_id,
        "review": build_privilege_path_assessment(project, findings, scans)
    }
