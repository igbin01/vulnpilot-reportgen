from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

from prompts import (
    build_report_prompt,
    build_attack_suggestion_prompt,
    build_final_report_prompt
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
    get_project_by_id
)
from auth import hash_password, verify_password, create_access_token, get_current_user
from config import OPENAI_API_KEY, OPENAI_MODEL


app = FastAPI(title="VulnPilot ReportGen", version="0.2.0")

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


class UserInput(BaseModel):
    username: str
    password: str


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
        "version": "0.2.0"
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

    if not reports:
        raise HTTPException(status_code=400, detail="No reports found for this project")

    prompt = build_final_report_prompt(project, reports)

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
            "final_report": response.choices[0].message.content
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Final report generation failed: {str(e)}"
        )