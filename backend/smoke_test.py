import os
import tempfile


def main():
    db_file = tempfile.NamedTemporaryFile(
        prefix="vulnpilot_smoke_",
        suffix=".db",
        delete=False,
    )
    db_path = db_file.name
    db_file.close()
    os.environ["DATABASE_NAME"] = db_path
    os.environ["OPENAI_API_KEY"] = ""

    try:
        from database import save_scan
        from main import (
            FindingCreate,
            ForgotPasswordInput,
            ProjectInput,
            ResetPasswordInput,
            UserInput,
            add_finding,
            create_new_project,
            forgot_password,
            generate_exploitability_review,
            generate_final_report,
            generate_privilege_path_review,
            list_findings,
            list_project_scans,
            list_projects,
            login_user,
            read_finding,
            read_project,
            read_scan,
            register_user,
            remove_finding,
            remove_project,
            reset_password,
        )
        from scanner import normalize_ports, normalize_url, summarize_result

        user = UserInput(username="smoke-user", password="secret123")
        registered = register_user(user)
        assert registered["status"] == "success"

        login = login_user(user)
        assert login["token_type"] == "bearer"
        assert login["access_token"]

        current_user = {
            "username": user.username,
            "user_id": registered["user_id"],
        }

        project = ProjectInput(
            name="Smoke Project",
            target_url="https://example.com",
            app_type="Web app",
            auth_type="None",
            description="Created by backend smoke test",
        )
        created_project = create_new_project(project, current_user=current_user)
        project_id = created_project["project_id"]

        projects = list_projects(current_user=current_user)
        assert len(projects["projects"]) == 1
        assert projects["projects"][0]["id"] == project_id

        fetched_project = read_project(project_id, current_user=current_user)
        assert fetched_project["project"]["target_url"] == project.target_url

        finding = FindingCreate(
            vulnerability_type="Cross-site scripting",
            affected_endpoint="/search",
            severity="Medium",
            test_performed="Submitted a benign script payload.",
            observed_result="The payload was reflected unencoded.",
            impact="An attacker could execute script in a user's browser.",
        )
        created_finding = add_finding(
            project_id,
            finding,
            current_user=current_user,
        )
        finding_id = created_finding["finding_id"]

        findings = list_findings(project_id, current_user=current_user)
        assert len(findings["findings"]) == 1
        assert findings["findings"][0]["id"] == finding_id

        fetched_finding = read_finding(finding_id, current_user=current_user)
        assert fetched_finding["finding"]["severity"] == finding.severity

        scan_result = {
            "target_url": project.target_url,
            "hostname": "example.com",
            "summary": {
                "pages_crawled": 1,
                "observations": 1,
                "interesting_paths": 0,
            },
            "observations": ["Smoke scan persistence check"],
            "errors": [],
        }
        scan_id = save_scan(
            current_user["user_id"],
            project_id,
            project.target_url,
            "web-baseline",
            scan_result,
        )

        scans = list_project_scans(project_id, current_user=current_user)
        assert len(scans["scans"]) == 1
        assert scans["scans"][0]["id"] == scan_id
        assert scans["scans"][0]["summary"]["pages_crawled"] == 1

        scan = read_scan(scan_id, current_user=current_user)
        assert scan["scan"]["result"]["observations"] == scan_result["observations"]

        final_report = generate_final_report(project_id, current_user=current_user)
        assert final_report["status"] == "success"
        assert final_report["generator"] == "local"
        assert "Final Penetration Testing Report" in final_report["final_report"]
        assert "Cross-site scripting" in final_report["final_report"]

        exploitability = generate_exploitability_review(project_id, current_user=current_user)
        assert exploitability["status"] == "success"
        assert "Exploitability Review" in exploitability["review"]
        assert "stealth" in exploitability["review"].lower()

        privilege = generate_privilege_path_review(project_id, current_user=current_user)
        assert privilege["status"] == "success"
        assert "Privilege Path Review" in privilege["review"]
        assert "server-side authorization" in privilege["review"]

        reset_request = forgot_password(ForgotPasswordInput(username=user.username))
        assert reset_request["status"] == "success"
        assert reset_request["reset_token"]

        reset = reset_password(
            ResetPasswordInput(
                token=reset_request["reset_token"],
                new_password="newsecret123",
            )
        )
        assert reset["status"] == "success"

        new_login = login_user(
            UserInput(username=user.username, password="newsecret123")
        )
        assert new_login["access_token"]

        removed = remove_finding(finding_id, current_user=current_user)
        assert removed["status"] == "success"
        assert list_findings(project_id, current_user=current_user)["findings"] == []

        deleted_project = remove_project(project_id, current_user=current_user)
        assert deleted_project["status"] == "success"
        assert list_projects(current_user=current_user)["projects"] == []

        assert normalize_url("example.com") == "https://example.com/"
        assert normalize_ports(["80", "443", "80", "bad", 70000]) == [80, 443]
        scanner_summary = summarize_result({
            "target_url": "https://example.com/",
            "hostname": "example.com",
            "http": {"status_code": 200, "title": "Example"},
            "dns": {"ip_addresses": ["93.184.216.34"]},
            "crawl": {
                "pages": [{"url": "https://example.com/"}],
                "discovered_urls": ["/api"],
                "forms": [],
                "assets": ["/app.js"],
            },
            "common_paths": [{"interesting": True}],
            "ports": [{"status": "open"}],
            "security_headers": {"x-frame-options": {"present": False}},
            "observations": [{"title": "Example"}],
            "recon": {"endpoints": [{"value": "/api/test"}]},
            "timing": {"elapsed_seconds": 0.25},
        })
        assert scanner_summary["assets_discovered"] == 1
        assert scanner_summary["endpoints_discovered"] == 1
        assert scanner_summary["elapsed_seconds"] == 0.25

        print("smoke ok")
    finally:
        try:
            os.unlink(db_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
