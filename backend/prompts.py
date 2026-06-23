def build_report_prompt(data):
    return f"""
You are a senior cybersecurity consultant preparing a professional penetration testing report.

Use only the evidence provided by the user. Do not invent endpoints, payloads, users, systems, or business details.

Finding Details:
- Vulnerability Type: {data.vulnerability_type}
- Affected Endpoint: {data.affected_endpoint}
- Severity: {data.severity}
- Report Style: {data.report_style}
- Output Format: {data.output_format}

Testing Evidence:
- Test Performed: {data.test_performed}
- Observed Result: {data.observed_result}
- Stated Impact: {data.impact}

Write the report with these sections:
1. Title
2. Severity
3. Description
4. Steps to Reproduce
5. Business Impact
6. Technical Impact
7. Remediation
8. Retest Recommendation

Rules:
- Match the requested report style.
- Match the requested output format.
- Be clear, practical, and client-ready.
- Do not exaggerate severity beyond what the user selected.
- If evidence is limited, state that clearly.
- Remediation should be specific and actionable.
"""
    

def build_attack_suggestion_prompt(data):
    return f"""
You are a senior cybersecurity consultant helping with safe, authorized penetration testing planning.

The user is working on an authorized assessment. Provide practical test planning guidance without destructive exploitation.

Target Information:
- Vulnerability Area: {data.vulnerability_type}
- Endpoint / Asset: {data.affected_endpoint}
- Known Test Performed: {data.test_performed}
- Observed Result: {data.observed_result}
- Impact Concern: {data.impact}

Produce output with these sections:
1. Likely Attack Surface
2. Suggested Safe Tests
3. Evidence to Collect
4. Risk Indicators
5. What to Avoid
6. Next Best Step

Rules:
- Keep suggestions defensive, safe, and authorization-focused.
- Do not include malware, persistence, stealth, evasion, credential theft, or destructive steps.
- Avoid giving instructions that would enable unauthorized exploitation.
- Focus on validation, access control testing, documentation, logging, remediation, and retesting.
- Be concise, practical, and professional.
"""

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def build_final_report_prompt(project, reports, findings=None, scans=None):
    combined_reports = "\n\n---\n\n".join(reports)
    finding_summary = format_findings_for_prompt(findings or [])
    scan_summary = format_scans_for_prompt(scans or [])

    return f"""
You are a senior cybersecurity consultant preparing a complete final penetration testing report.

Use only the project information and findings provided below. Do not invent systems, endpoints, vulnerabilities, or evidence.

Project Information:
- Project Name: {project["name"]}
- Target URL: {project["target_url"]}
- Application Type: {project["app_type"]}
- Authentication Type: {project["auth_type"]}
- Description: {project["description"]}

Individual Finding Reports:
{combined_reports}

Saved Findings:
{finding_summary}

Scan Summaries:
{scan_summary}

Create a polished final penetration testing report with these sections:

1. Cover Page
2. Executive Summary
3. Scope
4. Methodology
5. Findings Summary Table
6. Detailed Findings
7. Overall Risk Rating
8. Strategic Recommendations
9. Retest Recommendation
10. Conclusion

Rules:
- Make it client-ready and professional.
- Keep all findings grounded in the provided reports, saved findings, and scan summaries.
- Do not invent new vulnerabilities.
- Summarize clearly for both technical and non-technical readers.
- Use Markdown formatting.
- If there are no findings, state that no validated findings were provided.
"""


def build_final_report_markdown(project, reports=None, findings=None, scans=None):
    reports = reports or []
    findings = sort_findings(findings or [])
    scans = scans or []
    finding_rows = "\n".join(
        f"| {item.get('severity', 'Info')} | {item.get('vulnerability_type', 'Finding')} | {item.get('affected_endpoint', '-')} |"
        for item in findings
    ) or "| Info | No validated findings were provided | - |"
    detailed_findings = "\n\n".join(format_finding_detail(item) for item in findings)
    generated_reports = "\n\n---\n\n".join(reports)
    scan_section = format_scan_report_section(scans)

    if not detailed_findings:
        detailed_findings = "No saved findings are currently attached to this project."

    if generated_reports:
        detailed_findings = f"{detailed_findings}\n\n## Generated Finding Narratives\n\n{generated_reports}"

    return f"""# Final Penetration Testing Report

## Cover Page

**Project:** {project["name"]}
**Target:** {project["target_url"]}
**Application Type:** {project["app_type"]}
**Authentication Type:** {project["auth_type"]}

## Executive Summary

This report summarizes the validated findings, scan observations, and assessment evidence currently saved in VulnPilot for this project. The report is generated only from stored project data and does not infer unvalidated vulnerabilities.

## Scope

{project.get("description") or "Scope notes were not provided."}

## Methodology

The assessment record includes project scoping, same-origin reconnaissance, bounded content enumeration, optional port checks, saved findings, and generated finding narratives where available. All results should be reviewed against the authorized rules of engagement before delivery.

## Findings Summary Table

| Severity | Finding | Affected Asset |
| --- | --- | --- |
{finding_rows}

## Detailed Findings

{detailed_findings}

## Reconnaissance and Scan Summary

{scan_section}

## Overall Risk Rating

{overall_risk(findings)}

## Strategic Recommendations

- Prioritize remediation for Critical and High severity findings first.
- Validate access control and authentication boundaries for all affected endpoints.
- Harden security headers, cookie attributes, and exposed diagnostic paths.
- Retest all remediated findings and preserve evidence for closure.

## Retest Recommendation

Perform a focused retest after remediation. Retesting should confirm that each finding is no longer reproducible, related controls are covered, and no regression was introduced.

## Conclusion

The report is ready for review and can be refined with additional findings, generated narratives, or updated scan evidence as the assessment progresses.
"""


def build_exploitability_assessment(project, findings=None, scans=None):
    findings = sort_findings(findings or [])
    scans = scans or []
    finding_section = "\n\n".join(format_exploitability_item(item) for item in findings)

    if not finding_section:
        finding_section = "No saved findings are available. Add validated findings to produce a finding-specific exploitability review."

    return f"""# Exploitability Review

## Project

**Name:** {project["name"]}
**Target:** {project["target_url"]}

## Purpose

This review provides a safe, authorization-focused exploitability analysis. It does not perform exploitation, stealth, evasion, credential theft, persistence, or destructive actions.

## Exploitability Summary

{finding_section}

## Evidence Collection Plan

- Capture request and response pairs for each affected endpoint.
- Record the authenticated role, tenant, and preconditions used during validation.
- Preserve timestamps, account identifiers used for testing, and screenshots where relevant.
- Confirm server-side impact without accessing unauthorized data or disrupting service.

## Reporting Notes

Use this output to guide manual validation and client-ready reporting. Any exploitation beyond non-destructive validation must be separately authorized in the rules of engagement.

## Scan Context

{format_scan_report_section(scans)}
"""


def build_privilege_path_assessment(project, findings=None, scans=None):
    findings = sort_findings(findings or [])
    access_findings = [
        item for item in findings
        if any(keyword in " ".join([
            item.get("vulnerability_type", ""),
            item.get("test_performed", ""),
            item.get("observed_result", ""),
            item.get("impact", ""),
        ]).lower() for keyword in [
            "access",
            "authorization",
            "auth",
            "role",
            "permission",
            "tenant",
            "idor",
            "privilege",
            "admin",
            "jwt",
            "session",
        ])
    ]

    if not access_findings:
        access_findings = findings[:5]

    finding_section = "\n\n".join(format_privilege_item(item) for item in access_findings)
    if not finding_section:
        finding_section = "No saved findings currently indicate a privilege or authorization path. Add access-control findings to produce a stronger review."

    return f"""# Privilege Path Review

## Project

**Name:** {project["name"]}
**Target:** {project["target_url"]}

## Purpose

This review identifies potential privilege escalation and authorization-risk paths from saved evidence. It provides safe validation guidance and report language without executing privilege escalation, stealth, evasion, credential theft, or persistence.

## Potential Privilege Paths

{finding_section}

## Safe Validation Checklist

- Confirm the lowest-privileged role that can reach each affected endpoint.
- Compare behavior across user, manager, admin, and cross-tenant test accounts where authorized.
- Verify server-side authorization on every sensitive object reference and workflow transition.
- Document denied versus allowed requests with clear role and tenant context.
- Retest remediations using the same role matrix.

## Control Recommendations

- Enforce authorization on the server for every privileged action.
- Use deny-by-default role checks and tenant scoping.
- Avoid trusting client-side role indicators or mutable tokens without server verification.
- Add audit logging for privileged actions and failed authorization checks.

## Scan Context

{format_scan_report_section(scans)}
"""


def format_findings_for_prompt(findings):
    if not findings:
        return "No saved findings."

    return "\n".join(
        f"- [{item.get('severity', 'Info')}] {item.get('vulnerability_type', 'Finding')} at {item.get('affected_endpoint', '-')}: {item.get('observed_result', '')}"
        for item in sort_findings(findings)
    )


def format_scans_for_prompt(scans):
    if not scans:
        return "No scan summaries."

    lines = []
    for scan in scans[:5]:
        summary = scan.get("summary", {})
        lines.append(
            f"- {scan.get('profile', 'scan')} at {scan.get('created_at', '')}: "
            f"{summary.get('pages_crawled', 0)} pages, "
            f"{summary.get('endpoints_discovered', 0)} endpoints, "
            f"{summary.get('interesting_paths', 0)} interesting paths, "
            f"{summary.get('open_ports', 0)} open ports"
        )
    return "\n".join(lines)


def format_scan_report_section(scans):
    if not scans:
        return "No scan summaries are currently saved for this project."

    lines = []
    for scan in scans[:5]:
        summary = scan.get("summary", {})
        lines.append(
            f"- **{scan.get('profile', 'scan')}** ({scan.get('created_at', 'unknown time')}): "
            f"{summary.get('pages_crawled', 0)} pages crawled, "
            f"{summary.get('urls_discovered', 0)} URLs discovered, "
            f"{summary.get('endpoints_discovered', 0)} endpoints identified, "
            f"{summary.get('interesting_paths', 0)} interesting paths, "
            f"{summary.get('open_ports', 0)} open ports, "
            f"{summary.get('observation_count', 0)} observations."
        )
    return "\n".join(lines)


def format_finding_detail(item):
    return f"""### {item.get('vulnerability_type', 'Finding')}

**Severity:** {item.get('severity', 'Info')}
**Affected Endpoint:** {item.get('affected_endpoint', '-')}

**Test Performed:** {item.get('test_performed') or 'Not documented.'}

**Observed Result:** {item.get('observed_result') or 'Not documented.'}

**Impact:** {item.get('impact') or 'Not documented.'}

**Remediation Guidance:** Validate the affected control server-side, add regression tests, and retest using the same evidence path."""


def format_exploitability_item(item):
    return f"""### {item.get('vulnerability_type', 'Finding')}

- **Severity:** {item.get('severity', 'Info')}
- **Affected Endpoint:** {item.get('affected_endpoint', '-')}
- **Exploitability Factors:** Preconditions, authentication state, input control, and reproducibility should be validated from the saved evidence.
- **Current Evidence:** {item.get('observed_result') or 'No observed result documented.'}
- **Safe Validation:** Reproduce only the documented behavior in an authorized environment, capture request/response evidence, and avoid accessing data outside the agreed scope.
- **Report Impact:** {item.get('impact') or 'Impact requires additional documentation.'}"""


def format_privilege_item(item):
    return f"""### {item.get('vulnerability_type', 'Finding')}

- **Severity:** {item.get('severity', 'Info')}
- **Affected Endpoint:** {item.get('affected_endpoint', '-')}
- **Potential Privilege Path:** Review whether the documented behavior crosses role, tenant, ownership, or workflow boundaries.
- **Evidence:** {item.get('observed_result') or 'No observed result documented.'}
- **Safe Validation:** Test with authorized role-paired accounts and document allowed/denied outcomes without bypassing controls or using stealth.
- **Recommended Control:** Enforce server-side authorization and add audit logging for privileged transitions."""


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "")).lower(), 0),
        reverse=True,
    )


def overall_risk(findings):
    if not findings:
        return "No validated findings are currently saved, so no overall technical risk rating is assigned."

    highest = sort_findings(findings)[0].get("severity", "Info")
    return f"The current overall risk is assessed as **{highest}** based on the highest-severity saved finding. Adjust this rating after client review, compensating controls, and environmental context are confirmed."
