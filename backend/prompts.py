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

def build_final_report_prompt(project, reports):
    combined_reports = "\n\n---\n\n".join(reports)

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
- Keep all findings grounded in the provided reports.
- Do not invent new vulnerabilities.
- Summarize clearly for both technical and non-technical readers.
- Use Markdown formatting.
- If there are no findings, state that no validated findings were provided.
"""