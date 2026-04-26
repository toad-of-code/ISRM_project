# ISRM Project Master Documentation (End-to-End Viva Guide)

## 1) Project Identity

| Field | Details |
|---|---|
| Project Title | Information Security Risk Management for a Student Management System |
| Application Domain | Web-based student records and assignment handling |
| Tech Stack | Python Flask, SQLite, HTML templates, Bootstrap |
| Security Validation | Bandit (SAST), OWASP ZAP (DAST), STRIDE threat model |
| Project Span | Phase 1 to Phase 8 |
| Final Outcome | Vulnerable build created, assessed, modeled, hardened, and re-verified |

Why this table matters in viva:
- It gives examiners context in under 30 seconds.
- It positions the project as a full secure SDLC exercise, not only coding.

---

## 2) Full Project Journey (Phase-Wise)

| Phase | Objective | Key Deliverable | Status |
|---|---|---|---|
| Phase 1 | Build intentionally vulnerable app | Vulnerable Flask app and database setup | Completed |
| Phase 2 | Define vulnerability map (V1 to V9) | Structured vulnerability list with exploit intent | Completed |
| Phase 3 | Run security assessment | Bandit and ZAP reports with severity analysis | Completed |
| Phase 4 | Integrate scanning in CI/CD | GitHub Actions security pipeline | Completed |
| Phase 5 | Threat modeling | STRIDE model mapped by component | Completed |
| Phase 6 | Attack simulation and impact analysis | Attack-chain documentation (maintained separately) | Completed (separate docs) |
| Phase 7 | Security hardening | Secured application implementation | Completed |
| Phase 8 | Retesting and verification | Before/after comparison and control effectiveness | Completed |

Why this table matters in viva:
- It proves process maturity from design to verification.
- It shows that security was treated as a lifecycle activity, not a one-time scan.

---

## 3) System Architecture Overview

### 3.1 Vulnerable Architecture (Initial)
- Authentication and session logic in server routes.
- Role trust based on insecure client-side values.
- SQL statements built with concatenated input.
- Upload and download paths with weak/no sanitization.
- Admin ping feature exposed command execution risk.

### 3.2 Hardened Architecture (Final)
- Parameterized SQL access.
- Password hashing and stronger authentication checks.
- Session-based CSRF protection for state-changing requests.
- Security headers applied globally in response middleware.
- Upload controls: extension, MIME checks, size limits.
- Safer subprocess invocation with strict input validation.
- Secure filename handling for download/upload path safety.

How to explain in viva:
- Initial build demonstrates realistic attack surface.
- Final build demonstrates defense-in-depth across layers: input, auth, session, headers, file handling, and operations.

---

## 4) Repository Structure and Purpose

| Path | Purpose in Project |
|---|---|
| app.py | Deliberately vulnerable application used for baseline attack and scan exercises |
| app2.py | Hardened application with implemented mitigations |
| database.py | Database initialization and utility operations |
| templates folder | Frontend pages for login, signup, dashboard, upload, admin actions |
| vulnerability_assessment_report.md | Phase 3 combined SAST/DAST analysis |
| phase_4_explanation.md | CI/CD pipeline stage explanations |
| phase5_6_report.md | STRIDE threat model content (Phase 5) |
| phase8_verification_report.md | Detailed before/after security verification |
| phase8_viva_defense_one_page.md | One-page summary for direct viva/slides |
| bandit_report.json | Baseline SAST machine output |
| bandit_report_app2.json | Post-hardening SAST machine output |
| zap_report.html and zap_full_report.html | Baseline DAST reports |
| zap_report_app2.html and zap_report_app2.json | Post-hardening DAST reports |
| security_audit.log | Security-related runtime logging evidence |

Why this table matters in viva:
- It maps every claim to an artifact.
- It helps examiners verify evidence quickly.

---

## 5) Phase 1 and 2: Vulnerable Build and Vulnerability Design

### 5.1 Purpose
The project intentionally started with exploitable security weaknesses to support realistic risk assessment and remediation learning outcomes.

### 5.2 Planned Vulnerability Set

| Vulnerability ID | Vulnerability Theme | Security Impact |
|---|---|---|
| V1 | SQL injection | Authentication bypass, data disclosure, data tampering |
| V2 | Broken auth (no lockout/rate limit) | Brute-force credential compromise |
| V3 | Insecure upload | Malicious file upload and possible code execution |
| V4 | Privilege escalation logic flaw | Student-to-admin escalation |
| V5 | Command injection | Arbitrary OS command execution |
| V6 | Session hijacking weakness | Session prediction or theft risk |
| V7 | Path traversal | Unauthorized file read |
| V8 | Information disclosure | Debug leakage, internal detail exposure |
| V9 | Sensitive data exposure | Plaintext password and credential compromise |

How to explain in viva:
- The vulnerable model was deliberate for educational ISRM demonstration.
- Each vulnerability maps to specific attack goals and security controls.

---

## 6) Phase 3: Vulnerability Assessment (SAST and DAST)

## 6.1 Tools Used and Why

| Tool | Type | Why It Was Used | Output Type |
|---|---|---|---|
| Bandit | SAST | Detect insecure Python coding patterns before runtime exploitation | Console and JSON report |
| OWASP ZAP Baseline | DAST Passive | Detect web security misconfiguration and missing controls safely | HTML and JSON report |
| OWASP ZAP Full Scan | DAST Active | Actively probe exploitability (for example SQL injection confirmation) | HTML report |

Tool methodology explanation for viva:
- SAST checks source code behavior patterns.
- DAST checks running application behavior over HTTP requests/responses.
- Using both improves coverage and confidence.

### 6.2 Baseline Scan Summary

| Metric | Baseline Result |
|---|---:|
| Bandit total findings | 7 |
| Bandit high findings | 2 |
| ZAP baseline alerts | 19 |
| ZAP full scan high | 1 |

### 6.3 Combined Risk View

| Risk Area | Observed in Baseline |
|---|---|
| SQL injection | Confirmed in login and search attack surface |
| Command injection | Unsafe command execution pattern present |
| Missing CSRF controls | Forms lacking anti-CSRF protection |
| Missing security headers | CSP, clickjacking and browser hardening gaps |
| Cookie hardening gaps | Missing attributes and weak session protections |

How to explain these tables:
- Table 1 answers how many findings.
- Table 2 answers what kinds of findings.
- Together they justify the hardening roadmap.

---

## 7) Phase 4: CI/CD Security Pipeline

### 7.1 Pipeline Design

| Stage | Function |
|---|---|
| Checkout and setup | Prepare code and Python environment |
| SAST stage | Run Bandit and produce artifact |
| DAST stage | Run ZAP baseline against running app |
| Security gate | Parse reports and fail build on high-severity findings |
| Artifact archival | Keep reports for auditability and grading evidence |

### 7.2 Security Gate Logic
- If Bandit high severity count is greater than zero, pipeline fails.
- If ZAP high risk count is greater than zero, pipeline fails.
- This enforces secure quality criteria automatically during development.

How to explain in viva:
- CI/CD shifted security left and made vulnerability checks repeatable.
- The gate prevents insecure code from being accepted silently.

---

## 8) Phase 5: STRIDE Threat Modeling

### 8.1 STRIDE Mapping Summary

| STRIDE Category | Example in Project |
|---|---|
| Spoofing | SQLi login bypass and predictable session misuse |
| Tampering | Cookie and command tampering risks |
| Repudiation | Lack of strong early-stage auditing/log evidence |
| Information Disclosure | Debug details, plaintext credential exposure |
| Denial of Service | Unrestricted operations and upload abuse potential |
| Elevation of Privilege | Student-to-admin escalation path |

### 8.2 Component-Level Modeling
Threats were mapped to:
- Login flow
- Session and cookie handling
- Dashboard search
- File upload/download
- Admin ping utility
- Database and web server behavior

How to explain in viva:
- STRIDE turned scan outputs into system-level threat reasoning.
- It helped prioritize controls by impact and likelihood.

---

## 9) Phase 6: Attack Simulation and Risk Demonstration

Note for viva clarity:
- Detailed Phase 6 evidence is maintained in separate project documents.
- This master file summarizes the simulation logic used for final defense narration.

### 9.1 Typical Attack Chain Demonstrated

| Step | Attack Action | Linked Weakness |
|---|---|---|
| 1 | Initial compromise through auth/search manipulation | V1 and V2 |
| 2 | Privilege movement using weak trust/session behavior | V4 and V6 |
| 3 | Command-level exploitation or data retrieval | V5 and V7 |
| 4 | Sensitive information exposure and persistence | V8 and V9 |

### 9.2 Impact Narrative
- Confidentiality impact: user and student data exposure.
- Integrity impact: unauthorized updates/deletions possible.
- Availability impact: command misuse and resource abuse risks.

How to explain in viva:
- Demonstrate that independent weaknesses can combine into severe multi-stage compromise.
- Emphasize business impact, not only technical exploit details.

---

## 10) Phase 7: Secure Code Methodology (Hardening)

### 10.1 Methodology Used

| Methodology Principle | How Applied in Code |
|---|---|
| Input validation | Regex and strict validation on identifiers, names, hostnames, numeric bounds |
| Output and browser hardening | Security headers for framing, sniffing, CSP, permissions |
| Safe data access | Parameterized SQL statements |
| Strong authentication | Hashed passwords and login control improvements |
| Session security | Signed server-side session handling and cookie policy |
| Request integrity | CSRF token generation and verification |
| File handling safety | Extension and MIME checks, size cap, safe filename usage |
| Command safety | Validated input and bounded subprocess usage pattern |

### 10.2 Core Security Controls Implemented

| Control | Security Problem Solved |
|---|---|
| Parameterized queries | SQL injection mitigation |
| Password hashing | Plaintext credential exposure mitigation |
| Rate limiting and lockout logic | Brute-force mitigation |
| CSRF protection | Cross-site request forgery mitigation |
| Global response headers | Clickjacking/XSS/configuration hardening |
| Secure cookie settings | Session theft and cross-site attachment risk reduction |
| Upload restrictions | Malicious upload risk reduction |
| Path sanitization | Traversal mitigation |

How to explain in viva:
- Hardening was not one patch; it was layered control architecture.
- Controls were selected to match specific baseline findings and STRIDE threats.

---

## 11) Phase 8: Retesting and Verification

### 11.1 Before vs After Security Outcome

| Category | Before Hardening | After Hardening | Improvement |
|---|---:|---:|---:|
| Bandit HIGH | 2 | 0 | 100 percent reduction |
| Bandit MEDIUM | 3 | 0 | 100 percent reduction |
| Bandit LOW | 2 | 0 | 100 percent reduction |
| Bandit TOTAL | 7 | 0 | 100 percent reduction |
| ZAP HIGH/FAIL | 1 | 0 | 100 percent reduction |
| ZAP Total alerts or warnings | 19 | 7 | 63.2 percent reduction |
| ZAP PASS checks | Not established in baseline format | 60 | Strong positive verification |

### 11.2 Control Effectiveness Summary

| Area | Before | After | Conclusion |
|---|---|---|---|
| SQLi defenses | Weak | Strong | Effective |
| Password and auth security | Weak | Strong | Effective |
| CSRF defenses | Missing | Enabled | Effective |
| Header-based hardening | Missing | Enabled | Effective |
| Cookie/session safety | Weak | Improved | Effective |
| Upload and path safety | Weak | Improved | Effective |
| Command safety | Weak | Improved | Effective |

### 11.3 Interpretation of Residual Warnings
Residual warnings in final ZAP output are largely low-risk or informational and do not represent unresolved critical exploitation vectors.

How to explain in viva:
- Focus on severity shift and exploitability reduction, not raw warning count alone.
- Final status: no high-severity unresolved findings.

---

## 12) Table Explanation Guide (For Examiner Questions)

If asked, use this quick framework:

### 12.1 How to read findings tables
- Columns Before and After show risk trajectory.
- Percentage change quantifies mitigation effectiveness.
- Severity bands (high/medium/low) prioritize business urgency.

### 12.2 How to read control tables
- Each row maps one risk to one or more controls.
- Evidence column links control to measurable scan or behavior outcomes.
- Conclusion column summarizes whether mitigation is accepted.

### 12.3 How to read pipeline table
- Stage-oriented rows prove repeatability and automation.
- Gate logic row proves policy enforcement and governance.

---

## 13) Tools, Commands, and Methodology Notes

### 13.1 Core Security Testing Commands Used

| Tool | Example Command Pattern | Purpose |
|---|---|---|
| Bandit | bandit app.py database.py -f json -o bandit_report.json | Baseline static risk detection |
| Bandit (hardened) | bandit app2.py database.py -f json -o bandit_report_app2.json | Post-hardening verification |
| ZAP Baseline | docker run ... zap-baseline.py ... | Passive/quick dynamic assessment |
| ZAP Full | docker run ... zap-full-scan.py ... | Active exploitability probing |

### 13.2 Security Engineering Methodologies Applied

| Method | Description | Where Used |
|---|---|---|
| Secure SDLC progression | Build, assess, model, patch, verify | Full project lifecycle |
| Threat modeling | STRIDE categorization and component threat mapping | Phase 5 |
| Defense-in-depth | Layered controls rather than single fix | Phase 7 |
| Verification-driven closure | Re-run scans and compare objective metrics | Phase 8 |

---

## 14) Viva Delivery Script (Structured)

### 14.1 60-Second Opening
This project implements the full ISRM lifecycle on a Flask-based student management system. We first created a controlled vulnerable version with nine intentional weaknesses, then assessed it using Bandit and OWASP ZAP, modeled threats using STRIDE, integrated scanning into CI/CD, hardened the system with layered controls, and finally re-tested to quantify risk reduction. Final evidence shows zero high-severity findings after hardening and strong control effectiveness across all major attack surfaces.

### 14.2 2-Minute Deep-Dive Flow
1. Introduce baseline attack surface and vulnerability IDs.
2. Present scan evidence and severity profile.
3. Explain threat model and risk prioritization.
4. Show CI/CD security gate to prove automation maturity.
5. Demonstrate hardening controls and mapping to each vulnerability.
6. Conclude with before/after metrics and final acceptance.

### 14.3 Closing Line
The project demonstrates measurable security maturity improvement from exploitable baseline to verified hardened state, supported by repeatable testing, documented threat modeling, and objective before/after evidence.

---

## 15) Final Submission Checklist

| Item | Included |
|---|---|
| Vulnerable source and secure source | Yes |
| Baseline SAST and DAST evidence | Yes |
| CI/CD workflow and explanation | Yes |
| STRIDE threat model | Yes |
| Hardening implementation details | Yes |
| Retest and comparison evidence | Yes |
| One-page viva summary | Yes |
| Master end-to-end document | Yes (this file) |

---

## 16) Suggested Appendix References for Viva
- vulnerability_assessment_report.md
- phase_4_explanation.md
- phase5_6_report.md
- phase8_verification_report.md
- phase8_viva_defense_one_page.md
- bandit_report.json
- bandit_report_app2.json
- zap_full_report.html
- zap_report_app2.html
- zap_report_app2.json

This master document is designed for direct viva use: narrative plus evidence plus explainable tables.
