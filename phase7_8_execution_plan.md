# Phase 7-8 Execution Plan

## Goal
Complete the secured version of the student management system and verify the mitigations with fresh scans and a before/after comparison.

## Scope
- In scope: Phase 7 code hardening in `app2.py`, required template updates, and Phase 8 retesting/reporting.
- Out of scope: Changing the existing Phase 1-3 deliverables and Phase 6 calculations. Any gaps there will be noted only, not edited.

## Plan
1. Confirm current secure-code gaps in `app2.py` and templates.
2. Add CSRF protection and security headers to `app2.py`.
3. Harden session cookies and session lifetime settings.
4. Port the missing admin student CRUD routes into `app2.py` with secure authorization.
5. Add form validation and upload hardening.
6. Update templates for CSRF tokens and any route/form alignment issues.
7. Run validation checks and confirm the app still boots.
8. Re-run Bandit and OWASP ZAP against the secured app.
9. Create the Phase 8 comparison report with before/after findings and control effectiveness.

## Deliverables
- Updated `app2.py`
- Updated templates under `templates/`
- Fresh Phase 8 scan outputs
- Before/after control effectiveness report

## Success Criteria
- No missing route errors for admin student actions.
- Security headers and CSRF protection are in place.
- Session cookies are hardened.
- Bandit/ZAP results show reduced findings versus the baseline reports.
- A concise Phase 8 verification report is available in the workspace.
