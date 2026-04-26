# Phase 8 Viva/Defense One-Page Summary

## Project Snapshot
| Item | Value |
|---|---|
| Project | ISRM Student Management System |
| Baseline Build | app.py (intentionally vulnerable) |
| Hardened Build | app2.py |
| Verification Tools | Bandit 1.9.4 (SAST), OWASP ZAP 2.17.0 (DAST) |
| Verification Date | 26-Apr-2026 |

## Before vs After: Headline Metrics
| Metric | Before (Baseline) | After (Hardened) | Outcome |
|---|---:|---:|---|
| Bandit HIGH findings | 2 | 0 | 100% removed |
| Bandit MEDIUM findings | 3 | 0 | 100% removed |
| Bandit LOW findings | 2 | 0 | 100% removed |
| Bandit Total findings | 7 | 0 | 100% removed |
| ZAP HIGH/FAIL | 1 | 0 | 100% removed |
| ZAP Total alerts/warnings | 19 | 7 | 63.2% reduction |
| ZAP PASS checks | N/A in baseline | 60 | Strong hardening evidence |

## Control-by-Control Comparison
| Vulnerability Area | Before | After | Evidence |
|---|---|---|---|
| SQL Injection | Vulnerable | Secured | Parameterized queries; Bandit B608 cleared |
| Command Injection | Risk present | Secured | Safe subprocess pattern; no unsafe finding |
| Password Security | Weak/plaintext risk | Secured | pbkdf2:sha256 hashing + policy |
| CSRF | Missing | Secured | Token generation + validation; ZAP 10202 pass |
| Security Headers | Missing | Secured | X-Frame-Options, CSP, X-Content-Type-Options, etc. |
| Session/Cookies | Weak flags | Secured | HttpOnly + SameSite + Secure |
| File Upload | Weak checks | Secured | Extension/MIME/size validation |
| Path Traversal | Risk present | Secured | secure_filename and safe file handling |
| Debug/Info Leakage | Exposed risk | Secured | debug disabled, reduced disclosure |

## Residual Warnings (After Hardening)
| Warning Type | Interpretation | Risk Level |
|---|---|---|
| Server version header | Informational exposure | Low |
| CSP unsafe-inline note | Acceptable for current templates | Low |
| Form-related potential XSS flags | Contextual/likely false-positive under template escaping | Low |
| COEP header not set | Optional modern hardening | Info |

## Final Defense Statement
| Decision Point | Conclusion |
|---|---|
| Are critical vulnerabilities fixed? | Yes (0 HIGH in final SAST/DAST) |
| Is hardening effective? | Yes (all major controls implemented and validated) |
| Is system ready for submission/demo? | Yes |
| Next production step | Enforce HTTPS + HSTS and continue periodic scans |

## 30-Second Viva Script
"We compared the vulnerable baseline app with the hardened app using Bandit and OWASP ZAP. The baseline had 7 Bandit findings including 2 high, and 1 high-severity ZAP issue. After implementing parameterized queries, CSRF protection, secure session cookies, security headers, upload validation, and password hashing, the hardened build showed 0 Bandit findings and 0 high-severity ZAP failures. This demonstrates full closure of critical risk and strong security improvement suitable for deployment with standard production controls like HTTPS and HSTS."