# ISRM Phase 5 — STRIDE Threat Modeling

---

## Phase 5: STRIDE Threat Model

| Application Component | Threat Category (STRIDE) | Threat Description |
|----------------------|--------------------------|-------------------|
| Login System | **Spoofing** | SQL Injection (V1) allows an attacker to bypass authentication by injecting `' OR '1'='1' --` as the username, impersonating any user including admin |
| Login System | **Spoofing** | Predictable session IDs (V6) follow the pattern `username_counter` — an attacker can guess a valid session ID and impersonate another user |
| Login System | **Spoofing** | Brute force attack (V2) — no rate-limiting or account lockout allows unlimited password guessing to compromise accounts |
| Login System | **Repudiation** | No audit logging — failed and successful login attempts are not recorded, so malicious access cannot be traced back to an attacker |
| Login System | **Information Disclosure** | Plaintext password storage (V9) — if the database is accessed, all user credentials are immediately exposed without any hashing |
| Cookie/Session System | **Tampering** | Role stored in plaintext cookie (V4) — an attacker can change `document.cookie = "role=admin"` in the browser to grant themselves admin privileges |
| Cookie/Session System | **Tampering** | Cookies lack HttpOnly, Secure, and SameSite flags — vulnerable to JavaScript theft, transmission over HTTP, and cross-site attachment |
| Cookie/Session System | **Elevation of Privilege** | Cookie tampering (V4) allows any authenticated student user to escalate to admin role and access admin-only tools like the ping utility |
| Dashboard Search | **Spoofing** | SQL Injection in search (V1) — admin search query is concatenated via f-string, allowing UNION-based extraction of all usernames and passwords |
| Dashboard Search | **Information Disclosure** | SQL Injection enables data exfiltration — attacker can extract the entire `users` table including plaintext passwords via crafted search input |
| File Upload Module | **Tampering** | Insecure file upload (V3) — no file type, extension, or MIME validation allows uploading of malicious scripts (e.g., web shells) to the server |
| File Upload Module | **Denial of Service** | No file size limit — an attacker can upload extremely large files to fill server disk space and crash the application |
| File Upload Module | **Elevation of Privilege** | Uploaded web shell (V3) can execute arbitrary code on the server with the Flask process's privileges, leading to full system compromise |
| File Download Module | **Information Disclosure** | Path traversal (V7) — unsanitized `../` sequences in the `file` parameter allow downloading any file on the server, including `app.py`, `database.py`, and `student_mgmt.db` |
| Admin Ping Tool | **Tampering** | Command injection (V5) — user input passed to `subprocess.run()` with `shell=True` allows injecting arbitrary OS commands (e.g., `; cat /etc/passwd`) |
| Admin Ping Tool | **Elevation of Privilege** | Combined with cookie tampering (V4→V5), any user can access the admin tool and execute OS commands, achieving full remote code execution on the server |
| Admin Ping Tool | **Denial of Service** | Command injection can be used to shut down the server, delete files, or consume all system resources |
| Database | **Information Disclosure** | Plaintext passwords in SQLite (V9) — combined with path traversal (V7), the entire `student_mgmt.db` file can be downloaded and all credentials extracted |
| Database | **Tampering** | SQL Injection (V1) can be used to INSERT, UPDATE, or DELETE records, modifying student data, grades, or creating rogue admin accounts |
| Web Server (Flask) | **Information Disclosure** | Debug mode enabled (V8) — exposes full stack traces, source code, file paths, and the interactive Werkzeug debugger to any user who triggers an error |
| Web Server (Flask) | **Information Disclosure** | Hardcoded weak secret key `supersecretkey123` — if discovered, an attacker can forge Flask session cookies |
| Web Server (Flask) | **Information Disclosure** | Server header leaks Werkzeug/Flask version information, aiding attacker reconnaissance |
