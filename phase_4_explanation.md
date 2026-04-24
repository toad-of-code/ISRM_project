# ISRM Phase 4 — CI/CD Pipeline Explanation

## Pipeline Overview

The GitHub Actions workflow (`.github/workflows/security.yml`) automates the Phase 3 security scanning process. It runs on every push/PR to the `main` branch and consists of **3 jobs**:

```
┌──────────────┐     ┌──────────────┐     ┌───────────────────┐
│  SAST Scan   │────▶│  DAST Scan   │────▶│  Security Gate    │
│  (Bandit)    │     │  (OWASP ZAP) │     │  (Pass/Fail)      │
└──────────────┘     └──────────────┘     └───────────────────┘
```

---

## Stage-by-Stage Explanation

### Stage 1: SAST — Bandit Scan (`sast-scan`)

| Step | What It Does |
|------|-------------|
| **Checkout Code** | Pulls the latest application code from the GitHub repository using `actions/checkout@v4` |
| **Setup Python** | Installs Python 3.12 and caches pip packages so future builds run faster |
| **Install Dependencies** | Installs Flask (from `requirements.txt`) and the Bandit security scanner |
| **Run Bandit (JSON)** | Executes `bandit app.py database.py -f json -o bandit_report.json` to generate a machine-readable report |
| **Run Bandit (Console)** | Runs Bandit again with `-ll` flag (Medium+ severity) for readable console output; **fails the step if high-severity issues are found** |
| **Upload Report** | Archives `bandit_report.json` as a downloadable artifact (kept for 30 days) |

### Stage 2: DAST — OWASP ZAP Scan (`dast-scan`)

| Step | What It Does |
|------|-------------|
| **Checkout Code** | Same as Stage 1 — pulls the code so we can start the Flask app |
| **Setup Python** | Installs Python 3.12 and project dependencies |
| **Start Flask App** | Launches `python app.py` in the background and waits 5 seconds for it to be ready on port 5000 |
| **Run ZAP Scan** | Uses the official `zaproxy/action-baseline` GitHub Action to run a ZAP baseline scan against `http://localhost:5000`, generating both HTML and JSON reports |
| **Upload Reports** | Archives `zap_report.html` and `zap_report.json` as downloadable artifacts |

### Stage 3: Security Quality Gate (`security-gate`)

| Step | What It Does |
|------|-------------|
| **Download Reports** | Downloads the Bandit and ZAP artifacts from the previous stages |
| **Check Bandit Findings** | Parses `bandit_report.json` and counts vulnerabilities with `issue_severity == "HIGH"`. If any exist → **build fails** |
| **Check ZAP Findings** | Parses `zap_report.json` and counts alerts with `riskcode == 3` (High risk). If any exist → **build fails** |
| **Final Verdict** | Prints a pass/fail summary |

---

## How the Build Fails on High-Severity Vulnerabilities

The pipeline uses two mechanisms:

1. **Bandit exit code** — In the console output step, Bandit naturally returns a non-zero exit code when it finds issues at Medium severity or above (`-ll` flag). This causes the GitHub Actions step to fail.

2. **Security Quality Gate** — The final job explicitly parses the JSON reports and checks for high-severity findings using a Python one-liner. If the count is greater than 0, it runs `exit 1` which fails the build.

---

## How to Use

1. Push the `.github/workflows/security.yml` file to your GitHub repository
2. The pipeline triggers automatically on push or PR to `main`
3. View results in the **Actions** tab on GitHub
4. Download scan reports from the **Artifacts** section of each run
5. You can also trigger it manually via **Actions → Security Scan Pipeline → Run workflow**

---

## File Location

```
ISRM/
├── .github/
│   └── workflows/
│       └── security.yml    ← CI/CD Pipeline (this file)
├── app.py
├── database.py
├── requirements.txt
└── ...
```
