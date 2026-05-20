# DevSecOps Pipeline — Security-First CI/CD

A production-grade, fully automated DevSecOps pipeline that injects security
checks at every stage of development. Every tool is **free and open-source**.
Zero dollars spent.

## Architecture

```
Developer machine          GitHub Actions Pipeline                    Production
─────────────────   ────────────────────────────────────────────   ─────────────
git commit
    │
    ▼
[Gitleaks]          Stage 1: TruffleHog — full git history scan
pre-commit hook         │
blocks secrets          ▼
before push         Stage 2: Semgrep — SAST source code scan
                        │
                        ▼
                    Stage 3: OWASP Dep-Check + pip-audit
                        │
                        ▼
                    Stage 4: pytest — security unit tests
                        │
                        ▼
                    Stage 5: Trivy + Hadolint — container scan
                        │
                        ▼
                    Stage 6: OWASP ZAP — active DAST scan
                        │
                        ▼
                    Stage 7: Security summary report
                        │
                        ▼ (only if all stages pass)
                    Stage 8: Deploy ──────────────────────────► Render (free)
```

## Tools Used (all free)

| Stage | Tool | What it finds |
|-------|------|---------------|
| Pre-commit | **Gitleaks** | Secrets before they're pushed |
| 1 — Secret scan | **TruffleHog v3** | Secrets in full git history |
| 2 — SAST | **Semgrep OSS** | SQL injection, XSS, hardcoded creds in code |
| 3 — SCA | **OWASP Dependency-Check + pip-audit** | CVEs in dependencies |
| 4 — Tests | **pytest** | Security regression tests |
| 5 — Container | **Trivy + Hadolint** | CVEs in Docker image layers, Dockerfile bad practices |
| 6 — DAST | **OWASP ZAP** | Vulnerabilities in the running app (OWASP Top 10) |
| 7 — Report | **Custom Python script** | Aggregated summary posted to PR |
| Deploy | **Render free tier** | Free hosting |

## Quick Start

### 1 — Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/devsecops-pipeline.git
cd devsecops-pipeline
```

### 2 — Install pre-commit hooks (runs Gitleaks locally)

```bash
pip install pre-commit
pre-commit install
# Now every `git commit` automatically scans for secrets
```

### 3 — Run the app locally

```bash
cd app
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000
```

### 4 — Run the tests locally

```bash
pip install pytest pytest-cov
pytest tests/ -v
```

### 5 — Run Semgrep locally

```bash
pip install semgrep
semgrep --config=auto --config=.semgrep.yml app/
```

### 6 — Set up GitHub repository

1. Push this code to a new GitHub repo (can be public for unlimited free Actions minutes)
2. Go to **Settings → Secrets and variables → Actions** and add:
   - `FLASK_SECRET_KEY` — any long random string (run `python -c "import secrets; print(secrets.token_hex(32))"`)
   - `RENDER_DEPLOY_HOOK_URL` — from your Render dashboard (optional, for auto-deploy)
   - `RENDER_APP_URL` — your Render app URL (optional)
3. Push to `main` — the pipeline starts automatically

### 7 — Deploy to Render (free)

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Render auto-detects `render.yaml` and configures everything
4. Set `FLASK_SECRET_KEY` in the Render dashboard under Environment
5. Click Deploy

## What the Pipeline Protects Against

| Attack | How it's caught |
|--------|----------------|
| Leaked AWS keys / API tokens | TruffleHog (Stage 1), Gitleaks (pre-commit) |
| SQL injection | Semgrep rule + pytest security tests |
| Cross-site scripting (XSS) | Semgrep XSS rules + pytest + ZAP active scan |
| Vulnerable dependency (e.g. Log4Shell) | pip-audit + OWASP Dependency-Check |
| Container escape via OS CVE | Trivy image scan |
| Misconfigured HTTP headers | ZAP passive scan + pytest header tests |
| Running app as root | Hadolint Dockerfile lint |
| Stack trace leakage | pytest (verifies 500 errors are generic) |
| Brute force | Flask-Limiter rate limiting |
| Clickjacking | X-Frame-Options: DENY header |

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml   # The entire CI/CD pipeline
├── app/
│   ├── app.py                       # Flask web application
│   ├── requirements.txt             # Python dependencies
│   ├── Dockerfile                   # Hardened Docker image
│   └── templates/
│       └── index.html               # Frontend
├── tests/
│   └── test_security.py             # Security-focused test suite
├── scripts/
│   └── generate_report.py           # Security report aggregator
├── .pre-commit-config.yaml          # Pre-commit hook config
├── .gitleaks.toml                   # Gitleaks custom rules
├── .semgrep.yml                     # Custom SAST rules
├── .zap-rules.tsv                   # ZAP finding overrides
├── dependency-check-suppressions.xml
├── render.yaml                      # Render deployment config
└── README.md
```

## Security Findings Dashboard

After each pipeline run:
- **GitHub Security tab** — Semgrep + Trivy + Hadolint findings in SARIF format
- **GitHub Step Summary** — the auto-generated security report
- **PR comments** — security summary posted automatically on every pull request
- **Artifacts** — full HTML/JSON reports downloadable from each pipeline run

## Resume Talking Points

- "Built a multi-stage DevSecOps pipeline covering SAST, SCA, DAST, secret scanning, and container scanning"
- "Integrated OWASP ZAP for active penetration testing against a staging environment on every PR"
- "Wrote custom Semgrep rules targeting project-specific SQL injection and secret patterns"
- "Implemented security-as-code: all gates are version-controlled YAML/TOML, not dashboard click-ops"
- "Pipeline generates consolidated security reports posted automatically to pull request comments"
- "Entire pipeline costs $0 using free-tier tools and platforms"
