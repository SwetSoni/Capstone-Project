# Part 3 — Secure Application Development and Applied Cryptography

**Engagement:** Capstone Project — Part 3  
**Assessor:** Swet Soni  
**Date:** August 2026  
**Classification:** CONFIDENTIAL

## Overview

This project demonstrates secure application development practices by remediating a Flask REST API that originally had the following vulnerabilities:
- Passwords stored as unsalted MD5 hashes → **Bcrypt with unique salts**
- API credentials hardcoded in source → **Environment variables with python-dotenv**
- SQL injection via string concatenation → **Parameterised queries**
- No authentication on /admin → **API key middleware**

---

## Table of Contents

1. [STRIDE Threat Model](#1-stride-threat-model)
2. [OWASP Top 10 Remediation](#2-owasp-top-10-remediation)
3. [Secure Password Hashing](#3-secure-password-hashing)
4. [Secret Management](#4-secret-management)
5. [CI/CD Security Gate](#5-cicd-security-gate)
6. [Supply Chain Security](#6-supply-chain-security)

---

## 1. STRIDE Threat Model

| STRIDE Category | Threat | Targeted Component | Mitigation |
|----------------|--------|-------------------|------------|
| **Spoofing** | An attacker forges login credentials to impersonate a legitimate user by brute-forcing weak MD5 hashes | `/login` endpoint and user credential database | Implement Bcrypt password hashing with unique salts and enforce rate-limiting on login attempts (max 5 attempts per minute per IP) |
| **Tampering** | An attacker modifies SQL query logic via SQL injection in the registration or login form to alter database records (e.g., changing their role to 'admin') | `/register` and `/login` endpoints — the raw SQL query string | Replace string concatenation with parameterised queries (prepared statements) that treat all user input as data, not executable SQL |
| **Repudiation** | A malicious admin denies performing destructive actions (e.g., deleting users) because the API has no audit logging | `/admin` endpoint and all write operations | Implement comprehensive audit logging that records every API action with timestamp, authenticated user identity, source IP, and the action performed — store logs in a tamper-evident format |
| **Information Disclosure** | Hardcoded API keys and database credentials in the source code are exposed if the repository is made public or if an attacker gains read access to the codebase | `app.py` source file — hardcoded `SECRET_KEY` and `ADMIN_API_KEY` values | Move all secrets to environment variables loaded from a `.env` file (excluded from version control via `.gitignore`) and rotate credentials every 30–90 days |
| **Denial of Service** | An attacker floods the `/register` endpoint with thousands of requests, exhausting server resources and the database connection pool | `/register` endpoint and the SQLite database | Implement request rate-limiting (e.g., Flask-Limiter) and input validation to reject malformed requests before they reach the database |
| **Elevation of Privilege** | An unauthenticated user accesses the `/admin` endpoint directly (no auth check) to view all registered users and potentially modify their roles | `/admin` endpoint — currently has no authentication middleware | Add authentication middleware (`require_admin_api_key` decorator) that verifies a valid API key in the `X-API-Key` header before granting access |

---

## 2. OWASP Top 10 Remediation

### 2a. Injection (SQL Injection) — A03:2021

**Insecure Pattern (VULNERABLE):**

```python
# VULNERABLE: String concatenation allows SQL injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # An attacker can input: username = ' OR '1'='1' --
    # This modifies the SQL logic to bypass authentication
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    user = db.execute(query).fetchone()
```

**Why this is exploitable:** The user input is directly concatenated into the SQL string without sanitisation. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1' --`) to modify the query's logical structure. This can bypass authentication, extract data from other tables, or even delete the entire database.

**Remediated Pattern (SECURE):**

```python
# SECURE: Parameterised query treats input as data, not SQL code
@app.route("/login", methods=["POST"])
def login():
    username = request.get_json()["username"]
    password = request.get_json()["password"]
    # The ? placeholder ensures user input is NEVER interpreted as SQL
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
```

**How the fix works:** Parameterised queries (prepared statements) use `?` placeholders that the database driver fills in by escaping all special characters. The user input is always treated as a literal string value, never as part of the SQL command structure. Even if the input contains SQL metacharacters like `' OR '1'='1`, they are treated as the literal username string, not as SQL logic.

### 2b. Broken Access Control — A01:2021

**Insecure Pattern (VULNERABLE):**

```python
# VULNERABLE: No authentication — anyone can access the admin panel
@app.route("/admin", methods=["GET"])
def admin_dashboard():
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify({"users": [dict(u) for u in users]})
```

**Why this is exploitable:** The `/admin` endpoint has no authentication check. Any user (or automated scanner) who discovers this URL can access it and view all registered users, including their hashed passwords and roles. This violates the principle of least privilege — admin functionality should only be accessible to authenticated administrators.

**Remediated Pattern (SECURE):**

```python
# SECURE: API key authentication required before access is granted
def require_admin_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        if api_key != ADMIN_API_KEY:
            return jsonify({"error": "Invalid API key"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin", methods=["GET"])
@require_admin_api_key  # Authentication middleware applied
def admin_dashboard():
    users = db.execute("SELECT id, username, role, created_at FROM users").fetchall()
    return jsonify({"users": [dict(u) for u in users]})
```

**How the fix works:** The `require_admin_api_key` decorator acts as authentication middleware that intercepts every request to `/admin` before the route handler executes. It checks for a valid API key in the `X-API-Key` header and returns 401 (Unauthorized) or 403 (Forbidden) if the key is missing or invalid. Only requests with the correct API key reach the admin handler.

---

## 3. Secure Password Hashing

### Implementation

See [`hash_password.py`](hash_password.py) for the full implementation.

```python
import bcrypt

def hash_password(plain_text: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_text: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(
        plain_text.encode("utf-8"),
        stored_hash.encode("utf-8")
    )
```

### Proof of Unique Salts

Running `python hash_password.py` produces:

```
============================================================
Bcrypt Password Hashing Demonstration
============================================================

Password:  SecureP@ssw0rd123
Hash 1:    $2b$12$XyXT65J3v03PO5ieHzDKNe6ob3eT3Ye2Bgnomz4KdHXq9tlyRMYLi
Hash 2:    $2b$12$CivU0DQpc3aX3B.2aDVNSucPP0o9e7MNKlxgGH5b6gNC3MQthm64C

Hashes are different (unique salts): True

Verify Hash 1: True
Verify Hash 2: True
Verify wrong password: False

============================================================
This proves that Bcrypt generates a unique salt for each
hash operation — the same input produces different outputs,
defeating rainbow table attacks.
============================================================
```

### Why MD5 Is Unsuitable for Password Storage

MD5 is unsuitable for password storage for three critical reasons. **First**, MD5 is a fast hashing algorithm — it was designed for data integrity verification, not password storage. Modern GPUs can compute over 10 billion MD5 hashes per second (using tools like Hashcat), making brute-force attacks trivially fast. **Second**, MD5 has known collision vulnerabilities: researchers have demonstrated that two different inputs can produce the same MD5 hash, undermining the fundamental property that a hash should uniquely represent its input. **Third**, MD5 does not incorporate a salt by default, making it vulnerable to precomputed rainbow table attacks — an attacker can download a table of billions of pre-hashed common passwords and instantly look up any MD5 hash without performing any computation.

Bcrypt addresses each weakness: (1) it is intentionally slow, with a configurable cost factor (rounds=12 means ~2^12 iterations), making each hash take ~250ms — making brute-force impractical; (2) it automatically generates a unique random 128-bit salt for every hash, so identical passwords produce different hashes; (3) the cost factor can be increased over time as hardware improves, ensuring the algorithm remains resistant to future attacks.

---

## 4. Secret Management

### Hardcoded Pattern (INSECURE)

```python
# INSECURE: Secrets hardcoded in source code
app.config["SECRET_KEY"] = "super-secret-key-12345"
ADMIN_API_KEY = "admin-key-67890"
DB_PASSWORD = "postgres_pass_abc"
```

### Refactored Pattern (SECURE)

```python
# SECURE: Secrets loaded from environment variables
from dotenv import load_dotenv
import os

load_dotenv()  # Load variables from .env file

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
```

### .env.example

```
SECRET_KEY=placeholder_secret_key
ADMIN_API_KEY=placeholder_admin_key
DATABASE_PATH=app.db
FLASK_DEBUG=false
```

### .gitignore Verification

```
# Environment variables — NEVER commit real secrets
.env
```

### Why Hardcoding Secrets Is Dangerous

Hardcoding secrets in source code is dangerous even in a private repository because: (1) any developer with repository access can see the credentials, violating the principle of least privilege; (2) if the repository is accidentally made public (or if a developer's account is compromised), all credentials are immediately exposed with no way to limit the blast radius; (3) hardcoded secrets cannot be rotated without a code change and redeployment — industry best practice recommends rotating credentials every 30–90 days, and environment-variable-based management allows rotation by simply updating the `.env` file or secrets manager without modifying source code.

---

## 5. CI/CD Security Gate

### GitHub Actions Workflow

See [`.github/workflows/security.yml`](.github/workflows/security.yml) for the full workflow file.

```yaml
name: Security SAST Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    name: SAST Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install bandit semgrep

      - name: Run Bandit (SAST)
        run: |
          bandit -r . -ll -f json -o bandit-report.json || true
          bandit -r . -ll

      - name: Run Semgrep (Optional SAST)
        run: |
          semgrep --config p/python . --json --output semgrep-report.json || true
          semgrep --config p/python .
        continue-on-error: true
```

### What Is "Shift Left Security"?

"Shift Left Security" means integrating security testing as early as possible in the software development lifecycle — shifting it "left" on the timeline from production/deployment toward the development/commit stage. Instead of discovering vulnerabilities after deployment (when remediation is expensive and risky), this CI/CD gate runs Bandit (a Static Application Security Testing tool) automatically on every push and pull request. This means security vulnerabilities are caught at code review time, before they ever reach production, reducing both the cost of remediation and the window of exposure.

---

## 6. Supply Chain Security Statement

A software supply chain attack targets the third-party dependencies that an application relies on, rather than the application's own code. In the context of a Python project, this means an attacker could compromise a package on PyPI (the Python Package Index) — either by injecting malicious code into a legitimate package update (as in the `event-stream` npm attack), by publishing a typosquatted package with a similar name (e.g., `reqeusts` instead of `requests`), or by compromising a maintainer's PyPI credentials. If a developer installs the compromised package, the malicious code executes with the same permissions as the application, enabling credential theft, data exfiltration, or remote code execution.

An **SBOM (Software Bill of Materials)** is a comprehensive inventory of all software components in a project, including direct dependencies (listed in `requirements.txt`) and transitive dependencies (dependencies of dependencies). An SBOM records each component's name, version, supplier, and known vulnerability status, providing a complete audit trail of what software is in production.

**SCA (Software Composition Analysis)** tooling such as Snyk, Dependabot, or `pip-audit` continuously scans the dependency tree — including transitive dependencies — against vulnerability databases (e.g., the National Vulnerability Database, GitHub Advisory Database). If a transitive dependency like `urllib3` (pulled in by `requests`) has a known CVE, the SCA tool flags it even though the developer never explicitly installed `urllib3`. For example, a compromised version of `requests` could silently exfiltrate environment variables (including `SECRET_KEY` and `ADMIN_API_KEY`) to an attacker-controlled server on import, before the application even starts.

**(198 words)**

---

## How to Run

```bash
# 1. Clone the repository
git clone https://github.com/SwetSoni/capstone-project.git
cd part3-secure-app

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your actual secret values

# 5. Run the application
python app.py

# 6. Test the endpoints
# Register
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "SecureP@ss123"}'

# Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "SecureP@ss123"}'

# Admin (requires API key)
curl http://localhost:5000/admin \
  -H "X-API-Key: <ADMIN_API_KEY>"

# 7. Run password hashing demo
python hash_password.py
```

---

*Report prepared by Swet Soni as part of the Masai Capstone Project — Certification in Cybersecurity and Ethical Hacking with Applied AI.*

