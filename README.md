# Penetration Testing & Vulnerability Assessment CLI Tool

A modular, Python-based CLI security auditing suite built to simulate cyber-attacks, identify infrastructure misconfigurations, and audit web application resilience.

---

## Features

- **Concurrent TCP Port Scanner & Banner Grabber**:
  - Multi-threaded scanning across common service ports.
  - Service banner grabbing *(reading initial greeting messages from daemons to identify exposed versions)*.
  - Flags insecure services (e.g., Telnet on port 23, cleartext FTP on port 21, and publicly exposed database ports).

- **Web Security Misconfiguration & Vulnerability Auditor**:
  - Probes for critical exposed secrets and cloud credentials (`/.env`, `/.aws/credentials`, `/id_rsa`, `/actuator/env`, `/wp-config.php.bak` = `CRITICAL`).
  - Detects exposed source code and database backups (`/.git/HEAD`, `/backup.zip`, `/config.php.bak` = `HIGH`).
  - Probes for CORS misconfigurations (arbitrary origin reflection with credentials enabled = `HIGH`).
  - Flags unencrypted HTTP endpoints lacking automatic HTTPS redirection (`HIGH`).
  - Inspects cookie attributes for missing `HttpOnly` and `Secure` flags (`MEDIUM` / `HIGH`).
  - Detects open directory indexing / server browsing listings (`HIGH`).
  - Probes for dangerous HTTP methods (`TRACE` method enabling Cross-Site Tracing = `MEDIUM`).
  - Audits optional defense-in-depth headers (HSTS, CSP, X-Frame-Options) under `Web Hardening` (`LOW` / `INFO`).
  - Inspects SSL/TLS certificates (validity, expiration countdown, cipher suite).

- **Rate-Limiting & Availability Resilience Auditor (DoS Defense Check)**:
  - Dispatches controlled, strictly bounded bursts of concurrent requests (up to 50 requests, max concurrency 10).
  - Detects active defensive mechanisms: `HTTP 429 Too Many Requests` (rate limiting) and `HTTP 403/503` (WAF interception).
  - Measures latency degradation under load.

- **Peak-Severity Scoring & Multi-Format Reporting**:
  - Automatically sorts all discovered vulnerabilities from **highest (CRITICAL) to lowest (INFO)** severity.
  - Interactive full-terminal dashboard with color-coded severity badges powered by `rich`.
  - Export capabilities to structured **JSON** and GitHub-flavored **Markdown** reports.

---

## Project Structure

```
Penetration testing tool/
├── main.py                     # CLI entrypoint script
├── pyproject.toml              # Project configuration & dependencies
├── pentest_tool/
│   ├── __init__.py
│   ├── cli.py                  # CLI argument parser and interactive wizard
│   ├── config.py               # Port definitions, headers catalog, sensitive paths
│   ├── reporter.py             # Rich console tables, risk scoring, JSON/MD export
│   └── modules/
│       ├── __init__.py
│       ├── base.py             # BaseModule and Finding abstractions
│       ├── port_scanner.py     # Concurrent TCP scanner & banner grabber
│       ├── web_auditor.py      # HTTP security headers, paths & SSL inspection
│       └── stress_auditor.py   # Availability & rate-limiting resilience auditor
├── reports/                    # Generated audit outputs & academic documentation
│   └── Penetration_Testing_Tool_Report.docx
├── scripts/
│   └── mock_target.py          # Local vulnerable test server for live demos
└── tests/
    └── test_audit.py           # Automated unit test suite
```

---

## Installation & Setup

1. **Activate the Virtual Environment**:
   ```bash
   source .venv/bin/activate
   ```

2. **Install Dependencies** (if not already installed):
   ```bash
   pip install rich requests
   ```

---

## Usage

### 1. Interactive Mode
Run without arguments to launch the interactive wizard:
```bash
python main.py
```

### 2. Full Automated Audit
Runs port scanning, web security assessment, and availability stress testing:
```bash
python main.py full https://example.com --json report.json --md report.md
```

### 3. Port Scanning Only
```bash
# Scan default top ports:
python main.py ports 127.0.0.1

# Scan specific ports or ranges:
python main.py ports 127.0.0.1 -p 22,80,443,8000-8080
```

### 4. Web Security & SSL Audit
```bash
python main.py web https://example.com --md web_report.md
```

### 5. Rate-Limiting & Availability Resilience Audit
```bash
python main.py resilience http://localhost:8888 -n 25 -c 5
```

---

## Local Demonstration & Testing

To test the tool in a safe, controlled environment:

1. **Start the local vulnerable mock server**:
   ```bash
   python scripts/mock_target.py 8888
   ```

2. **Run a full audit against the mock target** in another terminal:
   ```bash
   python main.py full http://127.0.0.1:8888 -p 8888 --requests 20 --concurrency 5
   ```

3. **Run automated test suite**:
   ```bash
   python -m unittest tests/test_audit.py
   ```
