# VulnScope

### Security Assessment and Vulnerability Scanning Platform

VulnScope is a Python-based web application that brings together multiple security assessment tools in one dashboard. It helps assess web security configurations, identify exposed network services, inspect SSL/TLS certificates, and review potential web vulnerabilities.

Built with Python and Flask, VulnScope includes scan history, risk scoring, SQLite storage, and PDF report generation.

## Features

### Implemented Modules

- **Security Header Scanner**
  - Checks important HTTP security headers.
  - Identifies missing security headers.
  - Classifies findings by severity.
  - Calculates a preliminary security risk level.

- **Network Port Scanner**
  - Integrates with Nmap.
  - Performs TCP connect scans.
  - Identifies open ports and services.
  - Retrieves basic service and version information.

- **SSL/TLS Scanner**
  - Inspects HTTPS configurations.
  - Identifies negotiated TLS versions and cipher suites.
  - Retrieves certificate subject and issuer information.
  - Checks certificate validity and expiration.

- **OWASP ZAP Integration**
  - Connects to the OWASP ZAP API.
  - Performs website spidering.
  - Runs passive security analysis.
  - Retrieves and displays vulnerability findings.

- **Risk Scoring**
  - Calculates finding scores.
  - Classifies findings by severity and confidence.
  - Generates an overall risk summary.

- **Dashboard and Scan History**
  - Centralized web dashboard.
  - Separate scanning interfaces.
  - SQLite-based scan history.
  - Historical assessment results.

- **PDF Reporting**
  - Generates downloadable assessment reports.
  - Presents scan findings and assessment information.

- **Application Security**
  - Administrator authentication.
  - Environment-based configuration.
  - Session management.
  - Input validation and protected application routes.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| SQLite | Database |
| Requests | HTTP communication |
| Nmap | Network scanning |
| OWASP ZAP | Web application security analysis |
| ReportLab | PDF generation |
| HTML5 | Frontend structure |
| CSS3 | Styling |
| JavaScript | Frontend functionality |
| Git and GitHub | Version control |

## Project Structure

```text
VulnScope/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
│
├── scanners/
│   ├── header_scanner.py
│   ├── port_scanner.py
│   ├── ssl_scanner.py
│   └── zap_scanner.py
│
├── templates/
│   ├── index.html
│   ├── port_scan.html
│   ├── scan_history.html
│   ├── ssl_scan.html
│   └── zap_scan.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│
├── utils/
│   ├── database.py
│   ├── report_generator.py
│   └── risk_scoring.py
│
├── database/
├── reports/
└── tests/
```

## Installation and Setup

### 1. Clone the repository

```powershell
git clone https://github.com/hakunamatata14/VulnScope.git
```

### 2. Navigate to the project

```powershell
cd VulnScope
```

### 3. Create a virtual environment

```powershell
python -m venv .venv
```

### 4. Activate the virtual environment

For Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 5. Install Python dependencies

```powershell
python -m pip install -r requirements.txt
```

### 6. Install external scanning tools

Install and configure:

- Nmap
- OWASP ZAP

Make sure Nmap is available in your system PATH.

Start OWASP ZAP and enable its API on the local loopback interface.

### 7. Configure environment variables

Create a `.env` file in the project root.

Example configuration:

```env
SECRET_KEY=generate_a_long_random_secret_key
VULNSCOPE_USERNAME=admin
VULNSCOPE_PASSWORD=replace_with_a_unique_password_of_at_least_16_characters
ZAP_BASE_URL=http://127.0.0.1:8080
ZAP_API_KEY=your_zap_api_key
```

Generate a secret key with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Use your own strong administrator password and the API key configured in OWASP ZAP.

**Never upload `.env` to GitHub.**

### 8. Run the application

```powershell
python app.py
```

### 9. Open VulnScope

Visit:

```text
http://127.0.0.1:5000/
```

Sign in using the administrator credentials configured in `.env`.

## How to Use

1. Start the VulnScope application.
2. Sign in to the administrator dashboard.
3. Select the required security assessment module.
4. Enter an authorized target.
5. Start the scan.
6. Review the scan results and severity classifications.
7. Check previous scans in scan history.
8. Generate and download available PDF reports.

## Security and Scanning Scope

VulnScope combines several types of assessment:

| Module | Assessment |
|---|---|
| Header Scanner | HTTP security header configuration |
| Port Scanner | Open TCP ports and service detection |
| SSL/TLS Scanner | TLS configuration and certificate information |
| OWASP ZAP | Spidering and passive web vulnerability analysis |
| Risk Scoring | Finding severity, confidence and risk prioritization |

The ZAP integration performs spidering and passive analysis; it does not perform active attack scans.

Risk scores are assessment aids and should not be treated as a substitute for a full professional security assessment.

## Legal Disclaimer

VulnScope is intended for educational purposes, cybersecurity learning, and authorized security assessments.

Only scan systems that you own or have explicit permission to assess.

Do not use this software to access, disrupt, or test systems without authorization. The developer is not responsible for misuse or damage resulting from unauthorized activity.

## Future Improvements

Potential future enhancements include:

- More advanced vulnerability classification.
- Improved PDF reporting and analytics.
- Additional security assessment modules.
- Automated regression and integration testing.
- Enhanced dashboard visualizations.
- Production deployment hardening.

## Author

**GitHub:** https://github.com/hakunamatata14

**Project:** VulnScope

---

*Developed as a hands-on cybersecurity, Python development, and vulnerability assessment portfolio project.*