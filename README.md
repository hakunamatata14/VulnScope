
# VulnScope

### Hybrid Vulnerability Assessment and Penetration Testing Platform

VulnScope is a Python-based web application designed to perform security assessments, identify missing HTTP security headers, maintain scan history, and generate PDF vulnerability assessment reports.

The project demonstrates practical cybersecurity concepts, Python development, web application security, vulnerability assessment, and automated reporting.

---

## Project Overview

VulnScope provides a web-based dashboard for conducting basic security assessments of authorized web targets.

The platform currently analyzes HTTP security headers, classifies missing headers by severity, stores scan history in SQLite, and generates downloadable PDF reports.

## Features

### Implemented Features

- Web-based security assessment dashboard
- HTTP security header analysis
- Detection of missing security headers
- High, Medium, and Low severity classification
- Preliminary risk-level calculation
- SQLite scan history management
- Automated PDF report generation
- PDF report downloads
- Flask session management
- Environment-based secret key configuration
- Basic target URL validation
- Git version control and GitHub integration

### Planned Features

- Nmap port and service scanning
- SSL/TLS configuration analysis
- OWASP ZAP integration
- CVSS-informed vulnerability scoring
- Advanced vulnerability classification
- Detailed assessment reporting
- Automated security testing

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Flask | Web application framework |
| Requests | HTTP requests |
| SQLite | Scan history storage |
| ReportLab | PDF report generation |
| HTML5 | Dashboard structure |
| CSS3 | Dashboard styling |
| JavaScript | Frontend functionality |
| Git | Version control |
| GitHub | Source code hosting |

---

## Project Architecture

```text
VulnScope/
│
├── app.py
├── requirements.txt
├── .gitignore
│
├── scanners/
│   └── header_scanner.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│
├── utils/
│   ├── database.py
│   └── report_generator.py
│
├── database/
├── reports/
└── tests/
```

---

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/hakunamatata14/VulnScope.git
```

### 2. Navigate to the project directory

```bash
cd VulnScope
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file in the project root directory.

Add a randomly generated secret key:

```text
SECRET_KEY=your_random_secret_key
```

Do not upload your `.env` file to GitHub.

### 7. Start the application

```bash
python app.py
```

### 8. Open the dashboard

Visit:

http://127.0.0.1:5000/

---

## How to Use

1. Start the Flask application.
2. Open the VulnScope dashboard.
3. Enter an authorized public HTTP or HTTPS target.
4. Start the security header assessment.
5. Review detected missing headers and severity classifications.
6. Review the scan history.
7. Generate and download the PDF assessment report.

---

## Security Assessment Scope

The current security header scanner checks the following HTTP response headers:

| Security Header | Purpose |
|---|---|
| Content-Security-Policy | Helps mitigate content injection and XSS |
| Strict-Transport-Security | Enforces HTTPS connections |
| X-Content-Type-Options | Helps prevent MIME sniffing |
| X-Frame-Options | Helps mitigate clickjacking |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Controls browser feature access |

The preliminary risk level is based on missing security headers. It is not a CVSS score or a complete vulnerability assessment.

---

## Legal Disclaimer

VulnScope is developed for educational purposes, cybersecurity learning, and authorized security assessments.

Only assess systems that you own or have explicit permission to test.

The developer is not responsible for unauthorized use or damage resulting from misuse of this software.

---

## Future Development

VulnScope is an ongoing cybersecurity portfolio project. Planned enhancements include network scanning, SSL/TLS analysis, OWASP ZAP integration, and advanced vulnerability scoring.

---

## Author

**GitHub:** https://github.com/hakunamatata14

**Project:** VulnScope

---

*Built as a hands-on cybersecurity and Python development portfolio project.*
