# PhishGuard — Cyber Ready Clinic Capstone

A local, demo-ready **Phishing Reporting & Training Portal** built with Python Flask, SQLite, HTML and CSS. All users, email examples and reports are fictional. No real emails are sent or received.

## Start on Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**.
https://awareness-training-and-phishing-report.onrender.com/dashboard

### Demo logins

| Role | Username | Password |
| --- | --- | --- |
| Employee | `employee` | `DemoEmployee!2026` |
| Analyst | `analyst` | `DemoAnalyst!2026` |
| Administrator | `admin` | `DemoAdmin!2026` |
| Employee (HR) | `HumanR` | `HumanResources1@` |

**Use only locally.** Demo credentials are public and unsuitable for real deployment.

## Live demo walkthrough (5–7 minutes)

1. Log in as `employee`. Open **Training Center**, answer the four fictional scenarios, and view explanations.
2. Open **Report Phishing**. Submit sender `support@company-security-example.com`, subject `URGENT: Verify your account`, and reason `Unrecognized domain and urgent request for credentials`.
3. Open **My Reports** to show the new pending ticket number.
4. Sign out; log in as `analyst`. Open **Analyst Queue**, review the new ticket, choose **Confirmed phishing**, add an analyst note, and save.
5. Sign out; log in as `admin`. Open **Administration** to show quiz participation and audit history.

## Run automated tests

```powershell
python -m unittest discover -s tests -v
```

## Scope and security limitations

- Local demonstration only; no external mail ingestion, Microsoft 365 integration, attachments, automated phishing campaigns, or malicious-link browsing.
- Demo credentials and synthetic reports are seeded automatically; use a fresh local database to reset.
- CSRF validation, server-side quiz scoring, hashed passwords, role checks, parameterized SQL, security headers, and escaped templates are implemented.
- Before production: add HTTPS, stable secret management, MFA/SSO, rate limiting, password recovery, audit retention policy, backups, deployment hardening, real tenant integration, and client-approved data handling.
- Training examples are educational heuristics; a message classified 'likely legitimate' is not guaranteed safe.

## Assessment alignment

- **Ready 5:** No formal end-user security awareness training; phishing reporting procedure is partial.
- **Discover 5:** Microsoft 365 / Exchange usage, small staff and MSP, many volunteers and board members, sensitive organizational information.
- **Project spreadsheet:** `training-01` (Phishing Awareness Training), `training-06` (Phishing Reporting Culture Kit), `incident-res-03` (Phishing Triage Playbook), and `email-securi-18` (Phishing Simulation Starter Kit).
- **October 2026 brainstorm:** Automated phishing campaign/training and cybersecurity education concepts.

The capstone combines training and reporting/triage workflows. It does not implement an actual phishing simulation campaign.
