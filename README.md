# privacy-risk-assessment-tool

A full-stack privacy and security scanning tool built with **Flask**, **MongoDB**, and third-party APIs. Designed for security researchers and developers to assess the privacy posture of websites.

## Features

- Security Header Scanner (via [Security Headers API](https://securityheaders.com))
- SSL/TLS Check (via [SSL Labs API](https://www.ssllabs.com/ssltest/))
- Tracker Detection (via DuckDuckGo)
- Breach Lookup (via [Have I Been Pwned](https://haveibeenpwned.com))
- ⚖ Compliance Check (GDPR, CCPA, ISO, NIST)
- Simple UI with Sidebar Navigation

## Tech Stack

- Flask (Python)
- MongoDB
- HTML/CSS/JS
- Bootstrap / Custom CSS
- REST APIs

## Key Note
# Mailtrap SMTP Config
- MAILTRAP_USERNAME = "ADD_YOUR_MAILTRAP_USERNAME"
- MAILTRAP_PASSWORD = "ADD_YOUR_MAILTRAP_PASSWORD"

## How to Run

```bash
git clone https://github.com/smil3xd34ult/privacy-risk-assessment-tool.git
cd privacy-risk-assessment-tool
pip install -r requirements.txt
python app.py
