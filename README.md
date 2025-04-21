# 🔐 Certificate Automation System — Documentation

## 📆 Overview

This automation tool handles **certificate lifecycle management**, including:
- SSL certificate expiration checks
- Automated CSR and private key generation
- Renewal via Venafi
- Certificate pickup and deployment

It supports multiple platforms:
- `apache2`
- `nginx`
- `Windows (IIS)`
- `NetApp`

## 🧬 Environment Setup

Ensure a `.env` file exists with:

```dotenv
NETAPP_IP=
NETAPP_USER=
NETAPP_PASSWORD=
dst=/your/cert/output/path
DBip=
venafiURL=
SysAdminUser=
SysPassword=
CollectionName=
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> Includes: `requests`, `loguru`, `python-dotenv`, `netmiko`, `paramiko`, `scp`, `pexpect`, `pydantic`.

## 📁 Project Structure

```
project/
│
├── cert_manager/
│   └── EditMongoDB.py         # MongoDB interaction logic
├── utils.py                   # Utilities (e.g., error log, shell command)
├── auth.py                    # Token management for Venafi
├── getCerts.py                    # Main automation script
├── .env                       # Environment secrets
├── log_*.log                  # Auto-generated runtime logs
└── requirements.txt
```

## 🔧 Key Functionalities

### 🔍 `get_ssl_expiry(domain, port=443)`
- Checks SSL certificate expiration in days using `openssl`.
- Logs remaining validity.

### 🔐 `generate_CSR_Key(fqdn, city, state, Country)`
- Uses `vcert gencsr` to generate a CSR and private key.
- Saves files to: `{dst}/{fqdn}/{fqdn}.csr` and `.key`.

### ♻️ Renewal Commands

Each method generates a CSR and renews a certificate:

- `renewCertApach2(id, fqdn)`
- `renewCertNginx(id, fqdn)`
- `renewCertWin(id, fqdn, pfxPassword)`
- `renewCertNetapp(id, fqdn)`

They execute `vcert renew` with appropriate flags for each server type.

### 📬 `pickup(id, fqdn)`
- Retrieves the certificate using Venafi Pickup ID.
- Saves the certificate chain and `.crt` to `{dst}/{fqdn}/`.

### 🛁 `generate_csr_from_netapp(fqdn)`
- Connects to NetApp using Netmiko.
- Runs `security certificate generate-csr` command.
- Extracts CSR and private key from command output.
- Saves files to local directory.

### 🧠 `get_cert_to_test()`
- Core automation loop:
  1. Fetches server list from MongoDB.
  2. Checks for certs expiring soon (`< config.days_remain`).
  3. Generates CSR.
  4. Renews the certificate using the appropriate platform method.
  5. Picks up the new cert.

## 🚰 Utilities

### ✅ `run_command(command_str)`
- Wrapper around `subprocess.run` to safely execute shell commands with error handling.

## 📨 Error Handling & Notifications

- Logging powered by **Loguru**.
- Logs are saved as: `log_HH-MM_DD-MM-YYYY.log`.
- `send_email_with_error_log` (optional) can be used to notify admins on failure.

## 📌 How to Use

### ↺ Trigger the Workflow

Run the main script manually or schedule with a cronjob:

```bash
python getCerts.py
```

## 🧚️ Testing & Debugging
- CSR/private key files are saved per `fqdn` for inspection.
- log with date of running the python automation will be created with commends that worked/failed

## ✅ Suggestions for Improvements

- Add unit tests and mocks for external calls.
- Implement retry mechanism on command failures.
- Support for additional platforms or protocols.
- Deploy as a service or container with a UI/dashboard.
