
# 🐳 Docker Vulnerability Scanner API

This project provides a lightweight FastAPI interface to interact with a PostgreSQL database containing vulnerability scan results for Docker images.

## 📦 Features

- Query vulnerabilities by CVE ID
- List vulnerabilities by Docker image and tag
- Risk scoring and fixed status detection
- Designed for open-source usage

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/docker-vuln-api.git
cd vuln_api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ Environment Variables

Create a `.env` file with your PostgreSQL credentials:

```
DB_NAME=docker_vuln_db
DB_USER=docker_scanner
DB_PASSWORD=docker123
DB_HOST=localhost
DB_PORT=5432
```

---

## ▶️ Running the API

```bash
python3 -m venv venv
source venv/bin/activate
uvicorn main:app --reload
```

Access the docs at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 📂 Endpoints Overview

### Get Vulnerability by CVE ID

**GET** `/vuln/{vuln_id}`

```bash
curl http://localhost:8000/vuln/CVE-2025-1234
```


### Get Vulnerabilities by Image

**GET** `/vulns/image/{image_name_tag}`

```bash
curl http://localhost:8000/vulns/image/nginx:stable-perl
```

---

## 🧪 Example Response

```json
{
  "vulnerability_id": "CVE-2025-1234",
  "title": "Example vuln",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "pkg_name": "openssl",
  "scanned_at": "2025-06-01T10:00:00",
  "installed_version": "1.0.2",
  "fixed_versions": "1.0.3",
  "description": "Buffer overflow in openssl",
  "published_date": "2025-05-30",
  "last_modified_date": "2025-06-01",
  "nvd_last_modified": "2025-06-02",
  "is_fixed": "No"
}
```


---

## 🧠 Maintainer

Andreea-Georgiana Tudor  
Faculty of Automatic Control and Computers  
University POLITEHNICA of Bucharest

