# JWT-auditor

# 🔐 JWT Security Auditor

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.2-green)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

A **comprehensive web-based tool** for auditing **JSON Web Tokens (JWTs)** to detect security issues, weak secrets, vulnerable algorithms, and suspicious claims.  

This tool is designed for **developers, security researchers, and penetration testers** to quickly evaluate JWT security in APIs and web applications.

---

## 🔍 Project Overview

JWTs are widely used for authentication and authorization in web apps and APIs. However, many developers implement JWTs insecurely:

- Using **alg=none** (no signature)  
- Using **weak secret keys** (HMAC)  
- Using **deprecated or unsupported algorithms**  
- Very **long token expiration**  
- Assigning sensitive roles (admin, superuser) without proper validation  

This project helps identify these issues and provides **recommendations** to secure your JWTs.

---

## 🚀 Features

- **Decode JWT** header, payload, and signature  
- **Detect vulnerable algorithms** (`none`, weak HMAC, etc.)  
- **Check expiration (`exp`) and issued-at (`iat`) claims**  
- Identify **suspicious claims** like `admin=true` or `role=root`  
- **Weak secret key brute-force** with custom wordlists  
- Clean **web interface** using modern glassmorphism design  
- Optionally **generate PDF reports** of audit results  
- Fully **portable** using `requirements.txt`  

---

## 🏗️ Architecture

┌───────────────────┐        ┌────────────────────────┐        ┌───────────────────────┐
│                   │ HTTP   │                        │  JWT   │                       │
│  Client Browser   ├──────▶│    Flask Web Server     ├──────▶│  JWT Audit Module     │
│                   │        │  (Frontend + Backend)  │        │  (Decoder & Analyzer) │
└───────────────────┘        └────────────────────────┘        └───────────────────────┘


- **Frontend**: HTML + CSS, responsive design  
- **Backend**: Python Flask  
- **Audit Module**: JWT decoding, security checks, weak secret brute-force  

---

## ⚡ Installation

1️⃣ **Clone the repository**

```bash
git clone https://github.com/SecHawkX/jwt-auditor
cd jwt-auditor
