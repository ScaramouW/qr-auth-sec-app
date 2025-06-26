# 🔐 Dynamic QR Code Anti-Replay Authenticator & OWASP Hardened Backend

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Framework: Laravel / Vue.js / Ionic](https://img.shields.io/badge/Framework-Laravel_%7C_Vue.js_%7C_Ionic-purple.svg)]()

## 📌 Project Overview
This repository contains the full implementation of a **dynamic QR Code attendance authentication system** protected against replay attacks, coupled with an **OWASP Top 10 hardened Laravel/PHP backend**.

---

## 🛠️ Security Features
1. **Dynamic QR Code Tokens**: Time-bounded HMAC-SHA256 tokens preventing static screen captures or attendance proxying.
2. **Anti-SQL Injection**: Strict PDO prepared statements and input sanitization across all API endpoints.
3. **Role-Based Access Control (RBAC)**: Fine-grained permission middleware separating Administrator, Instructor, and Student roles.
4. **Session Security**: Session token rotation, HttpOnly/SameSite cookie flags, and CSRF token protection.

---

## 📁 Repository Structure
```
qr-auth-sec-app/
├── README.md
├── backend/
│   └── qr_auth_controller.php     # Laravel Controller handling QR token generation & validation
├── mobile/
│   └── QrScannerComponent.vue     # Vue.js / Ionic dynamic QR Code scanner interface
└── .gitignore
```

---

## 👤 Author
- **Author:** Fahd BELHIBA
- **GitHub:** [@ScaramouW](https://github.com/ScaramouW)
