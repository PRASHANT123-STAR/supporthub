# SupportHub — Full-Stack IT Operations Portal with 2FA & RBAC

SupportHub is an IT operations portal built with React, FastAPI, SQLite, Role-Based Access Control (RBAC), and Mobile Two-Factor Authentication (2FA).

---

## 📁 Project Structure

```
supporthub/
├── schema.sql           # ANSI SQL Database Schema & Seed Data (employees, tickets, offers, activity_logs, mobile_auth_codes)
├── models.py            # Pydantic & Data Models with validation
├── database.py          # SQL Database Access Layer (Connection, CRUD, 2FA OTP, RBAC permissions)
├── server.py            # FastAPI REST API Backend & Static Web Server
├── supporthub.db        # SQLite Database (seeded with employees, tickets, RBAC)
├── requirements.txt     # Python dependencies (fastapi, uvicorn, pydantic)
├── start.bat            # Windows 1-click launcher
├── test_endpoints.py    # Automated test script for all endpoints & 2FA
└── public/
    └── index.html       # Single-Page React 18 + Babel + Recharts + Lucide UI
```

---

## 🚀 How to Open & Run in Your Personal IDE (VS Code, PyCharm, Cursor, etc.)

### 1. Extract the Zip File
Extract `supporthub.zip` into any folder on your machine.

### 2. Open Folder in Your IDE
- In **VS Code**: `File` -> `Open Folder...` -> Select the extracted `supporthub` folder.
- In **PyCharm**: `File` -> `Open...` -> Select the `supporthub` directory.

### 3. Install Dependencies
Open the integrated terminal in your IDE and run:
```bash
python -m pip install -r requirements.txt
```

### 4. Run the Server
Option A (Terminal):
```bash
python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```
Option B (Windows double-click):
Double-click `start.bat`.

### 5. Access the Web App
- **Web App**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔐 Preset Credentials for Testing

| Role | Employee ID | Password | Registered Mobile | Module Permissions |
|---|---|---|---|---|
| **Admin** | `E-105` | `admin123` | `+91 98765 00105` | Full Access (Dashboard, Tracker, Employees, Admin & Perms, Offer Letters, Password Reset) |
| **Support Engineer** | `E-101` | `password123` | `+91 98765 00101` | Dashboard, Issue Tracker, Employee Directory |
| **QA Analyst** | `E-102` | `password123` | `+91 98765 00102` | Dashboard, Issue Tracker, Employee Directory |
| **HR Executive** | `E-103` | `password123` | `+91 98765 00103` | Dashboard, Issue Tracker, Employee Directory, Offer Letters |

> **Note on 2FA:** After entering your Employee ID and Password, the system will prompt for a 6-digit Mobile Auth OTP sent to your registered phone number. In demo mode, a simulated SMS notification banner appears on the login screen showing the OTP for one-click verification.
