-- ==========================================================
-- SupportHub SQL Database Schema (ANSI SQL / SQLite / Postgres)
-- Role-Based Access Control (RBAC) & 2FA Mobile Authentication Schema
-- ==========================================================

-- 1. Employees Table
CREATE TABLE IF NOT EXISTS employees (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL,
    dept VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(30) NOT NULL DEFAULT '+91 98765 00100',
    password VARCHAR(255) NOT NULL DEFAULT 'password123',
    status VARCHAR(20) NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'away')),
    last_login VARCHAR(50) DEFAULT '—',
    last_logout VARCHAR(50) DEFAULT '—',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Role Permissions Table
CREATE TABLE IF NOT EXISTS role_permissions (
    role VARCHAR(100) PRIMARY KEY,
    modules TEXT NOT NULL,
    description VARCHAR(255)
);

-- 3. Mobile Auth Codes Table (2FA OTP)
CREATE TABLE IF NOT EXISTS mobile_auth_codes (
    emp_id VARCHAR(50) PRIMARY KEY,
    code VARCHAR(10) NOT NULL,
    phone VARCHAR(30) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Tickets / Issues Table
CREATE TABLE IF NOT EXISTS tickets (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    requester VARCHAR(255) NOT NULL,
    priority VARCHAR(20) NOT NULL CHECK (priority IN ('Low', 'Medium', 'High', 'Critical')),
    status VARCHAR(30) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'In Progress', 'Resolved')),
    assignee VARCHAR(255) NOT NULL DEFAULT 'Unassigned',
    created VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

-- 5. Offers / Candidate Offers Table
CREATE TABLE IF NOT EXISTS offers (
    id VARCHAR(50) PRIMARY KEY,
    candidate VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    dept VARCHAR(100) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Sent', 'Accepted', 'Declined')),
    date VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Payroll Table
CREATE TABLE IF NOT EXISTS payroll (
    id VARCHAR(50) PRIMARY KEY,
    employee_id VARCHAR(50) NOT NULL,
    pay_month VARCHAR(7) NOT NULL,
    basic_salary REAL NOT NULL DEFAULT 0,
    hra REAL NOT NULL DEFAULT 0,
    other_allowances REAL NOT NULL DEFAULT 0,
    gross_salary REAL NOT NULL DEFAULT 0,
    pf REAL NOT NULL DEFAULT 0,
    esi REAL NOT NULL DEFAULT 0,
    other_deductions REAL NOT NULL DEFAULT 0,
    total_deductions REAL NOT NULL DEFAULT 0,
    net_salary REAL NOT NULL DEFAULT 0,
    payment_status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK (payment_status IN ('Pending', 'Processed', 'Paid')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(employee_id, pay_month)
);

-- 7. Activity Logs Table
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emp VARCHAR(255) NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('login', 'logout')),
    time VARCHAR(50) NOT NULL,
    date VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================================
-- Initial Seed Data
-- ==========================================================

-- Default Role Permissions (RBAC Matrix)
INSERT OR REPLACE INTO role_permissions (role, modules, description) VALUES
('Admin', '["dashboard", "tracker", "employee", "admin", "offer"]', 'Full system access to all modules and configurations'),
('Support Engineer', '["dashboard", "tracker", "employee"]', 'Support team access for resolving issues and viewing directory'),
('HR Executive', '["dashboard", "tracker", "employee", "offer"]', 'HR access for recruitment offers and employee operations'),
('QA Analyst', '["dashboard", "tracker", "employee"]', 'Quality assurance access for logging & tracking issues'),
('Engineering Lead', '["dashboard", "tracker", "employee"]', 'Engineering access for technical issue management');

-- Default Seed Employees with registered Mobile Numbers & default password 'password123'
INSERT OR IGNORE INTO employees (id, name, role, dept, email, phone, password, status, last_login, last_logout) VALUES
('E-101', 'Ananya Rao', 'Support Engineer', 'IT Support', 'ananya.rao@company.com', '+91 98765 00101', 'password123', 'online', '09:02 AM', '—'),
('E-102', 'Vikram Sethi', 'QA Analyst', 'Quality', 'vikram.sethi@company.com', '+91 98765 00102', 'password123', 'online', '08:47 AM', '—'),
('E-103', 'Divya Menon', 'HR Executive', 'Human Resources', 'divya.menon@company.com', '+91 98765 00103', 'password123', 'offline', '08:55 AM', '06:12 PM'),
('E-104', 'Rahul Iyer', 'Support Engineer', 'IT Support', 'rahul.iyer@company.com', '+91 98765 00104', 'password123', 'offline', '09:11 AM', '05:40 PM'),
('E-105', 'Neha Kapoor', 'Admin', 'Operations', 'neha.kapoor@company.com', '+91 98765 00105', 'admin123', 'online', '08:30 AM', '—'),
('E-106', 'Arjun Das', 'Support Engineer', 'IT Support', 'arjun.das@company.com', '+91 98765 00106', 'password123', 'away', '09:20 AM', '—');

-- Default Tickets
INSERT OR IGNORE INTO tickets (id, title, requester, priority, status, assignee, created) VALUES
('TCK-2041', 'VPN disconnects every 20 minutes', 'Priya Nair', 'High', 'Open', 'Ananya Rao', 'Sep 3'),
('TCK-2040', 'Cannot access shared drive', 'Sanjay Gupta', 'Medium', 'In Progress', 'Rahul Iyer', 'Sep 3'),
('TCK-2039', 'Laptop won''t boot past login screen', 'Meera Pillai', 'Critical', 'In Progress', 'Arjun Das', 'Sep 2'),
('TCK-2038', 'Request for second monitor', 'Karan Malhotra', 'Low', 'Resolved', 'Ananya Rao', 'Sep 2'),
('TCK-2037', 'Outlook not syncing new emails', 'Fatima Sheikh', 'Medium', 'Resolved', 'Vikram Sethi', 'Sep 1'),
('TCK-2036', 'Password reset for HRMS portal', 'Ibrahim Khan', 'Low', 'Resolved', 'Rahul Iyer', 'Sep 1'),
('TCK-2035', 'Printer offline on 3rd floor', 'Ritu Chawla', 'Medium', 'Open', 'Unassigned', 'Sep 4'),
('TCK-2034', 'Zoom crashing during calls', 'Amit Bhatt', 'High', 'In Progress', 'Arjun Das', 'Sep 4');

-- Default Candidate Offers
INSERT OR IGNORE INTO offers (id, candidate, role, dept, status, date) VALUES
('OFR-118', 'Sneha Kulkarni', 'Frontend Developer', 'Engineering', 'Sent', 'Sep 3'),
('OFR-117', 'Rohan Verma', 'QA Engineer', 'Quality', 'Accepted', 'Aug 29'),
('OFR-116', 'Ayesha Siddiqui', 'HR Coordinator', 'Human Resources', 'Draft', 'Sep 4'),
('OFR-115', 'Karthik Subramaniam', 'DevOps Engineer', 'Engineering', 'Accepted', 'Aug 26'),
('OFR-114', 'Lavanya Reddy', 'Support Engineer', 'IT Support', 'Declined', 'Aug 22');

-- Default Activity Logs
INSERT OR IGNORE INTO activity_logs (id, emp, action, time, date) VALUES
(1, 'Ananya Rao', 'login', '09:02 AM', 'Today'),
(2, 'Divya Menon', 'logout', '06:12 PM', 'Yesterday'),
(3, 'Vikram Sethi', 'login', '08:47 AM', 'Today'),
(4, 'Rahul Iyer', 'logout', '05:40 PM', 'Yesterday'),
(5, 'Neha Kapoor', 'login', '08:30 AM', 'Today'),
(6, 'Arjun Das', 'login', '09:20 AM', 'Today'),
(7, 'Rahul Iyer', 'login', '09:11 AM', 'Today');
