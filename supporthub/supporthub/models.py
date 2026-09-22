"""
SupportHub Data Models
Defines Pydantic data schemas for validation, serialization, 2FA Mobile Authentication, and RBAC.
"""

from typing import Optional, List, Literal
from pydantic import BaseModel, Field


# -----------------------------
# Auth & 2FA Models
# -----------------------------
class InitiateLoginRequest(BaseModel):
    emp_id: str = Field(..., description="Employee ID e.g. E-105")
    password: str = Field(..., min_length=1, description="Employee password")


class InitiateLoginResponse(BaseModel):
    step: str = "mobile_auth_required"
    emp_id: str
    name: str
    masked_phone: str
    auth_code_preview: str
    message: str = "Mobile Auth code has been sent to your registered mobile number."


class VerifyMobileAuthRequest(BaseModel):
    emp_id: str = Field(..., description="Employee ID e.g. E-105")
    auth_code: str = Field(..., min_length=4, max_length=10, description="6-digit verification code")


class ResendMobileAuthRequest(BaseModel):
    emp_id: str = Field(..., description="Employee ID e.g. E-105")


class AuthEmployeeInfo(BaseModel):
    id: str
    name: str
    role: str
    dept: str
    email: str
    phone: str = "+91 98765 00100"
    status: str
    lastLogin: str = Field(alias="last_login", default="—")
    lastLogout: str = Field(alias="last_logout", default="—")

    class Config:
        populate_by_name = True


class LoginRequest(BaseModel):
    emp_id: str = Field(..., description="Employee ID e.g. E-105")
    password: str = Field(..., min_length=1, description="Employee password")


class LoginResponse(BaseModel):
    success: bool
    employee: AuthEmployeeInfo
    permissions: List[str]
    token: str


class RolePermission(BaseModel):
    role: str
    modules: List[str]
    description: Optional[str] = ""


class RolePermissionUpdate(BaseModel):
    modules: List[str]
    description: Optional[str] = None


class PasswordResetRequest(BaseModel):
    new_password: str = Field(..., min_length=4, max_length=100, description="New password for employee")
    admin_id: str = Field(..., description="ID of Admin performing the reset")


# -----------------------------
# Employee Models
# -----------------------------
class EmployeeBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    role: str = Field(..., min_length=1, max_length=100)
    dept: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=3, max_length=255)
    phone: Optional[str] = Field(default="+91 98765 00100", max_length=30)


class EmployeeCreate(EmployeeBase):
    id: Optional[str] = None
    password: Optional[str] = "password123"
    status: Literal["online", "offline", "away"] = "offline"


class EmployeeUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    dept: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    status: Optional[Literal["online", "offline", "away"]] = None
    last_login: Optional[str] = None
    last_logout: Optional[str] = None


class EmployeeResponse(EmployeeBase):
    id: str
    status: str
    lastLogin: str = Field(alias="last_login", default="—")
    lastLogout: str = Field(alias="last_logout", default="—")
    permissions: Optional[List[str]] = []

    class Config:
        populate_by_name = True


# -----------------------------
# Ticket Models
# -----------------------------
class TicketCreate(BaseModel):
    id: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=500)
    requester: str = Field(..., min_length=1, max_length=255)
    priority: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    status: Literal["Open", "In Progress", "Resolved"] = "Open"
    assignee: str = "Unassigned"
    created: Optional[str] = None


class TicketStatusUpdate(BaseModel):
    status: Optional[Literal["Open", "In Progress", "Resolved"]] = None
    priority: Optional[Literal["Low", "Medium", "High", "Critical"]] = None
    assignee: Optional[str] = None


class TicketResponse(BaseModel):
    id: str
    title: str
    requester: str
    priority: str
    status: str
    assignee: str
    created: str


# -----------------------------
# Payroll Models
# -----------------------------
class PayrollCreate(BaseModel):
    employee_id: str = Field(..., min_length=1, max_length=50)
    pay_month: str = Field(..., pattern=r"^\d{4}-\d{2}$")
    basic_salary: float = Field(..., ge=0)
    hra: float = Field(0, ge=0)
    other_allowances: float = Field(0, ge=0)
    pf: float = Field(0, ge=0)
    esi: float = Field(0, ge=0)
    other_deductions: float = Field(0, ge=0)
    payment_status: Literal["Pending", "Processed", "Paid"] = "Pending"


class PayrollUpdate(BaseModel):
    basic_salary: Optional[float] = Field(None, ge=0)
    hra: Optional[float] = Field(None, ge=0)
    other_allowances: Optional[float] = Field(None, ge=0)
    pf: Optional[float] = Field(None, ge=0)
    esi: Optional[float] = Field(None, ge=0)
    other_deductions: Optional[float] = Field(None, ge=0)
    payment_status: Optional[Literal["Pending", "Processed", "Paid"]] = None


class PayrollResponse(BaseModel):
    id: str
    employee_id: str
    employee_name: str
    pay_month: str
    basic_salary: float
    hra: float
    other_allowances: float
    gross_salary: float
    pf: float
    esi: float
    other_deductions: float
    total_deductions: float
    net_salary: float
    payment_status: str
    created_at: str
    updated_at: str


# -----------------------------
# Offer Letter Models
# -----------------------------
class OfferCreate(BaseModel):
    id: Optional[str] = None
    candidate: str = Field(..., min_length=1, max_length=255)
    role: str = Field(..., min_length=1, max_length=255)
    dept: str = Field(default="Engineering", max_length=100)
    status: Literal["Draft", "Sent", "Accepted", "Declined"] = "Draft"
    date: Optional[str] = None


class OfferStatusUpdate(BaseModel):
    status: Literal["Draft", "Sent", "Accepted", "Declined"]


class OfferResponse(BaseModel):
    id: str
    candidate: str
    role: str
    dept: str
    status: str
    date: str


# -----------------------------
# Activity Log Models
# -----------------------------
class ActivityLogCreate(BaseModel):
    emp: str
    action: Literal["login", "logout"]
    time: str
    date: str = "Today"


class ActivityLogResponse(BaseModel):
    id: int
    emp: str
    action: str
    time: str
    date: str


# -----------------------------
# Dashboard Aggregate Models
# -----------------------------
class StatSummary(BaseModel):
    totalTickets: int
    openTickets: int
    inProgressTickets: int
    resolvedTickets: int
    totalEmployees: int
    activeEmployees: int
    adminCount: int
    weeklyTrend: list[dict]
    priorityBreakdown: list[dict]
