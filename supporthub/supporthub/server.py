"""
SupportHub Full-Stack FastAPI Server
Provides RESTful APIs with Authentication, Role-Based Access Control (RBAC), and SQL Database Operations.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import database
from models import (
    InitiateLoginRequest,
    InitiateLoginResponse,
    VerifyMobileAuthRequest,
    ResendMobileAuthRequest,
    LoginRequest,
    LoginResponse,
    RolePermission,
    RolePermissionUpdate,
    PasswordResetRequest,
    EmployeeCreate,
    EmployeeUpdate,
    EmployeeResponse,
    TicketCreate,
    TicketStatusUpdate,
    TicketResponse,
    OfferCreate,
    OfferStatusUpdate,
    OfferResponse,
    ActivityLogCreate,
    ActivityLogResponse,
    PayrollCreate,
    PayrollUpdate,
    PayrollResponse,
)

BASE_DIR = Path(__file__).parent
PUBLIC_DIR = BASE_DIR / "public"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQL database & seed data on startup
    database.init_db()
    print("[OK] SupportHub SQL Database initialized successfully with 2FA Mobile Auth.")
    yield


app = FastAPI(
    title="SupportHub API",
    description="Full-stack SupportHub REST API with 2FA Mobile Authentication and Role-Based Permissions connected to SQL database",
    version="2.1.0",
    lifespan=lifespan,
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================
# 2FA MOBILE AUTHENTICATION & RBAC ENDPOINTS
# =============================================================
@app.post("/api/auth/initiate-login", response_model=InitiateLoginResponse, summary="Step 1: Validate Emp ID + Password & Send Mobile Auth Code")
def initiate_login(req: InitiateLoginRequest):
    emp = database.verify_employee_credentials(req.emp_id, req.password)
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Employee ID or password. (Hint: Try E-105 with admin123 or E-101 with password123)"
        )

    auth_info = database.generate_mobile_auth_code(req.emp_id)
    if not auth_info:
        raise HTTPException(status_code=500, detail="Failed to generate Mobile Auth Code.")

    return {
        "step": "mobile_auth_required",
        "emp_id": emp["id"],
        "name": emp["name"],
        "masked_phone": auth_info["masked_phone"],
        "auth_code_preview": auth_info["auth_code"],
        "message": f"Auth code sent to registered mobile number: {auth_info['masked_phone']}"
    }


@app.post("/api/auth/verify-mobile-auth", response_model=LoginResponse, summary="Step 2: Verify Mobile Auth Code (OTP)")
def verify_mobile_auth(req: VerifyMobileAuthRequest):
    auth_result = database.verify_mobile_auth_code(req.emp_id, req.auth_code)
    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired Mobile Auth code. Please check your SMS or resend code."
        )

    return {
        "success": True,
        "employee": auth_result["employee"],
        "permissions": auth_result["permissions"],
        "token": auth_result["token"]
    }


@app.post("/api/auth/resend-mobile-auth", response_model=InitiateLoginResponse, summary="Resend fresh Mobile Auth code")
def resend_mobile_auth(req: ResendMobileAuthRequest):
    auth_info = database.generate_mobile_auth_code(req.emp_id)
    if not auth_info:
        raise HTTPException(status_code=404, detail="Employee not found")

    return {
        "step": "mobile_auth_required",
        "emp_id": auth_info["emp_id"],
        "name": auth_info["name"],
        "masked_phone": auth_info["masked_phone"],
        "auth_code_preview": auth_info["auth_code"],
        "message": f"Fresh Auth code sent to mobile number: {auth_info['masked_phone']}"
    }


@app.post("/api/auth/login", response_model=LoginResponse, summary="Direct Login fallback")
def direct_login(req: LoginRequest):
    auth_result = database.authenticate_employee(req.emp_id, req.password)
    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Employee ID or password."
        )
    return {
        "success": True,
        "employee": auth_result["employee"],
        "permissions": auth_result["permissions"],
        "token": auth_result["token"]
    }


@app.post("/api/auth/logout", summary="Log out employee session")
def logout(payload: dict):
    emp_id = payload.get("emp_id")
    if not emp_id:
        raise HTTPException(status_code=400, detail="emp_id is required")
    database.logout_employee(emp_id)
    return {"success": True, "message": f"Logged out employee {emp_id}"}


@app.get("/api/permissions", response_model=List[RolePermission], summary="Get all role permission mappings")
def get_permissions():
    return database.get_all_role_permissions()


@app.put("/api/permissions/{role}", summary="Update module permissions for a role (Admin only)")
def update_permissions(role: str, payload: RolePermissionUpdate):
    return database.update_role_permissions(role, payload.modules, payload.description)


# =============================================================
# DASHBOARD STATS
# =============================================================
@app.get("/api/dashboard/stats", summary="Get dashboard summary and metrics")
def get_dashboard_stats():
    return database.get_dashboard_stats()


# =============================================================
# TICKET ENDPOINTS
# =============================================================
@app.get("/api/tickets", response_model=List[TicketResponse], summary="List all tickets")
def list_tickets():
    return database.get_all_tickets()


@app.post("/api/tickets", response_model=TicketResponse, status_code=status.HTTP_201_CREATED, summary="Create a new ticket")
def create_ticket(ticket: TicketCreate):
    created = database.create_ticket(ticket.model_dump())
    return created


@app.get("/api/tickets/{ticket_id}", response_model=TicketResponse, summary="Get ticket by ID")
def get_ticket(ticket_id: str):
    ticket = database.get_ticket_by_id(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.patch("/api/tickets/{ticket_id}/status", response_model=TicketResponse, summary="Update ticket status / cycle status")
def update_ticket_status(ticket_id: str, payload: Optional[TicketStatusUpdate] = None):
    ticket = database.get_ticket_by_id(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if payload and payload.status:
        new_status = payload.status
    else:
        order = ["Open", "In Progress", "Resolved"]
        curr_idx = order.index(ticket["status"]) if ticket["status"] in order else 0
        new_status = order[(curr_idx + 1) % len(order)]

    updated = database.update_ticket(ticket_id, {"status": new_status})
    return updated


@app.delete("/api/tickets/{ticket_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete ticket")
def delete_ticket(ticket_id: str):
    success = database.delete_ticket(ticket_id)
    if not success:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return None


# =============================================================
# EMPLOYEE ENDPOINTS
# =============================================================
@app.get("/api/employees", response_model=List[EmployeeResponse], summary="List all employees with role permissions")
def list_employees():
    return database.get_all_employees()


@app.post("/api/employees/bulk-import", summary="Bulk import employees from CSV or XLSX")
async def bulk_import_employees(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()
    if not (filename.endswith(".csv") or filename.endswith(".xlsx")):
        raise HTTPException(status_code=400, detail="Only CSV and XLSX files are supported.")

    content = await file.read()
    try:
        result = database.bulk_create_employees_from_file(content, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Bulk import failed: {exc}")

    return result


@app.get("/api/employees/import-template", summary="Download employee import CSV template")
def employee_import_template():
    from fastapi.responses import Response
    csv_text = "employee_id,name,email,phone,department,role,password\nE-106,Rahul Sharma,rahul@example.com,+91 98765 00106,IT Support,Support Engineer,password123\n"
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="employee_import_template.csv"'}
    )


@app.post("/api/employees", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED, summary="Add new employee with auto ID")
def create_employee(emp: EmployeeCreate):
    try:
        created = database.create_employee(emp.model_dump())
        return created
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create employee: {str(e)}")


@app.get("/api/employees/{emp_id}", response_model=EmployeeResponse, summary="Get employee by ID")
def get_employee(emp_id: str):
    emp = database.get_employee_by_id(emp_id)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp


@app.patch("/api/employees/{emp_id}", response_model=EmployeeResponse, summary="Update employee")
def update_employee(emp_id: str, updates: EmployeeUpdate):
    data = updates.model_dump(exclude_unset=True)
    emp = database.update_employee(emp_id, data)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp


@app.post("/api/employees/{emp_id}/toggle-status", response_model=EmployeeResponse, summary="Toggle employee online/offline")
def toggle_employee_status(emp_id: str):
    emp = database.get_employee_by_id(emp_id)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    new_status = "offline" if emp["status"] == "online" else "online"
    time_str = "09:00 AM"
    updates = {"status": new_status}
    if new_status == "online":
        updates["last_login"] = time_str
        database.create_activity_log({"emp": emp["name"], "action": "login", "time": time_str, "date": "Today"})
    else:
        updates["last_logout"] = time_str
        database.create_activity_log({"emp": emp["name"], "action": "logout", "time": time_str, "date": "Today"})

    return database.update_employee(emp_id, updates)


@app.post("/api/employees/{emp_id}/reset-password", summary="Reset employee password (Admin only)")
def reset_password(emp_id: str, req: PasswordResetRequest):
    success = database.reset_employee_password(emp_id, req.new_password, req.admin_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized or Employee not found. Only administrators can reset employee passwords."
        )
    return {"success": True, "message": f"Password for employee {emp_id} has been reset successfully."}


@app.delete("/api/employees/{emp_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete employee")
def delete_employee(emp_id: str):
    success = database.delete_employee(emp_id)
    if not success:
        raise HTTPException(status_code=404, detail="Employee not found")
    return None


# =============================================================
# PAYROLL ENDPOINTS
# =============================================================
@app.get("/api/payroll", response_model=List[PayrollResponse], summary="List employee payroll records")
def list_payroll():
    return database.get_all_payroll()


@app.post("/api/payroll", response_model=PayrollResponse, status_code=status.HTTP_201_CREATED, summary="Create monthly payroll")
def create_payroll(payroll: PayrollCreate):
    try:
        return database.create_payroll(payroll.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create payroll: {exc}")


@app.patch("/api/payroll/{payroll_id}", response_model=PayrollResponse, summary="Update payroll or payment status")
def update_payroll(payroll_id: str, updates: PayrollUpdate):
    try:
        updated = database.update_payroll(payroll_id, updates.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Payroll record not found")
    return updated


@app.delete("/api/payroll/{payroll_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete payroll record")
def delete_payroll(payroll_id: str):
    if not database.delete_payroll(payroll_id):
        raise HTTPException(status_code=404, detail="Payroll record not found")
    return None


# =============================================================
# OFFER LETTER ENDPOINTS
# =============================================================
@app.get("/api/offers", response_model=List[OfferResponse], summary="List all offer letters")
def list_offers():
    return database.get_all_offers()


@app.post("/api/offers", response_model=OfferResponse, status_code=status.HTTP_201_CREATED, summary="Create offer draft")
def create_offer(offer: OfferCreate):
    return database.create_offer(offer.model_dump())


@app.patch("/api/offers/{offer_id}/advance", response_model=OfferResponse, summary="Advance offer status")
def advance_offer_status(offer_id: str):
    offer = database.get_offer_by_id(offer_id)
    if not offer:
        raise HTTPException(status_code=404, detail="Offer not found")

    order = ["Draft", "Sent", "Accepted"]
    if offer["status"] in order:
        curr_idx = order.index(offer["status"])
        next_status = order[min(curr_idx + 1, len(order) - 1)]
    else:
        next_status = "Sent"

    return database.update_offer(offer_id, {"status": next_status})


@app.delete("/api/offers/{offer_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete offer")
def delete_offer(offer_id: str):
    success = database.delete_offer(offer_id)
    if not success:
        raise HTTPException(status_code=404, detail="Offer not found")
    return None


# =============================================================
# ACTIVITY LOG ENDPOINTS
# =============================================================
@app.get("/api/activity-logs", response_model=List[ActivityLogResponse], summary="List recent activity logs")
def list_activity_logs(limit: int = 20):
    return database.get_all_activity_logs(limit=limit)


@app.post("/api/activity-logs", response_model=ActivityLogResponse, status_code=status.HTTP_201_CREATED, summary="Add activity log entry")
def create_activity_log(log: ActivityLogCreate):
    return database.create_activity_log(log.model_dump())


# =============================================================
# STATIC UI SERVING
# =============================================================
if PUBLIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(PUBLIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
def serve_index():
    index_file = PUBLIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "SupportHub API is running. Access /docs for interactive Swagger UI."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

