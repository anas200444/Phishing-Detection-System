import os
import sys
import uvicorn
import requests
import re
from fastapi import FastAPI, Request, Form, UploadFile, File, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import urljoin
from typing import Optional
from io import StringIO
import csv
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

sub_folders = ["URL", "IP_Address", "Email", "Phone", "SMS", "qr", "backend"]
for folder in sub_folders:
    folder_path = os.path.join(current_dir, folder)
    if folder_path not in sys.path:
        sys.path.append(folder_path)

try:
    from Email import check_email
    from IP_Address import IP_check
    from Phone import check_phone
    from URL import check_url
    from SMS import check_sms
    from qr import check_qr
except Exception as e:
    print(f" ML Modules failed to load: {e}")

try:
    from backend.firestore_reports import (
        verify_firebase_token,
        list_reported_indicators,
        update_report_status,
        export_reports_csv_rows,
        get_indicator_report_summary,
    )
except Exception as e:
    print(f" Firestore report module failed to load: {e}")

app = FastAPI(title="Multi-Vector Analysis Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

USER_ONLY_PAGES = {"email", "ip", "phone", "url", "sms", "qr", "report"}
ADMIN_ALLOWED_PAGES = {"dashboard", "login"}


def resolve_final_url(url: str, max_redirects: int = 15):
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return url

    current_url = url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    visited = set([current_url])

    for _ in range(max_redirects):
        try:
            resp = requests.get(current_url, headers=headers, allow_redirects=False, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"Redirect resolution error at {current_url}: {e}")
            return current_url

        next_url = None

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if location:
                next_url = urljoin(current_url, location)

        elif resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", "").lower():
            html = resp.text

            meta_match = re.search(
                r'(?i)<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=["\']?([^"\'>]+)["\']?',
                html
            )

            if meta_match:
                next_url = urljoin(current_url, meta_match.group(1).strip())
            else:
                js_match = re.search(
                    r'(?i)window\.location\.(?:replace|href)\s*=?\s*["\']([^"\']+)["\']',
                    html
                )
                if js_match:
                    next_url = urljoin(current_url, js_match.group(1).strip())

        if next_url:
            if not (next_url.startswith("http://") or next_url.startswith("https://")):
                return next_url

            if next_url in visited:
                break

            visited.add(next_url)
            current_url = next_url
        else:
            break

    return current_url


def get_admin_emails():
    return [
        email.strip().lower()
        for email in os.getenv("ADMIN_EMAILS", "").split(",")
        if email.strip()
    ]


def is_admin_email(email: str) -> bool:
    admin_emails = get_admin_emails()
    return bool(email) and email.strip().lower() in admin_emails


def get_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Firebase ID token.")

    return authorization.replace("Bearer ", "").strip()


def decode_token_or_raise(token: str):
    try:
        return verify_firebase_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.")


def require_admin_user(authorization: Optional[str]):
    token = get_bearer_token(authorization)
    user = decode_token_or_raise(token)

    user_email = (user.get("email") or "").lower()

    if not is_admin_email(user_email):
        raise HTTPException(status_code=403, detail="Admin access required.")

    return user


def get_user_from_session_cookie(request: Request):
    session_token = request.cookies.get("firebase_id_token")

    if not session_token:
        return None

    try:
        return verify_firebase_token(session_token)
    except Exception:
        return None


def request_user_is_admin(request: Request) -> bool:
    user = get_user_from_session_cookie(request)

    if not user:
        return False

    user_email = (user.get("email") or "").lower()
    return is_admin_email(user_email)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/{page}", response_class=HTMLResponse)
async def serve_page(request: Request, page: str):
    valid_pages = [
        "dashboard",
        "email",
        "ip",
        "phone",
        "url",
        "sms",
        "qr",
        "login",
        "report",
    ]

    if page not in valid_pages:
        return HTMLResponse("Page not found", status_code=404)

    # Backend protection:
    # If logged-in admin tries to open any user-only scanner/report page manually,
    # redirect to admin dashboard.
    if page in USER_ONLY_PAGES and request_user_is_admin(request):
        return RedirectResponse(url="/", status_code=302)

    # If admin is already logged in and opens /login manually, redirect to dashboard.
    if page == "login" and request_user_is_admin(request):
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse(request, f"{page}.html")


@app.get("/api/auth/role")
async def api_auth_role(authorization: Optional[str] = Header(None)):
    token = get_bearer_token(authorization)
    user = decode_token_or_raise(token)

    user_email = (user.get("email") or "").lower()

    return {
        "success": True,
        "uid": user.get("uid"),
        "email": user_email,
        "is_admin": is_admin_email(user_email),
    }


@app.post("/api/auth/session")
async def api_auth_session(request: Request, authorization: Optional[str] = Header(None)):
    token = get_bearer_token(authorization)
    user = decode_token_or_raise(token)

    response = JSONResponse({
        "success": True,
        "uid": user.get("uid"),
        "email": user.get("email"),
        "is_admin": is_admin_email((user.get("email") or "").lower()),
    })

    response.set_cookie(
        key="firebase_id_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )

    return response


@app.post("/api/auth/logout")
async def api_auth_logout():
    response = JSONResponse({"success": True})
    response.delete_cookie("firebase_id_token", path="/")
    return response


@app.post("/api/analyze/email")
async def analyze_email(email: str = Form(...)):
    return check_email.evaluate_email(email)


@app.post("/api/analyze/ip")
async def analyze_ip(ip: str = Form(...)):
    return IP_check.evaluate_ip(ip)


@app.post("/api/analyze/phone")
async def analyze_phone(phone: str = Form(...)):
    return check_phone.check_phone_number(phone)


@app.post("/api/analyze/url")
async def analyze_url(url: str = Form(...)):
    resolved_url = resolve_final_url(url)
    lower_url = resolved_url.lower()

    if lower_url.startswith("mailto:"):
        return check_email.evaluate_email(resolved_url[7:])

    if lower_url.startswith("tel:"):
        return check_phone.check_phone_number(resolved_url[4:])

    if lower_url.startswith("sms:") or lower_url.startswith("smsto:"):
        clean_sms = re.sub(r"^(sms:|smsto:)", "", resolved_url, flags=re.IGNORECASE)
        return check_sms.evaluate_sms(clean_sms)

    return check_url.evaluate_url(resolved_url)


@app.post("/api/analyze/sms")
async def analyze_sms(sms: str = Form(...)):
    return check_sms.evaluate_sms(sms)


@app.post("/api/analyze/qr_upload")
async def analyze_qr_upload(file: UploadFile = File(...)):
    contents = await file.read()
    result = check_qr.extract_qr_payload(contents)

    if result.get("success"):
        payload = result["payload"]
        final_payload = resolve_final_url(payload)

        return {
            "success": True,
            "payload": final_payload,
            "original_payload": payload if final_payload != payload else None
        }

    return JSONResponse(result)


@app.get("/api/reports")
async def api_list_reports(
    indicator_type: str = Query("all"),
    authorization: Optional[str] = Header(None),
):
    require_admin_user(authorization)
    reports = list_reported_indicators(indicator_type)
    return {"success": True, "reports": reports}


@app.patch("/api/reports/{collection_name}/{document_id}/status")
async def api_update_report_status(
    collection_name: str,
    document_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    admin_user = require_admin_user(authorization)
    body = await request.json()

    new_status = body.get("status")
    notes = body.get("review_notes", "")

    result = update_report_status(
        collection_name=collection_name,
        document_id=document_id,
        new_status=new_status,
        reviewed_by=admin_user.get("uid"),
        reviewed_by_email=admin_user.get("email"),
        review_notes=notes,
    )

    return {"success": True, "result": result}


@app.get("/api/reports/export.csv")
async def api_export_reports_csv(
    indicator_type: str = Query("all"),
    authorization: Optional[str] = Header(None),
):
    require_admin_user(authorization)

    rows = export_reports_csv_rows(indicator_type)

    output = StringIO()
    fieldnames = [
        "collection_name",
        "document_id",
        "indicator_type",
        "indicator_label",
        "indicator_value",
        "report_count",
        "status",
        "reported_by",
        "reported_by_email",
        "timestamp",
        "reviewed_by",
        "reviewed_by_email",
        "reviewed_at",
        "review_notes",
        "source",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=reported_indicators.csv"
        },
    )


@app.get("/api/reports/count")
async def api_report_count(
    indicator_value: str = Query(...),
    indicator_type: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
):
    require_admin_user(authorization)
    summary = get_indicator_report_summary(indicator_value, indicator_type)
    return {"success": True, "summary": summary}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)