import os
import sys
import uvicorn
import requests
import re
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import urljoin


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

sub_folders = ["URL", "IP_Address", "Email", "Phone", "SMS", "qr"]
for folder in sub_folders:
    folder_path = os.path.join(current_dir, folder)
    if folder_path not in sys.path:
        sys.path.insert(0, folder_path)

# ---  Imports ---
try:
    from Email import check_email 
    from IP_Address import IP_check 
    from Phone import check_phone 
    from URL import check_url
    from SMS import check_sms
    from qr import check_qr  
except Exception as e:
    print(f" ML Modules failed to load: {e}")

app = FastAPI(title="Multi-Vector Analysis Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def resolve_final_url(url: str, max_redirects: int = 15):
    """
     redirects  until the final destination.
    """
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return url

    current_url = url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
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
        elif resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', '').lower():
            html = resp.text
            meta_match = re.search(r'(?i)<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=["\']?([^"\'>]+)["\']?', html)
            if meta_match:
                next_url = urljoin(current_url, meta_match.group(1).strip())
            else:
                js_match = re.search(r'(?i)window\.location\.(?:replace|href)\s*=?\s*["\']([^"\']+)["\']', html)
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

# --- Frontend Routes ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")

@app.get("/{page}", response_class=HTMLResponse)
async def serve_page(request: Request, page: str):
    valid_pages = ["dashboard", "email", "ip", "phone", "url", "sms", "qr", "login"]
    if page in valid_pages:
        return templates.TemplateResponse(request, f"{page}.html")
    return HTMLResponse("Page not found", status_code=404)


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
    elif lower_url.startswith("tel:"):
        return check_phone.check_phone_number(resolved_url[4:])
    elif lower_url.startswith("sms:") or lower_url.startswith("smsto:"):
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)